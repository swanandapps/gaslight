#!/usr/bin/env python3
"""Tier 2 hunt driver: point gaslight at many real, independently-built MCP
servers, each in a locked-down container, and collect what fires.

Isolation model (simpler than the earlier host-sink + socat-proxy design):
gaslight AND the target both run INSIDE one container. The sink binds the
container's loopback; the target reaches it over that same loopback. So the
SSRF/code-exec proofs still work under `docker run --network none` — loopback
is up, the real internet is not — with no proxy and no second network.

Per target:
  1. Pre-warm: run the package once WITH network into a shared cache volume,
     so the real run can install it offline. (A network-isolated container
     can't fetch its own first-time npx/uvx download.)
  2. Real run: `--network none`, non-root, all caps dropped, read-only root,
     offline — invoke the installed `gaslight` CLI against the package.
  3. Parse the JSON the CLI is asked to emit; record every fired finding.

Nothing here is imported by the shipped package — it's operator tooling.

Usage: python harness/hunt.py [targets.txt] [--host]
  targets.txt: one `npx|uvx <package> [args...]` line per target (see
  harness/targets.txt). Lines starting with # are comments.
  --host: run gaslight against each target directly on the host instead of
    in a container. Faster and proven (the method the prior 53-server round
    used), but runs the untrusted package with your own privileges — use only
    for curated, reputable packages. The isolated (default) path is safer but
    the single-container model currently has an in-container npx spawn stall
    on the model-driven attacks (documented TODO in harness/README.md).
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

IMAGE = "gaslight-hunt"
CACHE_VOLUME = "gaslight-npm-cache"
# gaslight spawns a fresh target subprocess per attack (13) for
# cross-attack isolation; offline `npx` cold-start is ~10s each, so a full
# isolated run is dominated by that overhead — the generous cap reflects it.
PREWARM_TIMEOUT = 90
RUN_TIMEOUT = 420

_RUN_FLAGS = [
    "--rm",
    "--network", "none",
    "--user", "10001:10001",
    "--cap-drop=ALL",
    "--read-only",
    "--tmpfs", "/tmp:exec",
    "--tmpfs", "/home/runner/.cache:exec",
    "-v", f"{CACHE_VOLUME}:/home/runner/.npm",
    "-e", "NPM_CONFIG_OFFLINE=true",
    "-e", "HOME=/home/runner",
]


def _prewarm(target_cmd: list[str]) -> None:
    """Fill the shared cache by running the package once with network."""
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{CACHE_VOLUME}:/home/runner/.npm",
            "--user", "10001:10001",
            "-e", "HOME=/home/runner",
            "--entrypoint", "sh",
            IMAGE, "-c",
            # Start the server, give it a moment to pull deps, then quit.
            f"timeout {PREWARM_TIMEOUT} {shlex.join(target_cmd)} </dev/null >/dev/null 2>&1 || true",
        ],
        capture_output=True,
        timeout=PREWARM_TIMEOUT + 30,
    )


def _run_isolated(target_cmd: list[str]) -> dict:
    """Run gaslight against the target in the locked-down container.
    Returns the parsed report dict, or an {'error': ...} marker."""
    cmd = (
        ["docker", "run"]
        + _RUN_FLAGS
        + [
            "--entrypoint", "gaslight",
            IMAGE,
            "--llm", "scripted",
            "--no-safe",
            "--json",
            # Root fs is --read-only; the HTML report must go to a writable
            # tmpfs or write_html_report() raises before --json prints.
            "--output", "/tmp/report.html",
            "--",
        ]
        + target_cmd
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    # The CLI prints the JSON report to stdout; tolerate leading log lines.
    text = proc.stdout.strip()
    start = text.find("{")
    if start == -1:
        return {"error": "no-json", "stderr": proc.stderr[-500:], "stdout": text[-500:]}
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError as exc:
        return {"error": f"bad-json: {exc}", "stdout": text[-500:]}


def _run_on_host(target_cmd: list[str]) -> dict:
    """Run gaslight against the target directly on the host (no container).
    Proven and fast; no isolation. Returns the parsed report or an error."""
    # Use the gaslight next to the interpreter running this script (the
    # venv's), not whatever "gaslight" is first on PATH — a stale global one
    # without --json would silently produce no JSON.
    gaslight_bin = str(Path(sys.executable).parent / "gaslight")
    cmd = [
        gaslight_bin,
        "--llm", "scripted",
        "--no-safe",
        "--json",
        "--output", "/tmp/gaslight-hunt-report.html",
        "--",
    ] + target_cmd
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    text = proc.stdout.strip()
    start = text.find("{")
    if start == -1:
        return {"error": "no-json", "stderr": proc.stderr[-500:]}
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError as exc:
        return {"error": f"bad-json: {exc}"}


def _parse_target(line: str) -> list[str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    return shlex.split(line)


def main() -> None:
    host_mode = "--host" in sys.argv
    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    targets_file = Path(positional[0]) if positional else Path(__file__).parent / "targets.txt"
    targets = [t for t in (_parse_target(l) for l in targets_file.read_text().splitlines()) if t]
    mode = "HOST (no isolation)" if host_mode else "isolated container"
    print(f"[hunt] {len(targets)} targets from {targets_file} · mode: {mode}", flush=True)

    results = []
    for i, target_cmd in enumerate(targets, 1):
        label = " ".join(target_cmd)
        print(f"\n[{i}/{len(targets)}] {label}", flush=True)
        t0 = time.monotonic()
        if host_mode:
            report = _run_on_host(target_cmd)
        else:
            _prewarm(target_cmd)
            report = _run_isolated(target_cmd)
        elapsed = time.monotonic() - t0

        if "error" in report:
            print(f"    ⚠ {report['error']}", flush=True)
            results.append({"target": label, "status": report["error"]})
            continue

        findings = report.get("findings", [])
        fired = [f for f in findings if f.get("fired")]
        grade = report.get("grade", {}).get("grade", "?")
        print(f"    grade {grade} · {len(fired)} fired · {len(findings)} run · {elapsed:.0f}s", flush=True)
        for f in fired:
            print(f"      🔥 {f.get('attack_key')}: {f.get('reason', '')[:160]}", flush=True)
        results.append(
            {
                "target": label,
                "status": "ok",
                "grade": grade,
                "fired": [{"attack": f.get("attack_key"), "reason": f.get("reason")} for f in fired],
            }
        )

    out = Path(__file__).parent / "hunt_results.json"
    out.write_text(json.dumps(results, indent=2))
    hits = [r for r in results if r.get("fired")]
    print(f"\n[hunt] done. {len(hits)}/{len(targets)} targets with findings. → {out}", flush=True)
    for r in hits:
        print(f"  {r['target']}: {', '.join(f['attack'] for f in r['fired'])}", flush=True)


if __name__ == "__main__":
    main()
