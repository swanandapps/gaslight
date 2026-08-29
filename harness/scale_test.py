"""Repeatable end-to-end scale test — run gaslight against real public MCP repos.

The lesson that created this file: you cannot judge a black-box scanner on the
authors' own projects. You have to clone code you didn't write, set it up like a
real user would, and run the whole flow — discover the server, launch it, scan
it — then look at what broke. Gate a release on this.

For each repo in harness/scale_repos.json it: shallow-clones, runs the repo's
setup commands, asks gaslight's own discovery to find the server, then runs a
real `gaslight --json` scan against the guessed command. It records exactly where
each repo fell over (clone / setup / discovery / launch / scan) so failure modes
are countable, not anecdotal.

Usage:
    python harness/scale_test.py                     # default repo list
    python harness/scale_test.py --repos <file.json> --workdir <dir> --jobs 4
    python harness/scale_test.py --skip-high-risk    # don't run repos flagged risky

Clones and reports land under harness/.scale-work/ (gitignored). Running third-
party setup executes their code — keep the list reputable and/or sandbox it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REPOS = HERE / "scale_repos.json"
DEFAULT_WORK = HERE / ".scale-work"
GASLIGHT = [sys.executable, "-m", "gaslight.cli"]


def _run(cmd: list[str], cwd: Path, timeout: int, env: dict | None = None) -> tuple[int, str, str]:
    """Run a command, returning (exit_code, stdout, stderr). Never raises. stdout
    is kept separate so a --json scan's document isn't polluted by progress on
    stderr."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as exc:  # noqa: BLE001 - a harness must survive any repo
        return 1, "", f"{type(exc).__name__}: {exc}"


def _tail(text: str, n: int = 2) -> list[str]:
    return [ln for ln in text.strip().splitlines() if ln.strip()][-n:]


def _discover(target_dir: Path):
    """gaslight's own discovery — the guessed command for this repo, or None."""
    from gaslight.core.discovery import discover_targets

    targets = discover_targets(target_dir)
    return targets[0].get("command") if targets else None


def run_one(repo: dict, workdir: Path, timeouts: dict, discover_only: bool = False) -> dict:
    name = repo["name"]
    result: dict = {"name": name, "ecosystem": repo.get("ecosystem"), "stage": "clone"}
    dest = workdir / name
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=False)
    code, _out, err = _run(["git", "clone", "--depth", "1", repo["url"], str(dest)], workdir, timeouts["clone"])
    if code != 0:
        result.update(ok=False, detail=_tail(err, 1) or ["clone failed"])
        return result

    target = dest / repo["subdir"] if repo.get("subdir") else dest

    # Discovery reads manifests/source that exist right after clone, so a fast
    # coverage check skips the (slow) build/install entirely.
    if not discover_only:
        result["stage"] = "setup"
        # Some monorepos (pnpm/yarn workspaces) must install from the repo root
        # even though the server lives in a subdir.
        setup_dir = dest if repo.get("setup_from_root") else target
        for step in repo.get("setup") or []:
            code, out, err = _run(step.split() if isinstance(step, str) else step, setup_dir, timeouts["setup"])
            if code != 0:
                result.update(ok=False, setup_failed=step, detail=_tail(out + err, 2))
                return result
        result["setup_ok"] = True

    result["stage"] = "discovery"
    command = _discover(target)
    result["discovered"] = command is not None
    result["command"] = command
    if command is None:
        result.update(ok=False, detail=["discovery found no server"])
        return result
    if discover_only:  # fast long-tail coverage: did we find the server + a plausible command?
        result.update(ok=True, stage="discovery")
        return result

    result["stage"] = "scan"
    code, out, err = _run([*GASLIGHT, "--json", "--output", os.devnull, "--", *command], target, timeouts["scan"])
    data = None
    doc = out.strip()
    if doc:
        try:
            data = json.loads(doc)
        except ValueError:
            start = doc.rfind("\n{")  # tolerate any leading noise before the JSON doc
            if start != -1:
                try:
                    data = json.loads(doc[start:])
                except ValueError:
                    data = None
    if data:
        result.update(
            ok=True, connected=True, tool_count=data.get("tool_count"),
            grade=data.get("grade", {}).get("grade"),
        )
    else:
        result.update(ok=False, connected=False, detail=_tail(err, 3))
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repos", type=Path, default=DEFAULT_REPOS)
    ap.add_argument("--workdir", type=Path, default=DEFAULT_WORK)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--skip-high-risk", action="store_true")
    ap.add_argument("--discover-only", action="store_true", help="stop after discovery (fast coverage check, no scan)")
    ap.add_argument("--clone-timeout", type=int, default=180)
    ap.add_argument("--setup-timeout", type=int, default=600)
    ap.add_argument("--scan-timeout", type=int, default=300)
    args = ap.parse_args()

    repos = json.loads(args.repos.read_text())
    if args.skip_high_risk:
        repos = [r for r in repos if r.get("risk") != "high"]
    # Resolve to absolute: clone uses cwd=workdir with dest=workdir/name, so a
    # relative workdir would resolve the dest against cwd and double the path.
    args.workdir = args.workdir.resolve()
    args.workdir.mkdir(parents=True, exist_ok=True)
    timeouts = {"clone": args.clone_timeout, "setup": args.setup_timeout, "scan": args.scan_timeout}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_one, r, args.workdir, timeouts, args.discover_only): r for r in repos}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            mark = "OK " if r.get("ok") else "XX "
            print(
                f"[{len(results)}/{len(repos)}] {mark}{r['name']:28} "
                f"discovered={r.get('discovered')} scanned={r.get('connected')} "
                f"tools={r.get('tool_count','-')} grade={r.get('grade','-')} "
                f"(failed at: {r.get('stage') if not r.get('ok') else '-'})",
                flush=True,
            )

    report = args.workdir / "report.json"
    report.write_text(json.dumps(results, indent=2))
    disc = sum(1 for r in results if r.get("discovered"))
    scanned = sum(1 for r in results if r.get("connected"))
    print(f"\n=== {len(results)} repos · discovered {disc} · scanned {scanned} ===")
    print("failure modes by stage:")
    stages: dict[str, int] = {}
    for r in results:
        if not r.get("ok"):
            stages[r.get("stage", "?")] = stages.get(r.get("stage", "?"), 0) + 1
    for stage, n in sorted(stages.items(), key=lambda kv: -kv[1]):
        print(f"  {stage}: {n}")
    print(f"full report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
