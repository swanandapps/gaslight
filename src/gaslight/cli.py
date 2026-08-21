"""Thin CLI wrapper. All the real logic lives in gaslight.core — this file
only parses args, wires the pieces together, and prints/exits.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from gaslight.core.attacks.injection_exfil import InjectionExfilAttack
from gaslight.core.attacks.memory_poisoning import MemoryPoisoningAttack
from gaslight.core.attacks.output_leakage import OutputLeakageAttack
from gaslight.core.attacks.tool_authz_probe import ToolAuthzProbeAttack
from gaslight.core.attacks.tool_metadata_poisoning import ToolMetadataPoisoningAttack
from gaslight.core.attacks.baseline_disclosure import BaselineDisclosureAttack
from gaslight.core.attacks.resource_exposure import ResourceExposureAttack
from gaslight.core.attacks.instruction_override import InstructionOverrideAttack
from gaslight.core.attacks.destructive_authz_probe import DestructiveActionAuthzProbeAttack
from gaslight.core.attacks.path_traversal import PathTraversalAttack
from gaslight.core.attacks.ssrf_probe import SsrfProbeAttack
from gaslight.core.attacks.code_execution import CodeExecutionAttack
from gaslight.core.attacks.argument_smuggling import ArgumentSmugglingAttack
from gaslight.core.attacks.claim_integrity import ClaimIntegrityAttack
from gaslight.core.attacks.denial_of_wallet import DenialOfWalletAttack
from gaslight.core.attacks.confused_deputy import ConfusedDeputyAttack
from gaslight.core.attacks.error_disclosure import ErrorDisclosureAttack
from gaslight.core.llm_secret_hints import suggest_possible_secrets
from gaslight.core.llm import NoProviderAvailable, detect_provider, llm_is_active
from gaslight.core.metrics import compute_metrics
from gaslight.core.reporter import print_terminal, write_html_report
from gaslight.core.surface import WARN, SurfaceFinding, scan_surface
from gaslight.core.baseline import diff_baseline, load_baseline, write_baseline
from gaslight.core.education import CLEAN_LINE, FIX_HINT, OPENING, SAFE_INTRO, fact_for, what_it_checks
from gaslight.core.scorer import grade
from gaslight.core.sink import Sink
from gaslight.core.attacks.base import Finding
from gaslight.core.blast import compute_blast
from gaslight.core.doctor import diagnose_launch, stderr_tail
from gaslight.core.target import TargetConnection, TargetSpec, TargetUnreachable
from gaslight.core.verdict import ToolVerdict, compute_destructive_verdict, compute_verdict


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader — KEY=VALUE per line, no override of already-set
    env vars. Avoids pulling in python-dotenv for three lines of parsing.
    """
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gaslight",
        description="Point it at your MCP agent. Watch it leak a secret.",
    )
    parser.add_argument(
        "command",
        nargs="*",
        help="Command to spawn your MCP server over stdio, e.g. `python server.py`",
    )
    parser.add_argument(
        "--url",
        help="Connect to a remote MCP server over HTTP+SSE instead of spawning a local process",
    )
    parser.add_argument(
        "--llm",
        choices=["anthropic", "openai", "ollama", "scripted"],
        default=None,
        help=(
            "Model for the OPTIONAL LLM layer (enriches the report; never decides a verdict). "
            "'ollama' uses a free local model — nothing leaves your machine. Default: auto-detect "
            "from env, and if no model is configured, run the deterministic core alone (no error)."
        ),
    )
    parser.add_argument(
        "--safe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Restrict authorization/override/traversal/network/execution probing to "
            "non-destructive, non-disclosing behavior (default: on). With --safe: "
            "instruction-override intercepts its destructive call before it reaches the "
            "target; the destructive-action probe declines to call at all; the "
            "path-traversal, ssrf-probe, and code-execution-probe probes still perform "
            "their real call (none is destructive by payload design) but mask and truncate "
            "whatever they find before storing it. Pass --no-safe only when you want the "
            "real call, or the full unmasked content, respectively."
        ),
    )
    parser.add_argument(
        "--classify-secrets",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Ask the model to suggest additional secret-shaped content the deterministic "
            "scanner missed (default: off). Always supplementary — rendered separately, "
            "labeled unverified, never affects the grade or any finding. Sends the target's "
            "raw tool/resource output to the configured LLM provider — do not enable against "
            "data you don't want leaving this machine."
        ),
    )
    parser.add_argument("--output", default="gaslight-report.html", help="Where to write the HTML report")
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print a machine-readable JSON report to stdout instead of the rich terminal output "
            "(target, grade, and every finding). For programmatic callers and batch runs. The HTML "
            "report is still written to --output."
        ),
    )
    parser.add_argument(
        "--skip",
        default="",
        help=(
            "Comma-separated attack keys to skip (e.g. 'code-execution-probe,ssrf-probe'). "
            "Use when a specific tool must not be probed — e.g. a raw-SQL tool wired to a real "
            "production warehouse you don't want a code-execution payload sent to."
        ),
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Pass an environment variable to the target process (repeatable). Many real "
            "servers won't start without one — a database URL, an API token. Point these at a "
            "THROWAWAY/TEST backend, never production: gaslight will send real attack "
            "payloads to whatever this connects to. Without it the target runs with a "
            "stripped environment, which is the safe default."
        ),
    )
    parser.add_argument("--max-turns", type=int, default=6)
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help=(
            "Rug-pull guard for CI. First run records the target's tools (names, descriptions, "
            "schemas) to FILE as your approved baseline; later runs compare against it and flag "
            "any tool that changed since — a tool-mutation red flag. Delete FILE to re-record "
            "after an update you approve."
        ),
    )
    return parser


def _compute_verdicts(findings: list) -> list[ToolVerdict]:
    by_key = {f.attack_key: f for f in findings}
    verdicts: list[ToolVerdict] = []

    injection_finding = by_key.get(InjectionExfilAttack.key)
    probe_finding = by_key.get(ToolAuthzProbeAttack.key)
    exfil_tool_name = None
    if injection_finding is not None:
        exfil_tool_name = injection_finding.candidate_exfil_tool
    if exfil_tool_name is None and probe_finding is not None:
        exfil_tool_name = probe_finding.candidate_exfil_tool
    if exfil_tool_name is not None:
        verdicts.append(compute_verdict(exfil_tool_name, injection_finding, probe_finding))

    override_finding = by_key.get(InstructionOverrideAttack.key)
    destructive_probe_finding = by_key.get(DestructiveActionAuthzProbeAttack.key)
    destructive_tool_name = None
    if override_finding is not None:
        destructive_tool_name = override_finding.candidate_destructive_tool
    if destructive_tool_name is None and destructive_probe_finding is not None:
        destructive_tool_name = destructive_probe_finding.candidate_destructive_tool
    if destructive_tool_name is not None:
        verdicts.append(
            compute_destructive_verdict(destructive_tool_name, override_finding, destructive_probe_finding)
        )

    return verdicts


async def _collect_ai_hints(provider, findings: list) -> list[str]:
    """--classify-secrets support: run the optional LLM classifier over every
    text surface a baseline-disclosure or resource-exposure finding
    observed — both transcript text (baseline-disclosure) and the generic
    `raw_observed_text` bucket (resource-exposure, which has no transcript
    since no agent turn ever runs) — deduping into one flat hint list."""
    ai_hints: list[str] = []
    for finding in findings:
        if finding.attack_key not in ("baseline-disclosure", "resource-exposure"):
            continue
        for entry in finding.transcript:
            for call in entry.tool_calls:
                for hint in await suggest_possible_secrets(provider, call.result_text):
                    if hint not in ai_hints:
                        ai_hints.append(hint)
            for hint in await suggest_possible_secrets(provider, entry.assistant_text):
                if hint not in ai_hints:
                    ai_hints.append(hint)
        for text in finding.raw_observed_text:
            for hint in await suggest_possible_secrets(provider, text):
                if hint not in ai_hints:
                    ai_hints.append(hint)
    return ai_hints


def _report_json(
    target_label: str,
    tool_count: int,
    findings: list,
    grade_result,
    metrics=None,
    metrics_avg=None,
    surface=None,
    llm=None,
) -> str:
    """A machine-readable report for programmatic callers (the Tier 2 hunt
    driver, CI). Deliberately flat and stable: target, tool_count, grade, the
    five metric scores, and one entry per finding with the fields a triage step
    actually reads."""
    payload = {
        "target": target_label,
        "tool_count": tool_count,
        "grade": {
            "grade": grade_result.grade,
            "fired_count": grade_result.fired_count,
            "total_count": grade_result.total_count,
            "summary": grade_result.summary,
        },
        "findings": [
            {
                "attack_key": f.attack_key,
                "fired": f.fired,
                "attempted": f.attempted,
                "reason": f.reason,
            }
            for f in findings
        ],
    }
    if metrics is not None:
        payload["metrics"] = {
            "average": metrics_avg,
            "scores": [
                {
                    "name": m.name,
                    "score": m.score,
                    "band": m.band,
                    "breached": m.breached,
                }
                for m in metrics
            ],
        }
    if surface is not None:
        payload["surface"] = [
            {
                "severity": s.severity,
                "category": s.category,
                "tool_name": s.tool_name,
                "message": s.message,
            }
            for s in surface
        ]
    if llm is not None:
        payload["llm"] = llm
    return json.dumps(payload, indent=2)


def _downgrade_if_backend_was_down(finding, target) -> None:
    """A "no leak" recorded while the target's own backend was unreachable was
    never actually tested — every probe came back as a connection error, and
    the attacks read an error as "the tool refused me". Left alone, that
    renders as a clean pass: the single worst failure mode for a tool whose
    entire credibility rests on never claiming safety it didn't prove. So it
    is rewritten as an honest "not tested" (attempted=False), which the metrics
    already treat as N/A rather than as a passing check.

    Only a non-firing result is touched. A CONFIRMED finding stands on its own
    physical proof — a canary that actually arrived is real regardless of how
    many other calls failed."""
    if finding.fired or not finding.attempted or target.backend_failures == 0:
        return
    finding.attempted = False
    finding.reason = (
        f"not tested — the target's own backend was unreachable "
        f"({target.backend_failures} call(s) failed to connect or authenticate), so this "
        f"attack never actually reached a working tool. Previously recorded: {finding.reason}"
    )


def _build_attacks(safe: bool, skip: set[str] | None = None):
    skip = skip or set()
    attacks = [
        InjectionExfilAttack(),
        ToolAuthzProbeAttack(safe=safe),
        ToolMetadataPoisoningAttack(),
        MemoryPoisoningAttack(),
        OutputLeakageAttack(),
        BaselineDisclosureAttack(),
        ResourceExposureAttack(),
        InstructionOverrideAttack(safe=safe),
        DestructiveActionAuthzProbeAttack(safe=safe),
        PathTraversalAttack(safe=safe),
        SsrfProbeAttack(safe=safe),
        CodeExecutionAttack(safe=safe),
        ClaimIntegrityAttack(safe=safe),
        ConfusedDeputyAttack(safe=safe),
        ArgumentSmugglingAttack(safe=safe),
        ErrorDisclosureAttack(safe=safe),
        # Registered last on purpose: it asks for a large payload, so if a
        # pathological target hangs on it, every other attack has already run.
        DenialOfWalletAttack(safe=safe),
    ]
    return [a for a in attacks if a.key not in skip]


async def _run(args: argparse.Namespace, console: Console) -> int:
    # In --json mode all human-facing progress goes to stderr so stdout stays
    # a single clean JSON document for the caller to parse.
    if args.json:
        console = Console(stderr=True)

    env = {}
    for pair in getattr(args, "env", []) or []:
        if "=" not in pair:
            console.print(f"[red]error:[/] --env expects KEY=VALUE, got {pair!r}")
            return 2
        key, value = pair.split("=", 1)
        env[key] = value

    if args.url:
        spec = TargetSpec(url=args.url)
    elif args.command:
        spec = TargetSpec(command=args.command, env=env or None)
    else:
        console.print("[red]error:[/] provide a command to spawn (stdio) or --url (HTTP)")
        return 2

    try:
        provider = detect_provider(args.llm)
    except NoProviderAvailable as exc:
        console.print(f"[red]error:[/] {exc}")
        return 2

    # Transparency: say plainly whether the optional LLM layer is on, and where
    # its boundary is. The deterministic core runs identically either way.
    llm_active = llm_is_active(provider)
    if llm_active:
        console.print(
            f"[green]🧠  LLM layer on[/] ({provider.name}) — drives the victim-agent tests and can "
            "help read ambiguous leaks. It never decides a verdict: every CONFIRMED still comes from "
            "a canary physically reaching our sink."
        )
    else:
        console.print(
            "[dim]🧠  LLM layer off — deterministic core only (no model needed, nothing leaves your "
            "machine). All attacks still run. For a richer report, set ANTHROPIC_API_KEY / "
            "OPENAI_API_KEY, or use --llm ollama (free, local).[/]"
        )

    skip = {k.strip() for k in args.skip.split(",") if k.strip()}
    attacks = _build_attacks(safe=args.safe, skip=skip)

    # Discovery uses its own short-lived connection, closed before any attack
    # runs — it only needs the tool/resource list for the banner and the
    # static surface pass (zero calls, schema-only — see core/surface.py).
    # Capture the target's own startup output on this one connection, so a
    # launch failure becomes a plain-language diagnosis (see core/doctor.py)
    # rather than a wall of someone else's traceback. Constructed separately
    # from the `async with` so its stderr is still readable after __aenter__
    # raises.
    discovery = TargetConnection(spec, capture_stderr=True)
    try:
        async with discovery as target:
            console.print(
                f"[bold cyan]🔍  Found your agent[/]  ·  {len(target.tools)} tool(s): "
                f"{', '.join(target.tool_names())}"
            )
            tool_count = len(target.tools)
            # Kept past the connection close: the blast radius needs the tool
            # list to know which reaches exist at all, and each attack gets its
            # own fresh connection after this one is gone.
            discovered_tools = list(target.tools)
            surface = scan_surface(target.tools, target.resources)
    except TargetUnreachable as exc:
        # Expected outcome, not a crash. Diagnose why it wouldn't start and
        # give the user one concrete next step.
        console.print(f"[bold red]✗  couldn't start the target[/] — {exc}")
        # Diagnose from the target's own startup output AND the exception text:
        # a crash that writes to stderr (missing credential) shows up in the
        # former, while a failure with no output (bad command -> FileNotFound)
        # only shows up in the latter.
        hints = diagnose_launch(f"{exc}\n{discovery.stderr_text}", spec)
        if hints:
            console.print("\n[yellow]Likely cause:[/]")
            for hint in hints:
                console.print(f"  • {hint}")
        tail = stderr_tail(discovery.stderr_text)
        if tail:
            console.print("\n[dim]last output from the target:[/]")
            for line in tail:
                console.print(f"  [dim]{escape(line)}[/]")
        return 2

    # Rug-pull guard (see core/baseline.py). Record on first sight, compare
    # afterwards — drift rides into the report as WARN-level surface findings,
    # never touching the grade, same discipline as the static surface pass.
    if getattr(args, "baseline", None):
        baseline_path = Path(args.baseline)
        if baseline_path.exists():
            drift = diff_baseline(load_baseline(baseline_path), discovered_tools)
            surface.extend(SurfaceFinding(WARN, "baseline-drift", d.tool_name, d.message) for d in drift)
            if drift:
                console.print(
                    f"[yellow]⚠  {len(drift)} change(s) since the approved baseline[/] — "
                    "see the report's Surface section."
                )
            else:
                console.print("[green]✓  tools match the approved baseline[/] — no drift.")
        else:
            write_baseline(baseline_path, discovered_tools)
            console.print(
                f"[cyan]📌  baseline recorded[/] — {len(discovered_tools)} tool(s) → {baseline_path}. "
                "Future runs with --baseline will flag any change; delete the file to re-record."
            )

    # Every attack gets its own fresh TargetConnection rather than sharing one
    # across the loop. Attacks that plant data on the target (injection-exfil,
    # output-leakage, and any future module) would otherwise leave state a
    # later attack's read-back could pick up on the same live subprocess —
    # a false negative masquerading as "no leak". Correctness over speed:
    # one extra subprocess spawn per attack is the right trade for a
    # security tool that must never let stale cross-attack state imply safe.
    # A little personality up front, then the plain safety reassurance.
    console.print()
    console.print(f"[bold]🔦  {OPENING}[/]")
    console.print(f"[dim]{SAFE_INTRO}[/]")
    console.print()

    with Sink() as sink:
        findings = []
        backend_down = False
        for i, attack in enumerate(attacks):
            what = what_it_checks(attack.key)
            banner = f"[cyan]🧪  {attack.name}[/]"
            console.print(f"{banner} — [dim]{what}[/]" if what else banner)
            # Sprinkle a true, plain-language fact through the slow beats — gives
            # the tool a voice and teaches while the subprocess spins up.
            if i > 0 and i % 4 == 0:
                console.print(f"   [yellow]💡 {fact_for(i)}[/]")
            try:
                async with TargetConnection(spec) as target:
                    finding = await attack.run(target, provider, sink)
                    _downgrade_if_backend_was_down(finding, target)
                    backend_down = backend_down or target.backend_failures > 0
            except TargetUnreachable as exc:
                # The target started for discovery but not this time (flaky
                # boot, a crash left behind by an earlier attack). Record it
                # as untested rather than losing the whole run.
                finding = Finding(
                    attack_key=attack.key,
                    fired=False,
                    reason=f"could not connect to the target for this attack — {exc}",
                    attempted=False,
                )
            except Exception as exc:
                # Any other failure in one attack — most likely the optional LLM
                # provider being unreachable (a down `--llm ollama`, an API blip,
                # a rate limit) inside a model-driven attack — must degrade THAT
                # attack to not-tested, never abort the run and discard the
                # deterministic findings already collected. Printed, not
                # swallowed, so a real bug is still visible.
                console.print(
                    f"[yellow]⚠  {attack.name} could not run this attack[/] "
                    f"([dim]{type(exc).__name__}: {escape(str(exc))[:160]}[/]) — recorded as not tested."
                )
                finding = Finding(
                    attack_key=attack.key,
                    fired=False,
                    reason=f"attack could not run ({type(exc).__name__}: {exc}) — recorded as not tested.",
                    attempted=False,
                )
            findings.append(finding)

    if backend_down:
        console.print(
            "\n[yellow]⚠ The target's own backend was unreachable during this run[/] — "
            "checks that needed a working tool are reported as [bold]not tested[/], not as passed. "
            "Point it at a throwaway/test backend to get the full result."
        )

    ai_hints: list[str] = []
    if args.classify_secrets and llm_active:
        try:
            ai_hints = await _collect_ai_hints(provider, findings)
        except Exception as exc:
            # Same defense as the attack loop: a provider failure during the
            # optional secret classifier must not sink the report we already have.
            console.print(
                f"[yellow]⚠  secret classification skipped[/] ([dim]{type(exc).__name__}[/]) — the model layer was unreachable."
            )
    elif args.classify_secrets and not llm_active:
        console.print(
            "[dim]  (--classify-secrets needs a model — skipped. Set a key or --llm ollama to enable it.)[/]"
        )

    verdicts = _compute_verdicts(findings)

    grade_result = grade(findings)
    metrics, metrics_avg = compute_metrics(findings)
    blast = compute_blast(discovered_tools, findings)
    console.print()
    print_terminal(
        spec.label, tool_count, findings, grade_result, verdicts, ai_hints,
        metrics=metrics, metrics_avg=metrics_avg, surface=surface, console=console,
    )

    report_path = write_html_report(
        Path(args.output), spec.label, findings, grade_result, verdicts, ai_hints,
        metrics=metrics, metrics_avg=metrics_avg, tool_count=tool_count, surface=surface, blast=blast,
    )
    console.print(f"\n[bold]📋  Your report card:[/] {report_path} [dim](open it in your browser)[/]")

    # Personality + the AI-first fix loop: gaslight finds and proves it; the
    # user's own agent fixes it. A clean run gets a friendly win instead.
    if grade_result.fired_count > 0 or any(s.severity == "warn" for s in surface):
        console.print(f"\n[cyan]🤖  {FIX_HINT}[/]")
    else:
        console.print(f"\n[green]✓  {CLEAN_LINE}[/]")

    if args.json:
        llm_info = {
            "active": llm_active,
            "provider": provider.name,
            "role": "enrichment" if llm_active else "off",
            "decides_verdict": False,
        }
        print(_report_json(spec.label, tool_count, findings, grade_result, metrics, metrics_avg, surface, llm_info))

    return 1 if grade_result.fired_count > 0 else 0


def main() -> None:
    _load_dotenv(Path.cwd() / ".env")
    args = build_parser().parse_args()
    console = Console()
    exit_code = asyncio.run(_run(args, console))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
