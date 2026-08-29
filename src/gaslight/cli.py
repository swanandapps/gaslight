"""Thin CLI wrapper. All the real logic lives in gaslight.core — this file
only parses args, wires the pieces together, and prints/exits.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import sys
import tempfile
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
from gaslight.core.llm import NoProviderAvailable, ScriptedProvider, detect_provider, llm_is_active
from gaslight.core.metrics import METRICS, compute_metrics

# The five layers a run is grouped into for display — the same order as the
# report's gauges. Each attack maps to exactly one (built from METRICS), so the
# live run reads like the report: Network → Filesystem → Leakage → Authorization
# → Integrity.
_PHASE_ORDER = [m.name for m in METRICS]
_ATTACK_PHASE = {a.attack_key: m.name for m in METRICS for a in m.audits}


def _group_by_phase(attacks):
    """Order attacks into the five display phases, preserving order within each.
    Returns [(phase_name, [attacks]), …] for phases that have any attack."""
    buckets: dict[str, list] = {name: [] for name in _PHASE_ORDER}
    for attack in attacks:
        buckets.setdefault(_ATTACK_PHASE.get(attack.key, "Other"), []).append(attack)
    ordered = [(name, buckets[name]) for name in _PHASE_ORDER if buckets.get(name)]
    if buckets.get("Other"):
        ordered.append(("Other", buckets["Other"]))
    return ordered
from gaslight.core.reporter import print_terminal, write_html_report
from gaslight.core.surface import WARN, SurfaceFinding, scan_surface
from gaslight.core.baseline import diff_baseline, load_baseline, write_baseline
from gaslight.core.education import CLEAN_LINE, FIX_HINT, what_it_checks
from gaslight.core.wizard import load_config, run_wizard, save_config


def _running_in_targets_env(command) -> bool:
    """True when gaslight appears to be launching the target with the SAME Python
    interpreter gaslight itself is running under — the tell-tale of a
    `pip install gaslight` INTO the app's own venv, which can change the app's
    dependencies. gaslight should run isolated (uvx/pipx); the target is a
    separate process. Only meaningful for a python-launched stdio target."""
    if not command:
        return False
    exe = command[0]
    base = os.path.basename(exe).lower()
    if "python" not in base:
        return False
    resolved = shutil.which(exe) or exe
    try:
        return os.path.realpath(resolved) == os.path.realpath(sys.executable)
    except OSError:
        return False


def _ask_blocking(question):
    """Run a questionary prompt to completion and return its value.

    The wizard runs inside gaslight's own asyncio loop (`_run` is async), but
    questionary/prompt_toolkit spin up their OWN loop via `asyncio.run()` — which
    raises "cannot be called from a running event loop" when nested. So we run
    the prompt on a worker thread, where no loop is running. Ctrl-C surfaces as a
    None answer (questionary's default), which the caller turns into a cancel."""
    import threading

    box: dict = {}

    def worker():
        try:
            box["value"] = question.ask()
        except BaseException as exc:  # re-raised on the calling thread below
            box["error"] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


class _QuestionaryPrompter:
    """The real terminal UI for the wizard — arrow-key select menus and inline
    text/password prompts, in the create-vite / create-next-app spirit. Kept out
    of wizard.py so the wizard stays testable with a stub. `.ask()` returns None
    when the user hits Ctrl-C; we turn that into a clean cancel."""

    @staticmethod
    def _cancel(value):
        if value is None:
            raise KeyboardInterrupt
        return value

    def select(self, message, options):
        import questionary

        choices = [questionary.Choice(title=o["name"], value=o["value"]) for o in options]
        q = questionary.select(message, choices=choices, instruction="(↑↓ to move, ⏎ to pick)")
        return self._cancel(_ask_blocking(q))

    def text(self, message, default=""):
        import questionary

        return self._cancel(_ask_blocking(questionary.text(message, default=default)))

    def password(self, message):
        import questionary

        return self._cancel(_ask_blocking(questionary.password(message)))

    def confirm(self, message, default=True):
        import questionary

        return self._cancel(_ask_blocking(questionary.confirm(message, default=default)))


def _spec_from_settings(settings, env):
    """Build a TargetSpec from a wizard result."""
    if settings.get("url"):
        return TargetSpec(url=settings["url"])
    merged_env = {**env, **(settings.get("env") or {})}
    return TargetSpec(command=settings["command"], env=merged_env or None)


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _resolve_target_without_args(env, llm, console):
    """Resolve a target when neither --command nor --url was given: a saved
    .gaslight.json first, then the interactive setup wizard (only in a real
    terminal). Returns (TargetSpec | None, llm, from_auto). `from_auto` is True
    when the wizard's Auto path picked the target — the caller then falls back to
    the manual wizard if that target won't start. None spec = "give up, show the
    plain error" (correct for CI / non-interactive)."""
    cwd = Path.cwd()
    cfg = load_config(cwd)
    if cfg and (cfg.get("command") or cfg.get("url")):
        cfg_llm = llm if llm is not None else cfg.get("llm")
        console.print("[dim]Using target from .gaslight.json[/]")
        if cfg.get("url"):
            return TargetSpec(url=cfg["url"]), cfg_llm, False
        return TargetSpec(command=list(cfg["command"]), env=env or None), cfg_llm, False

    if _interactive():
        settings = run_wizard(console, _QuestionaryPrompter(), cwd=cwd)
        chosen_llm = llm if llm is not None else settings.get("llm")
        if settings.get("save"):
            saved = save_config(
                cwd, {"command": settings.get("command"), "url": settings.get("url"), "llm": settings["llm"]}
            )
            console.print(f"[dim]Saved to {saved.name} — next time just run `gaslight`.[/]")
        return _spec_from_settings(settings, env), chosen_llm, settings.get("mode") == "auto"

    return None, llm, False


def _manual_fallback(env, console):
    """After a Quick scan fails to start the target, re-run the wizard forced to
    Configure so the user can correct the command / add a test backend. Returns
    (TargetSpec, llm)."""
    settings = run_wizard(console, _QuestionaryPrompter(), cwd=Path.cwd(), force_configure=True)
    return _spec_from_settings(settings, env), settings.get("llm")
from gaslight.core.scorer import grade
from gaslight.core.sink import Sink
from gaslight.core.attacks.base import Finding
from gaslight.core.banner import print_banner
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
        if line.startswith("export "):  # common in shell-style .env files
            line = line[len("export ") :]
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
        help=(
            "Connect to a remote MCP server over HTTP instead of spawning a local process. "
            "The transport is auto-detected — Streamable HTTP (current) or the older HTTP+SSE."
        ),
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

    async def add_hints_from(text: str) -> None:
        for hint in await suggest_possible_secrets(provider, text):
            if hint not in ai_hints:
                ai_hints.append(hint)

    for finding in findings:
        if finding.attack_key not in ("baseline-disclosure", "resource-exposure"):
            continue
        for entry in finding.transcript:
            for call in entry.tool_calls:
                await add_hints_from(call.result_text)
            await add_hints_from(entry.assistant_text)
        for text in finding.raw_observed_text:
            await add_hints_from(text)
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
    # "Previously recorded" must capture the ORIGINAL attack reason (what it
    # concluded before this downgrade), so read finding.reason before rewriting it.
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


async def _run_attack(attack, spec, provider, sink):
    """Run one attack against a fresh connection. Returns
    (finding, backend_failed, warning_text|None). Never raises — a failure in
    one attack degrades to a not-tested finding so the run always completes."""
    try:
        async with TargetConnection(spec) as target:
            finding = await attack.run(target, provider, sink)
            _downgrade_if_backend_was_down(finding, target)
            return finding, target.backend_failures > 0, None
    except TargetUnreachable as exc:
        # Started for discovery but not this time (flaky boot, or a crash an
        # earlier attack left behind). Record untested rather than lose the run.
        return (
            Finding(
                attack_key=attack.key,
                fired=False,
                reason=f"not tested — could not connect to the target for this attack ({exc}).",
                attempted=False,
            ),
            False,
            None,
        )
    except Exception as exc:
        # Any other failure — most likely the optional LLM provider being
        # unreachable inside a model-driven attack — degrades THIS attack to
        # not-tested, never aborts the run. Surfaced (not swallowed) via warning.
        return (
            Finding(
                attack_key=attack.key,
                fired=False,
                reason=f"not tested — attack could not run ({type(exc).__name__}: {exc}).",
                attempted=False,
            ),
            False,
            f"{attack.name} could not run ({type(exc).__name__}: {escape(str(exc))[:120]}) — recorded as not tested.",
        )


def _short_result(finding) -> str:
    """One-word status for the pipeline's compact check line — detail lives in
    the report."""
    if finding.fired:
        return "found"
    if not finding.attempted:
        return "not tested"
    return "clean"


# The attacks that actually drive a model (via core/harness.py). Only these
# change when you turn the LLM on — everything else is a direct, deterministic
# probe. Used to decide whether "add an LLM for realism" is even relevant to a
# given target: if none of these were attempted, an LLM would change nothing.
_MODEL_DRIVEN = frozenset(
    {"injection-exfil", "memory-poisoning", "output-leakage", "instruction-override", "tool-metadata-poisoning"}
)


def _truncate_tools(names: list[str], keep: int = 4) -> str:
    if len(names) <= keep:
        return ", ".join(names)
    return ", ".join(names[:keep]) + f"  … +{len(names) - keep} more"


def _print_run_card(console, tool_names, llm_active, provider_name, safe) -> None:
    """One compact, aligned card shown just before the scan — replaces the old
    stack of separate banners (found-agent dump, LLM line, personality opener,
    safety paragraph). Tools / Engine / Safety, one line each."""
    console.print()
    console.print(f"[dim]{'Tools':<7}[/]{_truncate_tools(tool_names)}")
    if llm_active:
        engine = f"[green]LLM on[/] ({provider_name}) — a real model drives your tools like an agent; never decides a verdict"
    else:
        engine = "deterministic core — a scripted agent drives your tools (offline, no key). Add [bold]--llm ollama[/] for a real one"
    console.print(f"[dim]{'Engine':<7}[/]{engine}")
    if safe:
        console.print(f"[dim]{'Safety':<7}[/]safe mode — no destructive actions · probes stay local · secrets masked")
    else:
        console.print(f"[yellow]{'Safety':<7}⚠ unsafe mode — destructive probes enabled[/]")
    console.print()


@contextlib.contextmanager
def _muffle_stderr():
    """Redirect the OS-level stderr fd to a throwaway file for the duration of the
    block, then restore it. Real agents (and chatty libraries) log to stderr on
    every tool call; that output, landing on the same terminal the live pipeline
    is drawing on, corrupts it into stacked frames. Muffling the fd — not just
    Python's sys.stderr — catches every target subprocess and library at the
    source, however deep it's spawned. Only wraps the live view; the plain path
    and --json keep their stderr so progress and diagnostics still show."""
    saved = os.dup(2)
    sink_file = tempfile.TemporaryFile()
    try:
        os.dup2(sink_file.fileno(), 2)
        yield
    finally:
        os.dup2(saved, 2)
        os.close(saved)
        sink_file.close()


async def _run_live(console, spec, provider, sink, phases, tool_count):
    """Drive the scan under a live, in-place pipeline (real terminals only). The
    bar redraws as each phase resolves; only the current phase's checks stream
    below it. Warnings are deferred and printed after so they never corrupt the
    live region. The settled bar is printed once at the end so the visual result
    persists above the detailed report."""
    from rich.live import Live

    from gaslight.core.runview import RunView

    view = RunView(spec.label, tool_count, [(name, [a.name for a in atks]) for name, atks in phases])
    findings: list = []
    backend_down = False
    warnings: list[str] = []
    console.print()
    with _muffle_stderr(), Live(view.render(), console=console, refresh_per_second=12, transient=True) as live:
        for pidx, (_phase, phase_attacks) in enumerate(phases):
            view.start_phase(pidx)
            for attack in phase_attacks:
                view.start_check(pidx, attack.name, what_it_checks(attack.key) or "")
                live.update(view.render())
                finding, bd, warn = await _run_attack(attack, spec, provider, sink)
                backend_down = backend_down or bd
                if warn:
                    warnings.append(warn)
                view.finish_check(
                    pidx, attack.name, fired=finding.fired, attempted=finding.attempted, result=_short_result(finding)
                )
                live.update(view.render())
                findings.append(finding)
    console.print(view.render_bar())
    for warn in warnings:
        console.print(f"[yellow]⚠  {warn}[/]")
    return findings, backend_down


async def _run_plain(console, spec, provider, sink, phases):
    """Sequential fallback for pipes / CI / --json: plain lines, no escape codes,
    every finding printed as it resolves."""
    findings: list = []
    backend_down = False
    for pnum, (phase, phase_attacks) in enumerate(phases, 1):
        console.print(f"\n[bold]Phase {pnum}/{len(phases)} · {phase}[/]  [dim]{'─' * 24}[/]")
        for attack in phase_attacks:
            what = what_it_checks(attack.key)
            console.print(f"[cyan]🧪  {attack.name}[/]" + (f" — [dim]{what}[/]" if what else ""))
            finding, bd, warn = await _run_attack(attack, spec, provider, sink)
            backend_down = backend_down or bd
            if warn:
                console.print(f"[yellow]⚠  {warn}[/]")
            findings.append(finding)
    return findings, backend_down


async def _run(args: argparse.Namespace, console: Console) -> int:
    # In --json mode all human-facing progress goes to stderr so stdout stays
    # a single clean JSON document for the caller to parse.
    if args.json:
        console = Console(stderr=True)

    # Branded load banner — first thing shown, once, in an interactive terminal.
    if not args.json and console.is_terminal:
        print_banner(console)

    env = {}
    for pair in getattr(args, "env", []) or []:
        if "=" not in pair:
            console.print(f"[red]error:[/] --env expects KEY=VALUE, got {pair!r}")
            return 2
        key, value = pair.split("=", 1)
        env[key] = value

    auto_from_wizard = False
    if args.url:
        spec = TargetSpec(url=args.url)
    elif args.command:
        spec = TargetSpec(command=args.command, env=env or None)
    else:
        # No target given. Try a saved .gaslight.json, then (if interactive) the
        # setup wizard, then fall back to the plain error for CI/non-tty.
        spec, args.llm, auto_from_wizard = _resolve_target_without_args(env, args.llm, console)
        if spec is None:
            console.print(
                "[red]error:[/] no target given. Run [bold]gaslight -- <command>[/] (e.g. "
                "`gaslight -- npx -y some-mcp-server`) or `gaslight --url <url>`."
            )
            return 2

    # Safety: warn if gaslight is running from the target's own environment (the
    # sign it was installed into the app's venv). It should run isolated.
    if spec.command and _running_in_targets_env(spec.command):
        console.print(
            "[yellow]⚠  gaslight looks like it's running from your agent's own environment[/] — "
            "installing it there can change your app's dependencies. Run it isolated instead: "
            "[bold]uvx gaslight …[/] (see the README)."
        )

    skip = {k.strip() for k in args.skip.split(",") if k.strip()}
    attacks = _build_attacks(safe=args.safe, skip=skip)

    # Discovery uses its own short-lived connection, closed before any attack
    # runs — it only needs the tool/resource list for the banner and the static
    # surface pass. Its stderr is captured so a launch failure becomes a plain
    # diagnosis (core/doctor.py), not a raw traceback. If the wizard's Auto path
    # chose the target and it won't start, drop into the manual wizard once and
    # retry — "try setting it up per your project".
    tool_count = 0
    discovered_tools: list = []
    surface: list = []
    while True:
        discovery = TargetConnection(spec, capture_stderr=True)
        try:
            async with discovery as target:
                tool_count = len(target.tools)
                discovered_tools = list(target.tools)
                surface = scan_surface(target.tools, target.resources)
            break
        except TargetUnreachable as exc:
            console.print(f"[bold red]✗  couldn't start the target[/] — {exc}")
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
            if auto_from_wizard and _interactive():
                console.print("\n[yellow]Couldn't start your agent — let's configure it together.[/]")
                spec, args.llm = _manual_fallback(env, console)
                auto_from_wizard = False
                continue
            return 2

    # The optional LLM layer, resolved after discovery (it isn't needed to
    # connect). If the chosen provider has no key, DEGRADE to the deterministic
    # core rather than aborting — the LLM is enrichment, it must never block a
    # scan (found in the wild: a run died after discovering the agent because a
    # wizard-chosen provider had no key).
    try:
        provider = detect_provider(args.llm)
    except NoProviderAvailable as exc:
        console.print(
            f"[yellow]⚠  {exc}[/]\n[dim]Running the deterministic core instead — the LLM layer is optional.[/]"
        )
        provider = ScriptedProvider()
    llm_active = llm_is_active(provider)

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
    # One compact run card — tools, engine, safety — then straight into the scan.
    _print_run_card(console, [t.name for t in discovered_tools], llm_active, provider.name, args.safe)

    phases = _group_by_phase(attacks)
    # The live pipeline is a transient overlay for real terminals only. On a pipe,
    # in CI, or under --json it would emit escape codes into someone's log, so
    # those get plain sequential lines instead. Findings persist either way.
    use_live = not args.json and console.is_terminal

    with Sink() as sink:
        findings = []
        backend_down = False
        if use_live:
            findings, backend_down = await _run_live(console, spec, provider, sink, phases, tool_count)
        else:
            findings, backend_down = await _run_plain(console, spec, provider, sink, phases)

    # Coverage, made visible: what ran, what didn't, why, and how to fix it.
    tested = [f for f in findings if f.attempted]
    skipped = [f for f in findings if not f.attempted]
    backend_skips = [f for f in skipped if "backend" in f.reason.lower() or "could not connect" in f.reason.lower()]
    notool_skips = [f for f in skipped if f not in backend_skips]
    console.print()
    coverage = f"[bold]Coverage:[/] tested {len(tested)} of {len(findings)} checks."
    if skipped:
        reasons = []
        if notool_skips:
            reasons.append(f"{len(notool_skips)} don't apply (no matching tool)")
        if backend_skips:
            reasons.append(f"{len(backend_skips)} a backend was unreachable")
        coverage += f" [dim]{len(skipped)} not tested: {' · '.join(reasons)}.[/]"
    console.print(coverage)

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

    # Two honest, distinct ways to get a stronger report — shown only when each
    # actually applies. They are NOT the same knob: --env widens COVERAGE (lets
    # backend-needing tools run); --llm raises REALISM (a real model instead of
    # the scripted stand-in drives the model-based attacks). We only suggest the
    # LLM when a model-driven attack actually ran — otherwise it would change
    # nothing on this target, and gaslight doesn't sell upgrades that do nothing.
    upgrades: list[str] = []
    if backend_skips:
        upgrades.append(
            f"[yellow]Broader coverage[/] — {len(backend_skips)} check(s) couldn't run because a tool's "
            "backend was unreachable. Start a test backend and re-run with [bold]--env KEY=VALUE[/] "
            "(throwaway creds, never production)."
        )
    if not llm_active and any(f.attack_key in _MODEL_DRIVEN and f.attempted for f in findings):
        upgrades.append(
            "[cyan]More realistic[/] — this report used the deterministic core (no LLM). Add "
            "[bold]--llm ollama[/] (free, local) to drive the model-based attacks with a real model "
            "instead of the scripted stand-in."
        )
    if upgrades:
        console.print("\n[bold]Make this report stronger:[/]")
        for line in upgrades:
            console.print(f"  • {line}")

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
