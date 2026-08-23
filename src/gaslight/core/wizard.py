"""Interactive setup — the friendly way to point gaslight at an agent.

Shown when someone runs `gaslight` with no target in an interactive terminal
(the CLI checks isatty first, so this never fires in CI). Uses arrow-key select
menus with a description on every option, in the spirit of create-vite /
create-next-app — the questions themselves teach what gaslight needs.

All UI goes through an injected `prompter` (a questionary-backed one in the CLI,
a stub in tests) with four methods: select / text / password / confirm. Answers
can be saved to `.gaslight.json` (target + LLM choice only — never credentials).
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from gaslight.core.discovery import discover_targets

CONFIG_NAME = ".gaslight.json"


def load_config(cwd: Path) -> dict | None:
    """Load a saved `.gaslight.json` from `cwd`, or None if absent/unreadable."""
    path = cwd / CONFIG_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def save_config(cwd: Path, settings: dict) -> Path:
    """Persist non-secret settings (command/url + llm). Never writes env values —
    credentials must not land in a file that could be committed."""
    keep = {k: settings[k] for k in ("command", "url", "llm") if settings.get(k) is not None}
    path = cwd / CONFIG_NAME
    path.write_text(json.dumps(keep, indent=2) + "\n", encoding="utf-8")
    return path


_CMD_HINT = "Launch command  (e.g.  npx -y some-mcp-server   or   .venv/bin/python -m pkg.server)"


def _describe(target: dict) -> str:
    return target.get("url") or " ".join(target.get("command", []))


def _target_to_cmd(target: dict):
    if target.get("url"):
        return None, target["url"]
    return list(target.get("command") or []), None


def _choose_target(console, prompter, cwd: Path):
    """Return (command:list|None, url:str|None).

    Presents the auto-detected target as a *statement* ("here's how it starts")
    set apart with spacing, then asks a *separate* highlighted question ("start
    it this way?"). Keeping the finding and the question visually distinct is the
    whole point — that separation was what the old flat menu was missing."""
    targets = discover_targets(cwd)
    if not targets:
        console.print("[dim]Couldn't auto-detect how your agent starts — enter its command below.[/]\n")
        return shlex.split(prompter.text(_CMD_HINT)), None

    primary = targets[0]
    source = primary.get("source", "your project")
    qualifier = "  [dim](best guess)[/]" if primary.get("guess") else ""
    console.print(f"[green]✓  Found your agent[/]{qualifier}")
    console.print(f"[dim]   Detected in {source} — this is how it starts:[/]\n")
    console.print(f"       [bold cyan]{_describe(primary)}[/]\n")

    options = [{"name": "Yes, use this", "value": "use"}]
    if len(targets) > 1:
        options.append({"name": f"Pick a different one  ({len(targets) - 1} more found)", "value": "other"})
    options.append({"name": "I'll type the command myself", "value": "custom"})

    choice = prompter.select("Start it this way?", options)
    if choice == "use":
        return _target_to_cmd(primary)
    if choice == "other":
        picked = prompter.select(
            "Which one?",
            [{"name": _describe(t) + ("  (best guess)" if t.get("guess") else ""), "value": t} for t in targets[1:]],
        )
        return _target_to_cmd(picked)
    return shlex.split(prompter.text(_CMD_HINT)), None


def _resolve_llm(provider: str, prompter, console) -> str:
    """Turn an LLM menu pick into an llm value, asking for a key inline when a
    hosted provider is chosen and none is in the environment."""
    if provider == "off":
        return "scripted"  # deterministic core regardless of any stray env key
    if provider == "ollama":
        return "ollama"
    env_name = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
    if os.environ.get(env_name):
        console.print(f"[dim]Using {env_name} from your environment.[/]")
        return provider
    key = (prompter.password(f"Paste your {env_name}  (used only for this run, never saved)") or "").strip()
    if key:
        os.environ[env_name] = key  # this process only; save_config never writes it
        return provider
    console.print("[dim]No key entered — using the deterministic core instead.[/]")
    return "scripted"


def run_wizard(console, prompter, *, cwd: Path | None = None, force_configure: bool = False) -> dict:
    """Walk the user through setup with select menus. Returns
    {"mode", "command", "url", "env", "llm", "save"}.

    Two paths. **Quick scan** returns immediately with the detected target and
    the deterministic core (no key, no setup) — the caller runs the whole scan;
    if it can't start, the caller re-enters with force_configure=True. **Configure**
    walks through a test backend and the LLM."""
    cwd = cwd or Path.cwd()
    # Welcome: one bold line + one sentence, no bordered box (council: Jobs/PG —
    # you installed it, you know what it is; separation comes from whitespace).
    console.print()
    console.print("[bold]gaslight[/] — automated penetration testing for AI agents.")
    console.print("[dim]Safe, controlled attacks on your agent, graded, with a report your AI can fix from.[/]")
    console.print()

    # 1. Target
    command, url = _choose_target(console, prompter, cwd)
    console.print()

    # 2. Quick vs Configure — each option says exactly what it does (no hidden LLM).
    if not force_configure:
        mode = prompter.select(
            "How do you want to run it?",
            [
                {"name": "Quick scan  —  run the security checks now · no API key, no setup", "value": "quick"},
                {"name": "Configure   —  add a test backend and/or an LLM, then run", "value": "configure"},
            ],
        )
        if mode == "quick":
            return {"mode": "auto", "command": command, "url": url, "env": {}, "llm": "scripted", "save": False}

    # 3. Test backend
    console.print()
    env: dict[str, str] = {}
    if prompter.select(
        "Do your agent's tools need a backend to run (a database, an API)?",
        [
            {"name": "No  —  scan what runs without one", "value": False},
            {"name": "Yes —  I'll add a TEST connection (throwaway only)", "value": True},
        ],
    ):
        console.print("[yellow]Use a TEST backend and throwaway values — gaslight sends real payloads.[/]")
        while True:
            pair = prompter.text("  KEY=VALUE  (blank to finish)")
            if not pair.strip():
                break
            if "=" in pair:
                key, value = pair.split("=", 1)
                env[key.strip()] = value.strip()

    # 4. Optional LLM layer — say what you GET, in a word each. It never decides
    # a verdict; the deterministic core stands alone.
    console.print()
    console.print("[dim]An optional AI layer makes probes smarter and writes findings in plain English.[/]")
    console.print("[dim]It never decides a verdict — the deterministic checks do that.[/]")
    provider = prompter.select(
        "Add an AI layer?",
        [
            {"name": "No — deterministic checks only   (fast · free · private)", "value": "off"},
            {"name": "Ollama                           (free · local · nothing leaves your machine)", "value": "ollama"},
            {"name": "OpenAI                           (needs an API key)", "value": "openai"},
            {"name": "Anthropic                        (needs an API key)", "value": "anthropic"},
        ],
    )
    llm = _resolve_llm(provider, prompter, console)

    # 5. Save
    save = prompter.confirm("Save these settings to .gaslight.json for next time (never saves keys)?", default=True)
    return {"mode": "configure", "command": command, "url": url, "env": env, "llm": llm, "save": save}
