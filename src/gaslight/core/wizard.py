"""Interactive setup — the friendly way to point gaslight at an agent.

Shown when someone runs `gaslight` with no target in an interactive terminal
(the CLI checks isatty first, so this never fires in CI). The questions
themselves teach what gaslight needs and what it is: how your agent starts, a
test backend if its tools need one, and an optional LLM for a richer report.

Answers can be saved to `.gaslight.json` (command + LLM choice only — never
credentials), so the next run is just `gaslight`.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

CONFIG_NAME = ".gaslight.json"


def load_config(cwd: Path) -> dict | None:
    """Load a saved `.gaslight.json` from `cwd`, or None if absent/unreadable.
    Shape: {"command": [...]} or {"url": "..."}, optional "llm"."""
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


def run_wizard(console, *, prompt_ask, confirm_ask) -> dict:
    """Walk the user through setup. `prompt_ask(text, **kw)` and
    `confirm_ask(text, **kw)` are injected (rich.prompt in the CLI, stubs in
    tests) so this stays testable. Returns
    {"command": [...], "env": {...}, "llm": str|None, "save": bool}."""
    console.print("\n[bold]Let's set up a scan.[/] gaslight attacks your agent's tools and grades them — safely.\n")

    # 1. How the agent starts. gaslight launches it as a separate process.
    console.print(
        "[dim]How does your agent start? Examples:\n"
        "  npx -y some-mcp-server\n"
        "  .venv/bin/python -m your_pkg.server   (run from the project root)[/]"
    )
    command = shlex.split(prompt_ask("Launch command"))

    # 2. Backend / credentials. This is where people learn gaslight isn't just a
    #    scanner — deep coverage needs the agent's tools to actually work.
    env: dict[str, str] = {}
    if confirm_ask(
        "Does your agent need a backend or credentials to run (a database URL, an API key)?",
        default=False,
    ):
        console.print(
            "[yellow]Use a TEST backend and throwaway values — gaslight sends real payloads, "
            "so never point it at production.[/]"
        )
        while True:
            pair = prompt_ask("  KEY=VALUE (blank to finish)", default="")
            if not pair.strip():
                break
            if "=" in pair:
                key, value = pair.split("=", 1)
                env[key.strip()] = value.strip()

    # 3. Optional LLM layer, explained.
    console.print(
        "\n[dim]An optional LLM makes probes smarter and explains findings in plain English. "
        "It never decides a verdict — every CONFIRMED still comes from physical proof.[/]"
    )
    choice = prompt_ask("LLM layer", choices=["off", "ollama", "anthropic", "openai"], default="off")
    # "off" -> force the deterministic core, so a stray API key in the env
    # doesn't silently turn the layer on.
    llm = "scripted" if choice == "off" else choice

    save = confirm_ask(
        "Save these settings (command + LLM choice, never credentials) to .gaslight.json?",
        default=True,
    )
    return {"command": command, "env": env, "llm": llm, "save": save}
