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

from gaslight.core.discovery import discover_targets

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


_CUSTOM_HINT = (
    "How does your agent start? e.g.  npx -y some-mcp-server   or   "
    ".venv/bin/python -m your_pkg.server   (from the project root)"
)


def _choose_target(console, cwd: Path, prompt_ask):
    """Return (command:list|None, url:str|None). Offers auto-detected targets
    plus a custom option; falls straight to custom if nothing was detected."""
    targets = discover_targets(cwd)
    if targets:
        console.print("[bold]Found these ways to start an agent:[/]")
        for i, t in enumerate(targets, 1):
            desc = t.get("url") or " ".join(t.get("command", []))
            tag = " [yellow](best guess — edit if wrong)[/]" if t.get("guess") else ""
            console.print(f"  [bold]{i}[/] {t['name']} — [dim]{desc}[/]{tag}  [dim]· {t['source']}[/]")
        console.print("  [bold]c[/] custom — enter the command myself")
        pick = str(prompt_ask("Pick a target", default="1")).strip().lower()
        if pick != "c" and pick.isdigit() and 1 <= int(pick) <= len(targets):
            chosen = targets[int(pick) - 1]
            if chosen.get("url"):
                return None, chosen["url"]
            command = chosen.get("command") or []
            if chosen.get("guess"):
                command = shlex.split(prompt_ask("Launch command (edit if needed)", default=" ".join(command)))
            return command, None
        # any other input → custom
    else:
        console.print("[dim]Couldn't auto-detect how your agent starts — no MCP config or server file found.[/]")
    console.print(f"[dim]{_CUSTOM_HINT}[/]")
    return shlex.split(prompt_ask("Launch command")), None


def run_wizard(console, *, prompt_ask, confirm_ask, cwd: Path | None = None, force_manual: bool = False) -> dict:
    """Walk the user through setup. `prompt_ask(text, **kw)` and
    `confirm_ask(text, **kw)` are injected (rich.prompt in the CLI, stubs in
    tests) so this stays testable. Returns
    {"mode", "command", "url", "env", "llm", "save"}.

    Two paths: **Auto** (offered when a target is confidently detected) returns
    immediately with just the detected target and the deterministic core, so the
    caller can run the whole scan with no further questions — if it fails to
    start, the caller re-enters with force_manual=True. **Manual** walks through
    the command, a test backend, and the LLM."""
    cwd = cwd or Path.cwd()
    console.print("\n[bold]Let's set up a scan.[/] gaslight attacks your agent's tools and grades them — safely.\n")

    # Auto vs Manual — offer Auto only when we actually detected how to start it.
    if not force_manual:
        targets = discover_targets(cwd)
        if targets:
            top = targets[0]
            desc = top.get("url") or " ".join(top.get("command", []))
            hedge = " [yellow](best guess)[/]" if top.get("guess") else ""
            console.print(f"Detected how your agent starts: [bold]{desc}[/]{hedge}\n")
            console.print("  [bold]a[/]  Auto  — run the full scan now, using that (recommended)")
            console.print("  [bold]m[/]  Manual — set the command, a test backend, and the LLM yourself")
            if str(prompt_ask("Auto or manual?", choices=["a", "m"], default="a")).strip().lower() == "a":
                return {
                    "mode": "auto",
                    "command": top.get("command"),
                    "url": top.get("url"),
                    "env": {},
                    "llm": "scripted",  # deterministic core; fast first result
                    "save": False,
                }

    # --- Manual path ---
    # 1. How the agent starts — auto-detect from configs/manifests first, then
    #    offer "custom", so nobody stares at a blank prompt.
    command, url = _choose_target(console, cwd, prompt_ask)

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
    return {"mode": "manual", "command": command, "url": url, "env": env, "llm": llm, "save": save}
