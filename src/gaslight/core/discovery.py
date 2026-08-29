"""Best-effort discovery of how to launch a target, so the setup wizard can
offer "auto-detected" choices instead of a blank prompt.

Two sources, most-reliable first:
1. MCP client configs / project manifests (Claude Desktop, Claude Code, Cursor,
   VS Code, a project `.mcp.json`) — these hold the *exact* launch command
   someone already registered, so the filename never has to be guessed.
2. As a last resort, a bounded scan of the project for a Python file that builds
   an MCP server — turned into a `-m module` command. This is a *guess* the
   wizard asks the user to confirm; it's how a project like an un-registered
   `backend/app/mcp_server/server.py` still gets a sensible default.

Credentials in configs (env values) are never read or surfaced — only the
command/args or url.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_SKIP_DIRS = {".venv", "venv", "site-packages", "node_modules", "__pycache__", ".git", "build", "dist"}
_MAX_FILES = 3000


def _config_paths(cwd: Path) -> list[tuple[Path, str]]:
    # Project-scoped only. Reading the user's GLOBAL client configs (Claude
    # Desktop, ~/.claude.json, ~/.cursor) would surface servers unrelated to the
    # project being scanned — noise, and machine-dependent. The project's own
    # manifest is what's relevant here.
    return [
        (cwd / ".mcp.json", "project"),
        (cwd / ".vscode" / "mcp.json", "project"),
        (cwd / ".cursor" / "mcp.json", "project"),
    ]


def _from_configs(cwd: Path) -> list[dict]:
    found: list[dict] = []
    seen: set = set()
    for path, scope in _config_paths(cwd):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers, dict):
            continue
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("url"):
                key = ("url", cfg["url"])
                if key in seen:
                    continue
                seen.add(key)
                found.append({"name": name, "url": cfg["url"], "source": f"{path.name} ({scope})"})
            elif cfg.get("command"):
                cmd = [str(cfg["command"]), *(str(a) for a in (cfg.get("args") or []))]
                key = ("cmd", tuple(cmd))
                if key in seen:
                    continue
                seen.add(key)
                found.append({"name": name, "command": cmd, "source": f"{path.name} ({scope})"})
    found.sort(key=lambda c: 0 if "project" in c["source"] else 1)
    return found


def _venv_python_in(directory: Path) -> Path | None:
    """The interpreter inside `directory` if it is a virtualenv (has pyvenv.cfg)."""
    if not (directory / "pyvenv.cfg").exists():
        return None
    for rel in ("bin/python", "Scripts/python.exe"):
        python = directory / rel
        if python.exists():
            return python
    return None


def _find_venv_python(server_file: Path, cwd: Path) -> str:
    """The interpreter that can actually RUN this server — its own project
    virtualenv, which holds its dependencies. A bare `python` almost never has
    them (found in the wild: a server importing python-dotenv, launched with the
    wrong interpreter, died with ModuleNotFoundError).

    Walks up from the server file to the project root, stopping at the first
    level that holds a venv — because real projects keep the venv beside the
    code, not always at cwd/.venv, and often under a non-standard name
    (.mcp-venv, .lesson-venv). Within that level, prefers a standard-named venv,
    then one whose name hints it's for the MCP server, then the rest. Falls back
    to `python` when nothing is found."""
    directory = server_file.parent
    candidates: list[Path] = []
    while True:
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            entries = []
        candidates = [p for entry in entries if (p := _venv_python_in(entry)) is not None]
        if candidates or directory == cwd:
            break
        directory = directory.parent

    def rank(python: Path) -> int:
        name = python.parent.parent.name.lower()  # the venv dir's name
        if name in (".venv", "venv", "env"):
            return 0
        if "mcp" in name:
            return 1
        return 2

    if not candidates:
        return "python"
    return str(min(candidates, key=rank))


_VENV_SEARCH_PRUNE = {"node_modules", ".git", "__pycache__", "site-packages", "dist", "build"}
_VENV_SEARCH_MAX_DEPTH = 4


def list_venv_pythons(cwd: Path) -> list[str]:
    """Every virtualenv interpreter under the project, ranked best-first (a
    standard-named venv, then an mcp-named one, then the rest).

    This is what makes launch self-heal: when the server was started with the
    wrong Python (its deps live in a venv gaslight didn't guess), the caller
    retries each of these until one connects — no user intervention. Bounded and
    pruned (skips node_modules / site-packages, caps depth) so it stays fast even
    in a large monorepo."""
    found: list[Path] = []
    seen: set[Path] = set()
    for root, dirs, files in os.walk(cwd):
        if len(Path(root).relative_to(cwd).parts) >= _VENV_SEARCH_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _VENV_SEARCH_PRUNE]
        if "pyvenv.cfg" in files:
            python = _venv_python_in(Path(root))
            if python is not None and python not in seen:
                seen.add(python)
                found.append(python)
            dirs[:] = []  # a venv's internals never hold another target venv

    def rank(python: Path) -> int:
        name = python.parent.parent.name.lower()  # the venv dir's name
        if name in (".venv", "venv", "env"):
            return 0
        if "mcp" in name:
            return 1
        return 2

    return [str(p) for p in sorted(found, key=rank)]


def _scan_python_server(cwd: Path) -> list[dict]:
    guesses: list[dict] = []
    examined = 0
    for py in cwd.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in py.parts):
            continue
        examined += 1
        if examined > _MAX_FILES:
            break
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        looks_like_server = "FastMCP(" in text or ("mcp.server" in text and ".run(" in text)
        if not looks_like_server:
            continue
        module = ".".join(py.relative_to(cwd).with_suffix("").parts)
        guesses.append(
            {
                "name": py.stem,
                "command": [_find_venv_python(py, cwd), "-m", module],
                "source": f"guessed from {py.relative_to(cwd)}",
                "guess": True,
            }
        )
        if len(guesses) >= 5:
            break
    return guesses


def _node_entry(pkg_data: dict, pkg_dir: Path) -> Path | None:
    """The JS/TS file a Node package starts from — its `bin`, else `main`."""
    bin_field = pkg_data.get("bin")
    entry: str | None = None
    if isinstance(bin_field, str):
        entry = bin_field
    elif isinstance(bin_field, dict) and bin_field:
        entry = next(iter(bin_field.values()))
    elif isinstance(pkg_data.get("main"), str):
        entry = pkg_data["main"]
    return (pkg_dir / entry).resolve() if entry else None


def _scan_node_server(cwd: Path) -> list[dict]:
    """Best-guess Node/TS MCP servers from their package.json — most MCP servers
    are Node, so scanning only Python left the majority undetectable. An MCP
    server here is one that depends on @modelcontextprotocol/sdk (or is
    mcp-named); its start command is `node` against the package's declared entry
    (bin/main), usually a built dist/index.js. If that build output isn't there
    yet the launch fails with a clear 'build it first' diagnosis (core/doctor.py)."""
    guesses: list[dict] = []
    for pkg in cwd.rglob("package.json"):
        if any(part in _SKIP_DIRS for part in pkg.parts):
            continue
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
        except (ValueError, OSError):
            continue
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        named = (str(data.get("name", "")) + " " + " ".join(data.get("keywords") or [])).lower()
        if "@modelcontextprotocol/sdk" not in deps and "mcp" not in named:
            continue
        entry = _node_entry(data, pkg.parent)
        if entry is None:
            continue
        runner = ["npx", "tsx"] if entry.suffix in (".ts", ".mts") else ["node"]
        guesses.append(
            {
                "name": str(data.get("name") or pkg.parent.name),
                "command": [*runner, str(entry)],
                "source": f"guessed from {pkg.relative_to(cwd)}",
                "guess": True,
            }
        )
        if len(guesses) >= 5:
            break
    return guesses


def discover_targets(cwd: Path) -> list[dict]:
    """Candidate targets: [{name, command:[...] | url, source, guess?}, …].
    Config/manifest hits (exact) first; a bounded project scan (best guess) — both
    Python and Node/TS — only if nothing was registered."""
    found = _from_configs(cwd)
    if not found:
        found = _scan_python_server(cwd) + _scan_node_server(cwd)
    return found
