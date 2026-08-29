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

try:
    import tomllib as _tomllib
except ModuleNotFoundError:  # Python 3.10 ships no stdlib tomllib
    _tomllib = None

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


# Dirs that hold code but not the server entry — a FastMCP reference in a test or
# example is not the thing to launch (found in the wild: a repo's tests/ matched
# and gaslight guessed `-m tests.test_new_features`).
_PY_SERVER_SKIP_DIRS = _SKIP_DIRS | {"tests", "test", "examples", "example", "docs", "doc", "sample", "samples"}


def _is_test_file(py: Path) -> bool:
    return py.name.startswith("test_") or py.name.endswith("_test.py") or py.name == "conftest.py"


def _module_for(py: Path, cwd: Path) -> str:
    """The `-m` module path to run this file. Drops a leading `src.` (src-layout:
    the package installs importable without it) and collapses `pkg/__main__.py`
    to `pkg` (running a package executes its __main__)."""
    parts = list(py.relative_to(cwd).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__main__":
        parts = parts[:-1]
    return ".".join(parts)


def _server_score(py: Path, text: str) -> int:
    """Rank how likely a matching file is the REAL server entry, so the launch
    command points at it and not at some other file that merely mentions MCP."""
    score = 0
    if py.name == "__main__.py":
        score += 3
    if py.name in ("server.py", "main.py", "app.py", "__init__.py"):
        score += 2
    if "if __name__" in text:
        score += 1
    if "FastMCP(" in text:
        score += 1
    return score


def _pyproject_scripts(text: str) -> dict[str, str]:
    """A pyproject.toml's `[project.scripts]` console-script entry points:
    {script_name: "module.path:function"}. This is the AUTHORITATIVE way a
    Python project declares how it launches — the exact analog of package.json's
    `bin` — so we read it instead of guessing the module from source markers
    (which miss a server that subclasses FastMCP rather than calling `FastMCP(`)."""
    if _tomllib is not None:
        try:
            data = _tomllib.loads(text)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict):
            scripts = (data.get("project") or {}).get("scripts") or {}
            if isinstance(scripts, dict):
                return {str(k): str(v) for k, v in scripts.items() if isinstance(v, str)}
    # No stdlib tomllib (3.10), or a parse error: recover just the
    # [project.scripts] table with a line scan.
    out: dict[str, str] = {}
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == "[project.scripts]"
            continue
        if in_section and "=" in stripped and not stripped.startswith("#"):
            name, _, target = stripped.partition("=")
            name = name.strip().strip('"').strip("'")
            target = target.strip().strip('"').strip("'")
            if name and target:
                out[name] = target
    return out


def _project_is_mcp(text: str) -> bool:
    """Whether this pyproject describes an MCP project — mcp-named, or depending
    on the `mcp` / `fastmcp` package. Consulted only to accept a project's lone
    console script when its name doesn't itself say 'mcp'."""
    if _tomllib is not None:
        try:
            data = _tomllib.loads(text)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict):
            project = data.get("project") or {}
            name = str(project.get("name", "")).lower()
            deps = " ".join(str(d).lower() for d in (project.get("dependencies") or []))
            return "mcp" in name or "mcp" in deps or "fastmcp" in deps
    return "mcp" in text.lower()


def _console_script_command(target: str, pyproject: Path, cwd: Path) -> list[str]:
    """The command that runs a `[project.scripts]` entry point `module:func`.
    Calls the entry function directly with the project's own venv python —
    exactly what pip's generated console script does — so it launches even when
    the module has no `__main__`/`if __name__` guard. That guard is often absent:
    the entry function lives in __init__.py, or in a main.py with no guard, where
    `python -m module` would import the file but never start the server."""
    module, sep, func = target.partition(":")
    module, func = module.strip(), func.strip()
    python = _find_venv_python(pyproject, cwd)
    if sep and func.isidentifier() and module:
        return [python, "-c", f"import sys; from {module} import {func}; sys.exit({func}())"]
    return [python, "-m", module]


def _scan_python_pyproject(cwd: Path) -> list[dict]:
    """Authoritative Python discovery from each pyproject.toml's declared
    console-script entry point — no source-marker guessing. This finds servers
    the source scan misses (e.g. a FastMCP subclass, where `FastMCP(` never
    appears). Picks the mcp-named script; if a lone script is declared by an
    otherwise-MCP project, takes that."""
    guesses: list[dict] = []
    for pyproject in cwd.rglob("pyproject.toml"):
        if any(part in _SKIP_DIRS for part in pyproject.parts):
            continue
        try:
            text = pyproject.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scripts = _pyproject_scripts(text)
        if not scripts:
            continue
        selected = [(n, t) for n, t in scripts.items() if "mcp" in n.lower() or "mcp" in t.lower()]
        if not selected and len(scripts) == 1 and _project_is_mcp(text):
            selected = list(scripts.items())
        for name, target in selected[:3]:
            guesses.append(
                {
                    "name": name,
                    "command": _console_script_command(target, pyproject, cwd),
                    "source": f"declared in {pyproject.relative_to(cwd)} [project.scripts]",
                    "_module": target.partition(":")[0].strip(),
                }
            )
        if len(guesses) >= 5:
            break
    return guesses


def _scan_python_server(cwd: Path) -> list[dict]:
    # Declared entry points (pyproject [project.scripts]) are authoritative —
    # take them first, then fall back to source-marker guessing for anything
    # they don't already cover.
    declared = _scan_python_pyproject(cwd)
    claimed = {g.get("_module") for g in declared}

    candidates: list[tuple[int, Path]] = []
    examined = 0
    for py in cwd.rglob("*.py"):
        if any(part in _PY_SERVER_SKIP_DIRS for part in py.parts) or _is_test_file(py):
            continue
        examined += 1
        if examined > _MAX_FILES:
            break
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "FastMCP(" not in text and not ("mcp.server" in text and ".run(" in text):
            continue
        candidates.append((_server_score(py, text), py))

    candidates.sort(key=lambda c: -c[0])  # the most server-looking file first
    guesses: list[dict] = []
    for _score, py in candidates[:5]:
        module = _module_for(py, cwd)
        if not module or module in claimed:  # already covered by a declared entry point
            continue
        guesses.append(
            {
                "name": py.stem,
                "command": [_find_venv_python(py, cwd), "-m", module],
                "source": f"guessed from {py.relative_to(cwd)}",
                "guess": True,
            }
        )
    for g in declared:
        g.pop("_module", None)  # internal dedup key, not part of the public shape
    return declared + guesses


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


def _go_main_package(cwd: Path) -> Path | None:
    """The directory of the Go `package main` to run — root, else the best cmd/…
    (one whose name looks like the server, not a helper like mcpcurl)."""
    skip = _SKIP_DIRS | {"vendor", "examples", "example", "testdata", "scripts", "script"}
    mains: list[Path] = []
    for go in cwd.rglob("*.go"):
        if any(part in skip for part in go.parts):
            continue
        try:
            text = go.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "package main" in text and "func main(" in text:
            mains.append(go.parent)

    def rank(directory: Path) -> int:
        rel = directory.relative_to(cwd)
        if str(rel) == ".":  # a main package at the repo root is the server
            return 0
        last = rel.parts[-1].lower()
        if "cmd" in rel.parts and last == cwd.name.lower():  # cmd/<repo-name> — the canonical entry
            return 1
        if "cmd" in rel.parts and "server" in last:
            return 2
        if "cmd" in rel.parts:  # some other cmd/ helper (e.g. cmd/mcpcurl)
            return 4
        return 5

    return min(mains, key=rank) if mains else None


def _scan_go_server(cwd: Path) -> list[dict]:
    """Best-guess a Go MCP server from go.mod (an mcp dependency, or an mcp-named
    module) — run via `go run` against its main package. Needs the Go toolchain
    present, like any Go project."""
    gomod = cwd / "go.mod"
    if not gomod.exists():
        return []
    try:
        mod_text = gomod.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return []
    if "mcp" not in mod_text:
        return []
    main_dir = _go_main_package(cwd)
    if main_dir is None:
        return []
    where = "." if main_dir == cwd else "./" + str(main_dir.relative_to(cwd)).replace("\\", "/")
    return [{"name": cwd.name, "command": ["go", "run", where], "source": f"guessed from go.mod ({where})", "guess": True}]


def _scan_rust_server(cwd: Path) -> list[dict]:
    """Best-guess a Rust MCP server from Cargo.toml (an mcp/rmcp dependency, or an
    mcp-named crate) — run via `cargo run --release`. Needs the Rust toolchain."""
    cargo = cwd / "Cargo.toml"
    if not cargo.exists():
        return []
    try:
        text = cargo.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return []
    if "mcp" not in text and "rmcp" not in text:
        return []
    return [{"name": cwd.name, "command": ["cargo", "run", "--release"], "source": "guessed from Cargo.toml", "guess": True}]


def remote_mcp_hint(cwd: Path) -> str | None:
    """A one-line explanation when there's no local (stdio) server to launch but
    the project looks like a REMOTE MCP — a Cloudflare Workers app. Nothing runs
    locally, so instead of a blank "no server found" the user is told to run/deploy
    it and point gaslight at its URL. None when it's not a recognisable remote shape."""
    for name in ("wrangler.toml", "wrangler.json", "wrangler.jsonc"):
        if (cwd / name).exists() or any(cwd.glob(f"*/{name}")) or any(cwd.glob(f"apps/*/{name}")):
            return (
                "This looks like a REMOTE MCP server (a Cloudflare Workers app) — there's no local "
                "process to launch. Run it (`wrangler dev`) or use its deployed URL, then point "
                "gaslight at it:  gaslight --url https://<host>/mcp"
            )
    return None


def discover_targets(cwd: Path) -> list[dict]:
    """Candidate targets: [{name, command:[...] | url, source, guess?}, …].
    Config/manifest hits (exact) first; a bounded project scan (best guess) —
    Python, Node/TS, Go, Rust — only if nothing was registered."""
    found = _from_configs(cwd)
    if not found:
        found = (
            _scan_python_server(cwd)
            + _scan_node_server(cwd)
            + _scan_go_server(cwd)
            + _scan_rust_server(cwd)
        )
    return found
