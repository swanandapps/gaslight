"""Turn a target that won't start into a plain-language next step.

gaslight's promise is "point it at your agent, one command, get a report".
But before it can test anything, the target has to actually launch — and a
Tier-2/deep-dive sweep showed more than half of real published MCP servers
won't start on the first try: built for an older SDK, needing a newer Python,
needing a credential to boot, a wrong binary path. When that happens the user
sees a wall of someone else's traceback and it looks like OUR tool broke.

This reads the target's own startup output and maps the common failures to one
sentence the user can act on. It never guesses a security verdict — it only
explains why the thing under test didn't come up.
"""

from __future__ import annotations

from gaslight.core.target import TargetSpec

# The launch binary itself couldn't be exec'd (no Python ever started). Named so
# it can be suppressed when a traceback proves the server DID start (below).
_LAUNCH_NOT_FOUND = "The launch command couldn't be found. Double-check the path to the server binary."

# The server process started (there's a Python traceback) and then crashed trying
# to open a file it expected — most often a log/db path hardcoded relative to the
# working directory. That's a bug in the target, not in how gaslight launched it.
_SERVER_CRASHED_ON_FILE = (
    "The server STARTED but crashed opening a file it expected (often a log or database path it "
    "hardcodes relative to the working directory). This is a bug in the server, not in the launch "
    "command. Try running gaslight from the server's own project directory, or create the missing "
    "folder/file it names above, then re-run."
)

# (substrings to match in the target's startup output, plain-language fix).
# Ordered most-specific first; every matching rule is shown, so a server that
# trips two (old SDK *and* missing credential) gets both.
_SIGNALS: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        # The server started and answered, but its tool list won't parse: a tool's
        # inputSchema is missing the spec-required "type". The strict MCP client
        # rejects the whole listing, so gaslight can't reach the tools. This is a
        # real compliance bug in the target, NOT a missing credential — say so,
        # instead of falling through to the generic "needs a credential" guess.
        (
            "validation error for listtoolsresult",
            "validation errors for listtoolsresult",
            "inputschema.type",
            "input_schema.type",
        ),
        "The server STARTED, but its tool definitions don't match the MCP spec — a tool's input "
        "schema is missing its required \"type\" (it should be \"type\": \"object\"). The strict MCP "
        "client rejects the whole tool list, so gaslight couldn't reach the tools to scan them. "
        "That malformed schema is itself a real bug worth fixing in the server; once its tools "
        "declare a type, gaslight can scan it.",
    ),
    (
        (
            "no module named 'mcp.server.fastmcp'",
            # Any missing method on the MCP Server class is the old-SDK-vs-new
            # API mismatch — list_tools / list_resources / list_prompts /
            # call_tool / get_prompt all crash this way on a version skew.
            # Matched broadly on purpose: the narrow "'...list_tools'" form
            # missed a real mcp-server-sqlite crash on 'list_resources'.
            "'server' object has no attribute",
            "incompletefielddefinition",
            "validation error for jsonrpcmessage",
            "importerror: cannot import name",
        ),
        "This server was built for an OLDER MCP SDK and is crashing on a newer one. "
        "Reinstall it against MCP 1.x (e.g. `pip install \"mcp<2\"` in its environment) and run again.",
    ),
    (
        ("requires python", "requires-python", "python_requires", "requires a python version"),
        "This server needs a newer Python than the one launching it. Install it under a newer "
        "Python and point the launch command at that interpreter.",
    ),
    (
        (
            "econnrefused",
            "connection refused",
            "database_url",
            "no database configured",
            "api key",
            "api_key",
            "api token",
            "access token",
            "access_token",
            "environment variable",
            "not configured",
            "must be set",
            "is required",
            "missing credential",
            "authentication",
        ),
        "This server won't start without a credential (a database URL or an API token). "
        "Pass a THROWAWAY/test one with `--env KEY=VALUE` — never a production value.",
    ),
    (
        ("err_unknown_builtin_module", "unsupported node", "requires node"),
        "This server needs a different Node.js version. Point the launch command at a newer "
        "`node` (its absolute path), not whatever is first on PATH.",
    ),
    (
        ("no such file or directory: 'go'", "no such file or directory: 'cargo'",
         "no such file or directory: 'node'", "no such file or directory: 'npx'", "executable file not found"),
        "The language toolchain needed to run this server isn't installed or isn't on PATH "
        "(go / cargo / node). Install it, then re-run.",
    ),
    (
        ("command not found", "no such file or directory", "errno 2", "enoent"),
        _LAUNCH_NOT_FOUND,
    ),
    (
        ("permission denied", "errno 13", "eacces"),
        "The launch command isn't executable (permission denied) — try `chmod +x` on it.",
    ),
    (
        ("address already in use", "errno 48", "eaddrinuse"),
        "Its port is already in use — another copy of the server may still be running.",
    ),
    (
        ("modulenotfounderror", "no module named"),
        "The server couldn't import a dependency — most often because it ran with the WRONG "
        "Python, not its own virtualenv (which is where its dependencies live). Point the "
        "launch command at the project's venv, e.g. `path/to/.venv/bin/python -m your.module` "
        "(gaslight tries to find it automatically, but not every venv layout is guessable). If "
        "it really is missing, install it for the interpreter you're launching with.",
    ),
    (
        ("cannot find module", "err_module_not_found"),
        "A Node server that isn't built (or installed) yet — its entry file (often dist/…) "
        "doesn't exist. Build it first: `npm install && npm run build` in the server's folder, "
        "then re-run. If it's a published package, `npx <package-name>` also works.",
    ),
    (
        ("cannot parse", "invalid pyproject", "tomldecodeerror", "invalid config"),
        "The server's own config file failed to parse — this is a bug in the target, not in "
        "the launch command. Check its README for a supported version.",
    ),
)


def diagnose_launch(stderr_text: str | None, spec: TargetSpec) -> list[str]:
    """Plain-language likely causes for a target that failed to start, drawn
    from its startup output. Empty list when nothing matched — the caller
    should then fall back to a generic message plus the raw tail."""
    lowered = (stderr_text or "").lower()
    # A Python traceback means the process actually launched and then crashed —
    # so a "no such file" here is a file the SERVER tried to open, not a missing
    # launch binary. Diagnose the server crash and suppress the misleading
    # "check the path to the binary" line.
    started = "traceback (most recent call last)" in lowered
    hints: list[str] = []
    if started and ("filenotfounderror" in lowered or "no such file" in lowered):
        hints.append(_SERVER_CRASHED_ON_FILE)
    for signatures, message in _SIGNALS:
        if message is _LAUNCH_NOT_FOUND and started:
            continue
        if any(sig in lowered for sig in signatures) and message not in hints:
            hints.append(message)

    if not hints and spec.command is not None and not spec.env:
        # No recognised signature and no --env was supplied: the single most
        # common un-diagnosable startup failure is a silently-required
        # credential, so it's worth pointing at even without a matching string.
        hints.append(
            "The server exited during startup. If it needs a credential to run (a database URL "
            "or an API token), pass a throwaway/test one with `--env KEY=VALUE`."
        )
    return hints


def stderr_tail(stderr_text: str | None, lines: int = 4) -> list[str]:
    """The last few non-empty lines of the target's startup output, trimmed —
    shown under the diagnosis so the user can see the raw error too."""
    if not stderr_text:
        return []
    non_empty = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    return [line[:200] for line in non_empty[-lines:]]
