"""The doctor turns a target that won't start into a plain next step. Pure
mapping from startup output to advice — no subprocess needed. See
core/doctor.py."""

from gaslight.core.doctor import diagnose_launch, stderr_tail
from gaslight.core.target import TargetSpec

_SPEC = TargetSpec(command=["node", "server.js"])
_SPEC_WITH_ENV = TargetSpec(command=["node", "server.js"], env={"DATABASE_URL": "x"})


def _hint(text, spec=_SPEC):
    return " ".join(diagnose_launch(text, spec))


def test_missing_credential_is_diagnosed():
    out = _hint("[pgtalk] fatal: no database configured. Set DATABASE_URL in your config.")
    assert "credential" in out and "--env" in out


def test_old_sdk_crash_is_diagnosed():
    out = _hint("AttributeError: 'Server' object has no attribute 'list_tools'")
    assert "OLDER MCP SDK" in out


def test_old_sdk_crash_on_other_server_methods_is_diagnosed():
    # A real mcp-server-sqlite crash surfaced this: the narrow 'list_tools'
    # signature missed 'list_resources' and fell through to a wrong credential
    # hint. Any missing Server method is the same old-SDK skew.
    for method in ("list_resources", "list_prompts", "call_tool", "get_prompt"):
        out = _hint(f"AttributeError: 'Server' object has no attribute '{method}'")
        assert "OLDER MCP SDK" in out, method


def test_missing_python_version_is_diagnosed():
    out = _hint("error: package requires Python >=3.13, current is 3.11")
    assert "newer Python" in out


def test_bad_command_is_diagnosed():
    out = _hint("FileNotFoundError: [Errno 2] No such file or directory: '/nope'")
    assert "couldn't be found" in out


def test_node_version_is_diagnosed():
    out = _hint("Error [ERR_UNKNOWN_BUILTIN_MODULE]: No such built-in module")
    assert "Node.js version" in out


def test_broken_config_is_diagnosed():
    out = _hint("tomldecodeerror: invalid pyproject at line 4")
    assert "config file failed to parse" in out


def test_multiple_causes_are_all_shown():
    text = "requires Python >=3.13\n[server] DATABASE_URL is required"
    hints = diagnose_launch(text, _SPEC)
    assert len(hints) == 2


def test_unknown_failure_without_env_suggests_a_credential():
    hints = diagnose_launch("some totally opaque crash", _SPEC)
    assert len(hints) == 1
    assert "--env" in hints[0]


def test_unknown_failure_with_env_already_set_gives_no_generic_hint():
    # If they already passed --env, don't tell them to pass --env.
    assert diagnose_launch("some totally opaque crash", _SPEC_WITH_ENV) == []


def test_stderr_tail_returns_last_nonempty_lines_trimmed():
    text = "line one\n\n   \nline two\nline three\n"
    assert stderr_tail(text, lines=2) == ["line two", "line three"]


def test_stderr_tail_empty_on_no_output():
    assert stderr_tail("") == []
    assert stderr_tail(None) == []


def test_malformed_tool_schema_diagnosed_not_credential():
    # A server that starts fine but returns tool schemas missing "type" (found
    # in the wild: mcp-obsidian) must be diagnosed as a spec-compliance bug in
    # the target, NOT the generic "needs a credential" guess.
    err = (
        "ValidationError: 2 validation errors for ListToolsResult\n"
        "tools.0.inputSchema.type\n  Field required"
    )
    joined = " ".join(diagnose_launch(err, _SPEC)).lower()
    assert "match the mcp spec" in joined
    assert "credential" not in joined


def test_node_unbuilt_diagnosed_not_python_venv():
    joined = " ".join(diagnose_launch("Error: Cannot find module '/x/dist/index.js'", _SPEC)).lower()
    assert "build" in joined and "npm" in joined
    assert "virtualenv" not in joined  # must not confuse it with the python-venv case
