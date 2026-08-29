"""Best-effort target discovery for the wizard: exact commands from MCP
config/manifests, and a best-guess `-m module` from a project scan. See
core/discovery.py.
"""

import json

from gaslight.core.discovery import discover_targets


def test_reads_command_from_project_mcp_json(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg"]}}}')
    found = discover_targets(tmp_path)
    assert found and found[0]["command"] == ["npx", "-y", "pkg"]
    assert "guess" not in found[0]  # exact, not a guess


def test_reads_url_target(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"remote": {"url": "https://host/mcp"}}}')
    found = discover_targets(tmp_path)
    assert found and found[0]["url"] == "https://host/mcp"


def test_guesses_python_module_from_a_server_file(tmp_path):
    # a project like Munshi: an un-registered FastMCP server nested in a package.
    pkg = tmp_path / "backend" / "app" / "mcp_server"
    pkg.mkdir(parents=True)
    (pkg / "server.py").write_text("from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\nmcp.run()\n")
    found = discover_targets(tmp_path)
    guess = next((c for c in found if c.get("guess")), None)
    assert guess is not None
    assert guess["command"][-2:] == ["-m", "backend.app.mcp_server.server"]


def test_empty_project_finds_nothing(tmp_path):
    assert discover_targets(tmp_path) == []


def test_bad_config_is_ignored(tmp_path):
    (tmp_path / ".mcp.json").write_text("{not valid json")
    # falls through to the project scan (which finds nothing here) — no crash
    assert discover_targets(tmp_path) == []


def test_finds_nested_nonstandard_venv_and_prefers_mcp_named(tmp_path):
    # Mirrors a real project (01dev): venvs live in a subdir under non-standard
    # names, not cwd/.venv. Discovery must still point the guess at one — and
    # prefer the mcp-named venv for an MCP server.
    (tmp_path / "backend" / "app" / "mcp").mkdir(parents=True)
    server = tmp_path / "backend" / "app" / "mcp" / "tools.py"
    server.write_text("from mcp.server import FastMCP\napp = FastMCP('x')\napp.run()\n")
    for name in (".lesson-venv", ".mcp-venv"):
        binv = tmp_path / "backend" / name / "bin"
        binv.mkdir(parents=True)
        (tmp_path / "backend" / name / "pyvenv.cfg").write_text("home = /x\n")
        (binv / "python").write_text("")
        (binv / "python").chmod(0o755)

    targets = discover_targets(tmp_path)
    assert targets, "should guess a target"
    cmd = targets[0]["command"]
    assert cmd[0].endswith("backend/.mcp-venv/bin/python"), cmd[0]
    assert cmd[1:] == ["-m", "backend.app.mcp.tools"]


def test_falls_back_to_bare_python_when_no_venv(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "server.py").write_text("from mcp.server import FastMCP\nFastMCP('x').run()\n")
    targets = discover_targets(tmp_path)
    assert targets and targets[0]["command"][0] == "python"


def _make_venv(root, name):
    binv = root / name / "bin"
    binv.mkdir(parents=True)
    (root / name / "pyvenv.cfg").write_text("home = /x\n")
    (binv / "python").write_text("")
    (binv / "python").chmod(0o755)


def test_list_venv_pythons_ranks_and_prunes(tmp_path):
    from gaslight.core.discovery import list_venv_pythons

    _make_venv(tmp_path / "sub", ".mcp-venv")
    _make_venv(tmp_path / "sub", ".venv")
    _make_venv(tmp_path / "node_modules" / "pkg", ".venv")  # must be pruned

    pys = list_venv_pythons(tmp_path)
    assert pys and pys[0].endswith("sub/.venv/bin/python")  # standard-named first
    assert any(p.endswith("sub/.mcp-venv/bin/python") for p in pys)
    assert not any("node_modules" in p for p in pys)  # pruned, never descended


def test_venv_recovery_retries_then_exhausts(tmp_path):
    from gaslight.cli import _venv_recovery_spec
    from gaslight.core.target import TargetSpec

    _make_venv(tmp_path, ".venv")
    spec = TargetSpec(command=["python", "-m", "pkg.server"])
    tried = {"python"}
    recovered = _venv_recovery_spec(spec, "ModuleNotFoundError: No module named 'dotenv'", tried, tmp_path)
    assert recovered is not None and recovered.command[0].endswith(".venv/bin/python")
    assert recovered.command[1:] == ["-m", "pkg.server"]
    # the only venv is now tried — nothing left to heal with
    assert _venv_recovery_spec(recovered, "ModuleNotFoundError", tried, tmp_path) is None


def test_venv_recovery_only_for_module_errors(tmp_path):
    from gaslight.cli import _venv_recovery_spec
    from gaslight.core.target import TargetSpec

    _make_venv(tmp_path, ".venv")
    spec = TargetSpec(command=["python", "-m", "x"])
    assert _venv_recovery_spec(spec, "Connection refused", set(), tmp_path) is None  # not a wrong-Python signal
    assert _venv_recovery_spec(TargetSpec(command=["npx", "srv"]), "ModuleNotFoundError", set(), tmp_path) is None


def test_finds_node_mcp_server_from_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "@x/server-foo",
        "bin": {"foo": "dist/index.js"},
        "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"},
    }))
    targets = discover_targets(tmp_path)
    assert targets, "a Node MCP server must be discovered"
    cmd = targets[0]["command"]
    assert cmd[0] == "node" and cmd[-1].endswith("dist/index.js")


def test_node_ts_entry_uses_tsx(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "srv", "main": "src/index.ts",
        "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"},
    }))
    targets = discover_targets(tmp_path)
    assert targets and targets[0]["command"][:2] == ["npx", "tsx"]


def test_ignores_a_plain_node_lib(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "just-a-lib", "main": "index.js", "dependencies": {"lodash": "^4"},
    }))
    assert discover_targets(tmp_path) == []


def _fastmcp(text="from mcp.server import FastMCP\nFastMCP('x').run()\n"):
    return text


def test_skips_test_files_and_prefers_real_entry(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "server.py").write_text(_fastmcp())
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_it.py").write_text(_fastmcp())  # a FastMCP ref in a test — must be ignored
    targets = discover_targets(tmp_path)
    assert targets and targets[0]["command"][-1] == "pkg.server"
    assert all("test" not in t["command"][-1] for t in targets)


def test_strips_src_layout_prefix(tmp_path):
    (tmp_path / "src" / "mypkg").mkdir(parents=True)
    (tmp_path / "src" / "mypkg" / "server.py").write_text(_fastmcp())
    targets = discover_targets(tmp_path)
    assert targets and targets[0]["command"][-1] == "mypkg.server"  # not src.mypkg.server


def test_main_module_runs_the_package(tmp_path):
    (tmp_path / "mypkg").mkdir()
    (tmp_path / "mypkg" / "__main__.py").write_text(_fastmcp())
    targets = discover_targets(tmp_path)
    assert targets and targets[0]["command"][-1] == "mypkg"  # `-m mypkg` runs __main__.py
