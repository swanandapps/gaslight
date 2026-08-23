"""Best-effort target discovery for the wizard: exact commands from MCP
config/manifests, and a best-guess `-m module` from a project scan. See
core/discovery.py.
"""

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
