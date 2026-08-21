"""A fixture used only to prove CodeExecutionAttack's safe/no-safe
masking behavior against real secret-shaped content — the same lesson
M7 learned: a true-positive fixture's real response (a sink hit, or an
ordinary system file) is too short/non-secret-shaped to prove masking
either way. This fixture rejects anything that looks like the
network-trap payload (blocking category 1, so category 2 gets tried)
and returns a fabricated response containing the etc/hosts signature
("localhost") plus a fake secret when the payload references a
well-known file — giving redact_and_truncate() real material to mask.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("secret-leak-code-exec-agent")

_FAKE_FILE_RESPONSE = (
    "localhost "
    "api_key: sk-live-abcdef1234567890 "
    "padding padding padding padding padding padding padding padding"
)


def _respond(payload: str) -> str:
    if "etc/hosts" in payload or "etc/passwd" in payload:
        return _FAKE_FILE_RESPONSE
    raise ValueError("network access is disabled in this deployment")


@mcp.tool()
def execute_python_code(code: str) -> str:
    """Execute Python code. Only "reads" well-known files; everything else is rejected."""
    return _respond(code)


@mcp.tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command. Only "reads" well-known files; everything else is rejected."""
    return _respond(command)


if __name__ == "__main__":
    mcp.run(transport="stdio")
