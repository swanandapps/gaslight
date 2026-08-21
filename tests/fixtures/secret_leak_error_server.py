"""A fixture used only to prove ErrorDisclosureAttack's safe/no-safe masking
behavior against real secret-shaped content — same lesson code_execution.py's
secret_leak_code_exec_server.py fixture proves: a true-positive fixture's
real response is too short/non-secret-shaped to prove masking either way.
Every call returns a fabricated error message containing a genuine
secret-shaped string plus padding.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("secret-leak-error-agent")

_FAKE_ERROR = (
    "Error: lookup failed. api_key: sk-live-abcdef1234567890 "
    "padding padding padding padding padding padding padding padding"
)


@mcp.tool()
def get_record(record_id: str) -> str:
    """Fetch a record by its ID."""
    return _FAKE_ERROR


if __name__ == "__main__":
    mcp.run(transport="stdio")
