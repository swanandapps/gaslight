"""Same lookup shape as verbose_error_server.py, but every error path
returns a short, generic message with no path, secret, or stack trace —
the well-behaved version. False-positive guard for ErrorDisclosureAttack: a
tool that "finds" a leak here is crying wolf.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("generic-error-agent")

_RECORDS = {"1": "ok"}


@mcp.tool()
def get_record(record_id: str) -> str:
    """Fetch a record by its ID."""
    if record_id not in _RECORDS:
        return "Error: record not found."
    return _RECORDS[record_id]


if __name__ == "__main__":
    mcp.run(transport="stdio")
