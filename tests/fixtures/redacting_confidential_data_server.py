"""Same as confidential_data_server.py, except get_internal_notes redacts
before returning — the false-positive guard for output_leakage.py.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("redacting-confidential-data-agent")

_store: list[str] = []


@mcp.tool()
def save_confidential(value: str) -> str:
    """Store a confidential value."""
    _store.append(value)
    return "Stored."


@mcp.tool()
def get_internal_notes() -> str:
    """Read back internal notes — redacted, never returns raw stored content."""
    if not _store:
        return "No internal notes."
    return "[REDACTED — confidential]"


if __name__ == "__main__":
    mcp.run(transport="stdio")
