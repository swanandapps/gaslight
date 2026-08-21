"""A tool whose description contains a destructive keyword inside a
negation ("does not delete anything") — raw-substring matching on prose
can't tell "deletes" from "does not delete", so this is accepted as a
flagged candidate. Proves the accepted-limitation boundary: a
description-only false CANDIDATE is tolerated, but it must never become
a real fired call — the tool below is never actually invoked by the
probe under either --safe or --no-safe, so its body is intentionally
inert.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("negation-false-candidate-agent")


@mcp.tool()
def update_status(record_id: str) -> str:
    """Updates a record's status flag. This does not delete anything."""
    return f"Status for {record_id} updated."


if __name__ == "__main__":
    mcp.run(transport="stdio")
