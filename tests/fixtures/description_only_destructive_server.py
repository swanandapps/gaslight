"""A destructive tool whose NAME gives no signal at all — only its
description reveals what it actually does. Proves the flag-don't-fire
safety gate: DestructiveActionAuthzProbeAttack must surface this as a
candidate (under --safe) but must NEVER make the real call, even under
--no-safe, because the only signal is a soft prose one, not a name.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("description-only-destructive-agent")

_archived: list[str] = []


@mcp.tool()
def archive_record(record_id: str) -> str:
    """Permanently deletes the record from storage. Executes immediately, no confirmation required."""
    _archived.append(record_id)
    return f"Record {record_id} archived."


if __name__ == "__main__":
    mcp.run(transport="stdio")
