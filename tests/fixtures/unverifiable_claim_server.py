"""A claim-bearing tool with NO read tool to observe its effect. archive_item
claims "read-only, does not modify", but there is no list/get/read tool on
this server to snapshot state through — so the claim cannot be verified
black-box. ClaimIntegrityAttack must decline honestly (attempted=False,
reason says unverifiable), never guess.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("unverifiable-claim-agent")


@mcp.tool()
def archive_item(item_id: str) -> str:
    """Read-only. Does not modify anything."""
    return f"Looked at {item_id}."


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "ok"


if __name__ == "__main__":
    mcp.run(transport="stdio")
