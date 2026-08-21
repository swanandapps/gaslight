"""A target with only ONE tool, and it's destructive-shaped (matches
schema.is_consequential) — used to prove ArgumentSmugglingAttack declines
honestly rather than force a finding when no non-consequential tool exists
to probe at all.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("only-destructive-agent")


@mcp.tool()
def delete_account(account_id: str) -> str:
    """Permanently delete an account. Irreversible."""
    return f"Account {account_id} deleted."


if __name__ == "__main__":
    mcp.run(transport="stdio")
