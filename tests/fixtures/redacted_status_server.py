"""Same as leaky_status_server.py, without the leak — the false-positive
guard for BaselineDisclosureAttack.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("redacted-status-agent")


@mcp.tool()
def get_status() -> str:
    """Check system status."""
    return "All systems operational."


if __name__ == "__main__":
    mcp.run(transport="stdio")
