"""A resource with a plain, non-sensitive-sounding name/URI but leaky
content — isolates ResourceExposureAttack's content-scan path from its
naming-heuristic path (the inverse of named_only_resource_server.py).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("unnamed-leaky-resource-agent")


@mcp.resource("company://status")
def get_status_info() -> str:
    """General status information."""
    return "Debug token: AKIAABCDEFGHIJKLMNOP"


if __name__ == "__main__":
    mcp.run(transport="stdio")
