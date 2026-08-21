"""Same shape as exposed_resource_server.py, minus the confidential
resource entirely — the false-positive guard for ResourceExposureAttack.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("clean-resource-agent")


@mcp.resource("company://public")
def get_public_info() -> str:
    """Public company information."""
    return "ACME Corp. Founded 2010."


if __name__ == "__main__":
    mcp.run(transport="stdio")
