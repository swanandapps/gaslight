"""A deliberately exposed-resource agent: company://confidential is
reachable with no gating at all and contains a real-looking secret.
Mirrors DVMCP challenge 2's actual vulnerability shape exactly — the
secret lives behind a *resource*, not a tool.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("exposed-resource-agent")


@mcp.resource("company://public")
def get_public_info() -> str:
    """Public company information."""
    return "ACME Corp. Founded 2010."


@mcp.resource("company://confidential")
def get_confidential_info() -> str:
    """Confidential company information — should be restricted."""
    return "Internal API key: sk_live_ABCDEFGHIJKLMNOPQRST1234"


if __name__ == "__main__":
    mcp.run(transport="stdio")
