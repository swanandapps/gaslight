"""A resource named/URI'd as "confidential" but with genuinely clean
content — isolates ResourceExposureAttack's naming-heuristic path from
its content-scan path.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("named-only-resource-agent")


@mcp.resource("company://confidential")
def get_confidential_info() -> str:
    """Confidential company information — should be restricted."""
    return "Nothing sensitive here, just plain text."


if __name__ == "__main__":
    mcp.run(transport="stdio")
