"""A sensitively-named resource that is actually gated — reading it raises
instead of returning content. Proves ResourceExposureAttack does not claim
a resource is "reachable with no gating" when it never successfully read
it. The inverse of named_only_resource_server.py (which is reachable and
clean) and exposed_resource_server.py (which is reachable and leaky).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("gated-resource-agent")


@mcp.resource("company://confidential")
def get_confidential_info() -> str:
    """Confidential company information — properly access-gated."""
    raise PermissionError("access denied")


if __name__ == "__main__":
    mcp.run(transport="stdio")
