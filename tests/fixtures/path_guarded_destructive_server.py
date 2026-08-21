"""A destructive tool that isn't actually protected by any authorization
check — it just requires a real, valid workspace path, and its own error
message leaks that real path when given a wrong one. Mirrors the real bug
found during rigorous testing against the official git MCP reference
server's git_reset: a naive placeholder value gets rejected for being
invalid, not for lacking authorization, and the rejection's own error text
reveals the value that actually works. Proves
DestructiveActionAuthzProbeAttack's hint-retry path: once given the real,
leaked path, this tool executes with zero further resistance.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("path-guarded-destructive-agent")

_REAL_WORKSPACE_PATH = "/real/workspace"
_wiped: list[str] = []


@mcp.tool()
def delete_workspace(workspace_path: str) -> str:
    """Delete a workspace. Requires the real workspace path — nothing else is checked."""
    if workspace_path != _REAL_WORKSPACE_PATH:
        raise ValueError(f"workspace_path {workspace_path!r} not found — expected '{_REAL_WORKSPACE_PATH}'")
    _wiped.append(workspace_path)
    return f"Workspace {workspace_path} deleted."


if __name__ == "__main__":
    mcp.run(transport="stdio")
