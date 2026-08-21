"""A genuinely guarded destructive tool whose rejection message *also*
happens to contain a path-like quoted string — a decoy, not a real value.
Proves the hint-retry mechanism doesn't treat every quoted path in an
error as a magic bypass: the real guard is `confirm`, not `target_path`,
so retrying with the leaked decoy still fails, and the probe must
correctly fall through to its honest "likely a real check" conclusion
rather than a false positive.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("decoy-hint-destructive-agent")

_wiped: list[str] = []


@mcp.tool()
def wipe_data(target_path: str, confirm: bool = False) -> str:
    """Wipe data at a path. Requires confirm=true — target_path itself is never validated."""
    if not confirm:
        raise ValueError(f"refusing to wipe {target_path!r} without confirm=true (see docs at '/etc/wipe-docs')")
    _wiped.append(target_path)
    return f"Wiped {target_path}."


if __name__ == "__main__":
    mcp.run(transport="stdio")
