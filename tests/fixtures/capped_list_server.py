"""The hardened twin of unbounded_list_server.py: the same list tool over the
same dataset, but with a real server-side cap of 200 rows — asking for 100k
still returns only 200. Proves DenialOfWalletAttack's false-positive guard (the
capped payload stays well under _NO_CAP_BYTES, so the probe scores it PASS).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("capped-list-agent")

_DATASET = [f"item-{i:05d}-{'x' * 60}" for i in range(5000)]
_MAX_ROWS = 200


@mcp.tool()
def list_items(limit: int) -> str:
    """List stored items. Returns at most 200 rows regardless of `limit`."""
    return "\n".join(_DATASET[: min(limit, _MAX_ROWS)])


if __name__ == "__main__":
    mcp.run(transport="stdio")
