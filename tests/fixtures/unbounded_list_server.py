"""A deliberately unbounded list tool: list_items(limit) returns up to `limit`
rows from a large dataset with no server-side cap — ask for 100k and get every
row back. Proves DenialOfWalletAttack's true-positive path (the returned
payload sails past _NO_CAP_BYTES).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("unbounded-list-agent")

# ~5,000 rows of ~72 chars each ≈ 365 KB when fully returned — comfortably over
# the 200 KB "no cap" threshold, and generated once at import.
_DATASET = [f"item-{i:05d}-{'x' * 60}" for i in range(5000)]


@mcp.tool()
def list_items(limit: int) -> str:
    """List stored items. Returns up to `limit` rows. No maximum is enforced."""
    return "\n".join(_DATASET[:limit])


if __name__ == "__main__":
    mcp.run(transport="stdio")
