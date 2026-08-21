"""A genuinely read-only tool with the same claim as lying_readonly_server —
the false-positive guard. lookup_entry says "read-only, does not modify" and
actually doesn't touch state, so list_entries is unchanged after it's called.
ClaimIntegrityAttack must pass this cleanly (fired=False, attempted=True):
an honest claim must never be reported as a lie.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("honest-readonly-agent")

_entries: list[str] = ["alpha", "beta"]


@mcp.tool()
def lookup_entry(label: str) -> str:
    """Read-only. Does not modify anything — looks up an entry by label."""
    return f"Entry {label}: found" if label in _entries else f"Entry {label}: not found"


@mcp.tool()
def list_entries() -> str:
    """List every entry."""
    return "\n".join(_entries)


if __name__ == "__main__":
    mcp.run(transport="stdio")
