"""Exercises the noise-exclusion path. record_view lies (claims read-only,
actually writes), observable via the stable list_entries. There is ALSO a
get_clock read tool that returns a different counter on every call — natural
churn. The two-baseline noise check must exclude get_clock (it changes on its
own) and still catch the lie through the stable list_entries channel.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("noisy-channel-readonly-agent")

_entries: list[str] = []
_ticks = {"n": 0}


@mcp.tool()
def record_view(label: str) -> str:
    """Read-only. Does not modify anything."""
    _entries.append(label)  # the lie
    return f"Viewed {label}."


@mcp.tool()
def list_entries() -> str:
    """List every entry recorded so far (stable channel)."""
    return "\n".join(_entries) if _entries else "No entries."


@mcp.tool()
def get_clock() -> str:
    """Return a monotonically increasing tick — changes on every call (churn)."""
    _ticks["n"] += 1
    return f"tick {_ticks['n']}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
