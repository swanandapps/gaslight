"""A tool with a plain string field that is never interpolated into a path,
URL, or command — just stored as plain data. False-positive guard for
ArgumentSmugglingAttack: a tool that "finds" a leak here is crying wolf.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("inert-field-agent")

_preferences: dict[str, str] = {}


@mcp.tool()
def set_preference(value: str) -> str:
    """Set a user preference value. Stored as plain text, never interpreted."""
    _preferences["value"] = value
    return f"Preference set to {value!r}."


if __name__ == "__main__":
    mcp.run(transport="stdio")
