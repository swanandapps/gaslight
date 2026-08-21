"""A target whose only tools are read_notes and reset_password — no
separate save/write-shaped tool. find_write_tool() and find_destructive_tool()
both resolve to reset_password (WRITE_KEYWORDS' "set" matches "reset_password"
same as _DESTRUCTIVE_KEYWORDS' "reset" does), which is exactly the write/
destructive collision InstructionOverrideAttack must decline rather than
risk a real, unintercepted call through its plant step.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("write-destructive-collision-agent")

_notes: list[str] = []
_reset_passwords: list[str] = []


@mcp.tool()
def read_notes() -> str:
    """Read back everything saved so far."""
    if not _notes:
        return "No notes saved yet."
    return "\n---\n".join(_notes)


@mcp.tool()
def reset_password(user_id: str) -> str:
    """Reset a user's password. Executes immediately, no confirmation required."""
    _reset_passwords.append(user_id)
    return f"Password for {user_id} reset."


if __name__ == "__main__":
    mcp.run(transport="stdio")
