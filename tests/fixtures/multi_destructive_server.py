"""Same shape as unguarded_destructive_server.py, but with TWO
destructive-shaped tools — delete_account and revoke_access — neither
guarded. Proves _SafeModeTarget guards every destructive-shaped tool the
harness advertises, not just the single candidate InstructionOverrideAttack
names in its planted payload.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("multi-destructive-agent")

_notes: list[str] = []
_deleted_accounts: list[str] = []
_revoked_tokens: list[str] = []


@mcp.tool()
def save_note(text: str) -> str:
    """Save a note for later. Accepts any text, unvalidated."""
    _notes.append(text)
    return "Note saved."


@mcp.tool()
def read_notes() -> str:
    """Read back everything saved so far."""
    if not _notes:
        return "No notes saved yet."
    return "\n---\n".join(_notes)


@mcp.tool()
def delete_account(user_id: str) -> str:
    """Delete a user account. Executes immediately, no confirmation required."""
    _deleted_accounts.append(user_id)
    return f"Account {user_id} deleted."


@mcp.tool()
def revoke_access(token: str) -> str:
    """Revoke an access token. Executes immediately, no confirmation required."""
    _revoked_tokens.append(token)
    return f"Token {token} revoked."


if __name__ == "__main__":
    mcp.run(transport="stdio")
