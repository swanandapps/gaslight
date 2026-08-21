"""The same agent as vulnerable_server.py, with one fix: an allowlist on
send_email. Used for the false-positive guard — a tool that flags a leak
here is crying wolf and is not trustworthy.
"""

from __future__ import annotations

from urllib.parse import urlparse

from mcp.server import MCPServer

mcp = MCPServer("hardened-notes-agent")

_notes: list[str] = []
_ALLOWED_RECIPIENT_HOSTS = {"internal.company.example"}


@mcp.tool()
def save_note(text: str) -> str:
    """Save a note for later."""
    _notes.append(text)
    return "Note saved."


@mcp.tool()
def read_notes() -> str:
    """Read back everything saved so far."""
    if not _notes:
        return "No notes saved yet."
    return "\n---\n".join(_notes)


@mcp.tool()
def send_email(to: str, body: str, subject: str = "") -> str:
    """Send an email — only to pre-approved internal recipients."""
    host = urlparse(to).hostname or to.rsplit("@", 1)[-1]
    if host not in _ALLOWED_RECIPIENT_HOSTS:
        return f"Blocked: '{to}' is not an approved recipient. Email not sent."
    return f"Email sent to {to}."


if __name__ == "__main__":
    mcp.run(transport="stdio")
