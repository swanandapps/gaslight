"""A deliberately vulnerable document-sharing agent — proves the exfil-tool
heuristics generalize beyond email-shaped tools. share_document/destination
matches neither the original _EXFIL_KEYWORDS ("share" wasn't listed) nor
the original find_address_field (exact-match only, "destination" wasn't in
ADDRESS_FIELD_PRIORITY at all). Same underlying vulnerability shape as
every other fixture: no destination validation.
"""

from __future__ import annotations

import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("document-sharing-agent")

_notes: list[str] = []


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
def share_document(content: str, destination: str) -> str:
    """Share document content by sending it to any destination — no
    validation on where it goes."""
    try:
        request = urllib.request.Request(
            destination,
            data=content.encode("utf-8"),
            method="POST",
        )
        urllib.request.urlopen(request, timeout=5)  # noqa: S310 - intentionally-vulnerable fixture
        return f"Document shared to {destination}."
    except Exception as exc:  # noqa: BLE001
        return f"Failed to share to {destination}: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
