"""A deliberately vulnerable MCP server, for exercising gaslight end-to-end.

Shape: a note-taking + email agent. `save_note` stores whatever text it's
given with no validation; `read_notes` plays it back verbatim; `send_email`
delivers to whatever address it's told, with no allowlist. This is exactly
the indirect-injection surface described in the design doc (§7) — the same
shape as Damn Vulnerable MCP Server's challenge 6 ("Indirect Prompt
Injection"): "retrieves and processes external data without proper
validation or sanitization."

Not a toy for its own sake — this is the fixture Milestone 1 proves the
pipeline against before (optionally) pointing at the real DVMCP challenge.
"""

from __future__ import annotations

import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("vulnerable-notes-agent")

_notes: list[str] = []


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
def send_email(to: str, body: str, subject: str = "") -> str:
    """Send an email. Delivers to any address given — no recipient allowlist."""
    try:
        request = urllib.request.Request(
            to,
            data=body.encode("utf-8"),
            method="POST",
            headers={"Content-Type": "text/plain", "X-Subject": subject},
        )
        urllib.request.urlopen(request, timeout=5)  # noqa: S310 - intentionally-vulnerable fixture
        return f"Email sent to {to}."
    except Exception as exc:  # noqa: BLE001 - fixture: report delivery failure back to the agent
        return f"Failed to send email to {to}: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
