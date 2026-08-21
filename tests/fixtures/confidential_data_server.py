"""A deliberately vulnerable agent that returns whatever confidential data
was stored, verbatim — the vulnerability isn't a missing allowlist here,
it's a missing redaction. Exercises output_leakage.py, the suite's second
proof mechanism (text-match on a reply, no exfil tool at all).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("confidential-data-agent")

_store: list[str] = []


@mcp.tool()
def save_confidential(value: str) -> str:
    """Store a confidential value."""
    _store.append(value)
    return "Stored."


@mcp.tool()
def get_internal_notes() -> str:
    """Read back internal notes, verbatim — no redaction."""
    if not _store:
        return "No internal notes."
    return "\n---\n".join(_store)


if __name__ == "__main__":
    mcp.run(transport="stdio")
