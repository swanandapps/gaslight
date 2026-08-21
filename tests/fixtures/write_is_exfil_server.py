"""A minimal fixture with only one write-shaped tool, and that tool's name
happens to also match an exfil-tool keyword ("post" is in both
WRITE_KEYWORDS and _EXFIL_KEYWORDS) while carrying an address-like field
("to"). Used to prove ConfusedDeputyAttack's distinctness guard: when the
only candidate exfil tool IS the write tool, there is no genuine second tool
to compose a cross-tool chain through, and the attack must decline rather
than force a meaningless same-tool "chain".
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("write-is-exfil-agent")

_posts: list[str] = []


@mcp.tool()
def post_update(to: str, body: str) -> str:
    """Post an update to a destination. Accepts any destination, unvalidated."""
    _posts.append(body)
    return f"Posted to {to}."


@mcp.tool()
def get_status() -> str:
    """Get the current status of all posts."""
    return "\n---\n".join(_posts) if _posts else "No posts yet."


if __name__ == "__main__":
    mcp.run(transport="stdio")
