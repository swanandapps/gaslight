"""A deliberately unguarded URL-fetching agent: fetch_url(url) opens
whatever URL it's given with no destination validation at all. Proves
SsrfProbeAttack's true-positive path.
"""

from __future__ import annotations

import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("unguarded-fetch-agent")


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return its body as text. Accepts any URL, unvalidated."""
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    mcp.run(transport="stdio")
