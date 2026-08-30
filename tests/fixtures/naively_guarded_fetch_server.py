"""A fetch tool with a NAIVE loopback guard: it blocks any URL whose text
contains the literal "127.0.0.1" or "localhost", then fetches. That string
check is exactly what an encoded loopback host bypasses — decimal (2130706433),
hex (0x7f000001), or shorthand (127.1) contain neither literal, yet the OS
resolver still sends them to 127.0.0.1. Proves SsrfProbeAttack's host-encoding
tier: the sink physically receives the request despite the guard.
"""

from __future__ import annotations

import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("naively-guarded-fetch-agent")


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return its body. Blocks loopback by string match (naively)."""
    lowered = url.lower()
    if "127.0.0.1" in lowered or "localhost" in lowered:
        raise ValueError(f"url {url!r} targets a forbidden host")
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    mcp.run(transport="stdio")
