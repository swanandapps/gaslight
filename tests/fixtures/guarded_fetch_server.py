"""Same shape as unguarded_fetch_server.py, but fetch_url rejects any URL
whose hostname is loopback or link-local before fetching — same "raise,
don't silently return a blocked string" convention guarded_file_read_server.py
established, so it's correctly detectable as CallToolResult.is_error=True.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("guarded-fetch-agent")


def _is_forbidden_host(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_link_local
    except ValueError:
        return False


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return its body as text. Rejects loopback/link-local hosts."""
    host = urllib.parse.urlparse(url).hostname or ""
    if _is_forbidden_host(host):
        raise ValueError(f"url {url!r} targets a forbidden host: {host!r}")
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    mcp.run(transport="stdio")
