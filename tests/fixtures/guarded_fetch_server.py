"""Same shape as unguarded_fetch_server.py, but fetch_url is PROPERLY guarded:
it RESOLVES the hostname and rejects any address that lands on loopback,
link-local, or private space — so it holds even against encoded loopback hosts
(decimal/hex/shorthand), which a naive string check on the raw hostname would
miss. Raises rather than silently returning (the "raise, don't return a blocked
string" convention), so it's detectable as CallToolResult.is_error=True.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("guarded-fetch-agent")


def _is_forbidden_host(host: str) -> bool:
    # Resolve first, then judge the resolved IP(s). Resolving is what makes this
    # resistant to encoded loopback (2130706433, 0x7f000001, 127.1): they all
    # resolve to 127.0.0.1, which is_loopback catches — a raw-string check does not.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_link_local or ip.is_private:
            return True
    return False


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return its body as text. Rejects hosts that resolve to
    loopback/link-local/private addresses."""
    host = urllib.parse.urlparse(url).hostname or ""
    if _is_forbidden_host(host):
        raise ValueError(f"url {url!r} targets a forbidden host: {host!r}")
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    mcp.run(transport="stdio")
