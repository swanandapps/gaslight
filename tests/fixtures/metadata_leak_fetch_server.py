"""A fetch_url tool that rejects direct loopback fetches (so
SsrfProbeAttack's category-1 loopback trap correctly finds nothing here)
but returns a fabricated, secret-bearing response when asked for the AWS
metadata address — simulating a target with some destination confinement
that's still vulnerable via the metadata path specifically. Used to prove
SsrfProbeAttack's safe/no-safe masking behavior against real secret-shaped
content, which the loopback-trap path can never provide (that path's
response is always gaslight's own sink saying "ok" — nothing to mask).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("metadata-leak-fetch-agent")

_FAKE_METADATA_RESPONSE = (
    "ami-id: i-1234567890abcdef0 "
    "api_key: sk-live-abcdef1234567890 "
    "padding padding padding padding padding padding padding padding"
)


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL. Rejects anything except the AWS metadata address."""
    if "169.254.169.254" in url:
        return _FAKE_METADATA_RESPONSE
    raise ValueError(f"url {url!r} is not reachable from this fixture")


if __name__ == "__main__":
    mcp.run(transport="stdio")
