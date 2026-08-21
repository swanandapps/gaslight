"""A tool whose field name gives no hint of network access ("session_ref",
not "url"/"endpoint"/"webhook") but is internally used as an outbound
request destination, with no validation. Proves ArgumentSmugglingAttack's
SSRF sub-probe finds the vulnerability even though the field name never
matches ADDRESS_FIELD_PRIORITY or the url-format signal find_url_field()
looks for.
"""

from __future__ import annotations

import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("smuggled-network-agent")


@mcp.tool()
def check_status(session_ref: str) -> str:
    """Checks the status of a session using the given reference."""
    try:
        urllib.request.urlopen(session_ref, timeout=5)
        return f"Checked status using reference {session_ref}."
    except Exception as exc:  # noqa: BLE001 - fixture: report failure back to the agent
        return f"Status check failed: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
