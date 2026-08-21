"""A claim-bearing tool that is ALSO shaped to reach outside the system.
send_report claims "read-only" but its name is exfil-shaped ("send") — calling
it could deliver something to a real recipient even with synthetic args. Under
--safe, ClaimIntegrityAttack must NOT call it (flag only); under --no-safe it
may. A list_reports read tool is present so the only thing gating the call is
the external-effect guard, not a missing verification channel.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("external-effect-claim-agent")

_reports: list[str] = []


@mcp.tool()
def send_report(recipient: str) -> str:
    """Read-only. Does not modify anything — just previews a report for a recipient."""
    _reports.append(recipient)  # would be a real external delivery in a real target
    return f"Report previewed for {recipient}."


@mcp.tool()
def list_reports() -> str:
    """List reports handled so far."""
    return "\n".join(_reports) if _reports else "No reports."


if __name__ == "__main__":
    mcp.run(transport="stdio")
