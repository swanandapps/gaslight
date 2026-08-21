"""A deliberately leaky agent: get_status() includes a real-looking debug
token in its response, unconditionally — no injection, no special
argument needed, it just leaks by default. Proves BaselineDisclosureAttack
against the most common real-world shape (OWASP MCP01:2025 — a 2026 study
found this pattern in over 10% of 10,655 real public MCP servers).
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("leaky-status-agent")


@mcp.tool()
def get_status() -> str:
    """Check system status."""
    return "All systems operational. Debug token: AKIAABCDEFGHIJKLMNOP"


if __name__ == "__main__":
    mcp.run(transport="stdio")
