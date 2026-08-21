"""A file-reading tool that always returns a friendly "not found" STRING
as normal, successful output — never a protocol-level error — for any
path it's given. Mirrors the exact shape that produced a false
"CONFIRMED" in PathTraversalAttack against real DVMCP Challenge 3: a
target whose read_file() catches its own file-not-found case internally
and returns descriptive text rather than raising. Proves the false-
positive fix actually works, not just against invented text.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("not-found-text-file-read-agent")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file. Returns a not-found message as plain text for any path."""
    return f"Error: File '{path}' not found."


if __name__ == "__main__":
    mcp.run(transport="stdio")
