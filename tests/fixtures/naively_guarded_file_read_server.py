"""Same shape as guarded_file_read_server.py, but the guard is naive: it
strips the literal substring "../" ONCE (a single non-recursive
`str.replace`) instead of canonicalizing the resolved path. This blocks
plain "../" and absolute-path traversal, but is bypassable by "....//" —
a well-known real sanitizer-bypass technique: a single `.replace("../", "")`
pass collapses each "....//" unit to "../", so the "escaped" path still
resolves outside the sandbox. Proves PathTraversalAttack's fs-encoded
sub-check independently of fs-dotdot/fs-absolute, which this fixture
correctly blocks — the partial-credit shape the redesign spec's Filesystem
metric is built to score.
"""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("naively-guarded-file-read-agent")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SANDBOX_DIR = os.path.join(_BASE_DIR, "unguarded_file_read_sandbox")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the sandboxed directory. Strips the literal "../"
    substring once — a naive, bypassable guard."""
    sanitized = path.replace("../", "")
    if sanitized.startswith("/"):
        raise ValueError(f"path {path!r} escapes the sandboxed directory")
    full_path = os.path.join(_SANDBOX_DIR, sanitized)
    with open(full_path, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")
