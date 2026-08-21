"""Same shape as unguarded_file_read_server.py, but read_file canonicalizes
the resolved path and rejects (raises) anything that resolves outside the
intended sandboxed subdirectory — same "raise, don't silently return a
blocked string" convention M5a's guarded fixtures established, so it's
correctly detectable as CallToolResult.is_error=True rather than misread
as a successful-but-empty read.
"""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("guarded-file-read-agent")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SANDBOX_DIR = os.path.abspath(os.path.join(_BASE_DIR, "guarded_file_read_sandbox"))


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the sandboxed directory. Rejects any path that
    resolves outside the sandbox."""
    full_path = os.path.abspath(os.path.join(_SANDBOX_DIR, path))
    if os.path.commonpath([full_path, _SANDBOX_DIR]) != _SANDBOX_DIR:
        raise ValueError(f"path {path!r} escapes the sandboxed directory")
    with open(full_path, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")
