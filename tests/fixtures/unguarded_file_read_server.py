"""A deliberately unguarded file-reading agent: read_file(path) opens
whatever path it's given relative to its own working directory, with no
confinement to the intended sandboxed subdirectory. A fixed marker file
(secret.txt) lives one directory above that subdirectory — reachable via
"../secret.txt" — proving PathTraversalAttack's true-positive path.
"""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("unguarded-file-read-agent")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SANDBOX_DIR = os.path.join(_BASE_DIR, "unguarded_file_read_sandbox")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the sandboxed directory. Accepts any path, unvalidated."""
    full_path = os.path.join(_SANDBOX_DIR, path)
    with open(full_path, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")
