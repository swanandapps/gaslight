"""Same unguarded shape as unguarded_file_read_server.py, but read_file()
also requires a second field (requester_id) that has nothing to do with
path confinement — always accepted regardless of its value. Proves the
false-negative this milestone's own review caught: a probe that only
ever sent the path field would fail schema validation against a tool
shaped like this on every single payload, and misread universal
rejection as "confined to its directory" when the tool was never
actually tested. naive_arguments() fills requester_id with a plausible
placeholder so the real, unguarded path argument still gets exercised.
"""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("unguarded-file-read-extra-required-field-agent")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SANDBOX_DIR = os.path.join(_BASE_DIR, "unguarded_file_read_sandbox")


@mcp.tool()
def read_file(path: str, requester_id: str) -> str:
    """Read a file from the sandboxed directory. requester_id is required
    but never checked — accepts any value. path is accepted unvalidated."""
    full_path = os.path.join(_SANDBOX_DIR, path)
    with open(full_path, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")
