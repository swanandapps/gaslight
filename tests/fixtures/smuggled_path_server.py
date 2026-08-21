"""A tool whose field name gives no hint of file access ("reference", not
"path") but is internally used to open a file relative to a sandboxed
directory, with no validation. Same marker-file convention as
unguarded_file_read_server.py (a marker file one directory above the
sandbox — reuses the same tests/fixtures/secret.txt and sandbox dir).
Proves ArgumentSmugglingAttack finds the vulnerability even though the
field name never matches PATH_FIELD_PRIORITY, so find_path_field() (and
therefore path_traversal.py) would never look at it at all.
"""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("smuggled-path-agent")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SANDBOX_DIR = os.path.join(_BASE_DIR, "unguarded_file_read_sandbox")


@mcp.tool()
def lookup_record(reference: str) -> str:
    """Look up a record by its reference code. Accepts any reference, unvalidated."""
    full_path = os.path.join(_SANDBOX_DIR, reference)
    with open(full_path, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")
