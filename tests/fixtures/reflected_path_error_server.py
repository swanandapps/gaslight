"""A tool that resolves its argument against a base directory and echoes the
resulting absolute path in a verbose error. When gaslight probes it with the
placeholder record_id='test-value', the FileNotFoundError reads
"...: '/home/workdir/artifacts/test-value'" — but that path is just OUR OWN
injected value resolved to absolute. A server reflecting the input you handed it
is not disclosing a secret, so error-disclosure must NOT fire here (the real
"errors leak paths" case is a path the server reveals that we did not send).
"""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("reflected-path-error-agent")

_BASE = "/home/workdir/artifacts"


@mcp.tool()
def read_record(record_id: str) -> str:
    """Read a record by its id."""
    try:
        with open(os.path.join(_BASE, record_id)) as f:
            return f.read()
    except OSError as e:
        return str(e)  # verbose: "[Errno 2] No such file or directory: '/home/workdir/artifacts/test-value'"


if __name__ == "__main__":
    mcp.run(transport="stdio")
