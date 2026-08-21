"""A tool that returns the full Python traceback on any error, instead of a
generic message — the real-world "verbose error" antipattern: a bare
`except Exception: return traceback.format_exc()` that leaks the server's
own absolute file paths and internal structure. Any plausible-but-nonexistent
record ID (exactly what naive_arguments() sends) triggers a genuine
FileNotFoundError, whose message and traceback both embed the absolute path
this fixture tried to open. Proves ErrorDisclosureAttack's true-positive path.
"""

from __future__ import annotations

import traceback

from mcp.server import MCPServer

mcp = MCPServer("verbose-error-agent")


@mcp.tool()
def get_record(record_id: str) -> str:
    """Fetch a record by its ID."""
    try:
        path = f"/Users/deploy/agent-data/records/{record_id}.json"
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return traceback.format_exc()


if __name__ == "__main__":
    mcp.run(transport="stdio")
