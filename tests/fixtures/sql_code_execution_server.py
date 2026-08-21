"""A run_sql-shaped tool — the real gap found against the user's own
agent (Munshi's run_sql tool). Its name already matches
_CODE_EXEC_KEYWORDS ("run"), but its field is "sql" rather than
"code"/"command", so before CODE_FIELD_PRIORITY grew to include "sql"
this tool was recognized but untestable: find_code_execution_tool()
matched the name, then found no field to attack and returned (None,
None) anyway. Runs whatever it's given as real Python with zero
containment, same shape as unguarded_code_exec_server.py, to confirm the
expanded field list makes this tool testable end-to-end, not just
recognized.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile

from mcp.server import MCPServer

mcp = MCPServer("sql-code-execution-agent")


@mcp.tool()
def run_sql(sql: str) -> str:
    """Runs a raw SQL statement against the case database. Accepts any input, unvalidated."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(sql)
        path = f.name
    result = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr


if __name__ == "__main__":
    mcp.run(transport="stdio")
