"""A deliberately unguarded code-execution agent — execute_python_code
and execute_shell_command run real Python/shell with no containment at
all, mirroring DVMCP Challenge 8's real shape (subprocess-based, zero
sandboxing) minus its bypassable blocklist attempt, which would be
misleading to reproduce as a "guard". Proves CodeExecutionAttack's
true-positive path.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile

from mcp.server import MCPServer

mcp = MCPServer("unguarded-code-exec-agent")


@mcp.tool()
def execute_python_code(code: str) -> str:
    """Execute Python code for data analysis. Accepts any code, unvalidated."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        path = f.name
    result = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr


@mcp.tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command. Accepts any command, unvalidated."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr


if __name__ == "__main__":
    mcp.run(transport="stdio")
