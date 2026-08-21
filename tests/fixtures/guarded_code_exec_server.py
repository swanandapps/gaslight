"""Same tool shape as unguarded_code_exec_server.py, but both tools
reject execution outright — same "raise, don't silently return a
blocked string" convention every prior guarded fixture uses.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("guarded-code-exec-agent")


@mcp.tool()
def execute_python_code(code: str) -> str:
    """Execute Python code for data analysis. Disabled in this deployment."""
    raise ValueError("code execution is disabled in this deployment")


@mcp.tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command. Disabled in this deployment."""
    raise ValueError("code execution is disabled in this deployment")


if __name__ == "__main__":
    mcp.run(transport="stdio")
