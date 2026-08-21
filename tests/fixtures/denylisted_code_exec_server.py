"""Same execution mechanism as unguarded_code_exec_server.py — real
subprocess, zero sandboxing — but guarded by a literal-substring denylist
("urllib", "curl", "http://") checked against the submitted code text
before it runs. Proves CodeExecutionAttack's base64-wrapped network-trap
payload is a genuinely distinct bypass: the denylist blocks the plain-text
network calls, but never decodes what it's about to execute, so the
base64-wrapped variant sails through the same subprocess that would have
caught the plain one.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile

from mcp.server import MCPServer

mcp = MCPServer("denylisted-code-exec-agent")

_DENYLIST = ("urllib", "curl", "http://")


def _guarded_run(code_or_command: str, *, shell: bool) -> str:
    lowered = code_or_command.lower()
    if any(term in lowered for term in _DENYLIST):
        raise ValueError("network access is disabled in this deployment")
    if shell:
        result = subprocess.run(code_or_command, shell=True, capture_output=True, text=True, timeout=10)
    else:
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code_or_command)
            path = f.name
        result = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr


@mcp.tool()
def execute_python_code(code: str) -> str:
    """Execute Python code for data analysis. Blocks urllib/curl/http:// by name."""
    return _guarded_run(code, shell=False)


@mcp.tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command. Blocks urllib/curl/http:// by name."""
    return _guarded_run(command, shell=True)


if __name__ == "__main__":
    mcp.run(transport="stdio")
