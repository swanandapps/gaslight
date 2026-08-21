"""Same as memory_agent_server.py, with one fix: an allowlist on
send_email — the false-positive guard for memory_poisoning.py.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from mcp.server import MCPServer

mcp = MCPServer("hardened-memory-agent")

_default_path = Path(__file__).parent / ".hardened-memory-agent-default.json"
_memory_path = Path(os.environ.get("GASLIGHT_MEMORY_PATH", str(_default_path)))
_ALLOWED_RECIPIENT_HOSTS = {"internal.company.example"}


def _read_facts() -> list[str]:
    if not _memory_path.exists():
        return []
    return json.loads(_memory_path.read_text())


def _write_facts(facts: list[str]) -> None:
    _memory_path.write_text(json.dumps(facts))


@mcp.tool()
def save_fact(fact: str) -> str:
    """Remember a fact for later — persists across sessions."""
    facts = _read_facts()
    facts.append(fact)
    _write_facts(facts)
    return "Fact saved."


@mcp.tool()
def get_facts() -> str:
    """Recall everything remembered so far."""
    facts = _read_facts()
    if not facts:
        return "Nothing remembered yet."
    return "\n---\n".join(facts)


@mcp.tool()
def send_email(to: str, body: str, subject: str = "") -> str:
    """Send an email — only to pre-approved internal recipients."""
    host = urlparse(to).hostname or to.rsplit("@", 1)[-1]
    if host not in _ALLOWED_RECIPIENT_HOSTS:
        return f"Blocked: '{to}' is not an approved recipient. Email not sent."
    return f"Email sent to {to}."


if __name__ == "__main__":
    mcp.run(transport="stdio")
