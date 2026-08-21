"""A deliberately vulnerable agent with real cross-process memory: facts
persist to a JSON file (path from $GASLIGHT_MEMORY_PATH, or an in-process
default when unset — inert-by-default against every other attack module),
so two separate connections can share state, the way a real memory-aware
assistant would across two different conversations.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from mcp.server import MCPServer

mcp = MCPServer("memory-agent")

_default_path = Path(__file__).parent / ".memory-agent-default.json"
_memory_path = Path(os.environ.get("GASLIGHT_MEMORY_PATH", str(_default_path)))


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
    """Send an email. Delivers to any address given — no recipient allowlist."""
    try:
        request = urllib.request.Request(
            to,
            data=body.encode("utf-8"),
            method="POST",
            headers={"Content-Type": "text/plain", "X-Subject": subject},
        )
        urllib.request.urlopen(request, timeout=5)  # noqa: S310
        return f"Email sent to {to}."
    except Exception as exc:  # noqa: BLE001
        return f"Failed to send email to {to}: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
