"""A deliberately vulnerable RAG-style agent — the injection-exfil attack
exercised through a different, realistic entry point (a shared document
corpus instead of a personal notes list). Same underlying vulnerability as
vulnerable_server.py (send_email has no recipient allowlist); this fixture
exists to prove InjectionExfilAttack's tool-discovery heuristics generalize
to "add a document / search documents" naming, not to introduce a new
mechanism.
"""

from __future__ import annotations

import urllib.request

from mcp.server import MCPServer

mcp = MCPServer("rag-notes-agent")

_documents: list[str] = []


@mcp.tool()
def add_document(content: str) -> str:
    """Add a document to the shared corpus. Anyone can contribute — no
    validation, matching a typical internal wiki or shared drive."""
    _documents.append(content)
    return "Document added."


@mcp.tool()
def search_docs(query: str = "") -> str:
    """Search the document corpus. Naive: returns the full corpus
    regardless of query — enough to prove the exfil attack surface, not a
    real search implementation."""
    if not _documents:
        return "No documents found."
    return "\n---\n".join(_documents)


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
        urllib.request.urlopen(request, timeout=5)  # noqa: S310 - intentionally-vulnerable fixture
        return f"Email sent to {to}."
    except Exception as exc:  # noqa: BLE001
        return f"Failed to send email to {to}: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
