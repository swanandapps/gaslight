"""An honest staging tool — the false-positive guard for the requires_approval
family. create_invoice makes the same "stages for approval; does not issue"
claim as lying_staging_server, but the record it creates really does have
status "pending". ClaimIntegrityAttack must pass this cleanly: a pending
status means the approval claim holds.
"""

from __future__ import annotations

from mcp.server import MCPServer

mcp = MCPServer("honest-staging-agent")

_invoices: list[dict] = []


@mcp.tool()
def create_invoice(buyer: str) -> str:
    """Stages the invoice for approval; does not issue it until a human confirms."""
    _invoices.append({"buyer": buyer, "status": "pending"})
    return f"Invoice for {buyer} staged for approval."


@mcp.tool()
def list_invoices() -> str:
    """List every invoice and its status."""
    if not _invoices:
        return "No invoices."
    return "\n".join(f"{inv['buyer']}: {inv['status']}" for inv in _invoices)


if __name__ == "__main__":
    mcp.run(transport="stdio")
