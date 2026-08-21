"""Target adapter resource-awareness — MCP resources are a distinct
protocol primitive from tools, never previously touched by gaslight.
See docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.target import Target, TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_target_with_no_resources_gets_empty_list():
    # vulnerable_server.py (from M1) implements zero @mcp.resource() —
    # verified empirically that list_resources() returns an empty list
    # gracefully against a FastMCP-based server, no exception.
    async with TargetConnection(_spec("vulnerable_server.py")) as target:
        assert target.resources == []


async def test_target_resources_and_read_resource_round_trip():
    async with TargetConnection(_spec("exposed_resource_server.py")) as target:
        uris = [str(r.uri) for r in target.resources]
        assert "company://public" in uris
        assert "company://confidential" in uris

        confidential = next(r for r in target.resources if str(r.uri) == "company://confidential")
        result = await target.read_resource(str(confidential.uri))
        text = Target.resource_text(result)
        assert "sk_live_" in text
