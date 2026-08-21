"""True-positive + false-positive-guard pair for tool-metadata poisoning —
the injection lives in a tool description, never in tool output. See
docs/superpowers/specs/2026-08-17-m3-attack-suite-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.tool_metadata_poisoning import ToolMetadataPoisoningAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_poisoned_description_leaks_canary():
    with Sink() as sink:
        async with TargetConnection(_spec("tool_metadata_poisoned_server.py")) as target:
            finding = await ToolMetadataPoisoningAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "send_email"
    assert finding.canary_token is not None


async def test_plain_target_is_not_cooperating_and_is_declined_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await ToolMetadataPoisoningAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
