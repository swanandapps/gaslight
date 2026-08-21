"""True-positive + false-positive-guard pair for output-side leakage — the
verdict is a text match on the agent's own reply, never a sink hit. See
docs/superpowers/specs/2026-08-17-m3-attack-suite-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.output_leakage import OutputLeakageAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_confidential_value_leaks_into_agent_reply():
    with Sink() as sink:
        async with TargetConnection(_spec("confidential_data_server.py")) as target:
            finding = await OutputLeakageAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.canary_token is not None


async def test_redacted_target_does_not_leak():
    with Sink() as sink:
        async with TargetConnection(_spec("redacting_confidential_data_server.py")) as target:
            finding = await OutputLeakageAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
