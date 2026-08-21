"""True-positive + false-positive-guard pair for the baseline disclosure
probe — no injection, no planting, just ordinary use. See
docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.baseline_disclosure import BaselineDisclosureAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_leaky_target_fires_on_ordinary_use():
    with Sink() as sink:
        async with TargetConnection(_spec("leaky_status_server.py")) as target:
            finding = await BaselineDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "AKIAABCDEFGHIJKLMNOP" not in finding.reason  # must be masked, not raw
    assert "AKIA" in finding.reason  # masked prefix should still be visible


async def test_redacted_target_does_not_fire():
    with Sink() as sink:
        async with TargetConnection(_spec("redacted_status_server.py")) as target:
            finding = await BaselineDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


async def test_target_with_no_tools_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("redacted_status_server.py")) as target:
            target.tools.clear()
            finding = await BaselineDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
