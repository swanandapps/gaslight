"""True-positive + false-positive-guard pair for resource exposure, plus a
test isolating the naming-heuristic path from the content-scan path. No
model involved — resources are read directly. See
docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.resource_exposure import ResourceExposureAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_exposed_confidential_resource_fires():
    with Sink() as sink:
        async with TargetConnection(_spec("exposed_resource_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True


async def test_clean_target_does_not_fire():
    with Sink() as sink:
        async with TargetConnection(_spec("clean_resource_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


async def test_sensitively_named_resource_fires_even_with_clean_content():
    with Sink() as sink:
        async with TargetConnection(_spec("named_only_resource_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True


async def test_unnamed_resource_with_leaky_content_fires():
    with Sink() as sink:
        async with TargetConnection(_spec("unnamed_leaky_resource_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True


async def test_target_with_no_resources_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_gated_sensitive_resource_does_not_falsely_claim_no_gating():
    """Fix 4: a sensitively-named resource whose read is correctly refused
    (raises) must not be reported as "reachable with no gating" — that's
    the exact opposite of what happened. This fixture's only resource is
    both sensitively named and refused, so if the naming check ran before
    (and independent of) the read succeeding, this would incorrectly fire.
    """
    with Sink() as sink:
        async with TargetConnection(_spec("gated_resource_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert "no gating" not in finding.reason


async def test_resource_exposure_captures_raw_observed_text():
    """Fix 3b: every successfully-read resource's text is threaded onto
    the returned Finding's raw_observed_text, so --classify-secrets has
    something to look at even though resource-exposure never runs a model
    or produces a transcript."""
    with Sink() as sink:
        async with TargetConnection(_spec("exposed_resource_server.py")) as target:
            finding = await ResourceExposureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert any("sk_live_ABCDEFGHIJKLMNOPQRST1234" in text for text in finding.raw_observed_text)
