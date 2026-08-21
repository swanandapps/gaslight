"""True-positive + false-positive-guard pairs for the claim-integrity attack,
plus the unverifiable-decline and external-effect-safety behaviors. See
docs/superpowers/specs/2026-08-19-claim-integrity-design.md.
"""

import sys
from pathlib import Path

from dataclasses import dataclass

from gaslight.core.attacks.claim_integrity import ClaimIntegrityAttack, verification_read_tools
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


@dataclass
class _Tool:
    name: str
    input_schema: dict
    description: str | None = None


def test_verification_read_tools_excludes_external_effect_shaped_reads():
    # A "list_and_revoke"-style tool matches a read keyword ("list") but also a
    # destructive one ("revoke") — it must NOT be used as a snapshot channel,
    # since snapshotting calls it for real.
    tools = [
        _Tool(name="list_invoices", input_schema={"properties": {}}),
        _Tool(name="list_and_revoke_sessions", input_schema={"properties": {}}),
        _Tool(name="get_and_send_report", input_schema={"properties": {}}),
        _Tool(name="create_invoice", input_schema={"properties": {}}),
    ]
    safe = {t.name for t in verification_read_tools(tools, exclude_name="create_invoice")}
    assert safe == {"list_invoices"}


async def test_fires_on_lying_readonly_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("lying_readonly_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.claim_tool == "record_view"
    assert "read-only" in finding.reason.lower()


async def test_passes_honest_readonly_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("honest_readonly_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is True
    assert finding.claim_tool == "lookup_entry"


async def test_fires_on_lying_staging_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("lying_staging_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.claim_tool == "create_invoice"
    assert "issued" in finding.reason.lower()


async def test_fires_on_lying_staging_even_with_an_unrelated_pending_record():
    # Regression: a lying create_invoice (issues immediately) must still fire
    # when list_invoices ALSO contains an unrelated record sitting "pending".
    # The verdict inspects the canary invoice's own line, not the whole list,
    # so the unrelated pending word must not mask the lie.
    with Sink() as sink:
        async with TargetConnection(_spec("lying_staging_with_other_pending_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.claim_tool == "create_invoice"
    assert "issued" in finding.reason.lower()


async def test_passes_honest_staging_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("honest_staging_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is True
    assert finding.claim_tool == "create_invoice"


async def test_excludes_a_churning_channel_and_still_catches_the_lie():
    # get_clock changes on its own between the two baseline reads and must be
    # excluded as noise; the lie is still caught through the stable
    # list_entries channel, where the canary appears.
    with Sink() as sink:
        async with TargetConnection(_spec("noisy_channel_readonly_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.claim_tool == "record_view"


async def test_declines_honestly_when_claim_is_unverifiable():
    with Sink() as sink:
        async with TargetConnection(_spec("unverifiable_claim_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.claim_tool == "archive_item"
    assert "verif" in finding.reason.lower()


async def test_declines_when_no_tool_makes_a_claim():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await ClaimIntegrityAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_safe_mode_does_not_call_an_external_effect_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("external_effect_claim_server.py")) as target:
            finding = await ClaimIntegrityAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.claim_tool == "send_report"
    assert "no-safe" in finding.reason.lower()


async def test_no_safe_mode_runs_the_external_effect_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("external_effect_claim_server.py")) as target:
            finding = await ClaimIntegrityAttack(safe=False).run(target, ScriptedProvider(), sink)

    # send_report claims read-only but writes; under --no-safe it gets called
    # and the lie is caught.
    assert finding.attempted is True
    assert finding.fired is True
    assert finding.claim_tool == "send_report"


def test_default_construction_is_safe():
    assert ClaimIntegrityAttack()._safe is True


def test_construction_rejects_non_bool_safe():
    import pytest

    with pytest.raises(TypeError):
        ClaimIntegrityAttack(safe="yes")
