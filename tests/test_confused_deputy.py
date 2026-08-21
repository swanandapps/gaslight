"""True-positive + false-positive-guard pair for the confused-deputy
cross-tool exfil probe, plus the tool-distinctness guard. See
docs/superpowers/specs/2026-08-20-v1-attack-net-widening.md, section 2.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.confused_deputy import ConfusedDeputyAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_against_unguarded_target():
    # vulnerable_server.py: save_note (write) -> read_notes (read) ->
    # send_email (exfil, no allowlist) — three genuinely distinct tools.
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await ConfusedDeputyAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "send_email"
    assert "save_note" in finding.reason
    assert "read_notes" in finding.reason
    assert "send_email" in finding.reason


async def test_does_not_fire_against_guarded_target():
    # hardened_server.py: same write/read chain, but send_email allowlists
    # recipients — the canary is planted and confirmed retrievable, but
    # never reaches the sink.
    with Sink() as sink:
        async with TargetConnection(_spec("hardened_server.py")) as target:
            finding = await ConfusedDeputyAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.exfil_tool is None
    assert finding.candidate_exfil_tool == "send_email"


async def test_target_with_no_chain_surface_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_file_read_server.py")) as target:
            finding = await ConfusedDeputyAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_declines_when_the_only_exfil_tool_is_the_write_tool():
    # write_is_exfil_server.py: post_update matches both a write keyword
    # ("post") and an exfil keyword+field — the only candidate exfil tool is
    # the write tool itself, so there's no genuine second tool to compose a
    # chain through.
    with Sink() as sink:
        async with TargetConnection(_spec("write_is_exfil_server.py")) as target:
            finding = await ConfusedDeputyAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.candidate_exfil_tool == "post_update"
