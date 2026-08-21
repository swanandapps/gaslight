"""Cross-session proof: a fact planted in one connection is recalled and
leaked in a completely separate, later connection — the thing no
single-session fixture can demonstrate. See
docs/superpowers/specs/2026-08-17-m3-attack-suite-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.memory_poisoning import MemoryPoisoningAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fact_planted_in_one_session_leaks_in_a_later_session():
    with Sink() as sink:
        async with TargetConnection(_spec("memory_agent_server.py")) as target:
            finding = await MemoryPoisoningAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "send_email"
    assert finding.canary_token is not None


async def test_hardened_target_does_not_leak_recalled_fact():
    with Sink() as sink:
        async with TargetConnection(_spec("hardened_memory_agent_server.py")) as target:
            finding = await MemoryPoisoningAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


async def test_no_real_persistence_declines_honestly():
    """vulnerable_server.py has write/read/exfil-shaped tools by name, but its
    notes are an in-memory list that resets every fresh subprocess — no real
    cross-session persistence. Session 2 never recalls anything planted in
    session 1, so the attack's precondition never held. This must be reported
    as never-tested (attempted=False), not as "tested and clean.\""""
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await MemoryPoisoningAttack().run(target, ScriptedProvider(), sink)

    assert finding.attempted is False
