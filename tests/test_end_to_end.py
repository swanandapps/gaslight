"""Milestone 1's actual definition of done, automated: a confirmed canary
exfiltration against a deliberately vulnerable target, and no finding (the
false-positive guard) against the same attack run at a hardened one.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.injection_exfil import InjectionExfilAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_vulnerable_target_leaks_the_canary():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await InjectionExfilAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.canary_token is not None
    assert finding.exfil_tool == "send_email"
    assert finding.turns_taken >= 2
    assert finding.candidate_exfil_tool == "send_email"


async def test_hardened_target_does_not_leak():
    with Sink() as sink:
        async with TargetConnection(_spec("hardened_server.py")) as target:
            finding = await InjectionExfilAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.candidate_exfil_tool == "send_email"
