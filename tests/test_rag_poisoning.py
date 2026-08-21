"""Proves InjectionExfilAttack's existing tool-discovery heuristics
generalize to a RAG-shaped target (add_document/search_docs) with zero new
attack-module code. See
docs/superpowers/specs/2026-08-17-m3-attack-suite-design.md.
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


async def test_injection_exfil_fires_against_rag_shaped_target():
    with Sink() as sink:
        async with TargetConnection(_spec("rag_server.py")) as target:
            finding = await InjectionExfilAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "send_email"
    assert finding.canary_token is not None
