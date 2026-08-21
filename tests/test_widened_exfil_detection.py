"""Proves the widened exfil-tool heuristics catch a previously-invisible
shape: share_document(content, destination) matches neither the original
_EXFIL_KEYWORDS ("share" wasn't in the list) nor the original
find_address_field (exact-match only against a fixed word list;
"destination" wasn't in it, and even if it were, exact-match would still
miss compound variants like "webhook_url"/"share_with"). See core/schema.py
and the widened ADDRESS_FIELD_PRIORITY/word-boundary matching there.
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


async def test_injection_exfil_fires_against_share_shaped_target():
    with Sink() as sink:
        async with TargetConnection(_spec("document_sharing_server.py")) as target:
            finding = await InjectionExfilAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "share_document"
    assert finding.canary_token is not None
