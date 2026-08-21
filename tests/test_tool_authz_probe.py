"""M2's direct authorization probe: true-positive + false-positive-guard
pair, mirroring the shape of tests/test_end_to_end.py for M1's attack.
Reuses the same two fixtures — no new fixture needed. vulnerable_server.py's
send_email always attempts outbound delivery regardless of destination
validity (so a call routed to our sink will reach it); hardened_server.py's
send_email validates the recipient host before ever attempting delivery (so
it never will) — exactly the code-gate-present-vs-absent split this probe
needs to prove.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.tool_authz_probe import ToolAuthzProbeAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_probe_fires_against_unvalidated_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await ToolAuthzProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "send_email"
    assert finding.candidate_exfil_tool == "send_email"
    assert finding.canary_token is not None


async def test_probe_does_not_fire_against_allowlisted_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("hardened_server.py")) as target:
            finding = await ToolAuthzProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.candidate_exfil_tool == "send_email"


async def test_probe_fires_when_address_field_is_the_only_string_field():
    """Regression for the whole-branch-review finding: a tool whose only
    string parameter *is* the address field (address_field == content_field,
    e.g. `notify(endpoint: str)`) used to get no canary anywhere, because the
    old code only ever carried the canary via a distinct content field. The
    fix embeds the canary in the destination URL itself, so this must still
    correctly detect the leak.
    """
    with Sink() as sink:
        async with TargetConnection(_spec("address_only_server.py")) as target:
            finding = await ToolAuthzProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "notify"
    assert finding.canary_token is not None
