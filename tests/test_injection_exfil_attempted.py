"""Regression for the whole-branch-review finding (Finding 2): a target with
an exfil-capable tool but no write/read-shaped surface must not produce a
`Finding` that looks identical to "tested, and the model refused." Before
this fix, `InjectionExfilAttack`'s early-return paths all set `fired=False`
with no way to distinguish "never got the chance" from "genuinely clean."

`exfil_only_server.py` exposes exactly one tool, `send_email` — exfil-capable,
but no `save_note`/`read_notes`-shaped tool to plant through or read back —
so the attack must bail out before ever invoking `VictimHarness.run()`, i.e.
before any model is ever called.
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


async def test_injection_not_attempted_when_no_write_or_read_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("exfil_only_server.py")) as target:
            finding = await InjectionExfilAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.turns_taken == 0
