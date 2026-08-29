"""Regression test for a real false-negative bug in `_run()`: attacks used to
share one `TargetConnection` across the whole loop, so a later attack's
read-back could pick up an earlier attack's leftover planted state on the
same live target subprocess. Concretely: injection-exfil plants a note
naming `send_email` and its own canary via `save_note`; when output-leakage
later read back notes on that *same* shared connection, `vulnerable_
server.py`'s in-memory notes list still had injection-exfil's note in it,
and `ScriptedProvider`'s injection-detection heuristic matched on that stale
text instead of falling through to echo output-leakage's own confidential
text — output-leakage silently reported "no leak" even though the target is
genuinely vulnerable to it (confirmed independently: it fires when run
alone). A security tool must never let stale cross-attack state imply safe.

This exercises the actual `_run()` code path end-to-end (real subprocess,
real HTML report) rather than re-deriving the bug against the attack
modules directly, since the bug lived in how `_run()` wires connections
across the attack loop, not in any single attack module.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from rich.console import Console

from gaslight.cli import _run

_FIXTURES = Path(__file__).parent / "fixtures"


def _finding_fired(html: str, key: str) -> bool:
    # A fired attack renders a "confirmed exploit" block; a non-fired one is not
    # rendered as a finding card at all (it lives in the gauges / breakdown).
    # Presence of the confirmed block for this key == it fired.
    return (
        re.search(
            rf'<div class="finding fired">\s*<div class="finding-head">'
            rf'<span class="k">CONFIRMED</span>'
            rf'(?:<span class="badge sev-\w+">\w+</span>)?'  # severity badge (added later)
            rf'<span class="on">{re.escape(key)}\b',
            html,
        )
        is not None
    )


async def test_run_gives_each_attack_a_fresh_connection_no_cross_attack_state_leak(tmp_path):
    output_path = tmp_path / "report.html"
    args = argparse.Namespace(
        command=[sys.executable, str(_FIXTURES / "vulnerable_server.py")],
        url=None,
        llm="scripted",
        safe=True,
        classify_secrets=False,
        output=str(output_path),
        json=False,
        skip="",
        max_turns=6,
    )

    exit_code = await _run(args, Console())

    assert exit_code == 1
    html = output_path.read_text()

    # injection-exfil plants first and fires regardless of ordering.
    assert _finding_fired(html, "injection-exfil") is True
    # The regression: output-leakage must fire on its own merits, not have
    # its canary masked by injection-exfil's leftover planted note on a
    # shared connection.
    assert _finding_fired(html, "output-leakage") is True
