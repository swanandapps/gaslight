"""Denial-of-Wallet (unbounded consumption): no LLM, no injection — call a
list/fetch/size-bounded tool and ask it for far more than it should ever
return, then measure the response. If the tool hands back an oversized payload
with no cap of its own, a caller can drive it into expensive work at will —
the "your agent burned $X in a loop" failure (real incident: a compromised
tool inflated per-query cost 658x, "Beyond Max Tokens", Jan 2026).

Deliberately model-free and sibling to ssrf_probe.py: whether a tool bounds how
much it returns is entirely a target-owned code property, no model involved.
The proof is a measured byte size, not an opinion.

This is a hardening gap, not a confirmed compromise like RCE — so it reports a
WEAK sub-check (which docks the Authorization score) rather than a breach that
would drop the whole grade to F. The Finding stays fired=False; the CheckResult
carries the verdict (see core/metrics.py: WEAK lowers the score without ever
breaching, and fired=False keeps it off the blast radius).

We ask for a large-but-FINITE amount, never infinity: a well-behaved server
caps it small and fast, a vulnerable one returns a big-but-measurable payload —
neither should hit the 60s call timeout, which is a backend-death signal we
must not trip on purpose. Belt-and-suspenders, this attack is registered last
so a pathological hang can't starve the others.

Fetching/listing isn't destructive, so the real call always happens regardless
of --safe (same as ssrf_probe.py). What --safe gates is what gets stored: by
default the previewed response is masked and hard-truncated before it reaches a
Finding; --no-safe stores it raw. The size measurement is taken on the full
response, before any truncation, either way.
"""

from __future__ import annotations

from gaslight.core.attacks.base import CHECK_PASS, CHECK_WEAK, AttackModule, CheckResult, Finding
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import find_unbounded_tool, naive_arguments
from gaslight.core.secrets_scan import redact_and_truncate
from gaslight.core.sink import Sink
from gaslight.core.target import Target

# Large but finite: enough to expose a missing cap, small enough that a
# well-behaved server returns quickly rather than us tripping the call timeout.
_HUGE = 100_000
# A response over this size, when we asked for far more than any UI would, means
# the server applied no cap of its own. ~200 KB — well above any sane page of
# results, well below what a capped server ever returns in these fixtures.
_NO_CAP_BYTES = 200_000
_PREVIEW_LENGTH = 150
_COST_CAP_CHECK = "cost-cap"


class DenialOfWalletAttack(AttackModule):
    key = "denial-of-wallet"
    name = "Denial-of-Wallet (Unbounded Consumption)"
    description = (
        "Asks a list/fetch tool for far more than it should return — no model, no injection — "
        "and measures the response, checking whether the server caps how much work one call can demand."
    )

    def __init__(self, *, safe: bool = True) -> None:
        if not isinstance(safe, bool):
            raise TypeError(f"safe must be a bool, got {type(safe).__name__}")
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider and sink are accepted to satisfy the AttackModule interface
        # but unused — this attack proves itself by measured response size, with
        # no model turn and no sink round-trip. That's the point.
        tool, size_field = find_unbounded_tool(target.tools)
        if tool is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no list/fetch/size-bounded tool to probe for unbounded consumption.",
                attempted=False,
            )

        args = naive_arguments(tool.input_schema, exclude=size_field)
        if size_field is not None:
            args[size_field] = _HUGE
        result = await target.call_tool(tool.name, args)
        text = Target.result_text(result)
        size = len(text)
        asked = f"{size_field}={_HUGE}" if size_field is not None else "everything (no size knob)"

        if size > _NO_CAP_BYTES:
            preview = redact_and_truncate(text, _PREVIEW_LENGTH) if self._safe else text
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{tool.name} returned {size} bytes with no server-side cap "
                    f"(asked for {asked}) — response: {preview!r}"
                ),
                checks=[CheckResult(_COST_CAP_CHECK, CHECK_WEAK)],
            )

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(f"{tool.name} capped or refused the oversized request (asked for {asked}, got {size} bytes)."),
            checks=[CheckResult(_COST_CAP_CHECK, CHECK_PASS)],
        )
