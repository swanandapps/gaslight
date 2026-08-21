"""Claim-integrity probe: does a tool's own stated safety promise actually
hold? A tool's description says "read-only" or "stages for approval, does not
issue"; the driving LLM trusts that promise, so if it's false the whole safety
model is false. This attack verifies the promise against the target's OWN
observable state — no LLM opinion, no privileged database access, just the
target's own read tools, the same door any MCP client has.

The cycle (see the design doc for the full reasoning):
  1. Baseline-read every read-shaped tool (S0).
  2. Read again with no action between (S0') — anything that changed on its
     own is natural churn (timestamps, counters) and is excluded.
  3. Call the tool under test exactly once, with a canary in a text field.
  4. Read again (S1).
  5. Verdict from the surviving, churn-excluded delta.

Because exactly one write happens between S0' and S1 and churn is subtracted,
any surviving change is attributable to the tool under test.

Safety: arguments are synthetic, the canary is inert — a read_only tool that
secretly writes only ever stores our marker; a staging tool that secretly
commits only ever commits our synthetic record, never real business data.
The one real external-effect risk is a claim-bearing tool that is ALSO shaped
to reach outside (send/delete/fetch): under --safe such a tool is flagged, not
called; --no-safe runs it.

Accepted limitations (documented, not solved):
  - Noise check is two back-to-back reads. A slow-cadence field that doesn't
    tick between them is treated as stable; if it ticks during the write, a
    no-string-field read_only tool can false-fire (mitigated: a tool we could
    canary-tag fires only on the canary appearing, not on generic change).
  - A read channel excluded as noisy is not re-read afterward, so if the ONLY
    channel that would show a write is itself noisy, the write is missed.
  - Status verdict is line-scoped to the canary's record; a read tool that
    renders one record across multiple lines can still split the status word
    away from the canary line.

See docs/superpowers/specs/2026-08-19-claim-integrity-design.md.
"""

from __future__ import annotations

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.canary import mint
from gaslight.core.claims import Claim, committed_status_words, detect_claim, pending_status_words
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import (
    _CODE_EXEC_KEYWORDS,
    _DESTRUCTIVE_KEYWORDS,
    _EXFIL_KEYWORDS,
    _NETWORK_KEYWORDS,
    _match_source,
    find_all_read_tools,
    find_string_field,
    naive_arguments,
)
from gaslight.core.sink import Sink
from gaslight.core.target import Target
from mcp import types

# A claim-bearing tool matching any of these could have a real side effect
# even with synthetic args (deliver to a real recipient, delete real data,
# reach the network, run real code) — so it is not auto-called under --safe,
# and it is never used as a read channel for snapshotting either.
_EXTERNAL_EFFECT_KEYWORDS = (
    _EXFIL_KEYWORDS + _DESTRUCTIVE_KEYWORDS + _NETWORK_KEYWORDS + _CODE_EXEC_KEYWORDS
)


def _lines_with_token(snapshot: dict[str, str], token: str) -> str | None:
    """The specific line(s) mentioning `token`, across a snapshot's read
    responses — so a status verdict inspects the canary's OWN record, not the
    whole list. A list_* read tool returns every record; scanning the full
    text let an unrelated record's status word decide the verdict (the
    committed+pending false-negative raised in review). Line-scoped is the
    right granularity for the common one-record-per-line list shape; a
    multi-line-per-record shape is a documented, accepted imprecision."""
    for text in snapshot.values():
        matching = [line for line in text.splitlines() if token in line]
        if matching:
            return "\n".join(matching)
    return None


def verification_read_tools(tools: list[types.Tool], exclude_name: str) -> list[types.Tool]:
    """Read-shaped tools safe to use purely for observing state: read-named,
    not the tool under test, and NOT also shaped to reach outside (a
    "list_and_purge"-style name that matches a read keyword and a destructive
    one must not be called just to take a snapshot)."""
    return [
        t
        for t in find_all_read_tools(tools)
        if t.name != exclude_name and _match_source(t, _EXTERNAL_EFFECT_KEYWORDS) is None
    ]


def _first_claim_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, Claim | None]:
    """The first tool whose description carries a testable safety claim."""
    for tool in tools:
        claim = detect_claim(tool.description)
        if claim is not None:
            return tool, claim
    return None, None


class ClaimIntegrityAttack(AttackModule):
    key = "claim-integrity"
    name = "Claim Integrity"
    description = (
        "Checks whether a tool's own stated safety promise ('read-only', 'requires approval') "
        "actually holds, by acting and then reading the target's own state back — no model "
        "opinion, no privileged access."
    )

    def __init__(self, *, safe: bool = True) -> None:
        if not isinstance(safe, bool):
            raise TypeError(f"safe must be a bool, got {type(safe).__name__}")
        self._safe = safe

    async def _snapshot(self, target: Target, read_tools: list[types.Tool]) -> dict[str, str]:
        snap: dict[str, str] = {}
        for tool in read_tools:
            try:
                result = await target.call_tool(tool.name, naive_arguments(tool.input_schema))
                snap[tool.name] = Target.result_text(result)
            except Exception as exc:  # a read tool that errors is simply not a usable channel
                snap[tool.name] = f"<error: {type(exc).__name__}>"
        return snap

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider/sink are unused: this attack proves via the target's own
        # read tools, not a model or the sink.
        tool, claim = _first_claim_tool(target.tools)
        if tool is None or claim is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no tool makes a testable safety claim (read-only / requires-approval) to verify.",
                attempted=False,
            )

        # External-effect guard: a claim-bearing tool that is also shaped to
        # reach outside the system could have a real side effect even with
        # synthetic args. Under --safe, flag it rather than call it.
        if self._safe and _match_source(tool, _EXTERNAL_EFFECT_KEYWORDS) is not None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{tool.name} claims {claim.phrase!r} but is also shaped to reach outside the "
                    "system (send/delete/network) — calling it could have a real external effect, "
                    "so it is not auto-verified under --safe. Rerun with --no-safe to test it."
                ),
                claim_tool=tool.name,
                attempted=False,
            )

        # Read tools used only to observe state must themselves be safe to
        # call — exclude any that also look destructive/exfil/network/code-exec
        # (the snapshot-safety hole raised in review).
        read_tools = verification_read_tools(target.tools, tool.name)
        if not read_tools:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{tool.name} claims {claim.phrase!r}, but the target exposes no read tool to "
                    "observe its effect through — the claim cannot be verified black-box."
                ),
                claim_tool=tool.name,
                attempted=False,
            )

        # Baseline + noise check: two reads with no action between. A read
        # tool whose text changes on its own is natural churn; exclude it.
        baseline = await self._snapshot(target, read_tools)
        baseline2 = await self._snapshot(target, read_tools)
        stable_tools = [t for t in read_tools if baseline.get(t.name) == baseline2.get(t.name)]
        if not stable_tools:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{tool.name} claims {claim.phrase!r}, but every read channel changes on its own "
                    "between two baseline reads (too noisy to attribute any change) — declined rather "
                    "than risk a false finding."
                ),
                claim_tool=tool.name,
                attempted=False,
            )

        # Act once, tagging a text field with a canary so its appearance in
        # state is unambiguous proof the call wrote.
        canary = mint("claim")
        string_field = find_string_field(tool.input_schema)
        args = naive_arguments(tool.input_schema)
        if string_field is not None:
            args[string_field] = canary.token
        await target.call_tool(tool.name, args)

        after = await self._snapshot(target, stable_tools)
        observed = list(baseline2.values()) + list(after.values())
        canary_injected = string_field is not None

        if claim.family == "read_only":
            return self._verdict_read_only(
                tool, claim, canary.token, canary_injected, baseline2, after, observed
            )
        return self._verdict_requires_approval(tool, claim, canary.token, after, observed)

    def _verdict_read_only(self, tool, claim, canary_token, canary_injected, before, after, observed):
        canary_seen = any(canary_token in text for text in after.values())
        changed = any(before.get(name) != after.get(name) for name in after)
        # When we could tag the call with a canary, the canary appearing in
        # state is the reliable signal — a generic "something changed" alone
        # can be natural churn the two-baseline check didn't catch (a
        # slow-cadence field ticking over during the write). Only fall back to
        # the generic-change signal when no string field was taggable, since
        # then the canary can't be the evidence. (Residual, documented: a
        # no-string-field tool that writes AND sits behind a churning channel
        # can still false-fire; a tool that writes without echoing its
        # string arg can be missed — both accepted limitations.)
        fired = canary_seen if canary_injected else changed
        if fired:
            how = (
                f"the value it was given ({canary_token}) now appears in the target's state"
                if canary_seen
                else "the target's observable state changed after the call"
            )
            return Finding(
                attack_key=self.key,
                fired=True,
                reason=(
                    f"{tool.name} claims {claim.phrase!r}, but calling it modified the target: {how}. "
                    "The tool's own read tools contradict its own description."
                ),
                claim_tool=tool.name,
                raw_observed_text=observed,
            )
        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"{tool.name} claims {claim.phrase!r}, and calling it left the target's observable "
                "state unchanged — the claim holds."
            ),
            claim_tool=tool.name,
            attempted=True,
            raw_observed_text=observed,
        )

    def _verdict_requires_approval(self, tool, claim, canary_token, after, observed):
        # Inspect the status of the canary's OWN record — the specific line(s)
        # mentioning it — not the whole list, so an unrelated record's status
        # word can't decide the verdict.
        canary_text = _lines_with_token(after, canary_token)
        if canary_text is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{tool.name} claims {claim.phrase!r}, but the item it created could not be found "
                    "in any read channel afterward — its committed/staged status can't be verified "
                    "black-box."
                ),
                claim_tool=tool.name,
                attempted=False,
                raw_observed_text=observed,
            )

        committed = committed_status_words(canary_text)
        pending = pending_status_words(canary_text)
        if committed and not pending:
            return Finding(
                attack_key=self.key,
                fired=True,
                reason=(
                    f"{tool.name} claims {claim.phrase!r}, but the record it created shows status "
                    f"{committed[0]!r} immediately — no approval step gates it. The tool's own read "
                    "tools contradict its own description."
                ),
                claim_tool=tool.name,
                raw_observed_text=observed,
            )
        if pending:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{tool.name} claims {claim.phrase!r}, and the record it created shows status "
                    f"{pending[0]!r} — the approval claim holds."
                ),
                claim_tool=tool.name,
                attempted=True,
                raw_observed_text=observed,
            )
        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"{tool.name} claims {claim.phrase!r}; the item it created was found, but with no "
                "recognizable committed/pending status word — can't verify the claim black-box."
            ),
            claim_tool=tool.name,
            attempted=False,
            raw_observed_text=observed,
        )
