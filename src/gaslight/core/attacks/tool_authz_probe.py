"""The direct tool-authorization probe: no LLM, no injection — just call a
risky tool ourselves with an attacker-style destination and see whether a
real, deterministic code-level check stops it, or it just complies.

Deliberately dumb on purpose. If a tool blocks this, it has a real
allowlist/validation behind it. If it doesn't, no amount of model good
behavior saves you — see docs/brain/M2_DESIGN.md, "Mechanism A".

Same verdict mechanism as injection_exfil.py: the canary either reaches the
sink or it doesn't. No CallToolResult.is_error inspection, no guessing at
*why* a tool declined — some tools reject via an MCP-level error, some (see
tests/fixtures/hardened_server.py) just return a polite "blocked" string
with no error flag at all. The sink is the only thing that can't be talked
out of the truth.
"""

from __future__ import annotations

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.canary import mint
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import find_exfil_tool, find_string_field
from gaslight.core.sink import Sink
from gaslight.core.target import Target


class ToolAuthzProbeAttack(AttackModule):
    key = "tool-authz-probe"
    name = "Direct Tool-Authorization Probe"
    description = (
        "Calls a risky tool directly with an attacker-style destination — no model, no "
        "injection — and checks whether a real code-level restriction blocks it."
    )

    def __init__(self, *, safe: bool = True) -> None:
        # Every probe this module can run today already routes its
        # "attacker" destination to our own sink and only ever targets
        # exfil-shaped tools — safe by construction. `safe` is accepted and
        # threaded through from the CLI now so a future milestone that adds
        # genuinely destructive-tool probing has a real flag to gate on; it
        # has no behavioral effect yet.
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        exfil_tool, address_field = find_exfil_tool(target.tools)
        if exfil_tool is None or address_field is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no viable exfil-capable tool with an address-like field to probe.",
                # Not attempted, not passed: with no tool of this shape there was
                # nothing to probe, so this must score as N/A. Every sibling
                # attack already does this; this one didn't, and a target with no
                # exfil-shaped tool was reporting a clean pass for a check that
                # never ran.
                attempted=False,
            )

        canary = mint("authz-probe")
        # Embed the canary in the destination itself — provably deliverable
        # for any exfil-shaped tool, regardless of schema. Sink.received()
        # matches on CapturedRequest.full_text, which includes the parsed
        # query string, so this alone is enough to detect a leak even when
        # the tool's only string field is the address field itself.
        args = {address_field: f"{sink.url}?ref={canary.token}"}
        content_field = find_string_field(exfil_tool.input_schema)
        if content_field and content_field != address_field:
            # Redundant second carrier when a distinct content field exists.
            args[content_field] = f"authorization probe — reference {canary.token}"

        await target.call_tool(exfil_tool.name, args)
        caught = sink.received(canary.token)

        return Finding(
            attack_key=self.key,
            fired=caught is not None,
            reason=(
                f"{exfil_tool.name} accepted an arbitrary, attacker-controlled destination with "
                "no rejection — no code-level check exists."
                if caught is not None
                else f"{exfil_tool.name} did not deliver to the attacker-controlled destination — "
                "a code-level check exists (or the tool never attempted delivery)."
            ),
            canary_token=canary.token,
            exfil_tool=exfil_tool.name if caught is not None else None,
            candidate_exfil_tool=exfil_tool.name,
            sink_request_summary=(f"{caught.method} {caught.path}" if caught is not None else None),
        )
