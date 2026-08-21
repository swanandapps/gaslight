"""Argument smuggling: no LLM, no injection — try a path-traversal marker
payload and an SSRF canary URL against every string field on every tool that
ISN'T already that tool's own recognized path/url/code field, in case the
target interpolates an ordinary-looking argument into a path, URL, or query
internally. Model-free by design, sibling to path_traversal.py/ssrf_probe.py:
this widens WHICH field gets attacked, not how the proof works — it reuses
the exact same physical proofs (a marker signature read back, or a canary
physically reaching our sink).

Every other model-free probe in this project assumes the vulnerable field is
the one that LOOKS like a path or a URL. Real targets don't always agree: a
`create_invoice(customer_id)` tool might use customer_id to build a file
path for a receipt template, or a `lookup_order(reference)` tool might use
reference to build an internal callback URL. This module tries the
field-independent case — does THIS string field, whatever it's named, end up
interpolated somewhere unsafe — across every tool and every field the other
probes never look at.

Never probes a tool whose name or description looks destructive or
exfil-shaped (schema.is_consequential — the same guard schema._qualify() uses
for field-only tool targeting): a probe that only ever touches our own sink
or reads back a marker signature must never be the thing that actually
triggers a real irreversible action.

Scope, deliberately kept tight: one marker attempt and one sink attempt per
non-obvious field (not a full traversal-depth sweep, not every loopback host
spelling — those are what path_traversal.py/ssrf_probe.py already do
exhaustively against the field that's SUPPOSED to hold that content). This
module's job is breadth across fields and tools, not depth on any one field.
"""

from __future__ import annotations

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.canary import mint
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import (
    find_all_string_fields,
    find_code_field,
    find_path_field,
    find_url_field,
    is_consequential,
    naive_arguments,
)
from gaslight.core.secrets_scan import redact_and_truncate
from gaslight.core.sink import Sink
from gaslight.core.target import Target

_MARKER_FILENAME = "secret.txt"
_MARKER_SIGNATURE = "PATH TRAVERSAL MARKER"
# One shallow attempt, not a depth sweep — depth is path_traversal.py's job
# once a field is already known to be path-like; this module's job is
# breadth across fields that AREN'T known to be. Matches the marker
# convention's existing fixtures (a marker file one directory above a
# single-nested sandbox), so a fixture built for this attack needs no new
# marker file of its own.
_TRAVERSAL_PAYLOAD = "../" + _MARKER_FILENAME
_PREVIEW_LENGTH = 150


def _recognized_fields(schema: dict | None) -> set[str]:
    """The fields other probes already target directly on this tool — never
    worth smuggling into, since path_traversal.py/ssrf_probe.py/
    code_execution.py already exercise them thoroughly."""
    return {f for f in (find_path_field(schema), find_url_field(schema), find_code_field(schema)) if f is not None}


class ArgumentSmugglingAttack(AttackModule):
    key = "argument-smuggling"
    name = "Argument Smuggling (Non-Obvious Field Interpolation)"
    description = (
        "Tries a path-traversal marker and an SSRF canary against every string field on "
        "every tool that isn't already the recognized path/url/code field — no model, no "
        "injection — in case an ordinary-looking argument gets interpolated into a path, "
        "URL, or query internally."
    )

    def __init__(self, *, safe: bool = True) -> None:
        # Every payload here is either a marker-file read (harmless,
        # confined-directory content) or a canary aimed at our own sink —
        # harmless-by-construction regardless of --safe, same as
        # path_traversal.py/ssrf_probe.py. Accepted for constructor symmetry;
        # gates what gets stored, not what gets called.
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        canary = mint("arg-smuggle")
        network_probe_url = f"{sink.url}?ref={canary.token}"
        fields_tried = 0

        for tool in target.tools:
            if is_consequential(tool):
                continue
            recognized = _recognized_fields(tool.input_schema)
            for field in find_all_string_fields(tool.input_schema):
                if field in recognized:
                    continue
                fields_tried += 1

                marker_args = naive_arguments(tool.input_schema, exclude=field)
                marker_args[field] = _TRAVERSAL_PAYLOAD
                marker_result = await target.call_tool(tool.name, marker_args)
                if not marker_result.is_error:
                    text = Target.result_text(marker_result)
                    if _MARKER_SIGNATURE in text:
                        preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
                        return Finding(
                            attack_key=self.key,
                            fired=True,
                            reason=(
                                f"{tool.name} — marker returned from the {field!r} field, "
                                f"interpolated into a path — response: {preview!r}"
                            ),
                        )

                network_args = naive_arguments(tool.input_schema, exclude=field)
                network_args[field] = network_probe_url
                await target.call_tool(tool.name, network_args)
                caught = sink.received(canary.token)
                if caught is not None:
                    return Finding(
                        attack_key=self.key,
                        fired=True,
                        reason=(
                            f"{tool.name} — canary reached the sink via the {field!r} field, "
                            "interpolated into an outbound URL or query."
                        ),
                        canary_token=canary.token,
                        exfil_tool=tool.name,
                        sink_request_summary=f"{caught.method} {caught.path}",
                    )

        if fields_tried == 0:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no non-consequential tool exposed a string field beyond its own recognized path/url/code field.",
                attempted=False,
            )

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"probed {fields_tried} non-obvious string field(s) across {len(target.tools)} tool(s) — "
                "none interpolated a marker or SSRF payload into a path, URL, or query."
            ),
        )
