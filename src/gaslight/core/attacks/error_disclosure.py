"""Verbose-error disclosure: no LLM, no injection — call every tool with
deliberately malformed or implausible arguments and check whether the
resulting error text leaks a secret, an internal filesystem path, or a
Python stack trace. Model-free by design, sibling to baseline-disclosure.py:
the target's own default error-handling behavior is the thing under test,
not anything gaslight injects or plants.

Real-world antipattern this proves: a bare `except Exception as e: return
str(e)` (or worse, `return traceback.format_exc()`) instead of a generic
"internal error" message. `str(e)` on a `FileNotFoundError` naturally embeds
the absolute path the code tried to open; a full traceback additionally
reveals the server's own source-file layout. Neither requires the attacker
to control anything — an ordinary, plausible-looking bad argument is enough.

Malformed-argument strategy, in order of how likely each is to actually
reach the tool's own code rather than being rejected generically by MCP's
own schema validation (naive_arguments()'s docstring already establishes
that a request failing schema validation never reaches the target's
implementation at all):
1. Empty args (every required field omitted) — cheap; occasionally a
   framework's own "missing argument" message is itself unexpectedly
   verbose.
2. naive_arguments() — schema-VALID but semantically implausible
   placeholder values ("test-value", 1, False). This is the primary,
   most-reliable probe: it's guaranteed to pass schema validation and reach
   real tool logic, and a placeholder ID/name is exactly the shape of value
   a real lookup is likely to fail loudly on.
3. naive_arguments() with the first required string field overridden to an
   oversized value — catches buffer/length-constraint-shaped errors
   specifically.
4. Every required field given a value of the WRONG JSON type — best-effort;
   may be rejected by the same schema validation naive_arguments() exists
   to route around, kept as a fourth attempt since it costs nothing extra
   when it doesn't apply.

Guard against false positives the same way baseline-disclosure.py does:
firing requires a real secret-scan hit, a genuine absolute-path signature, or
a literal stack-trace marker — never "the error was long or unusual-looking."
And a path leak that is only OUR OWN injected argument reflected back (the tool
resolved our placeholder to an absolute path and echoed it in a FileNotFoundError)
does NOT fire — that's the server describing the input we handed it, not
disclosing something it chose to hide. Only a path revealing more than we sent
counts (see _path_is_reflected_input).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import is_consequential, naive_arguments
from gaslight.core.secrets_scan import find_high_confidence_secrets, mask_secret, redact_and_truncate
from gaslight.core.sink import Sink
from gaslight.core.target import Target

_PREVIEW_LENGTH = 200
_OVERSIZED_LENGTH = 5000

_ABS_PATH_PATTERNS = [
    re.compile(r"/Users/[^\s\"'<>]+"),
    re.compile(r"/home/[^\s\"'<>]+"),
    # A Windows drive letter must stand alone. Without the lookbehind this
    # matched "s:\n" — the tail of the word "Options:" followed by an escaped
    # newline — inside kubectl's ordinary public help text, and reported it as
    # a leaked path.
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\[^\s\"'<>]+"),
]
_STACK_TRACE_MARKERS = ("Traceback (most recent call last)", '  File "')


@dataclass
class _Leak:
    value: str
    kind: str  # "secret" | "path" | "stack-trace"


def _path_is_reflected_input(path: str, injected: set[str]) -> bool:
    """True when a leaked absolute path is just OUR OWN injected argument value
    resolved to absolute — e.g. we sent record_id='test-value', the tool did
    open(os.path.join(base, 'test-value')) and the FileNotFoundError echoed
    '/home/app/artifacts/test-value'. A server reflecting the input you handed it
    in an error is not disclosing anything it chose to keep secret, so it must not
    count. The check is tight — only the path's FINAL component matching what we
    sent — so a path that reveals more than our input (a different basename, a
    deeper directory, an added extension) still fires as a genuine leak."""
    tail = path.rstrip("/").rsplit("/", 1)[-1]
    return any(val and (tail == val or path.endswith("/" + val)) for val in injected)


def _find_leak(text: str, injected: set[str] | None = None) -> _Leak | None:
    if not text:
        return None
    # Only a RECOGNISABLE secret format confirms a finding here — never an
    # entropy guess. This attack fires CONFIRMED and drops the grade to F, so
    # its evidence has to be real: a random-looking build hash or request id in
    # an error message must not be reported as a leaked credential (the source
    # of every false positive found while testing real servers). An absolute
    # path and a stack trace below are likewise deterministic signatures, not
    # guesses.
    secrets = find_high_confidence_secrets(text)
    if secrets:
        return _Leak(secrets[0], "secret")
    injected = injected or set()
    for pattern in _ABS_PATH_PATTERNS:
        for m in pattern.finditer(text):
            # Skip a path that is only our own injected value reflected back —
            # but keep scanning: a genuine path elsewhere in the same error
            # (a config/home/source path we did NOT send) still fires.
            if _path_is_reflected_input(m.group(0), injected):
                continue
            return _Leak(m.group(0), "path")
    for marker in _STACK_TRACE_MARKERS:
        if marker in text:
            return _Leak(marker, "stack-trace")
    return None


def _empty_arguments(schema: dict[str, Any] | None) -> dict[str, Any]:
    return {}


def _oversized_arguments(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """naive_arguments()'s normal fill, with the first required string field
    blown out to _OVERSIZED_LENGTH chars. None when there's no required
    string field to oversize."""
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(props, dict) or not isinstance(required, list):
        return None
    for key in required:
        spec = props.get(key, {})
        if isinstance(spec, dict) and spec.get("type") == "string":
            args = naive_arguments(schema)
            args[key] = "A" * _OVERSIZED_LENGTH
            return args
    return None


def _wrong_type_arguments(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Every required field filled with a value of the WRONG declared JSON
    type — an integer where a string is expected, a string where a number
    is expected. Best-effort: may never reach the tool's own code if MCP's
    schema validation rejects it first (see module docstring)."""
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(props, dict) or not isinstance(required, list) or not required:
        return None
    args: dict[str, Any] = {}
    for key in required:
        spec = props.get(key, {})
        declared = spec.get("type") if isinstance(spec, dict) else None
        if declared == "string":
            args[key] = 12345
        elif declared in ("integer", "number"):
            args[key] = "not-a-number"
        elif declared == "boolean":
            args[key] = "not-a-boolean"
        elif declared == "array":
            args[key] = "not-an-array"
        else:
            args[key] = 12345
    return args


def _malformed_variants(schema: dict[str, Any] | None) -> list[tuple[str, dict[str, Any]]]:
    variants: list[tuple[str, dict[str, Any]]] = [
        ("empty-arguments", _empty_arguments(schema)),
        ("implausible-placeholder", naive_arguments(schema)),
    ]
    oversized = _oversized_arguments(schema)
    if oversized is not None:
        variants.append(("oversized-string", oversized))
    wrong_type = _wrong_type_arguments(schema)
    if wrong_type is not None:
        variants.append(("wrong-type", wrong_type))
    return variants


class ErrorDisclosureAttack(AttackModule):
    key = "error-disclosure"
    name = "Verbose-Error Disclosure"
    description = (
        "Calls every tool with deliberately malformed or implausible arguments — no model, "
        "no injection — and checks whether the resulting error text leaks a secret, an "
        "internal filesystem path, or a stack trace."
    )

    def __init__(self, *, safe: bool = True) -> None:
        # Every call here uses malformed/implausible arguments against a
        # non-consequential tool (see the is_consequential skip below) —
        # harmless-by-construction regardless of --safe. Accepted for
        # constructor symmetry; gates what gets stored, not what gets called.
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        if not target.tools:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="target exposes no tools to probe.",
                attempted=False,
            )

        probeable = [t for t in target.tools if not is_consequential(t)]
        if not probeable:
            # naive_arguments() is a real, schema-valid call, not a rejected
            # one — probing a destructive/exfil-shaped tool with it would be
            # an actual attempted action, not a harmless error-text fishing
            # expedition. Same guard as argument_smuggling.py, for the same
            # reason: skipped rather than risk a real side effect.
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="every tool on this target looks destructive or exfil-shaped — skipped rather than risk a real call.",
                attempted=False,
            )

        raw_observed: list[str] = []
        for tool in probeable:
            for label, args in _malformed_variants(tool.input_schema):
                result = await target.call_tool(tool.name, args)
                text = Target.result_text(result)
                if not text:
                    continue
                raw_observed.append(text)

                # The string values we injected this call — a path leak that is
                # only one of these reflected back isn't a disclosure (see
                # _path_is_reflected_input); a genuine leak still fires.
                injected = {str(v) for v in args.values()}
                leak = _find_leak(text, injected)
                if leak is None:
                    continue
                preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
                headline = mask_secret(leak.value) if leak.kind == "secret" else leak.value
                return Finding(
                    attack_key=self.key,
                    fired=True,
                    # A real secret in an error is High; a leaked path or stack
                    # trace is internal-info disclosure — real, but Medium.
                    severity="high" if leak.kind == "secret" else "medium",
                    # A leaked secret is a genuine disclosure (violation, sets the
                    # grade); a leaked path/stack trace is a minor hygiene gap
                    # (caps at B, flagged verify) — not a boundary breach.
                    disposition="violation" if leak.kind == "secret" else "hygiene",
                    reason=(
                        f"{tool.name} — a {label} call leaked a {leak.kind}-shaped string "
                        f"({headline!r}) in its error text — response: {preview!r}"
                    ),
                    raw_observed_text=raw_observed,
                )

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"probed {len(probeable)} tool(s) with malformed arguments — no error "
                "leaked a secret, path, or stack trace."
            ),
            raw_observed_text=raw_observed,
        )
