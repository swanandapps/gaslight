"""The direct destructive-action authorization probe: no LLM, no injection
— call a destructive tool ourselves with naive, unremarkable arguments and
see whether a real, deterministic code-level check stops it, or it just
complies. Same spirit as tool_authz_probe.py's exfil version, applied to a
destructive-tool shape.

Unlike the exfil probe, this one is NOT safe by construction — the exfil
probe always routes to gaslight's own sink, so calling it directly never
has a real side effect. There is no equivalent safety net for a destructive
tool: calling delete_account directly for real against a live target
actually deletes the account. `safe` (default True) exists specifically to
prevent that — see ToolAuthzProbeAttack's own constructor docstring, which
already anticipated this exact attack: "a future milestone that adds
genuinely destructive-tool probing has a real flag to gate on."

Known, accepted limitation, documented rather than solved in this
milestone: this relies on CallToolResult.is_error to detect a guard. A
target that blocks via a plain non-error string (the same convention
tests/fixtures/hardened_server.py's send_email uses) rather than a
protocol-level error would produce a false positive here. Verified
empirically that a raised exception inside a FastMCP tool correctly sets
is_error=True — this milestone's own fixtures use that pattern, so they're
correctly detected; a future milestone would need text-content or
state-verification heuristics to close the gap for the silent-block
convention.

A real-world validation run against an independently-built target (the
official git MCP reference server's git_reset, tested by hand outside this
codebase) surfaced a second, more serious false-negative: naive_arguments()
fills a required "identifying" field (repo_path) with an arbitrary
placeholder, the target rejects it for being an invalid path — nothing to
do with authorization — and the original version of this probe misread
that as "a real code-level check exists." A blind retry with a guessed
"better" value doesn't generalize (tried "." for a repository path; it
failed too, for reasons only the target's own configuration could reveal).
What does generalize: the rejection's own error text frequently leaks the
real value ("...outside the allowed repository '/real/path'"), because a
verbose validation error is a source of ground truth, not just noise — the
same idea blind SQL injection testing already relies on. `_extract_hint_values()`
pulls quoted, path-like substrings out of the rejection text; `run()`
retries the call substituting each hint into each required string field,
capped at `_MAX_HINT_RETRIES` attempts. A retry that succeeds is
unambiguous proof of no real check (a real value hit zero further
resistance); if every retry still fails (or no hint was ever leaked), the
finding says so honestly rather than claiming certainty a black-box probe
with no reconnaissance can't back up.
"""

from __future__ import annotations

import re

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import find_destructive_tool, naive_arguments
from gaslight.core.sink import Sink
from gaslight.core.target import Target

_HINT_PATTERN = re.compile(r"['\"]([^'\"]*/[^'\"]*)['\"]")
_MAX_HINT_RETRIES = 3


def _extract_hint_values(text: str) -> list[str]:
    """Plausible corrected values for an identifying field, pulled out of
    a rejection's own error text — quoted substrings containing a path
    separator, in first-seen order, deduplicated. Returns an empty list
    when the target's rejection never echoes anything path-like (e.g. a
    plain "invalid confirm_token" message), which is the common case and
    leaves the caller with nothing to retry."""
    seen: list[str] = []
    for match in _HINT_PATTERN.finditer(text):
        candidate = match.group(1)
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


def _required_string_fields(schema: dict) -> list[str]:
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = schema.get("required", []) if isinstance(schema, dict) else []
    return [key for key in required if isinstance(props.get(key), dict) and props[key].get("type") == "string"]


class DestructiveActionAuthzProbeAttack(AttackModule):
    key = "destructive-authz-probe"
    name = "Destructive-Action Authorization Probe"
    description = (
        "Calls a destructive tool directly with naive arguments — no model, no injection — "
        "and checks whether a real code-level check blocks it. Performs a real, irreversible "
        "call when run; gated behind --no-safe."
    )

    def __init__(self, *, safe: bool = True) -> None:
        if not isinstance(safe, bool):
            raise TypeError(f"safe must be a bool, got {type(safe).__name__}")
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        destructive_tool, match_source = find_destructive_tool(target.tools)
        if destructive_tool is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no viable destructive-shaped tool to probe.",
                attempted=False,
            )

        if self._safe:
            signal = "its name" if match_source == "name" else "its description"
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    "direct destructive-tool probing requires --no-safe — this would perform "
                    f"a real, irreversible action against the target (candidate flagged by {signal})."
                ),
                candidate_destructive_tool=destructive_tool.name,
                attempted=False,
            )

        if match_source == "description":
            return Finding(
                attack_key=self.key,
                fired=False,
                reason=(
                    f"{destructive_tool.name} looks destructive from its description, but its name "
                    "gives no signal; not auto-probed even under --no-safe, to avoid firing a real "
                    "irreversible call on a soft prose signal — inspect this tool manually."
                ),
                candidate_destructive_tool=destructive_tool.name,
                attempted=False,
            )

        args = naive_arguments(destructive_tool.input_schema)
        result = await target.call_tool(destructive_tool.name, args)

        if not result.is_error:
            return Finding(
                attack_key=self.key,
                fired=True,
                reason=(
                    f"{destructive_tool.name} executed an arbitrary direct call with no rejection — "
                    "no code-level check exists."
                ),
                destructive_tool=destructive_tool.name,
                candidate_destructive_tool=destructive_tool.name,
            )

        hints = _extract_hint_values(Target.result_text(result))
        string_fields = _required_string_fields(destructive_tool.input_schema)
        attempts = 0
        for field in string_fields:
            for hint in hints:
                if attempts >= _MAX_HINT_RETRIES:
                    break
                attempts += 1
                retry_args = dict(args)
                retry_args[field] = hint
                retry_result = await target.call_tool(destructive_tool.name, retry_args)
                if not retry_result.is_error:
                    return Finding(
                        attack_key=self.key,
                        fired=True,
                        reason=(
                            f"{destructive_tool.name} rejected a naive guess for {field!r}, but its "
                            f"own error message leaked a real value ({hint!r}); retrying with it "
                            "succeeded with no further resistance — no real code-level check exists, "
                            "only argument validation."
                        ),
                        destructive_tool=destructive_tool.name,
                        candidate_destructive_tool=destructive_tool.name,
                    )
            if attempts >= _MAX_HINT_RETRIES:
                break

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"{destructive_tool.name} rejected the direct call, and "
                f"{len(hints)} value(s) leaked in its own error text still didn't get through — "
                "likely a real code-level check, though a black-box probe with no reconnaissance "
                "can't fully rule out an unrecognized argument format."
            ),
            candidate_destructive_tool=destructive_tool.name,
        )
