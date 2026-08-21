"""The static surface pass: zero calls, zero risk — everything here is read
straight off `tools/list` and `resources/list`, before a single probe runs.

Every other finding in this project comes from actually calling a tool: a
canary at a sink, a marker signature, a state contradiction. That discipline
is the whole reason a CONFIRMED here means something real, and it must never
soften. But there's a class of real signal that needs no call at all — an
unconstrained `command` string field, a tool named `delete_account` with no
`destructiveHint` set, a server that exposes both code-execution and network
tools in the same breath. A human reviewer would clock these instantly just
reading the schema; this module does the same thing, deterministically.

Non-negotiable: every finding here is `info` or `warn`, never `CONFIRMED`.
Nothing in this module feeds core.metrics's scoring or core.scorer's grade —
it renders in its own report section. Blurring "the schema looks sloppy"
with "we proved an exploit" would be exactly the soft-signal inflation the
canary-proof discipline exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp import types

from gaslight.core.schema import (
    find_all_destructive_tools,
    find_code_execution_tool,
    find_code_field,
    find_file_read_tool,
    find_network_tool,
    find_path_field,
    find_unambiguous_code_field,
    find_url_field,
)
from gaslight.core.secrets_scan import find_secret_like_strings, mask_secret

INFO, WARN = "info", "warn"


@dataclass(frozen=True)
class SurfaceFinding:
    severity: str  # "info" | "warn"
    category: str
    tool_name: str | None  # None for target-wide findings (privilege combos)
    message: str


def _field_spec(schema: dict | None, field: str) -> dict:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    spec = props.get(field, {}) if isinstance(props, dict) else {}
    return spec if isinstance(spec, dict) else {}


def _unconstrained_fields(tools: list[types.Tool]) -> list[SurfaceFinding]:
    """A dangerous-shaped field (path/url/code) with no maxLength, pattern,
    or enum constraining what can be sent to it."""
    findings = []
    # `find_code_field` also matches the ambiguous `query`, which is usually a
    # search box rather than an interpreter. An unconstrained free-text field
    # is still worth flagging either way — but call it what it is rather than
    # labelling a Jira search "(code)", which reads as a far scarier finding
    # than it is.
    checks = (("path", find_path_field), ("url", find_url_field), ("code", find_code_field))
    for tool in tools:
        for kind, finder in checks:
            field = finder(tool.input_schema)
            if field is None:
                continue
            if kind == "code" and find_unambiguous_code_field(tool.input_schema) is None:
                kind = "query/free-text"
            spec = _field_spec(tool.input_schema, field)
            if not any(k in spec for k in ("maxLength", "pattern", "enum")):
                findings.append(
                    SurfaceFinding(
                        WARN,
                        "unconstrained-field",
                        tool.name,
                        f"{field!r} ({kind}) has no length limit or pattern constraint",
                    )
                )
    return findings


def _privilege_combos(tools: list[types.Tool]) -> list[SurfaceFinding]:
    """Dangerous capability combinations on one target. Deliberately does NOT
    flag network+file-read alone — an ordinary "fetch a URL and save it"
    agent legitimately has both; that combo is common enough to be noise, not
    signal. Only code-execution combined with either of the other two is the
    genuinely dangerous blast-radius jump, since code execution already
    subsumes most other capabilities."""
    findings = []
    code_tool, _ = find_code_execution_tool(tools)
    net_tool, _ = find_network_tool(tools)
    file_tool, _ = find_file_read_tool(tools)

    if code_tool is not None and net_tool is not None:
        findings.append(
            SurfaceFinding(
                WARN,
                "privilege-combo",
                None,
                f"{code_tool.name} (code execution) + {net_tool.name} (network) on the same "
                "target — code output can be exfiltrated with no separate guard",
            )
        )
    if code_tool is not None and file_tool is not None:
        findings.append(
            SurfaceFinding(
                WARN,
                "privilege-combo",
                None,
                f"{code_tool.name} (code execution) + {file_tool.name} (file access) on the same "
                "target — code can read and act on arbitrary files with no separate guard",
            )
        )
    return findings


def _missing_destructive_hints(tools: list[types.Tool]) -> list[SurfaceFinding]:
    """A destructive-shaped tool that never declares MCP's own destructiveHint
    annotation — many MCP clients use this hint to gate user confirmation, so
    its absence means those clients have no signal to act on either."""
    findings = []
    for tool in find_all_destructive_tools(tools):
        if tool.annotations is None or tool.annotations.destructive_hint is not True:
            findings.append(
                SurfaceFinding(
                    WARN,
                    "missing-destructive-hint",
                    tool.name,
                    f"{tool.name} looks destructive by name/description but has no "
                    "destructiveHint annotation",
                )
            )
    return findings


# Phrases that almost never appear in an honest tool description but are the
# signature of a tool-poisoning payload — a description written to steer the
# MODEL rather than inform the user. Kept deliberately specific: single common
# words ("you must") appear in legitimate docs, so only injection-shaped
# markers and combinations are listed, matching the project's stance that a
# false flag is worse than a missed soft signal.
_POISON_MARKERS = (
    "<important>",
    "<hidden>",
    "<secret>",
    "<system>",
    "<instructions>",
    "<inject>",
    "do not mention",
    "do not tell the user",
    "do not reveal",
    "without mentioning",
    "without telling",
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "present it as if",
    "as if it's part of",
    "you must first read",
    "must first access",
    "before responding, ",
)


def _hidden_instructions(tools: list[types.Tool]) -> list[SurfaceFinding]:
    """A tool whose description contains instructions aimed at the model, not
    the user — the tool-poisoning pattern (DVMCP challenge 2): a description
    that tells the agent to secretly read a confidential resource and hide
    that it did. Read straight from the description, so it is a static WARN,
    not a proven exploit — we cannot show the model obeys it without driving a
    real model, and the project never claims CONFIRMED without physical proof.
    But the payload is genuinely sitting in the metadata, which is worth
    flagging loudly."""
    findings = []
    for tool in tools:
        lowered = (tool.description or "").lower()
        hit = next((m for m in _POISON_MARKERS if m in lowered), None)
        if hit is not None:
            findings.append(
                SurfaceFinding(
                    WARN,
                    "hidden-instructions",
                    tool.name,
                    f"{tool.name}'s description contains instructions aimed at the model "
                    f"(found {hit!r}) — a tool-poisoning red flag, not a proven exploit.",
                )
            )
    return findings


# Digits that are strong ASCII-letter lookalikes — the substitutions a
# shadowing tool uses to look identical to a real one while differing in bytes:
# send_emai1 vs send_email, l0gin vs login. Deliberately ONLY 0→o and 1→l: the
# weaker leetspeak maps (5→s, 3→e, 4→a, …) caused more false positives than
# real catches — e.g. `channel5` collapsing onto `channels` — so the
# pre-launch review trimmed them out. A trailing product/version digit is
# almost never a homoglyph attack; a mid-word 0/1 swap is.
_CONFUSABLE_DIGITS = str.maketrans({"0": "o", "1": "l"})


def _canonical_name(name: str) -> str:
    return name.lower().translate(_CONFUSABLE_DIGITS)


def _tool_shadowing(tools: list[types.Tool]) -> list[SurfaceFinding]:
    """Two tools whose names are confusable — the tool-shadowing / typosquat
    pattern (OWASP MCP09): a malicious `send_emai1` sitting next to the real
    `send_email`, or a name carrying a unicode homoglyph, so a human and the
    model both risk picking the wrong one. Static and deterministic — read
    straight off the names, no call. Flags (a) any non-ASCII character in a
    tool name, and (b) two distinct names that collapse to the same canonical
    form once digit-for-letter lookalikes are undone. Plurals and tense
    (user/users) canonicalize differently, so ordinary similar names don't trip
    it."""
    findings: list[SurfaceFinding] = []

    for tool in tools:
        # Only MIXED-script names are the homoglyph red flag — an ASCII letter
        # sitting beside a non-ASCII lookalike (a Cyrillic 'а' inside otherwise
        # Latin text). A wholly non-Latin name is a legitimate localization, not
        # a spoof, so it isn't flagged (pre-launch review FP fix).
        has_non_ascii = any(ord(c) > 127 for c in tool.name)
        has_ascii_letter = any(c.isascii() and c.isalpha() for c in tool.name)
        if has_non_ascii and has_ascii_letter:
            findings.append(
                SurfaceFinding(
                    WARN,
                    "tool-shadowing",
                    tool.name,
                    f"{tool.name!r} mixes ASCII and non-ASCII letters — a possible homoglyph "
                    "disguising it as a legitimate tool.",
                )
            )

    by_canonical: dict[str, list[str]] = {}
    for tool in tools:
        by_canonical.setdefault(_canonical_name(tool.name), []).append(tool.name)
    for names in by_canonical.values():
        distinct = sorted(set(names))
        if len(distinct) > 1:
            findings.append(
                SurfaceFinding(
                    WARN,
                    "tool-shadowing",
                    None,
                    f"confusable tool names on one target: {', '.join(repr(n) for n in distinct)} — "
                    "one may be shadowing the other (typosquat / lookalike).",
                )
            )
    return findings


def _secrets_in_metadata(tools: list[types.Tool]) -> list[SurfaceFinding]:
    """Credential-shaped text accidentally left in a tool's own description —
    e.g. a real-looking example key pasted into a docstring."""
    findings = []
    for tool in tools:
        for hit in find_secret_like_strings(tool.description or ""):
            findings.append(
                SurfaceFinding(
                    WARN,
                    "secret-in-metadata",
                    tool.name,
                    f"description contains a secret-shaped string: {mask_secret(hit)}",
                )
            )
    return findings


def _filesystem_resources(resources: list[types.Resource]) -> list[SurfaceFinding]:
    """A static resource pointing at the filesystem — often intentional, so
    info rather than warn, just worth surfacing."""
    findings = []
    for resource in resources:
        if resource.uri.startswith("file://") or resource.uri.startswith("file:"):
            findings.append(
                SurfaceFinding(INFO, "filesystem-resource", None, f"resource {resource.uri!r} is filesystem-backed")
            )
    return findings


def scan_surface(tools: list[types.Tool], resources: list[types.Resource] | None = None) -> list[SurfaceFinding]:
    """Every static check, composed. Pure and synchronous — no tool calls, no
    network, safe to run before a single probe fires."""
    findings: list[SurfaceFinding] = []
    findings.extend(_unconstrained_fields(tools))
    findings.extend(_privilege_combos(tools))
    findings.extend(_missing_destructive_hints(tools))
    findings.extend(_hidden_instructions(tools))
    findings.extend(_tool_shadowing(tools))
    findings.extend(_secrets_in_metadata(tools))
    findings.extend(_filesystem_resources(resources or []))
    return findings
