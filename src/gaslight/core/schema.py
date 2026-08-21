"""Small heuristics over MCP tool JSON schemas, shared by the attack module
(finding a real tool to plant/exfiltrate through) and the scripted test
double (working out what a tool call driven by an injected instruction would
plausibly look like). Kept in one place so the two never drift apart.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from mcp import types

CONTENT_FIELD_PRIORITY = ("body", "content", "text", "notes", "note", "description", "message", "value")
ADDRESS_FIELD_PRIORITY = (
    "to",
    "recipient",
    "url",
    "endpoint",
    "target",
    "address",
    "webhook",
    "email",
    "destination",
    "channel",
    "account",
    "attendee",
    "uri",
    "link",
    "callback",
)

_EXFIL_KEYWORDS = (
    "send",
    "email",
    "notify",
    "webhook",
    "message",
    "forward",
    "publish",
    "post",
    "share",
    "export",
    "sync",
    "upload",
    "invite",
    "deliver",
    "broadcast",
    "submit",
    "dispatch",
)
_DESTRUCTIVE_KEYWORDS = (
    "delete",
    "remove",
    "reset",
    "revoke",
    "disable",
    "deactivate",
    "wipe",
    "purge",
    "terminate",
    "cancel",
    "drop",
    "destroy",
)
WRITE_KEYWORDS = ("create", "add", "save", "write", "set", "insert", "post", "update", "upload")
READ_KEYWORDS = ("read", "get", "list", "fetch", "search", "view", "summarize", "review")

# Names/descriptions that must never be handed a real probe call on a
# field-shape guess alone — a tool that sends or destroys is off-limits to the
# field-only path in _qualify(). Keyword+field matches are unaffected.
_CONSEQUENTIAL_GUARD = _DESTRUCTIVE_KEYWORDS + _EXFIL_KEYWORDS

PATH_FIELD_PRIORITY = ("path", "filepath", "filename", "file", "document", "dir", "directory", "location")


def _properties(schema: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    return props if isinstance(props, dict) else {}


def _match_source(tool: types.Tool, keywords: Sequence[str]) -> str | None:
    """'name' if any keyword is a substring of the tool name, else
    'description' if any is a substring of the tool description, else None.
    Name wins so a strong (name) signal stays distinguishable from a
    softer (description-only) one — callers that make a real irreversible
    call (the destructive probe) treat them differently; callers whose
    calls are harmless-by-construction don't need to. Raw-substring on
    both sources, matching the existing name-matching behavior exactly —
    deliberately not word-boundary split, since descriptions are prose and
    a looser match there costs nothing everywhere except a real destructive
    call, which is separately gated to never auto-fire on a description-only
    signal."""
    name = tool.name.lower()
    if any(keyword in name for keyword in keywords):
        return "name"
    description = (tool.description or "").lower()
    if any(keyword in description for keyword in keywords):
        return "description"
    return None


def is_consequential(tool: types.Tool) -> bool:
    """Whether a tool's name or description looks destructive or exfil-shaped
    — the same signal _qualify() uses to refuse a field-only match for the
    network/file/code probes. Exposed publicly for callers (argument_
    smuggling.py) that need to skip such a tool entirely, not just refuse one
    matching path through it: a probe that only ever touches our own sink or
    reads back a marker signature must never be the thing that actually
    triggers a real irreversible action."""
    return _match_source(tool, _CONSEQUENTIAL_GUARD) is not None


def find_string_field(schema: dict[str, Any] | None) -> str | None:
    """The best free-text field on a tool — where a payload would be smuggled in."""
    props = _properties(schema)
    for key in CONTENT_FIELD_PRIORITY:
        spec = props.get(key)
        if isinstance(spec, dict) and spec.get("type") == "string":
            return key
    for key, spec in props.items():
        if isinstance(spec, dict) and spec.get("type") == "string":
            return key
    return None


def find_all_string_fields(schema: dict[str, Any] | None) -> list[str]:
    """Every string-typed field on a schema, in declared order — used when a
    caller needs to probe ALL of a tool's free-text fields rather than just
    the single best candidate find_string_field() picks. argument_smuggling.py
    uses this to try a field-independent payload against every field that
    ISN'T already one of the tool's recognized path/url/code fields — the
    non-obvious field a real target might still interpolate unsafely."""
    props = _properties(schema)
    return [key for key, spec in props.items() if isinstance(spec, dict) and spec.get("type") == "string"]


def find_address_field(schema: dict[str, Any] | None) -> str | None:
    """The field an exfil-capable tool uses to say *where* something goes.

    Matches by word part (splitting on "_"), not raw substring — "to" must
    match a field literally named "to" or "reply_to", never "total". This
    is what lets compound, realistic field names ("webhook_url",
    "share_with") match without needing every variant spelled out in
    ADDRESS_FIELD_PRIORITY.
    """
    props = _properties(schema)
    for keyword in ADDRESS_FIELD_PRIORITY:
        for key in props:
            if keyword in key.lower().split("_"):
                return key
    return None


def _find_tool_with_field(tools, keywords, field_finder):
    """The best tool that both matches `keywords` (by name or description) and
    has a field `field_finder` recognizes. A name match anywhere in the list
    is preferred over any description-only match — the same strong-signal-wins
    rule find_destructive_tool() uses, so a weak, common-English-word
    description match on an earlier benign tool can't shadow a later tool that
    matches by name (the shadowing risk raised in review)."""
    description_candidate = None
    for tool in tools:
        source = _match_source(tool, keywords)
        if source is None:
            continue
        field = field_finder(tool.input_schema)
        if field is None:
            continue
        if source == "name":
            return tool, field
        if description_candidate is None:
            description_candidate = (tool, field)
    return description_candidate if description_candidate is not None else (None, None)


def _qualify(tools, keywords, field_finder, strong_field_finder):
    """Like _find_tool_with_field, but a tool ALSO qualifies on the shape of
    its arguments alone — a `strong_field_finder` hit (a real url/sql/path
    field) outweighs an unconventional name the keyword list never anticipated.
    This is what lets `import_shopify_orders(store_url=…)` or
    `query_warehouse(sql=…)` be recognized as network/code tools with no
    matching name keyword — the Munshi gap, closed with legacy math, no model.

    Precedence: name+field  >  description+field  >  strong-field-only. Every
    caller of this drives a harmless-by-construction probe (a read, a fetch to
    our own sink, a benign code payload) — but only when the probe reaches a
    read/fetch/exec tool. A field-only match is therefore REFUSED for any tool
    whose name or description looks destructive or exfil-shaped: `delete_account`
    happening to carry a `url` field must never be handed to the SSRF probe as
    a fetch tool, because the probe would then really call delete_account. A
    keyword+field match is still allowed through (that tool genuinely is what
    the keyword says), so this guard only fences the softer field-only path.
    """
    description_candidate = None
    field_only_candidate = None
    for tool in tools:
        field = field_finder(tool.input_schema)
        source = _match_source(tool, keywords) if field is not None else None
        if source == "name":
            return tool, field
        if source == "description" and description_candidate is None:
            description_candidate = (tool, field)
        if field_only_candidate is None and _match_source(tool, _CONSEQUENTIAL_GUARD) is None:
            strong = strong_field_finder(tool.input_schema)
            if strong is not None:
                field_only_candidate = (tool, strong)
    return description_candidate or field_only_candidate or (None, None)


def find_exfil_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, str | None]:
    """The best candidate exfil-capable tool: its name suggests it sends
    something somewhere, and it has an address-like field to say where.

    Shared by injection_exfil.py (drives this tool through an LLM) and
    tool_authz_probe.py (calls it directly, no LLM) so both attack modules
    agree on what counts as "exfil-capable" for a given target. Matches on
    name or description (via _match_source()) — this call is always
    harmless-by-construction, so a description-only false candidate costs
    nothing worse than a non-firing result. Prefers a name match over a
    description-only one (see _find_tool_with_field).
    """
    return _find_tool_with_field(tools, _EXFIL_KEYWORDS, find_address_field)


def find_destructive_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, str | None]:
    """The best candidate destructive tool and how it was matched: 'name' if
    its own name suggests an irreversible action, else 'description' if only
    its description does. Unlike find_exfil_tool(), no address field is
    needed — the mere act of calling it is the whole risk, not where
    something ends up. A name match anywhere in the list is preferred over
    any description-only match (the strongest available candidate is the
    one callers should probe); a caller that makes a real call MUST treat
    a 'description' source differently (flag, don't auto-fire) since a
    prose signal is much weaker than a name. Same limitation as
    find_exfil_tool(): first plausible candidate only, no severity
    ranking. Known, accepted consequence of preferring name matches: when
    a name-matched destructive tool exists, a description-only one
    elsewhere in the same target is not surfaced by this function (use
    find_all_destructive_tools() when every match is needed)."""
    description_fallback: types.Tool | None = None
    for tool in tools:
        source = _match_source(tool, _DESTRUCTIVE_KEYWORDS)
        if source == "name":
            return tool, "name"
        if source == "description" and description_fallback is None:
            description_fallback = tool
    if description_fallback is not None:
        return description_fallback, "description"
    return None, None


def find_all_destructive_tools(tools: list[types.Tool]) -> list[types.Tool]:
    """All tools whose name OR description suggests an irreversible action —
    used when a caller needs to guard against ANY destructive-shaped tool
    being called, not just react to the single best candidate
    find_destructive_tool() picks. This is a guard list, so broad is
    correct: description matches are included, unlike the strong/soft
    distinction find_destructive_tool() keeps for its own real-call
    decision."""
    return [t for t in tools if _match_source(t, _DESTRUCTIVE_KEYWORDS) is not None]


def find_write_tool(tools: list[types.Tool]) -> types.Tool | None:
    """The best candidate tool for planting a payload — its name suggests
    it creates or stores something. Deliberately name-only, unlike the
    other finders in this module: WRITE_KEYWORDS contains very common
    English substrings ("add", "set", "post"), and matching them against
    free-text descriptions produces real false positives — e.g. a
    read-only tool described as "reads everything saved so far" matches
    on "saved" containing "save", stealing the write-tool slot from the
    actual write-shaped tool. Confirmed empirically while implementing
    description-aware targeting; reverted to name-only rather than shipped
    with that false-match risk."""
    return next((t for t in tools if any(k in t.name.lower() for k in WRITE_KEYWORDS)), None)


def find_read_tool(tools: list[types.Tool]) -> types.Tool | None:
    """The best candidate tool for reading a payload back — its name
    suggests it retrieves or summarizes something. Name-only for the same
    reason as find_write_tool(): READ_KEYWORDS ("get", "list", "view") are
    too common in ordinary prose to safely raw-substring-match against
    descriptions."""
    return next((t for t in tools if any(k in t.name.lower() for k in READ_KEYWORDS)), None)


def find_all_read_tools(tools: list[types.Tool]) -> list[types.Tool]:
    """Every read-shaped tool — used by ClaimIntegrityAttack to snapshot the
    target's whole observable state before and after acting. Name-only, same
    reasoning as find_read_tool()."""
    return [t for t in tools if any(k in t.name.lower() for k in READ_KEYWORDS)]


def find_path_field(schema: dict[str, Any] | None) -> str | None:
    """The field a file-reading tool uses to say *which file*. Same
    word-boundary matching as find_address_field() — "path" matches a
    field literally named "path" or "file_path", never "pathological".
    "filepath" and "filename" are included as their own literal keywords
    in PATH_FIELD_PRIORITY so a compound name with no underscore to split
    on ("filepath") still matches.
    """
    props = _properties(schema)
    for keyword in PATH_FIELD_PRIORITY:
        for key in props:
            if keyword in key.lower().split("_"):
                return key
    return None


def find_file_read_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, str | None]:
    """The best candidate file-reading tool: its name suggests reading
    (reuses READ_KEYWORDS), and it has a path-like field to say which
    file. Mirrors find_exfil_tool()'s tuple-return shape and the same
    accepted limitation: first plausible candidate only, no attempt to
    rank multiple matches. Matches on name or description (name preferred),
    or on a path-shaped field alone — a read-file tool with an unconventional
    name (`open_document(document=…)`) still qualifies. The traversal probe
    only reads, so field-only qualifying is safe."""
    return _qualify(tools, READ_KEYWORDS, find_path_field, find_path_field)


_NETWORK_KEYWORDS = ("fetch", "browse", "scrape", "crawl", "download", "request", "import", "sync", "pull", "proxy")

# URL-shaped field names (a strict subset of ADDRESS_FIELD_PRIORITY) plus the
# JSON-Schema `format` markers for a URL. Used to qualify a network tool by
# argument shape alone — deliberately narrower than find_address_field(), which
# also matches messaging destinations (to/recipient/email/channel) that belong
# to an exfil tool, not a fetch tool.
_URL_FIELD_NAMES = ("url", "endpoint", "uri", "link", "webhook", "callback", "host")
_URL_FORMATS = ("uri", "url", "iri", "uri-reference")


def find_url_field(schema: dict[str, Any] | None) -> str | None:
    """A field that names or types a URL — a strong, name-independent signal
    that a tool reaches out over the network. Name match is word-boundary
    (like find_address_field); the `format` check catches a plainly-named
    field ("source", "target") that the schema still declares as a URI."""
    props = _properties(schema)
    for keyword in _URL_FIELD_NAMES:
        for key in props:
            if keyword in key.lower().split("_"):
                return key
    for key, spec in props.items():
        if isinstance(spec, dict) and spec.get("type") == "string" and str(spec.get("format", "")).lower() in _URL_FORMATS:
            return key
    return None


def find_network_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, str | None]:
    """The best candidate URL-fetching tool: its name suggests fetching remote
    content and it has an address-like field, OR it simply carries a
    URL-shaped field (find_url_field) whatever it's named — so a domain tool
    like `import_shopify_orders(store_url=…)` is caught without its verb ever
    appearing in _NETWORK_KEYWORDS. Harmless-by-construction (the probe only
    ever fetches our own sink / a metadata address), so field-only qualifying
    is safe."""
    return _qualify(tools, _NETWORK_KEYWORDS, find_address_field, find_url_field)


# Numeric "how many / how much" knobs — a field that lets a caller dial up how
# much work a tool does. Word-boundary matched (like find_path_field) and
# required to be numeric, so a string field literally named "size" (a clothing
# size) can't be mistaken for a limit. "max_results" / "page_size" are caught
# by their atomic parts ("max", "size") once the name is split on "_".
_SIZE_FIELD_NAMES = (
    "limit",
    "count",
    "max",
    "top",
    "rows",
    "size",
    "length",
    "depth",
    "num",
    "amount",
    "quantity",
    "results",
    "n",
    "k",
)

# Names/descriptions of tools that return a variable amount of data — the shape
# a denial-of-wallet probe dials up. Excludes exfil-shaped verbs (export,
# upload) on purpose: those are already fenced off by is_consequential, and we
# never want a "read-heavy" probe to trigger a real send.
_LISTING_KEYWORDS = (
    "list",
    "search",
    "all",
    "dump",
    "fetch",
    "read",
    "query",
    "history",
    "logs",
    "records",
    "get",
    "find",
    "enumerate",
)

# Mutation verbs that must never be handed a denial-of-wallet probe. The probe
# makes a REAL call with a huge N, so a tool whose name says it writes/creates
# — create_orders(count), update_records(rows), generate_invoices(quantity) —
# would perform a mass side effect even under --safe. is_consequential only
# fences destructive+exfil names; these write-shaped names are the gap the
# pre-launch review found. Matched as a substring of the lowered name (so
# camelCase createOrders is caught too); read tools are separately required to
# match _LISTING_KEYWORDS below, so over-skipping here only costs coverage,
# never safety.
_DOW_MUTATION_GUARD = (
    "create",
    "add",
    "insert",
    "update",
    "upsert",
    "write",
    "save",
    "upload",
    "generate",
    "provision",
    "issue",
    "register",
    "produce",
    "modify",
    "edit",
    "patch",
)


def find_size_field(schema: dict[str, Any] | None) -> str | None:
    """A numeric field that bounds how much a tool returns or does — the knob a
    denial-of-wallet probe dials up. Word-boundary name match, and the field
    must be integer/number typed so a string "size" isn't misread as a limit."""
    props = _properties(schema)
    for keyword in _SIZE_FIELD_NAMES:
        for key, spec in props.items():
            if not isinstance(spec, dict) or spec.get("type") not in ("integer", "number"):
                continue
            if keyword in key.lower().split("_"):
                return key
    return None


def find_unbounded_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, str | None]:
    """The best tool for a denial-of-wallet probe, and its size knob (or None).

    Prefers a tool carrying a numeric size field (limit/count/rows/…): dialing
    that up and measuring the response is the cleanest proof of a missing cap.
    Falls back to a listing/search/dump-shaped tool with no size knob at all —
    the absence of a cap parameter is itself what we test.

    SAFETY (pre-launch review finding): a candidate must be affirmatively
    read/list-shaped (_LISTING_KEYWORDS) AND must not carry a write/create verb
    in its name (_DOW_MUTATION_GUARD). The probe makes a real call with a huge
    N, so this is what keeps `create_orders(count=100000)` — not "consequential"
    by destructive/exfil name, but a mass write — from ever being selected, even
    under --safe. Over-skipping a legitimate read tool only costs a test; hitting
    a write tool would cause real harm, so the guard errs toward skipping. First
    plausible candidate only, no severity ranking."""
    size_candidate: tuple[types.Tool, str] | None = None
    listing_candidate: tuple[types.Tool, None] | None = None
    for tool in tools:
        if is_consequential(tool):
            continue
        if any(verb in tool.name.lower() for verb in _DOW_MUTATION_GUARD):
            continue
        if _match_source(tool, _LISTING_KEYWORDS) is None:
            continue
        size_field = find_size_field(tool.input_schema)
        if size_field is not None:
            if size_candidate is None:
                size_candidate = (tool, size_field)
        elif listing_candidate is None:
            listing_candidate = (tool, None)
    return size_candidate or listing_candidate or (None, None)


# "query" is deliberately NOT here. It is the single most ambiguous word in
# this file: a SQL query is code, a search query is a text box. Found in the
# wild — a real Confluence/Jira MCP server's `jira_search_projects(query)` was
# classified as a code-execution tool purely because of that word, which then
# produced two bogus "code execution + network on the same target" warnings.
# A genuine SQL tool is still reached: it either names itself (run_sql,
# execute_query) or carries an unambiguous field like `sql`.
_CODE_EXEC_KEYWORDS = ("execute", "run", "eval", "shell", "exec", "compute", "interpret")

CODE_FIELD_PRIORITY = ("code", "command", "script", "cmd", "sql", "statement", "query", "expression")
"""Every field that *might* carry executable input, including the ambiguous
`query`. Used when a tool has ALREADY been established as code-shaped by its
name or description — at that point `query` really does mean "the thing it
runs"."""

UNAMBIGUOUS_CODE_FIELDS = ("code", "command", "script", "cmd", "sql", "statement", "expression")
"""The subset that means executable input on its own, with no corroborating
name. `query` is excluded: on its own it far more often means a search box."""


def find_code_field(schema: dict[str, Any] | None) -> str | None:
    """The field a code-execution tool uses to say *what to run* — same
    word-boundary matching as find_path_field()."""
    return _first_field_matching(schema, CODE_FIELD_PRIORITY)


def find_unambiguous_code_field(schema: dict[str, Any] | None) -> str | None:
    """Like find_code_field(), but only fields that imply executable input
    without needing the tool's name to agree — what a field-shape-only match
    is allowed to qualify on."""
    return _first_field_matching(schema, UNAMBIGUOUS_CODE_FIELDS)


def _first_field_matching(schema: dict[str, Any] | None, keywords: Sequence[str]) -> str | None:
    props = _properties(schema)
    for keyword in keywords:
        for key in props:
            if keyword in key.lower().split("_"):
                return key
    return None


def find_code_execution_tool(tools: list[types.Tool]) -> tuple[types.Tool | None, str | None]:
    """The best candidate code-execution tool: its name suggests running
    or evaluating something, and it has a code/command-like field to say
    what. Mirrors find_file_read_tool()'s tuple-return shape and the same
    accepted limitation: first plausible candidate only. A target exposing
    more than one code-execution-shaped tool (DVMCP Challenge 8 exposes
    two: execute_python_code and execute_shell_command) only has its
    first match probed. Matches on name or description (name preferred), or
    on an UNAMBIGUOUS code field alone — `warehouse(sql=…)` qualifies on the
    `sql` field, while `jira_search_projects(query=…)` no longer does, since
    `query` alone is far more often a search box than an interpreter. The
    probe payloads are harmless-by-construction, so field-only qualifying is
    safe."""
    tool, field = _qualify(tools, _CODE_EXEC_KEYWORDS, find_code_field, find_unambiguous_code_field)
    if tool is not None:
        return tool, field

    # Description-aware fallback. A tool whose NAME or DESCRIPTION says it runs
    # commands, but whose parameter is named something domain-specific rather
    # than code/command/sql, still executes — DVMCP challenge 9's
    # network_diagnostic(target, options), "runs multiple network diagnostic
    # commands", is exactly this shape and slipped past name+field matching.
    # When the intent is clear from the text, probe the tool's best free-text
    # field. Safe by construction: the code-execution payload only ever curls
    # our own sink, so a tool that does not actually execute simply never
    # fires — no false CONFIRMED, and is_consequential keeps a
    # destructive/exfil-shaped tool off this path entirely.
    for candidate in tools:
        if is_consequential(candidate) or _match_source(candidate, _CODE_EXEC_KEYWORDS) is None:
            continue
        string_field = find_string_field(candidate.input_schema)
        if string_field is not None:
            return candidate, string_field
    return None, None


WELL_KNOWN_FILE_SIGNATURES = {
    "etc/hosts": "localhost",
    "etc/passwd": "root:",
}
"""Well-known, near-universally-present Unix system files paired with a
content signature specific enough that its presence in a response is
positive proof the real file came back — not merely the absence of
error-shaped phrasing. Shared by path_traversal.py (relative and
absolute-path categories) and code_execution.py (absolute-path category
only, since code execution has no notion of a confined directory)."""


def naive_arguments(schema: dict[str, Any] | None, *, exclude: str | None = None) -> dict[str, Any]:
    """Plausible values for whatever fields a tool schema requires — no
    confirmation token, no special authorization argument, just enough to
    satisfy the schema so a direct probe call reaches the tool's own
    implementation instead of failing schema validation and being
    misread as "the target rejected the call" (the dangerous direction
    for a security tool — a malformed probe isn't a security guard).
    `exclude` skips one field name a caller is supplying directly (e.g.
    the traversal payload itself). Boolean fields are filled with False
    rather than True: a naive caller wouldn't proactively affirm a
    confirmation-shaped flag (confirm, force, acknowledge), and filling
    with True would risk defeating exactly the guard a probe is trying
    to detect — False stays correct across dry_run-shaped flags too,
    since it keeps the call real. A required array field is filled with a
    single-element list (an integer-typed array gets `[1]`, anything else
    gets `["test-value"]`) — enough to satisfy schema validation for the
    common "list of identifiers" shape (e.g. `entityNames: string[]`).
    Known, accepted limitation: a required object or union-typed field
    (e.g. Pydantic's `anyOf`/`type: [x, "null"]` shape for optionals)
    still isn't filled, which could cause the same misread-as-guard
    failure this function exists to prevent — not solved here, would
    need broader schema coverage."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    required = schema.get("required", [])
    args: dict[str, Any] = {}
    for key in required:
        if key == exclude:
            continue
        spec = props.get(key, {}) if isinstance(props, dict) else {}
        if not isinstance(spec, dict):
            continue
        if spec.get("type") == "string":
            args[key] = "test-value"
        elif spec.get("type") == "integer":
            args[key] = 1
        elif spec.get("type") == "boolean":
            args[key] = False
        elif spec.get("type") == "array":
            items = spec.get("items", {})
            item_type = items.get("type") if isinstance(items, dict) else None
            args[key] = [1] if item_type == "integer" else ["test-value"]
    return args
