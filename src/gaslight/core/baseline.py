"""Rug-pull / tool-mutation regression: snapshot a target's tools once, then on
later runs flag any that changed since you approved them.

A rug-pull (OWASP MCP09 / supply-chain): a tool that is benign when you adopt
it, and later mutates its own description or schema to carry a tool-poisoning
payload or a new dangerous parameter. No single-run scan can catch it — the
tool looked fine the moment you looked. This does the one thing that catches
it: compares the tools you see now against a baseline you approved earlier, and
warns on any drift. Pure diff over names / descriptions / schemas —
deterministic, no model, and no call beyond the `tools/list` every scan already
does. It's the piece meant to live inside a CI/CD pipeline: record the baseline
when you first vet a server, then fail the build if a tool changes under you.

Like the static surface pass, drift is a WARN for human review, never a
CONFIRMED exploit: a description edit might be an honest fix. We flag that it
changed and let a person decide whether it's a rug-pull. The snapshot is
written with sorted keys and no timestamp, so the file is stable and diffable
and two snapshots of an unchanged server are byte-identical.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from mcp import types

from gaslight.core.schema import (
    find_all_destructive_tools,
    find_code_execution_tool,
    find_code_field,
    find_file_read_tool,
    find_network_tool,
    find_path_field,
    find_url_field,
)

# v2 added the per-tool "capabilities" + target "privilege_combos" fields used by
# scope-creep detection. v1 baselines (rug-pull only) still diff fine — the extra
# fields are additive and diff_baseline ignores them.
_SCHEMA_VERSION = 2

# Capabilities whose *appearance* is a privilege escalation worth flagging when a
# NEW tool carries them (the "unconstrained:*" tags are growth signals too, but
# only meaningful on a tool that already existed at baseline).
_DANGEROUS_CAPS = ("file-read", "network", "code-exec", "destructive")


def _canonical_schema(schema: object) -> str:
    """A stable string for an input schema — sorted keys, no whitespace — so an
    unchanged schema always hashes the same and any real change flips the hash."""
    try:
        return json.dumps(schema or {}, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(schema)


def _schema_hash(schema: object) -> str:
    return hashlib.sha256(_canonical_schema(schema).encode("utf-8")).hexdigest()[:16]


def _tool_capabilities(tool: types.Tool) -> list[str]:
    """The permission-relevant capabilities one tool exposes, derived from the
    same shape detectors the attacks use, so a tool's recorded surface matches
    what actually gets probed. Sorted for byte-stable snapshots."""
    caps: set[str] = set()
    one = [tool]
    if find_file_read_tool(one)[0] is not None:
        caps.add("file-read")
    if find_network_tool(one)[0] is not None:
        caps.add("network")
    if find_code_execution_tool(one)[0] is not None:
        caps.add("code-exec")
    if find_all_destructive_tools(one):
        caps.add("destructive")
    props = (tool.input_schema or {}).get("properties") or {}
    for kind, finder in (("path", find_path_field), ("url", find_url_field), ("code", find_code_field)):
        field = finder(tool.input_schema)
        if field is not None and not any(k in (props.get(field) or {}) for k in ("maxLength", "pattern", "enum")):
            caps.add(f"unconstrained:{kind}")
    return sorted(caps)


def _privilege_combos_present(tools: list[types.Tool]) -> list[str]:
    """Dangerous target-wide capability pairings — the same pairs surface.py
    flags: code execution alongside network egress or file access."""
    combos: list[str] = []
    has_code = find_code_execution_tool(tools)[0] is not None
    if has_code and find_network_tool(tools)[0] is not None:
        combos.append("code-exec+network")
    if has_code and find_file_read_tool(tools)[0] is not None:
        combos.append("code-exec+file-read")
    return sorted(combos)


def snapshot_tools(tools: list[types.Tool]) -> dict:
    """A serializable fingerprint of a target's tools — name, description, a hash
    of the input schema (rug-pull), and its permission-surface capabilities +
    target-wide privilege combos (scope-creep) — enough to detect any later
    mutation or privilege growth without storing the whole schema."""
    return {
        "version": _SCHEMA_VERSION,
        "tools": {
            tool.name: {
                "description": tool.description or "",
                "schema_hash": _schema_hash(tool.input_schema),
                "capabilities": _tool_capabilities(tool),
            }
            for tool in tools
        },
        "privilege_combos": _privilege_combos_present(tools),
    }


def write_baseline(path: str | Path, tools: list[types.Tool]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot_tools(tools), f, indent=2, sort_keys=True)


def load_baseline(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@dataclass(frozen=True)
class BaselineDrift:
    kind: str  # "tool-added" | "tool-removed" | "description-changed" | "schema-changed"
    tool_name: str
    message: str


def diff_baseline(baseline: dict, tools: list[types.Tool]) -> list[BaselineDrift]:
    """Every change between an approved baseline and the tools seen now, in a
    stable order (added, then removed, then per-tool changes by name)."""
    approved = baseline.get("tools", {}) if isinstance(baseline, dict) else {}
    current = snapshot_tools(tools)["tools"]
    drift: list[BaselineDrift] = []

    for name in sorted(set(current) - set(approved)):
        drift.append(
            BaselineDrift("tool-added", name, f"{name!r} is new since the baseline — not in the approved set.")
        )
    for name in sorted(set(approved) - set(current)):
        drift.append(
            BaselineDrift("tool-removed", name, f"{name!r} was in the approved baseline but is gone now.")
        )
    for name in sorted(set(approved) & set(current)):
        was, now = approved[name], current[name]
        if was.get("description", "") != now["description"]:
            drift.append(
                BaselineDrift(
                    "description-changed",
                    name,
                    f"{name!r} description changed since approval — a rug-pull red flag; review the new text.",
                )
            )
        if was.get("schema_hash") != now["schema_hash"]:
            drift.append(
                BaselineDrift(
                    "schema-changed",
                    name,
                    f"{name!r} input schema changed since approval — new or altered parameters; review before trusting.",
                )
            )
    return drift


def diff_scope_creep(baseline: dict, tools: list[types.Tool]) -> list[BaselineDrift]:
    """Directional permission-surface diff (MCP02): flag only privilege GROWTH
    since the approved baseline — a tool that gained a dangerous capability, a
    newly-added privileged tool, or a new dangerous capability combination.
    Capability *shrinkage* is hardening and is never flagged. Like rug-pull, this
    is WARN-level and never touches the grade."""
    approved = baseline.get("tools", {}) if isinstance(baseline, dict) else {}
    if approved and not any("capabilities" in t for t in approved.values()):
        # A pre-v2 baseline recorded no capabilities — there's nothing to diff
        # against. Say so once instead of silently doing nothing or false-firing.
        return [
            BaselineDrift(
                "scope-baseline-outdated",
                "",
                "baseline predates scope-creep tracking — re-record it with --baseline to enable "
                "permission-surface drift detection.",
            )
        ]

    current = snapshot_tools(tools)
    current_tools = current["tools"]
    drift: list[BaselineDrift] = []

    for name in sorted(set(approved) & set(current_tools)):
        gained = sorted(set(current_tools[name]["capabilities"]) - set(approved[name].get("capabilities", [])))
        if gained:
            drift.append(
                BaselineDrift(
                    "privilege-expanded",
                    name,
                    f"{name!r} gained {', '.join(gained)} since the baseline — a tool growing its "
                    "permissions after approval; review before trusting.",
                )
            )
    for name in sorted(set(current_tools) - set(approved)):
        dangerous = sorted(set(current_tools[name]["capabilities"]) & set(_DANGEROUS_CAPS))
        if dangerous:
            drift.append(
                BaselineDrift(
                    "dangerous-tool-added",
                    name,
                    f"{name!r} is new since the baseline and carries {', '.join(dangerous)} — a new "
                    "privileged tool not in the approved set.",
                )
            )
    approved_combos = set(baseline.get("privilege_combos", []))
    for combo in sorted(set(current["privilege_combos"]) - approved_combos):
        drift.append(
            BaselineDrift(
                "privilege-combo-added",
                "",
                f"a new dangerous capability combination appeared since the baseline: {combo} — "
                "review the tool(s) that introduced it.",
            )
        )
    return drift
