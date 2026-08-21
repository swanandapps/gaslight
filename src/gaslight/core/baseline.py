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

_SCHEMA_VERSION = 1


def _canonical_schema(schema: object) -> str:
    """A stable string for an input schema — sorted keys, no whitespace — so an
    unchanged schema always hashes the same and any real change flips the hash."""
    try:
        return json.dumps(schema or {}, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(schema)


def _schema_hash(schema: object) -> str:
    return hashlib.sha256(_canonical_schema(schema).encode("utf-8")).hexdigest()[:16]


def snapshot_tools(tools: list[types.Tool]) -> dict:
    """A serializable fingerprint of a target's tools — name, description and a
    hash of the input schema — enough to detect any later mutation without
    storing the whole schema."""
    return {
        "version": _SCHEMA_VERSION,
        "tools": {
            tool.name: {
                "description": tool.description or "",
                "schema_hash": _schema_hash(tool.input_schema),
            }
            for tool in tools
        },
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
