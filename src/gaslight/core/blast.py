"""Blast radius: how far damage actually travelled, from data the run already has.

The gauges answer "how much of each dimension held". This answers the question a
person actually asks first: *if something goes wrong with this agent, how far
does it reach?*

The one rule that makes it honest — and the reason it is not just a tool
inventory — is that **the lit area only grows where an attack physically
succeeded**. Having a file-reading tool does not light the machine ring; a file
we should never have been able to read coming back does. A guard that holds
keeps the radius small, which is exactly what a blast radius should mean.

Four states per ring:
  breached — a proving attack fired. Physical evidence, same bar as CONFIRMED.
  held     — a proving attack ran and was turned away. NOT "safe": it means
             these specific attacks failed, nothing more.
  reach    — the capability exists but no proving attack could run (usually the
             target's own backend was unreachable). Honestly unknown.
  none     — no tool of that shape exists at all.

No new attacks and no new data collection: capability comes from the same
schema finders the attacks use to pick targets, and state comes from the
Finding list the run already produces.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from mcp import types

from gaslight.core.attacks.base import Finding
from gaslight.core.schema import (
    find_code_execution_tool,
    find_exfil_tool,
    find_file_read_tool,
    find_network_tool,
)

BREACHED, HELD, REACH, NONE = "breached", "held", "reach", "none"

_STATE_LABEL = {
    BREACHED: "BREACHED",
    HELD: "HELD",
    REACH: "REACHABLE",
    NONE: "OUT OF REACH",
}


@dataclass(frozen=True)
class _ZoneSpec:
    key: str
    ring_label: str
    name: str
    # Attacks whose firing is physical proof of reaching THIS zone.
    proving_attacks: tuple[str, ...]


# Ordered innermost -> outermost. Each zone's proving attacks are exactly those
# whose success means "something got this far", never merely "a tool exists".
ZONES: tuple[_ZoneSpec, ...] = (
    _ZoneSpec(
        "host",
        "THIS MACHINE",
        "This machine — files & code",
        ("path-traversal", "code-execution-probe", "argument-smuggling"),
    ),
    _ZoneSpec(
        "net",
        "YOUR NETWORK",
        "Your network",
        ("ssrf-probe", "code-execution-probe", "argument-smuggling"),
    ),
    _ZoneSpec(
        "world",
        "DATA LEAVING",
        "Data leaving",
        ("injection-exfil", "tool-authz-probe", "confused-deputy"),
    ),
)


@dataclass
class BlastZone:
    key: str
    ring_label: str
    name: str
    state: str
    detail: str
    via: str | None = None

    @property
    def state_label(self) -> str:
        return _STATE_LABEL[self.state]


def _capability(tools: list[types.Tool]) -> dict[str, list[str]]:
    """Which tools grant reach into each zone. Deliberately tight — a generous
    capability map lights every ring amber and turns the picture into noise."""
    file_tool, _ = find_file_read_tool(tools)
    code_tool, _ = find_code_execution_tool(tools)
    net_tool, _ = find_network_tool(tools)
    exfil_tool, _ = find_exfil_tool(tools)
    return {
        "host": [t.name for t in (file_tool, code_tool) if t is not None],
        "net": [t.name for t in (net_tool, code_tool) if t is not None],
        "world": [t.name for t in (exfil_tool,) if t is not None],
    }


def compute_blast(tools: list[types.Tool], findings: list[Finding]) -> list[BlastZone]:
    caps = _capability(tools)
    by_key = {f.attack_key: f for f in findings}
    zones: list[BlastZone] = []

    for spec in ZONES:
        relevant = [by_key[k] for k in spec.proving_attacks if k in by_key]
        fired = [f for f in relevant if f.fired]
        via = caps[spec.key]

        if fired:
            state = BREACHED
            detail = fired[0].reason
        elif not via:
            state = NONE
            detail = "no tool of this kind exists on this target."
        elif any(f.attempted for f in relevant):
            state = HELD
            detail = f"{', '.join(via[:2])} turned away every payload we sent at this boundary."
        else:
            state = REACH
            detail = f"{', '.join(via[:2])} could reach here, but no attack could be completed to prove it."

        zones.append(
            BlastZone(
                key=spec.key,
                ring_label=spec.ring_label,
                name=spec.name,
                state=state,
                detail=detail,
                via=via[0] if via else None,
            )
        )
    return zones


# --- geometry, precomputed here so the template stays a template ---

_CORE_R = 54.0
_RING_STEP = 46.0
_SIZE = 440.0

_STROKE = {BREACHED: 3.5, HELD: 2.5, REACH: 2.0, NONE: 1.5}
_DASH = {BREACHED: "none", HELD: "7 6", REACH: "7 6", NONE: "3 8"}


def blast_geometry(zones: list[BlastZone]) -> dict:
    """Everything the SVG needs: ring radii, the glow radius, and the headline.

    The glow stops at the outermost BREACHED ring — never at the outermost
    *capable* one. That single choice is what stops this being a tool inventory.
    """
    breached = [z for z in zones if z.state == BREACHED]
    rings = []
    glow_r = _CORE_R
    for i, z in enumerate(zones):
        r = _CORE_R + _RING_STEP * (i + 1)
        rings.append(
            {
                "r": round(r, 1),
                "label": z.ring_label,
                "state": z.state,
                "stroke": _STROKE[z.state],
                "dash": _DASH[z.state],
                "label_y": round(_SIZE / 2 - r + 17, 1),
                "lit": z.state != NONE,
            }
        )
        if z.state == BREACHED:
            glow_r = r

    return {
        "size": _SIZE,
        "center": _SIZE / 2,
        "core_r": _CORE_R,
        "rings": rings,
        "glow_r": round(glow_r, 1),
        "breached": bool(breached),
        "furthest": breached[-1].ring_label if breached else None,
        "circumference": round(2 * math.pi * _CORE_R, 1),
    }


def blast_headline(zones: list[BlastZone]) -> str:
    """One plain sentence for the top of the report."""
    breached = [z for z in zones if z.state == BREACHED]
    if breached:
        return f"Damage reached {breached[-1].ring_label.lower()} — an attack physically got through."
    tested = [z for z in zones if z.state == HELD]
    if tested:
        return "Contained — every attack that could reach a working tool was turned away."
    return "Nothing could be tested — no attack reached a workable tool on this target."
