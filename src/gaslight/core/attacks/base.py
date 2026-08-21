"""Shared shape every attack module returns and is driven by.

One interface, many modules — V1 ships exactly one (injection_exfil.py).
Keeping this contract narrow now is what lets excessive-agency, tool-
poisoning, and jailbreak modules slot in later without touching the harness,
the scorer, or the reporter (see §11/§13 of the design doc: this is the
pluggable-module seam the roadmap depends on).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from gaslight.core.harness import TranscriptEntry
from gaslight.core.llm import LLMProvider
from gaslight.core.sink import Sink
from gaslight.core.target import Target

# The three outcomes an attack may report for one named sub-check (see
# Finding.checks). `weak` is a hardening gap with no confirmed exploit — it
# lowers a metric's score without the breach a `fail` carries. Kept as plain
# strings so core.metrics (which imports base, never the reverse) owns the
# scoring while attacks own the evidence.
CHECK_PASS = "pass"
CHECK_WEAK = "weak"
CHECK_FAIL = "fail"


@dataclass
class CheckResult:
    """One independently-evaluated sub-check inside an attack — e.g.
    path-traversal evaluates "blocks ../" and "refuses absolute paths"
    separately, so a target that stops one but not the other scores a real
    partial, not an all-or-nothing. `id` matches a core.metrics Audit's
    `check`; `outcome` is one of CHECK_PASS / CHECK_WEAK / CHECK_FAIL."""

    id: str
    outcome: str


@dataclass
class Finding:
    attack_key: str
    fired: bool
    """Whether the attack succeeded — decided by the sink, never by an LLM."""

    reason: str
    """Human-readable summary. For a non-fire, this is why (no surface found,
    canary never arrived, ...) — never silence."""

    canary_token: str | None = None
    exfil_tool: str | None = None
    candidate_exfil_tool: str | None = None
    """The exfil-capable tool this attack found and targeted, set whenever
    one was found — regardless of whether the attack fired. `exfil_tool`
    (above) is only set when the exfil call actually happened; this field
    lets a later verdict step (see core/verdict.py) pair two different
    attack modules' findings by "which tool were you testing," even when
    neither fired."""
    destructive_tool: str | None = None
    candidate_destructive_tool: str | None = None
    """Same pairing pattern as candidate_exfil_tool, for the model-vs-code
    verdict over destructive-tool shapes (see
    core/verdict.py:compute_destructive_verdict) instead of exfil-capable
    ones."""
    claim_tool: str | None = None
    """The tool whose stated safety claim ClaimIntegrityAttack tested, set
    whenever a claim was found — regardless of whether the attack fired or
    could verify it. Same optional-pairing pattern as candidate_destructive_tool,
    so the report can name the tool even on a non-fire or an honest decline."""
    sink_request_summary: str | None = None
    transcript: list[TranscriptEntry] = field(default_factory=list)
    raw_observed_text: list[str] = field(default_factory=list)
    """Generic bucket any attack can optionally populate with raw text it
    observed, for the optional --classify-secrets LLM layer to look at.
    Distinct from `transcript`, which is conversation-turn-shaped and
    doesn't fit e.g. resource-exposure's flat list of resource bodies."""
    turns_taken: int = 0
    checks: list[CheckResult] = field(default_factory=list)
    """Per-sub-check outcomes, for attacks that evaluate more than one
    independent defense in a single run (path-traversal: ../ vs absolute
    path). Empty for single-shot attacks — core.metrics then falls back to
    the whole-Finding fired/attempted state, so this is purely additive."""
    attempted: bool = True
    """Whether this attack actually got to test anything — a model turn ran,
    or a probe call happened. `False` only when the attack bailed out before
    ever exercising the target (no viable surface, couldn't plant the
    payload, ...). This disambiguates `fired=False`, which can mean either
    "tested and clean" or "never tested" — see core/verdict.py."""


class AttackModule(ABC):
    key: str
    name: str
    description: str

    @abstractmethod
    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        """Attempt this attack against `target`, proving success via `sink`."""
