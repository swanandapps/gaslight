"""Deterministic detection of a *safety claim* in a tool's description.

A safety claim is a promise the tool's own description makes about what
calling it will (not) do — "read-only", "requires approval", "does not
commit". The driving LLM takes these at face value; this module finds them
so ClaimIntegrityAttack can test whether they actually hold against the
target's own observable state. Pure text matching, no I/O — the matched
phrase is quoted verbatim in the eventual finding, so it must be a real
substring of the description.

See docs/superpowers/specs/2026-08-19-claim-integrity-design.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Order matters: requires_approval is checked first. A description like
# "stages a read-only preview for approval" carries the stronger, more
# specific promise (an approval gate) — that's the one worth testing, so it
# wins over the incidental "read-only".
_REQUIRES_APPROVAL_PHRASES = (
    "requires approval",
    "require approval",
    "for approval",
    "awaiting approval",
    "pending approval",
    "requires confirmation",
    "require confirmation",
    "needs confirmation",
    "left pending",
    "is pending",
    "staged",
    "stages",
    "as a draft",
    "creates a draft",
    "a draft",
    "dry run",
    "dry-run",
    "does not issue",
    "not issue",
    "does not commit",
    "not commit",
    "but does not commit",
    "prepares the action",
    "does not send",
    "before it is sent",
    "before executing",
)

_READ_ONLY_PHRASES = (
    "read-only",
    "read only",
    "does not modify",
    "do not modify",
    "doesn't modify",
    "without modifying",
    "view-only",
    "view only",
    "non-destructive",
    "nondestructive",
    "makes no changes",
    "no changes are made",
    "does not change",
    "does not write",
    "does not alter",
)


@dataclass(frozen=True)
class Claim:
    """A safety promise found in a tool's description.

    `family` is which kind of promise ("read_only" or "requires_approval");
    `phrase` is the exact lowercase substring that matched, ready to quote
    back in the finding as the tool's own words.
    """

    family: str
    phrase: str


def _first_phrase(text: str, phrases: tuple[str, ...]) -> str | None:
    for phrase in phrases:
        if phrase in text:
            return phrase
    return None


def detect_claim(description: str | None) -> Claim | None:
    """The safety claim a tool's description makes, or None.

    requires_approval is checked before read_only: an approval/staging
    promise is the stronger, more specific claim and the one worth testing
    when a description carries hints of both."""
    if not description:
        return None
    text = description.lower()

    phrase = _first_phrase(text, _REQUIRES_APPROVAL_PHRASES)
    if phrase is not None:
        return Claim(family="requires_approval", phrase=phrase)

    phrase = _first_phrase(text, _READ_ONLY_PHRASES)
    if phrase is not None:
        return Claim(family="read_only", phrase=phrase)

    return None


# Status vocabulary for the requires_approval verdict — deliberately
# conservative. A committed word present with no pending word is a
# contradiction of an approval claim; a pending word means the claim holds;
# neither present means "can't tell", which the attack flags rather than
# firing on.
_COMMITTED_STATUS = (
    "issued",
    "committed",
    "active",
    "sent",
    "completed",
    "confirmed",
    "posted",
    "paid",
    "processed",
    "finalized",
    "finalised",
    "live",
)
_PENDING_STATUS = (
    "pending",
    "draft",
    "staged",
    "awaiting",
    "unconfirmed",
    "queued",
    "for approval",
    "not yet",
    "under review",
)


def _words_present(text: str, words: tuple[str, ...]) -> list[str]:
    """Which of `words` appear in `text` as whole words. Word-boundary
    matching, not raw substring, so "paid" does not match "unpaid",
    "active" does not match "inactive", "live" does not match "delivery",
    and "sent" does not match "consent" — real collisions flagged in review
    that a substring test would get wrong."""
    low = text.lower()
    return [w for w in words if re.search(rf"\b{re.escape(w)}\b", low)]


def committed_status_words(text: str) -> list[str]:
    """Committed-shaped status words present in the given text, whole-word."""
    return _words_present(text, _COMMITTED_STATUS)


def pending_status_words(text: str) -> list[str]:
    """Pending-shaped status words present in the given text, whole-word."""
    return _words_present(text, _PENDING_STATUS)
