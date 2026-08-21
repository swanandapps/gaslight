"""Unit tests for deterministic claim detection from tool descriptions.
See docs/superpowers/specs/2026-08-19-claim-integrity-design.md.
"""

import pytest

from gaslight.core.claims import committed_status_words, detect_claim, pending_status_words


@pytest.mark.parametrize(
    "description",
    [
        "Read-only. Does not modify data.",
        "A read-only view of the ledger.",
        "Does not modify anything in the database.",
        "View-only access to records.",
        "This is a non-destructive lookup.",
    ],
)
def test_detects_read_only_claims(description):
    claim = detect_claim(description)
    assert claim is not None
    assert claim.family == "read_only"


@pytest.mark.parametrize(
    "description",
    [
        "Stages the invoice for approval; does not issue it.",
        "Creates a draft that requires approval before it is sent.",
        "Requires confirmation before executing.",
        "The record is left pending until a human approves it.",
        "Dry run only — no real effect.",
        "Prepares the action but does not commit it.",
    ],
)
def test_detects_requires_approval_claims(description):
    claim = detect_claim(description)
    assert claim is not None
    assert claim.family == "requires_approval"


@pytest.mark.parametrize(
    "description",
    [
        "Fetches the latest exchange rate for a currency.",
        "Sends an email to the given recipient.",
        "Adds two numbers together.",
        "",
    ],
)
def test_plain_descriptions_have_no_claim(description):
    assert detect_claim(description) is None


def test_none_description_has_no_claim():
    assert detect_claim(None) is None


def test_claim_carries_the_matched_phrase_verbatim_source():
    # The phrase is what gets quoted in the finding — it must be a substring
    # of the description so the report can show the promise in the author's
    # own words.
    description = "A totally safe, read-only helper."
    claim = detect_claim(description)
    assert claim is not None
    assert claim.phrase in description.lower()


def test_negated_claim_still_matches_as_known_limitation():
    # Raw substring matching can't tell "requires approval" from "does not
    # require approval". This is a documented, accepted limitation: the worst
    # case downstream is an unverifiable flag, never a false CLAIM-FALSE fire.
    # Asserted here so the limitation is visible, not silent.
    claim = detect_claim("This does not require approval; it runs immediately.")
    assert claim is not None
    assert claim.family == "requires_approval"


@pytest.mark.parametrize(
    "text,expected_absent",
    [
        ("Invoice status: unpaid", "paid"),
        ("Account is inactive", "active"),
        ("Delivery scheduled for Tuesday", "live"),
        ("Awaiting consent from the buyer", "sent"),
    ],
)
def test_committed_status_words_are_whole_word_not_substring(text, expected_absent):
    # "unpaid" must not match "paid", "inactive" not "active", "delivery" not
    # "live", "consent" not "sent" — real substring collisions flagged in review.
    assert expected_absent not in committed_status_words(text)


def test_committed_status_word_matches_as_a_whole_word():
    assert "issued" in committed_status_words("Invoice BVA-1: issued")


def test_pending_status_word_matches_as_a_whole_word():
    assert "pending" in pending_status_words("Invoice BVA-2: pending approval")
