"""The honesty + education layer: every check explains itself in plain words,
and the fun facts rotate deterministically. See core/education.py.
"""

from gaslight.cli import _build_attacks
from gaslight.core.education import FACTS, SAFE_INTRO, fact_for, what_it_checks


def test_every_registered_attack_has_a_plain_description():
    # Honesty guard: no attack may reach a user as a bare, scary-sounding name
    # with no explanation of what it actually checks. Adding an attack without
    # an entry fails here on purpose.
    for attack in _build_attacks(safe=True):
        assert what_it_checks(attack.key), f"{attack.key} has no plain-language description"


def test_descriptions_read_as_checks_not_threats():
    # Each one should describe a *check on the target's guards*, framed with
    # "whether …", not a boast about stealing anything.
    for attack in _build_attacks(safe=True):
        assert what_it_checks(attack.key).startswith("whether ")


def test_safe_intro_is_reassuring_and_honest():
    lowered = SAFE_INTRO.lower()
    assert "safe" in lowered
    assert "guardrail" in lowered  # frames it as checking defenses
    assert "real data" in lowered  # reassures without alarming words
    # Deliberately avoid negative/alarming words in user-facing copy.
    assert "steal" not in lowered
    assert "break-in" not in lowered


def test_facts_rotate_deterministically_and_wrap():
    assert fact_for(0) == FACTS[0]
    assert fact_for(1) == FACTS[1]
    assert fact_for(len(FACTS)) == FACTS[0]  # wraps around
    assert fact_for(len(FACTS) + 2) == FACTS[2]


def test_facts_are_present_and_nonempty():
    assert len(FACTS) >= 5
    assert all(isinstance(f, str) and f.strip() for f in FACTS)
