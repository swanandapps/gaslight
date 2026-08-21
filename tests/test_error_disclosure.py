"""True-positive + false-positive-guard pair for the verbose-error
disclosure probe, plus the consequential-tool skip and honest-decline
cases. See docs/superpowers/specs/2026-08-20-v1-attack-net-widening.md,
section 4.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.error_disclosure import ErrorDisclosureAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_when_traceback_leaks_a_path():
    with Sink() as sink:
        async with TargetConnection(_spec("verbose_error_server.py")) as target:
            finding = await ErrorDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "get_record" in finding.reason
    # The traceback's own "File ..." frame line (the real path on the
    # machine running the fixture) matches before the fixture's fake
    # "/Users/deploy/..." path later in the same text — either is a genuine
    # leak; only assert on the kind, not which specific path won.
    assert "path-shaped string" in finding.reason


async def test_does_not_fire_on_generic_error_message():
    with Sink() as sink:
        async with TargetConnection(_spec("generic_error_server.py")) as target:
            finding = await ErrorDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is True


async def test_skips_consequential_tools_and_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("only_destructive_server.py")) as target:
            finding = await ErrorDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_target_with_no_tools_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("generic_error_server.py")) as target:
            target.tools.clear()
            finding = await ErrorDisclosureAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_safe_mode_masks_a_genuine_secret_in_error_text():
    with Sink() as sink:
        async with TargetConnection(_spec("secret_leak_error_server.py")) as target:
            finding = await ErrorDisclosureAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "sk-live-abcdef1234567890" not in finding.reason


async def test_no_safe_stores_full_error_text():
    with Sink() as sink:
        async with TargetConnection(_spec("secret_leak_error_server.py")) as target:
            finding = await ErrorDisclosureAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "sk-live-abcdef1234567890" in finding.reason


def test_a_word_ending_in_a_letter_colon_backslash_is_not_a_windows_path():
    """Regression: "Options:\\n" inside kubectl's public help text matched the
    Windows drive-letter pattern as "s:\\n" and was reported as a leaked path."""
    from gaslight.core.attacks.error_disclosure import _find_leak

    assert _find_leak('{"help_text": "kubectl controls things.\\n\\nOptions:\\n  --kubeconfig"}') is None


def test_a_real_windows_path_is_still_detected():
    from gaslight.core.attacks.error_disclosure import _find_leak

    leak = _find_leak(r"Error opening C:\Users\admin\secrets\config.ini")
    assert leak is not None and leak.kind == "path"


def test_a_high_entropy_non_secret_no_longer_confirms_a_leak():
    """The structural fix: error-disclosure fires CONFIRMED, so it must never
    do so on an entropy guess. A build hash / request id in an error message
    (high entropy, not a credential) previously produced a false Grade F."""
    from gaslight.core.attacks.error_disclosure import _find_leak

    build_hash = "Build failed at commit a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    assert _find_leak(build_hash) is None


def test_a_recognisable_secret_in_error_text_still_confirms():
    from gaslight.core.attacks.error_disclosure import _find_leak

    leak = _find_leak("Auth failed with token sk-live-abcdef1234567890abcdef")
    assert leak is not None and leak.kind == "secret"


def test_a_password_pair_in_error_text_still_confirms():
    # Low-entropy but a named credential — caught by the pattern, not entropy.
    from gaslight.core.attacks.error_disclosure import _find_leak

    leak = _find_leak("DB connect error, password: super_secret_password123 rejected")
    assert leak is not None and leak.kind == "secret"
