"""True-positive + false-positive-guard pair for the path-traversal probe,
plus the safe/no-safe masking behavior. See
docs/superpowers/specs/2026-08-17-m6-path-traversal-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.path_traversal import PathTraversalAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_against_unguarded_target():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason


async def test_does_not_fire_against_guarded_target():
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


async def test_target_with_no_file_read_tool_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_reports_dotdot_absolute_and_encoded_as_separate_subchecks():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    ids = {c.id for c in finding.checks}
    assert ids == {"fs-dotdot", "fs-absolute", "fs-encoded"}


async def test_guarded_target_reports_all_three_subchecks_passing():
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    outcomes = {c.id: c.outcome for c in finding.checks}
    assert outcomes == {"fs-dotdot": "pass", "fs-absolute": "pass", "fs-encoded": "pass"}


async def test_naively_guarded_target_fires_via_encoded_bypass_only():
    """The '....//' single-replace-pass bypass: a guard that strips the
    literal "../" substring once (rather than canonicalizing the resolved
    path) blocks plain relative and absolute traversal, but not this
    encoding — proving fs-encoded is a real, independent sub-check, not a
    duplicate of fs-dotdot."""
    with Sink() as sink:
        async with TargetConnection(_spec("naively_guarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "encoded" in finding.reason
    outcomes = {c.id: c.outcome for c in finding.checks}
    assert outcomes == {"fs-dotdot": "pass", "fs-absolute": "pass", "fs-encoded": "fail"}


async def test_safe_mode_masks_and_truncates_the_response():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "PATH TRAVERSAL MARKER" in finding.reason  # enough to prove the hit
    assert "Filler text to pad the response further still." not in finding.reason  # not the tail


async def test_no_safe_stores_full_response():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_file_read_server.py")) as target:
            finding = await PathTraversalAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "Filler text to pad the response further still." in finding.reason


async def test_fires_against_target_with_extra_required_field():
    """Fix 2 (final review): a tool with a second required field
    (requester_id) unrelated to path confinement used to fail schema
    validation on every payload (only `path` was ever sent), which made
    the probe misread universal rejection as "confined to its directory"
    when the tool was never actually tested. naive_arguments() now fills
    the extra required field so the real, unguarded path argument still
    gets exercised."""
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_file_read_extra_required_field_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason


async def test_does_not_fire_on_not_found_text_returned_as_normal_output():
    with Sink() as sink:
        async with TargetConnection(_spec("not_found_text_file_read_server.py")) as target:
            finding = await PathTraversalAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


def test_constructor_rejects_non_bool_safe():
    import pytest

    with pytest.raises(TypeError):
        PathTraversalAttack(safe="yes")
