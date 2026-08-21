"""True-positive + false-positive-guard pair for the direct destructive-
action probe, plus the safe/no-safe gate proof — the single most important
behavior in this module. See
docs/superpowers/specs/2026-08-17-m5a-instruction-override-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.destructive_authz_probe import DestructiveActionAuthzProbeAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.schema import naive_arguments
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_default_construction_is_safe():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.attempted is False
    assert finding.candidate_destructive_tool == "delete_account"


async def test_safe_mode_declines_without_ever_calling_the_tool():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert "no-safe" in finding.reason
    assert finding.candidate_destructive_tool == "delete_account"


async def test_unsafe_mode_fires_when_tool_has_no_guard():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.destructive_tool == "delete_account"


async def test_unsafe_mode_does_not_fire_when_tool_rejects_naive_call():
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.destructive_tool is None


async def test_target_with_no_destructive_tool_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.candidate_destructive_tool is None


async def test_unsafe_mode_fires_via_leaked_error_hint():
    # path_guarded_destructive_server.py's delete_workspace rejects the
    # naive placeholder for being an invalid path, not for lacking
    # authorization, and leaks the real path in its own error text — the
    # same shape as the real bug found testing against the official git
    # MCP reference server's git_reset.
    with Sink() as sink:
        async with TargetConnection(_spec("path_guarded_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.destructive_tool == "delete_workspace"
    assert "leaked" in finding.reason
    assert "/real/workspace" in finding.reason


async def test_unsafe_mode_does_not_fire_on_a_decoy_hint():
    # decoy_hint_destructive_server.py's wipe_data leaks a path-like string
    # in its error text too, but it's a decoy — the real guard is
    # `confirm`, not `target_path`, so retrying with the leaked value must
    # still fail, and the probe must not report a false positive.
    with Sink() as sink:
        async with TargetConnection(_spec("decoy_hint_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.destructive_tool is None


async def test_safe_mode_flags_description_only_candidate_without_calling_it():
    with Sink() as sink:
        async with TargetConnection(_spec("description_only_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.candidate_destructive_tool == "archive_record"
    assert "description" in finding.reason


async def test_no_safe_still_does_not_fire_a_description_only_candidate():
    # The core safety property this milestone adds: a description-only
    # signal (no name match) must never trigger the real, irreversible
    # call, even under --no-safe.
    with Sink() as sink:
        async with TargetConnection(_spec("description_only_destructive_server.py")) as target:
            finding = await DestructiveActionAuthzProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert finding.candidate_destructive_tool == "archive_record"
    assert "description" in finding.reason


async def test_negation_in_description_is_flagged_as_candidate_but_never_fires():
    # "This does not delete anything" still contains the substring
    # "delete" — raw-substring prose matching can't distinguish that from
    # a real claim. Flag-level false positives are tolerated; fire-level
    # ones are not.
    with Sink() as sink:
        async with TargetConnection(_spec("negation_false_candidate_server.py")) as target:
            safe_finding = await DestructiveActionAuthzProbeAttack(safe=True).run(target, ScriptedProvider(), sink)
        async with TargetConnection(_spec("negation_false_candidate_server.py")) as target:
            unsafe_finding = await DestructiveActionAuthzProbeAttack(safe=False).run(
                target, ScriptedProvider(), sink
            )

    assert safe_finding.candidate_destructive_tool == "update_status"
    assert unsafe_finding.fired is False
    assert unsafe_finding.attempted is False


def test_naive_arguments_fills_required_array_with_a_single_element():
    schema = {
        "type": "object",
        "properties": {"entityNames": {"type": "array", "items": {"type": "string"}}},
        "required": ["entityNames"],
    }

    args = naive_arguments(schema)

    assert args["entityNames"] == ["test-value"]


def test_naive_arguments_fills_required_boolean_with_false():
    # A confirm-shaped required boolean is the most common destructive-tool
    # guard — filling it with True would defeat the exact guard this probe
    # is trying to detect, so it must come back False, not True.
    schema = {
        "type": "object",
        "properties": {
            "user_id": {"type": "string"},
            "confirm": {"type": "boolean"},
        },
        "required": ["user_id", "confirm"],
    }

    args = naive_arguments(schema)

    assert args["confirm"] is False
    assert args["user_id"] == "test-value"
