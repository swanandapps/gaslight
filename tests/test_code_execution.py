"""True-positive + false-positive-guard pair for the code-execution
probe, plus the safe/no-safe masking behavior. See
docs/superpowers/specs/2026-08-18-m8-code-execution-design.md.
"""

import sys
from pathlib import Path

import pytest

from gaslight.core.attacks.code_execution import CodeExecutionAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_against_unguarded_target():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_code_exec_server.py")) as target:
            finding = await CodeExecutionAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason


async def test_does_not_fire_against_guarded_target():
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_code_exec_server.py")) as target:
            finding = await CodeExecutionAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


async def test_fires_via_base64_bypass_against_denylisted_target():
    # The denylisted fixture blocks plain "urllib"/"curl"/"http://" text but
    # never decodes what it's about to execute — the base64-wrapped network
    # trap payload sails through and still physically reaches our sink.
    with Sink() as sink:
        async with TargetConnection(_spec("denylisted_code_exec_server.py")) as target:
            finding = await CodeExecutionAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason
    assert "base64" in finding.reason


async def test_fires_against_sql_shaped_field_via_expanded_field_list():
    # Real-world gap found against the user's own agent: run_sql's field
    # is "sql", not "code"/"command" — before CODE_FIELD_PRIORITY grew to
    # include "sql" this tool was recognized by name but had no field to
    # attack, so find_code_execution_tool() returned (None, None) and the
    # attack declined even though the tool has zero containment.
    with Sink() as sink:
        async with TargetConnection(_spec("sql_code_execution_server.py")) as target:
            finding = await CodeExecutionAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason


async def test_target_with_no_code_execution_tool_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await CodeExecutionAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_safe_mode_masks_and_truncates_file_read_response():
    with Sink() as sink:
        async with TargetConnection(_spec("secret_leak_code_exec_server.py")) as target:
            finding = await CodeExecutionAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "best-effort" in finding.reason
    assert "sk-live-abcdef1234567890" not in finding.reason


async def test_no_safe_stores_full_file_read_response():
    with Sink() as sink:
        async with TargetConnection(_spec("secret_leak_code_exec_server.py")) as target:
            finding = await CodeExecutionAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "sk-live-abcdef1234567890" in finding.reason


def test_constructor_rejects_non_bool_safe():
    with pytest.raises(TypeError):
        CodeExecutionAttack(safe="yes")


async def test_still_fires_via_plain_loopback_when_extra_sink_hosts_set(monkeypatch):
    # Same regression guard as ssrf_probe.py's equivalent test: an
    # unreachable GASLIGHT_EXTRA_SINK_HOSTS entry must not break the
    # normal same-machine case.
    monkeypatch.setenv("GASLIGHT_EXTRA_SINK_HOSTS", "this-host-does-not-resolve.invalid")
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_code_exec_server.py")) as target:
            finding = await CodeExecutionAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason
