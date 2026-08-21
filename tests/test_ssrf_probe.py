"""True-positive + false-positive-guard pair for the SSRF probe, plus the
safe/no-safe masking behavior. See
docs/superpowers/specs/2026-08-18-m7-ssrf-probe-design.md.
"""

import sys
from pathlib import Path

import pytest

from gaslight.core.attacks.ssrf_probe import SsrfProbeAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_against_unguarded_target():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_fetch_server.py")) as target:
            finding = await SsrfProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason


async def test_does_not_fire_against_guarded_target():
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_fetch_server.py")) as target:
            finding = await SsrfProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False


async def test_target_with_no_network_tool_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await SsrfProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_safe_mode_masks_and_truncates_metadata_response():
    with Sink() as sink:
        async with TargetConnection(_spec("metadata_leak_fetch_server.py")) as target:
            finding = await SsrfProbeAttack(safe=True).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "best-effort" in finding.reason
    assert "sk-live-abcdef1234567890" not in finding.reason


async def test_no_safe_stores_full_metadata_response():
    with Sink() as sink:
        async with TargetConnection(_spec("metadata_leak_fetch_server.py")) as target:
            finding = await SsrfProbeAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "sk-live-abcdef1234567890" in finding.reason


def test_constructor_rejects_non_bool_safe():
    with pytest.raises(TypeError):
        SsrfProbeAttack(safe="yes")


async def test_still_fires_via_plain_loopback_when_extra_sink_hosts_set(monkeypatch):
    # GASLIGHT_EXTRA_SINK_HOSTS adds candidates on top of, not instead of,
    # plain loopback — an unreachable extra host must not break the normal
    # same-machine case (loopback_hosts()'s own extension logic is unit
    # tested directly in test_sink.py; this proves the attack still works
    # end-to-end once that env var is present, i.e. no regression).
    monkeypatch.setenv("GASLIGHT_EXTRA_SINK_HOSTS", "this-host-does-not-resolve.invalid")
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_fetch_server.py")) as target:
            finding = await SsrfProbeAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "confirmed" in finding.reason
