"""True-positive pair (marker + network smuggling) plus false-positive-guard
and honest-decline cases for the argument-smuggling probe. See
docs/superpowers/specs/2026-08-20-v1-attack-net-widening.md, section 3.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.argument_smuggling import ArgumentSmugglingAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_via_marker_on_a_non_path_named_field():
    # lookup_record's field is "reference", not "path" — find_path_field()
    # would never recognize it, so path_traversal.py never probes it.
    with Sink() as sink:
        async with TargetConnection(_spec("smuggled_path_server.py")) as target:
            finding = await ArgumentSmugglingAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "'reference'" in finding.reason
    assert "PATH TRAVERSAL MARKER" in finding.reason


async def test_fires_via_sink_on_a_non_url_named_field():
    # check_status's field is "session_ref", not "url"/"endpoint" — neither
    # find_url_field() nor ADDRESS_FIELD_PRIORITY would ever recognize it.
    with Sink() as sink:
        async with TargetConnection(_spec("smuggled_network_server.py")) as target:
            finding = await ArgumentSmugglingAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.exfil_tool == "check_status"
    assert "'session_ref'" in finding.reason


async def test_does_not_fire_when_field_is_never_interpolated():
    with Sink() as sink:
        async with TargetConnection(_spec("inert_field_server.py")) as target:
            finding = await ArgumentSmugglingAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is True


async def test_skips_consequential_tools_and_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("only_destructive_server.py")) as target:
            finding = await ArgumentSmugglingAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_does_not_probe_the_tools_own_recognized_path_field_twice():
    # unguarded_file_read_server.py's read_file(path) — "path" IS the
    # recognized field (path_traversal.py's job), so argument-smuggling
    # should find no OTHER field to try here and decline.
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_file_read_server.py")) as target:
            finding = await ArgumentSmugglingAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
