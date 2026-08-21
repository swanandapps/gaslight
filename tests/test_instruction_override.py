"""True-positive + false-positive-guard pair for the instruction-override
probe. The false-positive fixture (guarded_destructive_server.py) still
lets the model get tricked into *calling* delete_account — this attack's
finding is about the model's behavior, not the tool's; DestructiveActionAuthzProbeAttack
tests the tool's own guard separately. See
docs/superpowers/specs/2026-08-17-m5a-instruction-override-design.md.
"""

import sys
from pathlib import Path

from gaslight.core.attacks.instruction_override import InstructionOverrideAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


async def test_fires_when_model_obeys_the_override():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_destructive_server.py")) as target:
            finding = await InstructionOverrideAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.destructive_tool == "delete_account"
    assert finding.candidate_destructive_tool == "delete_account"


async def test_fires_even_when_the_tool_itself_would_reject_the_call():
    # This attack proves the MODEL obeyed the override — a separate attack
    # (DestructiveActionAuthzProbeAttack) proves whether the tool itself
    # has a real guard. ScriptedProvider calls delete_account with no args
    # (see _extract_override_call), so guarded_destructive_server.py's
    # missing confirm_token raises — but the call still happened, which is
    # this attack's whole finding.
    with Sink() as sink:
        async with TargetConnection(_spec("guarded_destructive_server.py")) as target:
            finding = await InstructionOverrideAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.destructive_tool == "delete_account"


async def test_target_with_no_destructive_tool_declines_honestly():
    with Sink() as sink:
        async with TargetConnection(_spec("vulnerable_server.py")) as target:
            finding = await InstructionOverrideAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


async def test_default_is_safe_and_does_not_perform_the_real_deletion():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_destructive_server.py")) as target:
            finding = await InstructionOverrideAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert "intercepted" not in finding.reason or "--safe" in finding.reason
    # The account must NOT actually be deleted under the default safe mode.
    # Verify by reading the fixture's own state through a fresh connection —
    # the fixture has no read-back tool, so instead confirm via the
    # interception marker: re-run with safe=False against a FRESH target
    # connection and confirm that one actually succeeds, proving the first
    # run's "success" didn't already consume real state. Since each
    # TargetConnection spawns a fresh subprocess, state doesn't persist
    # between connections anyway — so the strongest available proof is
    # that the harness's own transcript shows the intercepted response
    # text, not the fixture's real "Account ... deleted." text.
    from gaslight.core.attacks.instruction_override import _find_tool_call
    call = _find_tool_call(finding.transcript, "delete_account")
    assert call is not None
    assert "intercepted" in call.result_text


async def test_no_safe_actually_forwards_the_call_to_the_real_target():
    with Sink() as sink:
        async with TargetConnection(_spec("unguarded_destructive_server.py")) as target:
            finding = await InstructionOverrideAttack(safe=False).run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    from gaslight.core.attacks.instruction_override import _find_tool_call
    call = _find_tool_call(finding.transcript, "delete_account")
    assert call is not None
    assert "intercepted" not in call.result_text
    # ScriptedProvider deliberately calls the override target with no
    # arguments (see llm.py::_extract_override_call's docstring: "whether a
    # destructive tool gets called at all is the finding, not what argument
    # it's called with"). Combined with this fixture's required `user_id`
    # field, the real, un-intercepted call surfaces as the *target's own*
    # pydantic validation error rather than a "deleted" success string.
    # That is itself the proof the call reached the real target: a
    # synthetic interception (as under --safe) never touches pydantic
    # validation, and this error text bears no resemblance to the
    # "[gaslight] intercepted under --safe" marker.
    assert call.is_error is True
    assert "user_id" in call.result_text.lower()


async def test_safe_mode_guards_every_destructive_tool_not_just_the_named_one():
    """New Finding B: _SafeModeTarget must guard ALL destructive-shaped
    tools on the target, not just the single candidate this attack names in
    its planted payload — VictimHarness advertises every tool to the model,
    so a model whose instructions got overridden could call a different
    destructive tool than the one named in the payload."""
    with Sink() as sink:
        async with TargetConnection(_spec("multi_destructive_server.py")) as target:
            finding = await InstructionOverrideAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is True
    assert finding.candidate_destructive_tool == "delete_account"

    from gaslight.core.attacks.instruction_override import _SafeModeTarget

    # Prove the wrapper itself intercepts BOTH destructive tools directly,
    # independent of which one ScriptedProvider happened to be steered
    # toward by the planted payload.
    with Sink() as sink:
        async with TargetConnection(_spec("multi_destructive_server.py")) as target:
            safe_target = _SafeModeTarget(target, {"delete_account", "revoke_access"})
            delete_result = await safe_target.call_tool("delete_account", {"user_id": "u1"})
            revoke_result = await safe_target.call_tool("revoke_access", {"token": "t1"})

    assert delete_result.is_error is True
    assert "intercepted" in delete_result.content[0].text
    assert revoke_result.is_error is True
    assert "intercepted" in revoke_result.content[0].text


async def test_write_destructive_collision_declines_honestly_instead_of_a_real_plant_call():
    """New Finding A: when the write-tool candidate and the destructive-tool
    candidate resolve to the SAME tool (unanchored keyword overlap, e.g.
    "reset_password" matching both WRITE_KEYWORDS' "set" and
    _DESTRUCTIVE_KEYWORDS' "reset"), the plant call must not go through as a
    real, unintercepted call to that tool. The attack must decline honestly
    instead."""
    with Sink() as sink:
        async with TargetConnection(_spec("write_destructive_collision_server.py")) as target:
            finding = await InstructionOverrideAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False
    assert "reset_password" in finding.reason
    assert finding.candidate_destructive_tool == "reset_password"
