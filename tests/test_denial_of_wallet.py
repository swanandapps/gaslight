"""True-positive + false-positive-guard pair for the denial-of-wallet probe,
plus its scoring behavior (a WEAK that docks Authorization without an F). See
docs/brain/TICKET_denial_of_wallet.md and core/attacks/denial_of_wallet.py.
"""

import sys
from pathlib import Path

import pytest
from mcp import types

from gaslight.core.attacks.base import CHECK_PASS, CHECK_WEAK, CheckResult, Finding
from gaslight.core.attacks.denial_of_wallet import DenialOfWalletAttack
from gaslight.core.llm import ScriptedProvider
from gaslight.core.metrics import compute_metrics
from gaslight.core.schema import find_unbounded_tool
from gaslight.core.sink import Sink
from gaslight.core.target import TargetConnection, TargetSpec


def _tool(name, props):
    return types.Tool(name=name, description=None, inputSchema={"type": "object", "properties": props})


def test_write_shaped_tool_is_never_selected_for_dow():
    # create_orders(count) is NOT destructive/exfil by name, so is_consequential
    # misses it — but calling it with count=100000 is a mass write. It must
    # never be selected. (Pre-launch review, finding 1.)
    assert find_unbounded_tool([_tool("create_orders", {"count": {"type": "integer"}})])[0] is None


def test_update_with_listing_noun_is_not_selected():
    # 'records' is a listing noun, but 'update' makes it a write — must skip.
    assert find_unbounded_tool([_tool("update_records", {"rows": {"type": "integer"}})])[0] is None


def test_legit_read_list_tool_is_still_selected():
    tool, field = find_unbounded_tool([_tool("list_items", {"limit": {"type": "integer"}})])
    assert tool is not None and field == "limit"


def test_domain_tool_with_no_read_verb_is_not_probed():
    # No read/list verb in the name -> not affirmatively safe -> skipped, even
    # though it looks harmless. Safety over coverage.
    assert find_unbounded_tool([_tool("orders", {"count": {"type": "integer"}})])[0] is None

_FIXTURES = Path(__file__).parent / "fixtures"


def _spec(fixture_name: str) -> TargetSpec:
    return TargetSpec(command=[sys.executable, str(_FIXTURES / fixture_name)])


def _cost_cap(finding: Finding) -> str | None:
    return next((c.outcome for c in finding.checks if c.id == "cost-cap"), None)


async def test_flags_uncapped_list_tool_as_weak():
    with Sink() as sink:
        async with TargetConnection(_spec("unbounded_list_server.py")) as target:
            finding = await DenialOfWalletAttack().run(target, ScriptedProvider(), sink)

    # A hardening gap, not a breach: the check is WEAK, but the Finding never
    # "fires" (so it stays off the blast radius and can't force an F).
    assert finding.fired is False
    assert finding.attempted is True
    assert _cost_cap(finding) == CHECK_WEAK
    assert "no server-side cap" in finding.reason


async def test_capped_list_tool_scores_pass():
    with Sink() as sink:
        async with TargetConnection(_spec("capped_list_server.py")) as target:
            finding = await DenialOfWalletAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert _cost_cap(finding) == CHECK_PASS
    assert "capped or refused" in finding.reason


async def test_target_with_no_listing_tool_declines_honestly():
    # only_destructive_server exposes just delete_account — consequential, so
    # find_unbounded_tool skips it and there is nothing safe to probe.
    with Sink() as sink:
        async with TargetConnection(_spec("only_destructive_server.py")) as target:
            finding = await DenialOfWalletAttack().run(target, ScriptedProvider(), sink)

    assert finding.fired is False
    assert finding.attempted is False


def test_constructor_rejects_non_bool_safe():
    with pytest.raises(TypeError):
        DenialOfWalletAttack(safe="yes")


def test_weak_docks_authorization_without_breaching():
    # Authorization = destructive-authz-probe (weight 3, PASS) + denial-of-wallet
    # (weight 2, WEAK). WEAK contributes to the denominator but not the numerator
    # and never breaches: 3/5 = 60, not an F-capped breach.
    findings = [
        Finding(attack_key="destructive-authz-probe", fired=False, reason="guarded"),
        Finding(
            attack_key="denial-of-wallet",
            fired=False,
            reason="no cap",
            checks=[CheckResult("cost-cap", CHECK_WEAK)],
        ),
    ]
    metrics, _ = compute_metrics(findings)
    authz = next(m for m in metrics if m.name == "Authorization")
    assert authz.score == 60
    assert authz.breached is False
