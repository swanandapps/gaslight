"""Pure unit tests for the CLI's verdict-pairing helper — no server, no
network, no subprocess. The two attack modules' Finding objects are the
only input.
"""

import json

from gaslight.cli import _build_attacks, _collect_ai_hints, _compute_verdicts, _report_json
from gaslight.core.attacks.base import Finding
from gaslight.core.scorer import grade
from gaslight.core.attacks.injection_exfil import InjectionExfilAttack
from gaslight.core.attacks.tool_authz_probe import ToolAuthzProbeAttack
from gaslight.core.harness import ToolCallRecord, TranscriptEntry
from gaslight.core.llm import LLMProvider, TurnResult


class _FakeProvider(LLMProvider):
    """Same fake used in test_llm_secret_hints.py — always suggests the
    same fixed hint, regardless of input text, so tests can assert on
    dedup/collection behavior without depending on real model output."""

    name = "fake"

    def __init__(self, reply_text: str) -> None:
        self._reply_text = reply_text

    def new_history(self, system, user_message):
        return {}

    async def run_turn(self, history, tools):
        return TurnResult(text=self._reply_text, tool_calls=[], stop_reason="end_turn")

    def append_tool_results(self, history, results):
        return history


def test_compute_verdicts_pairs_findings_by_tool_and_returns_one_verdict():
    findings = [
        Finding(attack_key=InjectionExfilAttack.key, fired=True, reason="x", candidate_exfil_tool="send_email"),
        Finding(attack_key=ToolAuthzProbeAttack.key, fired=False, reason="x", candidate_exfil_tool="send_email"),
    ]
    verdicts = _compute_verdicts(findings)
    assert len(verdicts) == 1
    assert verdicts[0].tool_name == "send_email"
    assert verdicts[0].label == "DEFENSE-IN-DEPTH WORKING"


def test_compute_verdicts_empty_when_no_candidate_tool_found():
    findings = [Finding(attack_key=InjectionExfilAttack.key, fired=False, reason="no surface")]
    assert _compute_verdicts(findings) == []


def test_build_attacks_includes_all_seventeen_modules():
    attacks = _build_attacks(safe=True)
    keys = {a.key for a in attacks}
    assert keys == {
        "injection-exfil",
        "tool-authz-probe",
        "tool-metadata-poisoning",
        "memory-poisoning",
        "output-leakage",
        "baseline-disclosure",
        "resource-exposure",
        "instruction-override",
        "destructive-authz-probe",
        "path-traversal",
        "ssrf-probe",
        "code-execution-probe",
        "claim-integrity",
        "confused-deputy",
        "argument-smuggling",
        "error-disclosure",
        "denial-of-wallet",
    }


def test_build_attacks_skip_removes_named_attacks():
    attacks = _build_attacks(safe=True, skip={"code-execution-probe", "ssrf-probe"})
    keys = {a.key for a in attacks}
    assert "code-execution-probe" not in keys
    assert "ssrf-probe" not in keys
    # everything else still present
    assert "claim-integrity" in keys
    assert "path-traversal" in keys


def test_build_attacks_skip_empty_keeps_all():
    assert len(_build_attacks(safe=True, skip=set())) == len(_build_attacks(safe=True))


def test_report_json_serializes_findings_grade_and_target():
    findings = [
        Finding(attack_key="ssrf-probe", fired=True, reason="reached the sink", claim_tool=None),
        Finding(attack_key="path-traversal", fired=False, reason="no read tool", attempted=False),
    ]
    grade_result = grade(findings)

    payload = json.loads(_report_json("npx -y some-server", 4, findings, grade_result))

    assert payload["target"] == "npx -y some-server"
    assert payload["tool_count"] == 4
    assert payload["grade"]["grade"] == grade_result.grade
    keys = {f["attack_key"] for f in payload["findings"]}
    assert keys == {"ssrf-probe", "path-traversal"}
    fired = [f for f in payload["findings"] if f["fired"]]
    assert len(fired) == 1
    assert fired[0]["attack_key"] == "ssrf-probe"
    assert fired[0]["reason"] == "reached the sink"


def test_compute_verdicts_includes_destructive_verdict_when_candidate_found():
    findings = [
        Finding(
            attack_key="instruction-override",
            fired=True,
            reason="obeyed",
            destructive_tool="delete_account",
            candidate_destructive_tool="delete_account",
        ),
        Finding(
            attack_key="destructive-authz-probe",
            fired=False,
            reason="rejected",
            candidate_destructive_tool="delete_account",
        ),
    ]
    verdicts = _compute_verdicts(findings)
    labels = {v.label for v in verdicts}
    assert "DEFENSE-IN-DEPTH WORKING" in labels


async def test_collect_ai_hints_classifies_baseline_disclosure_transcript():
    """Pre-existing behavior: --classify-secrets already looked at
    baseline-disclosure's transcript text. _collect_ai_hints is a pure
    extraction of that loop and must keep doing so."""
    entry = TranscriptEntry(
        turn=1,
        assistant_text="assistant reply text",
        tool_calls=[ToolCallRecord(name="get_status", arguments={}, result_text="tool result text", is_error=False)],
    )
    finding = Finding(attack_key="baseline-disclosure", fired=True, reason="x", transcript=[entry])
    hints = await _collect_ai_hints(_FakeProvider("suspicious-hint-value"), [finding])
    assert hints == ["suspicious-hint-value"]


async def test_collect_ai_hints_classifies_resource_exposure_raw_text():
    """Fix 3: resource-exposure never produces a transcript (no agent turn
    ever runs), so before Fix 3 the classify-secrets loop silently did
    nothing for it. Now raw_observed_text is classified too."""
    finding = Finding(
        attack_key="resource-exposure",
        fired=True,
        reason="x",
        raw_observed_text=["some resource body text"],
    )
    hints = await _collect_ai_hints(_FakeProvider("resource-hint-value"), [finding])
    assert hints == ["resource-hint-value"]


async def test_collect_ai_hints_ignores_other_attack_keys():
    finding = Finding(
        attack_key="injection-exfil",
        fired=True,
        reason="x",
        raw_observed_text=["should never be classified"],
    )
    hints = await _collect_ai_hints(_FakeProvider("should-not-appear"), [finding])
    assert hints == []


async def test_collect_ai_hints_dedups_across_findings():
    finding_a = Finding(attack_key="resource-exposure", fired=True, reason="x", raw_observed_text=["text a"])
    finding_b = Finding(attack_key="resource-exposure", fired=False, reason="x", raw_observed_text=["text b"])
    hints = await _collect_ai_hints(_FakeProvider("same-hint"), [finding_a, finding_b])
    assert hints == ["same-hint"]


def test_downgrade_marks_a_clean_result_as_untested_when_backend_was_down():
    """A "no leak" recorded while every call failed to connect was never
    actually tested — it must not render as a pass."""
    from gaslight.cli import _downgrade_if_backend_was_down
    from gaslight.core.target import Target, TargetSpec

    finding = Finding(attack_key="code-execution-probe", fired=False, reason="no payload reached out of scope.")
    target = Target(session=None, tools=[], spec=TargetSpec(command=["x"]))
    target.backend_failures = 4

    _downgrade_if_backend_was_down(finding, target)

    assert finding.attempted is False
    assert "not tested" in finding.reason
    assert finding.fired is False


def test_downgrade_leaves_a_confirmed_finding_alone():
    """A canary that physically arrived is real no matter how many other
    calls failed — proof stands on its own."""
    from gaslight.cli import _downgrade_if_backend_was_down
    from gaslight.core.target import Target, TargetSpec

    finding = Finding(attack_key="ssrf-probe", fired=True, reason="canary reached the sink.")
    target = Target(session=None, tools=[], spec=TargetSpec(command=["x"]))
    target.backend_failures = 9

    _downgrade_if_backend_was_down(finding, target)

    assert finding.fired is True
    assert finding.attempted is True


def test_downgrade_is_a_noop_on_a_healthy_run():
    from gaslight.cli import _downgrade_if_backend_was_down
    from gaslight.core.target import Target, TargetSpec

    finding = Finding(attack_key="path-traversal", fired=False, reason="no traversal payload escaped.")
    target = Target(session=None, tools=[], spec=TargetSpec(command=["x"]))

    _downgrade_if_backend_was_down(finding, target)

    assert finding.attempted is True
    assert finding.reason == "no traversal payload escaped."


def test_grade_summary_says_when_nothing_was_actually_tested():
    from gaslight.core.scorer import grade

    findings = [Finding(attack_key=f"a{i}", fired=False, reason="no tool", attempted=False) for i in range(3)]
    result = grade(findings)
    assert result.grade == "A"
    assert "Nothing was actually tested" in result.summary
    assert "not a pass" in result.summary


def test_grade_summary_counts_skipped_checks():
    from gaslight.core.scorer import grade

    findings = [
        Finding(attack_key="ran", fired=False, reason="clean"),
        Finding(attack_key="skipped-1", fired=False, reason="no tool", attempted=False),
        Finding(attack_key="skipped-2", fired=False, reason="no tool", attempted=False),
    ]
    result = grade(findings)
    assert "1 attack(s) actually tested" in result.summary
    assert "2 skipped" in result.summary
