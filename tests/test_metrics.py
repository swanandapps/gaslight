from gaslight.core.attacks.base import CheckResult, Finding
from gaslight.core.metrics import (
    BREACH_CAP,
    FAIL,
    METRICS,
    NA,
    PASS,
    _band,
    compute_metrics,
    outcome_for,
)

# One attack key per audit; deduplicated because a metric may split one attack
# into several sub-checks (Filesystem: path-traversal ../ vs absolute).
ATTACK_KEYS = {a.attack_key for m in METRICS for a in m.audits}


def _f(key, *, fired=False, attempted=True, checks=None):
    return Finding(attack_key=key, fired=fired, reason="x", attempted=attempted, checks=checks or [])


def _by_name(results):
    return {r.name: r for r in results}


def test_all_attacks_pass_scores_100_green():
    findings = [_f(k) for k in ATTACK_KEYS]
    results, avg = compute_metrics(findings)
    assert avg == 100
    for r in results:
        assert r.score == 100
        assert r.band == "green"
        assert r.breached is False


def test_partial_breach_scores_proportionally_not_a_flat_floor():
    # injection-exfil (Network, weight 3) fires; Network's other four checks
    # hold. Proportional score = 11/14 → 79, amber — a real partial, and never
    # green because it's breached.
    findings = [_f(k, fired=(k == "injection-exfil")) for k in ATTACK_KEYS]
    results, _ = compute_metrics(findings)
    net = _by_name(results)["Network"]
    assert net.breached is True
    assert net.score == 79
    assert net.band == "orange"
    assert _by_name(results)["Leakage"].score == 100


def test_single_check_metric_breach_goes_red():
    # Authorization has two checks (destructive guard + cost cap). The
    # destructive breach caps and reds the metric even though the cost-cap
    # check passes: 2/5 = 40, still red, still breached.
    findings = [_f(k, fired=(k == "destructive-authz-probe")) for k in ATTACK_KEYS]
    authz = _by_name(compute_metrics(findings)[0])["Authorization"]
    assert authz.score == 40
    assert authz.band == "red"
    assert authz.breached is True


def test_filesystem_subchecks_score_partial():
    # path-traversal reports ../ and encoded bypasses blocked, but absolute
    # path escaping; argument-smuggling holds. Filesystem =
    # (3 dotdot + 2 encoded + 2 argsmuggle) / (3+2+2+2) = 7/9 -> 78, amber,
    # breached — a real DVMCP-Challenge-3 shape.
    findings = [_f(k) for k in ATTACK_KEYS if k != "path-traversal"]
    findings.append(
        _f(
            "path-traversal",
            fired=True,
            checks=[
                CheckResult("fs-dotdot", PASS),
                CheckResult("fs-absolute", FAIL),
                CheckResult("fs-encoded", PASS),
            ],
        )
    )
    fs = _by_name(compute_metrics(findings)[0])["Filesystem"]
    assert fs.score == 78
    assert fs.band == "orange"
    assert fs.breached is True


def test_finding_without_checks_falls_back_to_whole_result():
    # A path-traversal finding with no per-check detail still scores: all
    # three of ITS Filesystem audits fall back to the fired state; the
    # separate argument-smuggling audit is unaffected and still holds.
    findings = [_f(k) for k in ATTACK_KEYS if k != "path-traversal"]
    findings.append(_f("path-traversal", fired=True))  # no checks
    fs = _by_name(compute_metrics(findings)[0])["Filesystem"]
    assert fs.score == 22  # 2 (argsmuggle pass) / 9 total weight
    assert fs.breached is True


def test_breached_metric_is_never_green():
    assert BREACH_CAP < 90


_FILESYSTEM_KEYS = {"path-traversal", "argument-smuggling"}


def test_absent_attack_is_na_and_excluded_from_average():
    # Both Filesystem-homed attacks absent -> the whole metric is N/A, not
    # just one of its four audits.
    findings = [_f(k) for k in ATTACK_KEYS if k not in _FILESYSTEM_KEYS]
    results, avg = compute_metrics(findings)
    fs = _by_name(results)["Filesystem"]
    assert fs.score is None
    assert fs.band == "na"
    assert fs.display == "–"
    assert avg == 100  # the all-N/A metric must not drag the average to zero


def test_not_attempted_finding_counts_as_na_not_pass():
    findings = [_f(k, attempted=(k not in _FILESYSTEM_KEYS)) for k in ATTACK_KEYS]
    results, _ = compute_metrics(findings)
    assert _by_name(results)["Filesystem"].score is None


def test_band_thresholds():
    assert _band(100) == "green"
    assert _band(90) == "green"
    assert _band(89) == "orange"
    assert _band(50) == "orange"
    assert _band(49) == "red"
    assert _band(0) == "red"
    assert _band(None) == "na"


def test_outcome_for_maps_states_and_checks():
    assert outcome_for(_f("x", fired=True)) == FAIL
    assert outcome_for(_f("x", fired=False)) == PASS
    assert outcome_for(_f("x", attempted=False)) == NA
    assert outcome_for(None) == NA
    # per-check resolution
    f = _f("x", fired=True, checks=[CheckResult("a", PASS), CheckResult("b", FAIL)])
    assert outcome_for(f, "a") == PASS
    assert outcome_for(f, "b") == FAIL


def test_every_attack_maps_into_exactly_one_metric():
    # Guards against a new attack being added without a home in the gauges.
    homes = {}
    for m in METRICS:
        for a in m.audits:
            homes.setdefault(a.attack_key, set()).add(m.name)
    for key, names in homes.items():
        assert len(names) == 1, f"{key} spans metrics {names}"
    assert len(ATTACK_KEYS) == 17
