"""The live scan pipeline view. It's a pure state → renderable unit, so we drive
its state and assert on the rendered text — no TTY, no timing."""

from gaslight.core.runview import RunView

PHASES = [
    ("Network", ["ssrf probe", "path traversal"]),
    ("Filesystem", ["resource exposure"]),
    ("Leakage", ["output leakage", "baseline disclosure"]),
]


def _view():
    return RunView("demo-agent", 7, PHASES)


def test_renders_header_and_all_phase_names():
    text = _view().render_str()
    assert "gaslight" in text
    assert "demo-agent" in text
    assert "7 tool(s)" in text
    for name in ("Network", "Filesystem", "Leakage"):
        assert name in text


def test_current_phase_checks_stream():
    view = _view()
    view.start_phase(0)
    view.start_check(0, "ssrf probe", what="can a tool be pointed at an internal address?")
    text = view.render_str()
    # the in-flight check shows its name and a testing indicator
    assert "ssrf probe" in text
    assert "testing" in text


def test_passed_check_shows_result():
    view = _view()
    view.start_phase(0)
    view.finish_check(0, "ssrf probe", fired=False, attempted=True, result="no leak")
    text = view.render_str()
    assert "ssrf probe" in text
    assert "no leak" in text


def test_breach_marks_phase_and_shows_in_current_block():
    view = _view()
    view.start_phase(2)
    view.finish_check(2, "output leakage", fired=True, attempted=True, result="canary exfiltrated")
    text = view.render_str()
    assert "canary exfiltrated" in text


def test_phase_state_transitions():
    view = _view()
    # nothing started
    assert view._phase_state(0) == "pending"
    # phase 0 active
    view.start_phase(0)
    assert view._phase_state(0) == "now"
    # resolve both checks clean, move on → done
    view.finish_check(0, "ssrf probe", fired=False, attempted=True)
    view.finish_check(0, "path traversal", fired=False, attempted=True)
    view.start_phase(1)
    assert view._phase_state(0) == "done"
    assert view._phase_state(1) == "now"
    assert view._phase_state(2) == "pending"


def test_breached_state_wins_even_when_current():
    view = _view()
    view.start_phase(2)
    view.finish_check(2, "output leakage", fired=True, attempted=True)
    assert view._phase_state(2) == "breached"


def test_skipped_check_does_not_count_as_breach():
    view = _view()
    view.start_phase(1)
    view.finish_check(1, "resource exposure", fired=False, attempted=False, result="not tested")
    view.start_phase(2)
    assert view._phase_state(1) == "done"


def test_render_str_is_stable_without_tty():
    # the whole point: renders to plain text off a TTY for tests / CI capture.
    out = _view().render_str(width=100)
    assert isinstance(out, str) and out.strip()
