from rich.console import Console

from gaslight.core.attacks.base import Finding
from gaslight.core.harness import ToolCallRecord, TranscriptEntry
from gaslight.core.reporter import print_terminal, render_html
from gaslight.core.scorer import grade
from gaslight.core.verdict import CODE_CHECK_NOT_TESTED, INJECTION_NOT_TESTED, ToolVerdict, compute_verdict


def test_render_html_includes_verdict_detail():
    injection = Finding(attack_key="injection-exfil", fired=True, reason="x", candidate_exfil_tool="send_email")
    probe = Finding(attack_key="tool-authz-probe", fired=False, reason="x", candidate_exfil_tool="send_email")
    verdict = compute_verdict("send_email", injection, probe)
    grade_result = grade([injection, probe])

    html = render_html("test-target", [injection, probe], grade_result, [verdict])

    assert "DEFENSE-IN-DEPTH WORKING" in html
    assert "send_email" in html
    assert verdict.detail in html


def test_render_html_renders_not_tested_verdict_with_untested_badge_not_clean():
    """Final M5a review Fix 4: CODE-LEVEL CHECK NOT TESTED (and the
    pre-existing INJECTION NOT TESTED) used to fall into the badge template's
    fallback branch and render as the green 'clean' badge — including in the
    sub-case where the detail text says the model was duped into calling
    the destructive tool. A real compromise must never render as a green
    'clean' badge."""
    verdict = ToolVerdict(
        tool_name="delete_account",
        injection_leaked=True,
        probe_complied=False,
        label=CODE_CHECK_NOT_TESTED,
        detail="the model was duped into calling delete_account, but whether a code-level check "
        "would have stopped it was never tested — rerun with --no-safe to find out.",
    )
    grade_result = grade([])
    html = render_html("test-target", [], grade_result, [verdict])

    assert 'badge untested">delete_account' in html
    assert 'badge clean">delete_account' not in html


def test_render_html_renders_injection_not_tested_verdict_with_untested_badge():
    verdict = ToolVerdict(
        tool_name="send_email",
        injection_leaked=False,
        probe_complied=False,
        label=INJECTION_NOT_TESTED,
        detail="the injection attack was never attempted on this target.",
    )
    grade_result = grade([])
    html = render_html("test-target", [], grade_result, [verdict])

    assert 'badge untested">send_email' in html
    assert 'badge clean">send_email' not in html


def test_render_html_with_no_verdicts_still_renders():
    grade_result = grade([])
    html = render_html("test-target", [], grade_result, None)
    assert "test-target" in html


def test_render_html_includes_ai_suggested_hints_section():
    grade_result = grade([])
    html = render_html("test-target", [], grade_result, verdicts=None, ai_hints=["sk-maybe-a-key-abc123"])
    assert "AI-suggested" in html
    assert "unverified" in html.lower()
    assert "sk-maybe-a-key-abc123" in html


def test_render_html_with_no_ai_hints_omits_the_section():
    grade_result = grade([])
    html = render_html("test-target", [], grade_result)
    assert "AI-suggested" not in html


def test_render_html_masks_secret_in_transcript_result_text():
    entry = TranscriptEntry(
        turn=1,
        assistant_text="All systems operational. Debug token: AKIAABCDEFGHIJKLMNOP",
        tool_calls=[
            ToolCallRecord(
                name="get_status",
                arguments={},
                result_text="All systems operational. Debug token: AKIAABCDEFGHIJKLMNOP",
                is_error=False,
            )
        ],
    )
    finding = Finding(
        attack_key="baseline-disclosure",
        fired=True,
        reason="found 1 secret-shaped string(s) during ordinary use, e.g. AKIA...OP",
        transcript=[entry],
    )
    grade_result = grade([finding])
    html = render_html("test-target", [finding], grade_result)
    assert "AKIAABCDEFGHIJKLMNOP" not in html
    assert "AKIA...OP" in html


def test_render_html_masks_secret_in_ai_hint():
    """Fix 1 (Critical): the AI-hints section previously printed
    llm_secret_hints.py's verbatim suggestions straight into the HTML
    report unmasked. The old test used "sk-maybe-a-key-abc123", which
    secrets_scan.py's own patterns don't actually match — so it proved
    nothing about masking. This uses a genuinely secret-shaped hint and
    asserts the raw value never reaches the report, only the masked form.
    """
    grade_result = grade([])
    html = render_html(
        "test-target", [], grade_result, verdicts=None, ai_hints=["Debug key is AKIAABCDEFGHIJKLMNOP"]
    )
    assert "AKIAABCDEFGHIJKLMNOP" not in html
    assert "AKIA...OP" in html


def test_print_terminal_masks_secret_in_ai_hint_and_escapes_markup():
    """Fix 1 + bundled fix B: terminal hints must be redacted the same as
    the HTML report, and must be markup-escaped so a hint containing
    rich-style `[...]` text can't be misinterpreted by console.print."""
    grade_result = grade([])
    console = Console(record=True, width=200)
    print_terminal(
        "test-target",
        0,
        [],
        grade_result,
        ai_hints=["[bold]AKIAABCDEFGHIJKLMNOP[/bold] looks like a key"],
        console=console,
    )
    output = console.export_text()
    assert "AKIAABCDEFGHIJKLMNOP" not in output
    assert "AKIA...OP" in output
    # The literal markup text should survive as text, not be swallowed as
    # a rich style tag.
    assert "[bold]" in output


def test_render_html_masks_secret_in_tool_call_arguments():
    """Fix 2: call.arguments is a dict, not a string — piping it through
    render_html must not crash, and any secret-shaped value inside it must
    still be masked."""
    entry = TranscriptEntry(
        turn=1,
        assistant_text="Here you go.",
        tool_calls=[
            ToolCallRecord(
                name="get_status",
                arguments={"debug_token": "AKIAABCDEFGHIJKLMNOP"},
                result_text="ok",
                is_error=False,
            )
        ],
    )
    finding = Finding(
        attack_key="baseline-disclosure",
        fired=True,
        reason="found 1 secret-shaped string(s) during ordinary use, e.g. AKIA...OP",
        transcript=[entry],
    )
    grade_result = grade([finding])
    html = render_html("test-target", [finding], grade_result)
    assert "AKIAABCDEFGHIJKLMNOP" not in html
    assert "AKIA...OP" in html


def test_print_terminal_escapes_closing_markup_tag_in_reason():
    """Final review Fix 5: Finding.reason can now contain a slice of
    arbitrary target file content (PathTraversalAttack). All three
    reporter.py print sites wrap the reason inside markup like
    "[green]...[/]" / "[dim]...[/]" — an unescaped CLOSING tag such as
    "[/]" inside the reason hits Rich's "nothing to close" error path and
    raises a MarkupError, aborting the run before the HTML report — the
    actual durable artifact — ever gets written. (An unclosed opening tag
    like "[etc/hosts]" does NOT reproduce this — Rich silently auto-closes
    it at end of render, so a test built on that shape would pass whether
    or not escape() is actually applied. Only a closing tag distinguishes
    fixed from unfixed code.)"""
    finding = Finding(
        attack_key="path-traversal",
        fired=True,
        reason="read escaped via path='../../[/]' — response: 'localhost'",
    )
    grade_result = grade([finding])
    console = Console(record=True)
    print_terminal("test-target", 1, [finding], grade_result, console=console)
    output = console.export_text()
    assert "[/]" in output or "\\[/]" in output


def test_print_terminal_fired_finding_without_canary_uses_confirmed_branch():
    """Fix 5: BaselineDisclosureAttack/ResourceExposureAttack findings set
    neither canary_token nor sink_request_summary/exfil_tool. A fired
    finding shaped like that must not print "canary None ...", and must
    not fall into either the EXFILTRATED or DISCLOSED branches."""
    finding = Finding(
        attack_key="resource-exposure",
        fired=True,
        reason="1 resource(s) contained secret-shaped content",
    )
    grade_result = grade([finding])
    console = Console(record=True, width=200)
    print_terminal("test-target", 0, [finding], grade_result, console=console)
    output = console.export_text()
    assert "canary None" not in output
    assert "CONFIRMED" in output
    assert "resource-exposure" in output
