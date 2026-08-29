"""The live scan view — a horizontal pipeline of the five security phases that
redraws in place as the run advances, so the user watches it move step to step
instead of scrolling a wall of output.

Deliberately a PURE state → renderable unit (council: Naval): you feed it phase
and check state, call `render()` for a Rich renderable, and it holds no console
and no timing of its own. That makes it render-to-string testable and reusable
(the same five-node model can later head the HTML report or a screenshot).

The live overlay is transient — never the record. The caller shows it only on a
real TTY and prints the persistent grade / gauges / findings afterwards; on a
pipe, in CI, or under --json it skips the Live view and the findings still print.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Group, RenderableType
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# Check states. A phase is "breached" if any check fired, "done" once every
# check has resolved with none fired, "now" while it's the active phase, else
# "pending".
PENDING, RUNNING, PASS, FAIL, SKIP = "pending", "running", "pass", "fail", "skip"

# Node glyphs + colors by phase state. Breach is loud and red — the one thing a
# user scanning the bar must never miss (council: Tufte — encode state, not motion).
_NODE = {
    "done": ("●", "green"),
    "breached": ("●", "bold red"),
    "now": ("◉", "bold cyan"),
    "pending": ("○", "grey42"),
}
_CONNECTOR = {"done": "green", "breached": "red", "now": "grey42", "pending": "grey42"}

_CHECK_GLYPH = {PASS: ("✓", "green"), FAIL: ("✗", "bold red"), SKIP: ("–", "grey42")}


@dataclass
class _Check:
    name: str
    what: str = ""
    state: str = PENDING
    result: str = ""


@dataclass
class _Phase:
    name: str
    checks: list[_Check] = field(default_factory=list)


class RunView:
    def __init__(self, target_label: str, tool_count: int, phases: list[tuple[str, list[str]]]):
        """`phases` is [(phase_name, [check_display_name, …]), …] — the same
        grouping the run loop uses, so the bar mirrors the report's gauges."""
        self.target_label = target_label
        self.tool_count = tool_count
        self.phases = [_Phase(name, [_Check(c) for c in checks]) for name, checks in phases]
        self._current = -1  # nothing active until start_phase(0)

    # -- state transitions the run loop drives --------------------------------

    def start_phase(self, phase_idx: int) -> None:
        self._current = phase_idx

    def start_check(self, phase_idx: int, name: str, what: str = "") -> None:
        check = self._find(phase_idx, name)
        if check:
            check.state = RUNNING
            check.what = what or check.what

    def finish_check(self, phase_idx: int, name: str, *, fired: bool, attempted: bool, result: str = "") -> None:
        check = self._find(phase_idx, name)
        if not check:
            return
        check.state = FAIL if fired else (PASS if attempted else SKIP)
        check.result = result

    def _find(self, phase_idx: int, name: str) -> _Check | None:
        if 0 <= phase_idx < len(self.phases):
            for check in self.phases[phase_idx].checks:
                if check.name == name:
                    return check
        return None

    # -- derived state --------------------------------------------------------

    def _phase_state(self, idx: int) -> str:
        phase = self.phases[idx]
        if any(c.state == FAIL for c in phase.checks):
            return "breached"
        resolved = all(c.state in (PASS, FAIL, SKIP) for c in phase.checks)
        if resolved and idx == self._current and idx == len(self.phases) - 1:
            return "done"
        if idx == self._current:
            return "now"
        if idx < self._current:
            return "done"
        return "pending"

    # -- rendering ------------------------------------------------------------

    def _pipeline_line(self) -> Text:
        line = Text()
        for idx, phase in enumerate(self.phases):
            state = self._phase_state(idx)
            glyph, colour = _NODE[state]
            if idx:
                prev = self._phase_state(idx - 1)
                line.append(" ── ", style=_CONNECTOR[prev])
            line.append(glyph, style=colour)
            line.append(" ")
            label_style = colour if state in ("now", "breached") else ("green" if state == "done" else "grey42")
            line.append(phase.name, style=label_style)
        return line

    def _current_block(self) -> RenderableType:
        if not (0 <= self._current < len(self.phases)):
            return Text("")
        phase = self.phases[self._current]
        table = Table.grid(padding=(0, 2))
        table.add_column(no_wrap=True)  # glyph / spinner
        table.add_column(no_wrap=True)  # check name
        table.add_column()             # result
        for check in phase.checks:
            if check.state == RUNNING:
                table.add_row(Spinner("dots", style="cyan"), Text(check.name), Text("testing…", style="dim"))
            elif check.state in (PASS, FAIL, SKIP):
                glyph, colour = _CHECK_GLYPH[check.state]
                table.add_row(Text(glyph, style=colour), Text(check.name), Text(check.result or "", style="dim"))
            else:
                table.add_row(Text("·", style="grey30"), Text(check.name, style="grey42"), Text(""))
        what = self._active_what(phase)
        header = Text(phase.name, style="bold")
        if what:
            header.append(f"  —  {what}", style="dim")
        return Group(header, table)

    @staticmethod
    def _active_what(phase: _Phase) -> str:
        for check in phase.checks:
            if check.state == RUNNING and check.what:
                return check.what
        return ""

    def _header(self) -> Text:
        head = Text()
        head.append("gaslight", style="bold")
        head.append(f"  ·  {self.target_label}  ·  {self.tool_count} tool(s)", style="dim")
        return head

    def render(self) -> RenderableType:
        """The live frame: header, the pipeline bar, and the current phase's
        checks streaming below it."""
        return Group(self._header(), Text(""), self._pipeline_line(), Text(""), self._current_block())

    def render_bar(self) -> RenderableType:
        """Just the settled pipeline bar — printed once after the run so the
        visual result persists in scrollback above the detailed report."""
        return Group(self._header(), Text(""), self._pipeline_line())

    def render_str(self, width: int = 80) -> str:
        """Render to plain text — used by tests to assert on state without a TTY."""
        from rich.console import Console

        console = Console(width=width, file=None, record=True, no_color=True)
        console.print(self.render())
        return console.export_text()
