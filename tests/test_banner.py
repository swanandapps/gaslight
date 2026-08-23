"""The launch banner — cosmetic, but it should render without error and adapt to
terminal width."""

from rich.console import Console

from gaslight.core.banner import TAGLINE, print_banner


def _render(width: int) -> str:
    console = Console(force_terminal=True, width=width, record=True, color_system=None)
    print_banner(console)
    return console.export_text()


def test_wide_banner_renders_wordmark_and_tagline():
    out = _render(90)
    assert "█" in out  # the block wordmark
    assert TAGLINE in out


def test_narrow_terminal_falls_back_to_one_line():
    out = _render(40)
    assert "█" not in out  # no giant wordmark on a narrow pane
    assert "gaslight" in out
    assert "penetration" in out  # tagline present (may soft-wrap at this width)
