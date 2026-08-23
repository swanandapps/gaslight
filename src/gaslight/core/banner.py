"""The launch banner — a fire-gradient "gaslight" wordmark shown once at
startup, the way a good CLI introduces itself. Purely cosmetic: only printed to
an interactive terminal (never in --json or a pipe), and narrow terminals fall
back to a one-line mark.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

# ansi_shadow figlet wordmark, embedded verbatim so there is no runtime figlet
# dependency. Six rows; each row is tinted a step along a flame gradient.
_WORDMARK = [
    ' ██████╗  █████╗ ███████╗██╗     ██╗ ██████╗ ██╗  ██╗████████╗',
    '██╔════╝ ██╔══██╗██╔════╝██║     ██║██╔════╝ ██║  ██║╚══██╔══╝',
    '██║  ███╗███████║███████╗██║     ██║██║  ███╗███████║   ██║   ',
    '██║   ██║██╔══██║╚════██║██║     ██║██║   ██║██╔══██║   ██║   ',
    '╚██████╔╝██║  ██║███████║███████╗██║╚██████╔╝██║  ██║   ██║   ',
    ' ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ',
]

# Top-to-bottom flame: bright yellow core cooling to deep ember red — the "light"
# of a gas flame.
_FLAME = ["#FFE066", "#FFC24A", "#FF9E33", "#FF7A1F", "#FF5714", "#E8380D"]

TAGLINE = "automated penetration testing for AI agents"

# Widest wordmark row (display columns); below this we use the compact fallback.
_MIN_WIDTH = 62


def print_banner(console: Console) -> None:
    console.print()
    if console.width < _MIN_WIDTH:
        console.print(Text("gaslight", style="bold #FF7A1F"))
        console.print(f"[dim]{TAGLINE}[/]")
        console.print()
        return
    for i, row in enumerate(_WORDMARK):
        console.print(Text(row, style=f"bold {_FLAME[min(i, len(_FLAME) - 1)]}"))
    console.print(f"[dim]   {TAGLINE}[/]")
    console.print()
