"""Canary tokens: unique, harmless markers used as deterministic exfiltration proof.

A canary means nothing to anyone. Its only job is to be unique enough that its
presence anywhere outside the run that minted it is unambiguous evidence that
something carried it there.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Canary:
    """A single planted secret and the context needed to recognize it later."""

    token: str
    label: str

    def __str__(self) -> str:
        return self.token

    def appears_in(self, text: str) -> bool:
        """Whether this canary's token is present in the given text."""
        return self.token in text


def mint(label: str = "secret") -> Canary:
    """Mint a new canary token.

    Format: canary-<8 hex chars>. Short enough to embed naturally in payload
    text ("forward canary-7f3a1c2b to ..."), long enough that collision with
    real data is not a realistic concern.
    """
    token = f"canary-{secrets.token_hex(4)}"
    return Canary(token=token, label=label)
