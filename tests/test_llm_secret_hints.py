"""Unit tests for the optional LLM-assisted secret-triage layer. The
deterministic scanner (core/secrets_scan.py) is what decides pass/fail
everywhere in this codebase — this layer is supplementary only, and is
tested here with a small fake provider rather than ScriptedProvider
(which is purpose-built for attack simulation and always replies
"No tools to use." when given zero tools — the wrong tool for testing a
plain text-in/text-out classifier). See
docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.
"""

from gaslight.core.llm import LLMProvider, TurnResult
from gaslight.core.llm_secret_hints import suggest_possible_secrets


class _FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, reply_text: str) -> None:
        self._reply_text = reply_text

    def new_history(self, system, user_message):
        return {}

    async def run_turn(self, history, tools):
        return TurnResult(text=self._reply_text, tool_calls=[], stop_reason="end_turn")

    def append_tool_results(self, history, results):
        return history


async def test_suggest_possible_secrets_parses_one_per_line():
    provider = _FakeProvider("sk-fake-suspicious-value\nanother-suspicious-token")
    hits = await suggest_possible_secrets(provider, "some text")
    assert hits == ["sk-fake-suspicious-value", "another-suspicious-token"]


async def test_suggest_possible_secrets_none_reply_returns_empty():
    provider = _FakeProvider("NONE")
    hits = await suggest_possible_secrets(provider, "some text")
    assert hits == []


async def test_suggest_possible_secrets_empty_text_short_circuits():
    provider = _FakeProvider("should never be called")
    hits = await suggest_possible_secrets(provider, "   ")
    assert hits == []
