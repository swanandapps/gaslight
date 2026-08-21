"""The victim-harness LLM: whichever model plays the agent being attacked.

Provider-agnostic by design — the promise in the README is `gaslight ./my-
agent` with zero config, and a user whose only key is OpenAI's shouldn't
bounce off a Claude-only tool during the one moment that's supposed to sell
them on it. `LLMProvider` is the seam: the harness and every attack module
only ever see `ToolSpec` / `ToolCall` / `TurnResult`, never a provider's
native message shape.

Conversation history is kept as an opaque, provider-owned object. Trying to
force one wire format across providers is how these adapters rot; instead
each provider appends to its own history and the harness never looks inside.

V1 ships two real backends: Anthropic (default when both keys are present —
reach + cost make Haiku 4.5 the right default for a loop that just needs to
*drive* an agent, not reason deeply) and OpenAI (auto-selected when only
OPENAI_API_KEY is set). Same interface, same harness, same attack module —
the victim's "sophistication" is a provider swap, not a different target.

`ScriptedProvider` is not a stand-in for a real model in production use — it
is a deterministic double for testing the rest of the pipeline (attack
plumbing, canary/sink detection, false-positive guard) without an API key or
network access. It must never be auto-selected; only an explicit `--llm
scripted` picks it.
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import anthropic
import openai

from gaslight.core.schema import find_address_field, find_string_field


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class ToolResultMessage:
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class TurnResult:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str


class NoProviderAvailable(RuntimeError):
    pass


class LLMProvider(ABC):
    """One model turn at a time, driven by the harness's agent loop."""

    name: str

    @abstractmethod
    def new_history(self, system: str, user_message: str) -> Any:
        """Start a fresh conversation; returns a provider-owned history object."""

    @abstractmethod
    async def run_turn(self, history: Any, tools: list[ToolSpec]) -> TurnResult:
        """Ask the model for its next move given the history and available tools."""

    @abstractmethod
    def append_tool_results(self, history: Any, results: list[ToolResultMessage]) -> Any:
        """Fold tool results back into history ahead of the next `run_turn`."""


# ---------------------------------------------------------------------------
# Anthropic (default)
# ---------------------------------------------------------------------------


@dataclass
class _AnthropicHistory:
    system: str
    messages: list[dict[str, Any]] = field(default_factory=list)


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str = "claude-haiku-4-5", max_tokens: int = 4096) -> None:
        self._client = anthropic.AsyncAnthropic()
        self._model = model
        self._max_tokens = max_tokens

    def new_history(self, system: str, user_message: str) -> _AnthropicHistory:
        return _AnthropicHistory(system=system, messages=[{"role": "user", "content": user_message}])

    async def run_turn(self, history: _AnthropicHistory, tools: list[ToolSpec]) -> TurnResult:
        tool_payload = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in tools
        ]
        kwargs: dict[str, Any] = dict(
            model=self._model,
            max_tokens=self._max_tokens,
            system=history.system,
            messages=history.messages,
        )
        if tool_payload:
            kwargs["tools"] = tool_payload

        response = await self._client.messages.create(**kwargs)

        # Anthropic requires the full assistant turn (all content blocks,
        # including tool_use) echoed back verbatim before the next request.
        history.messages.append({"role": "assistant", "content": response.content})

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, input=block.input))

        return TurnResult(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason or "end_turn",
        )

    def append_tool_results(
        self, history: _AnthropicHistory, results: list[ToolResultMessage]
    ) -> _AnthropicHistory:
        history.messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": r.tool_call_id,
                        "content": r.content,
                        "is_error": r.is_error,
                    }
                    for r in results
                ],
            }
        )
        return history


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------


@dataclass
class _OpenAIHistory:
    messages: list[dict[str, Any]] = field(default_factory=list)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        max_tokens: int = 4096,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        # base_url/api_key let this same provider drive an OpenAI-compatible
        # local server (Ollama) as well as the hosted API — see detect_provider.
        client_kwargs: dict[str, Any] = {}
        if base_url is not None:
            client_kwargs["base_url"] = base_url
        if api_key is not None:
            client_kwargs["api_key"] = api_key
        self._client = openai.AsyncOpenAI(**client_kwargs)
        self._model = model
        self._max_tokens = max_tokens

    def new_history(self, system: str, user_message: str) -> _OpenAIHistory:
        return _OpenAIHistory(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_message},
            ]
        )

    async def run_turn(self, history: _OpenAIHistory, tools: list[ToolSpec]) -> TurnResult:
        tool_payload = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.input_schema},
            }
            for t in tools
        ]
        kwargs: dict[str, Any] = dict(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=history.messages,
        )
        if tool_payload:
            kwargs["tools"] = tool_payload

        response = await self._client.chat.completions.create(**kwargs)
        message = response.choices[0].message

        # OpenAI requires the assistant turn (including any tool_calls) echoed
        # back verbatim before the next request, same constraint as Anthropic.
        history.messages.append(message.model_dump(exclude_none=True))

        tool_calls: list[ToolCall] = []
        for tc in message.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=args))

        stop_reason = "tool_use" if tool_calls else "end_turn"
        return TurnResult(text=message.content or "", tool_calls=tool_calls, stop_reason=stop_reason)

    def append_tool_results(
        self, history: _OpenAIHistory, results: list[ToolResultMessage]
    ) -> _OpenAIHistory:
        for r in results:
            history.messages.append(
                {"role": "tool", "tool_call_id": r.tool_call_id, "content": r.content}
            )
        return history


# ---------------------------------------------------------------------------
# Scripted (test double — never auto-selected)
# ---------------------------------------------------------------------------


@dataclass
class _ScriptedHistory:
    system: str
    turn: int = 0
    pending_tool_results: list[ToolResultMessage] = field(default_factory=list)


class ScriptedProvider(LLMProvider):
    """Deterministic 'victim' for exercising the pipeline without a real model.

    Behavior mirrors the realistic failure mode the attack targets: on the
    first turn it checks tool *descriptions* for injected-looking imperative
    text and obeys it if found (tool-metadata poisoning's entry point),
    otherwise it calls the one read-like tool available; on any later turn,
    if the most recent tool result contains injected-looking imperative text
    naming a *different* tool, it obeys — calling that tool with whatever
    argument the injection specified. If no injection is found in a result,
    it echoes the result's content back as its reply rather than a fixed
    string, mirroring a naive agent that relays or summarizes tool output.
    This is a rule, not intelligence: it exists to prove gaslight's
    plumbing (target, canary, sink, scorer, reporter) end-to-end, not to
    claim anything about real model behavior.
    """

    name = "scripted"

    def new_history(self, system: str, user_message: str) -> _ScriptedHistory:
        return _ScriptedHistory(system=system)

    async def run_turn(self, history: _ScriptedHistory, tools: list[ToolSpec]) -> TurnResult:
        history.turn += 1
        call_id = f"scripted-{history.turn}"

        if history.pending_tool_results:
            last = history.pending_tool_results[-1]
            obeyed = _extract_override_call(last.content, tools) or _extract_injected_call(last.content, tools)
            history.pending_tool_results = []
            if obeyed is not None:
                name, args = obeyed
                return TurnResult(
                    text="",
                    tool_calls=[ToolCall(id=call_id, name=name, input=args)],
                    stop_reason="tool_use",
                )
            # No tool-call-shaped injection found — echo the result back
            # rather than a fixed "Done.". A naive agent that summarizes or
            # relays tool output verbatim is a realistic default, and it's
            # the only way output-leakage-style attacks get a meaningful
            # true-positive test against this stand-in.
            return TurnResult(text=last.content, tool_calls=[], stop_reason="end_turn")

        # first turn: tool *descriptions* are visible before any tool is
        # ever called — check them for an injected-looking instruction
        # first (tool-metadata poisoning's entry point), then fall back to
        # calling the first read-shaped tool.
        descriptions_text = " ".join(t.description for t in tools if t.description)
        obeyed = _extract_injected_call(descriptions_text, tools)
        if obeyed is not None:
            name, args = obeyed
            return TurnResult(
                text="",
                tool_calls=[ToolCall(id=call_id, name=name, input=args)],
                stop_reason="tool_use",
            )

        read_tool = next((t for t in tools if _looks_like_reader(t.name)), None)
        if read_tool is None:
            return TurnResult(text="No tools to use.", tool_calls=[], stop_reason="end_turn")
        return TurnResult(
            text="",
            tool_calls=[ToolCall(id=call_id, name=read_tool.name, input={})],
            stop_reason="tool_use",
        )

    def append_tool_results(
        self, history: _ScriptedHistory, results: list[ToolResultMessage]
    ) -> _ScriptedHistory:
        history.pending_tool_results = list(results)
        return history


def _looks_like_reader(tool_name: str) -> bool:
    return any(k in tool_name.lower() for k in ("read", "get", "fetch", "list", "search"))


_CANARY_PATTERN = re.compile(r"canary-[0-9a-f]+", re.IGNORECASE)


def _extract_injected_call(text: str, tools: list[ToolSpec]) -> tuple[str, dict[str, Any]] | None:
    """Very small heuristic: does this text name a tool we have, an address
    to send to, and a reference code to carry along? Matches the shape of
    every injection payload the exfil attack module plants (see
    attacks/injection_exfil.py and core/schema.py) — not a general-purpose
    parser, and deliberately not one: this exists to exercise the pipeline,
    not to simulate real model reasoning.

    The address pattern is built from whatever field name
    `find_address_field` actually discovers on the tool's own schema,
    rather than a hardcoded word list — injection_exfil.py always writes
    the payload as literal `{address_field}={value}`, so this always
    matches regardless of which field name core/schema.py's
    ADDRESS_FIELD_PRIORITY was extended with (e.g. "destination",
    "webhook_url"), with no need to keep a second list in sync here.
    """
    for tool in tools:
        if tool.name.lower() not in text.lower():
            continue

        args: dict[str, Any] = {}

        address_field = find_address_field(tool.input_schema)
        if address_field:
            addr_pattern = re.compile(rf"{re.escape(address_field)}\s*[:=]\s*(\S+)", re.IGNORECASE)
            addr_match = addr_pattern.search(text)
            if addr_match:
                args[address_field] = addr_match.group(1).strip(".,)\"'")

        content_field = find_string_field(tool.input_schema)
        canary_match = _CANARY_PATTERN.search(text)
        if content_field and canary_match:
            args[content_field] = f"reference code: {canary_match.group(0)}"

        if args:
            return tool.name, args
    return None


_OVERRIDE_TRIGGER_PHRASES = (
    "pre-approved",
    "no confirmation needed",
    "no further confirmation",
    "already confirmed",
    "ignore previous instructions",
    "ignore the above",
    "new instructions",
)


def _extract_override_call(text: str, tools: list[ToolSpec]) -> tuple[str, dict[str, Any]] | None:
    """Recognizes a fake instruction-hierarchy override attempt — distinct
    from _extract_injected_call's exfil-shaped payloads: no address field,
    no canary-carrying content field required, just a trigger phrase plus a
    named tool. Matches the payload shape attacks/instruction_override.py
    plants. Calling with no args is deliberate: whether a destructive tool
    gets called at all is the finding, not what argument it's called with —
    unlike exfiltration, there's nowhere for the "damage" to need routing."""
    lowered = text.lower()
    if not any(phrase in lowered for phrase in _OVERRIDE_TRIGGER_PHRASES):
        return None
    for tool in tools:
        if tool.name.lower() in lowered:
            return tool.name, {}
    return None


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


# A local, OpenAI-compatible model server (Ollama). Free, offline, and nothing
# leaves the machine — the right default for a security tool that reads a
# target's tool schemas and replies. Overridable by env for a non-default host
# or model.
_OLLAMA_DEFAULT_URL = "http://localhost:11434/v1"
_OLLAMA_DEFAULT_MODEL = "qwen2.5:3b"


def detect_provider(explicit: str | None = None) -> LLMProvider:
    """Resolve the model that powers the OPTIONAL LLM layer. Honors an explicit
    choice; otherwise uses the first provider whose credentials are present.

    Crucially, when nothing is configured this does NOT raise — it falls back
    to the deterministic ScriptedProvider. gaslight's 17 attacks need no
    model at all; the LLM layer only enriches. A user with no key and no local
    model still gets a full deterministic run, never an error.
    """
    if explicit == "scripted":
        return ScriptedProvider()
    if explicit == "ollama":
        return OpenAIProvider(
            model=os.environ.get("GASLIGHT_OLLAMA_MODEL", _OLLAMA_DEFAULT_MODEL),
            base_url=os.environ.get("GASLIGHT_OLLAMA_URL", _OLLAMA_DEFAULT_URL),
            api_key="ollama",  # a local server ignores it, but the client requires one
        )
    # An EXPLICIT hosted-provider choice with no key must fail with a clean
    # message here — the SDK client otherwise raises its own error at
    # construction, which the CLI surfaces as a raw traceback.
    if explicit == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise NoProviderAvailable(
                "--llm anthropic needs ANTHROPIC_API_KEY set. Set it, use --llm ollama (free, local), "
                "or drop --llm to run the deterministic core."
            )
        return AnthropicProvider()
    if explicit == "openai":
        if not os.environ.get("OPENAI_API_KEY"):
            raise NoProviderAvailable(
                "--llm openai needs OPENAI_API_KEY set. Set it, use --llm ollama (free, local), "
                "or drop --llm to run the deterministic core."
            )
        return OpenAIProvider()
    if explicit is None and os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicProvider()
    if explicit is None and os.environ.get("OPENAI_API_KEY"):
        return OpenAIProvider()
    if explicit is not None:
        raise NoProviderAvailable(f"unknown or unavailable provider: {explicit}")
    # No explicit choice and no credentials: deterministic core, not an error.
    return ScriptedProvider()


def llm_is_active(provider: LLMProvider) -> bool:
    """True when a real model backs the optional LLM layer. ScriptedProvider is
    the deterministic fallback — present so the pipeline runs, not a model."""
    return getattr(provider, "name", None) != "scripted"
