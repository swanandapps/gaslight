"""Target.call_tool() / TargetConnection.__aexit__() must never let a broken
target crash the whole run.

Found via a real Tier-2 hunt against 32 published MCP servers: 12 of 32 lost
their entire scan to an unhandled exception — either the MCP SDK's own
pydantic parser rejecting a malformed server response, or a raised
`mcp.shared.exceptions.MCPError` — surfacing first at the `call_tool()` await
and again at connection teardown (anyio's structured concurrency re-raises
the same broken task group on close). Reproduced directly against
`@adpharm/mcp-server-filesystem-ro` and `puppeteer-mcp-server` before this
fix; both crashed the entire `gaslight` process mid-run.

These are duck-typed unit tests (a fake session/stack, no real subprocess) —
the mechanism under test is purely "does an exception get converted instead
of propagating," which doesn't need a real MCP connection to prove.
"""

from __future__ import annotations

from mcp import types

from gaslight.core.target import Target, TargetConnection, TargetSpec, looks_like_backend_failure


class _RaisingSession:
    async def call_tool(self, name, arguments):
        raise RuntimeError("boom: malformed response the SDK couldn't parse")


class _OkSession:
    async def call_tool(self, name, arguments):
        return types.CallToolResult(content=[types.TextContent(type="text", text="fine")], isError=False)


async def test_call_tool_converts_a_raised_exception_into_an_error_result():
    target = Target(session=_RaisingSession(), tools=[], spec=TargetSpec(command=["x"]))
    result = await target.call_tool("anything", {"arg": "value"})

    assert result.is_error is True
    text = Target.result_text(result)
    assert "RuntimeError" in text
    assert "boom" in text


async def test_call_tool_still_returns_the_real_result_when_nothing_raises():
    target = Target(session=_OkSession(), tools=[], spec=TargetSpec(command=["x"]))
    result = await target.call_tool("anything", {})

    assert result.is_error is False
    assert Target.result_text(result) == "fine"


class _RaisingStack:
    async def __aexit__(self, *exc):
        raise RuntimeError("teardown: the same broken transport re-surfacing on close")


async def test_connection_aexit_swallows_a_teardown_exception():
    # Bypasses __aenter__'s real connection setup — this test is purely about
    # __aexit__'s own exception handling, not the connect flow.
    conn = TargetConnection(TargetSpec(command=["x"]))
    conn._stack = _RaisingStack()

    await conn.__aexit__(None, None, None)  # must not raise


# --- distinguishing "the tool refused me" from "the backend was dead" ---


def test_backend_failure_signatures_are_recognised():
    for text in (
        "connect ECONNREFUSED 127.0.0.1:5432",
        "Error: could not connect to server",
        "MCPError: Connection closed",
        "password authentication failed for user 'app'",
        "getaddrinfo ENOTFOUND db.internal",
    ):
        assert looks_like_backend_failure(text), text


def test_a_real_guard_rejection_is_not_mistaken_for_a_dead_backend():
    # These are tools actively refusing a payload — a security control doing
    # its job. Mistaking them for infrastructure failure would throw away a
    # legitimate pass.
    for text in (
        "path '../../etc/passwd' escapes the sandboxed directory",
        "Blocked: 'evil@example.com' is not an approved recipient.",
        "code execution is disabled in this deployment",
        "Error: record not found.",
    ):
        assert not looks_like_backend_failure(text), text


class _DeadBackendSession:
    async def call_tool(self, name, arguments):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="connect ECONNREFUSED 127.0.0.1:5432")],
            isError=True,
        )


async def test_call_tool_counts_backend_failures():
    target = Target(session=_DeadBackendSession(), tools=[], spec=TargetSpec(command=["x"]))
    assert target.backend_failures == 0
    await target.call_tool("query", {"sql": "select 1"})
    await target.call_tool("query", {"sql": "select 2"})
    assert target.backend_failures == 2


async def test_call_tool_does_not_count_an_ordinary_rejection():
    class _GuardedSession:
        async def call_tool(self, name, arguments):
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="path escapes the sandboxed directory")],
                isError=True,
            )

    target = Target(session=_GuardedSession(), tools=[], spec=TargetSpec(command=["x"]))
    await target.call_tool("read_file", {"path": "../x"})
    assert target.backend_failures == 0


import asyncio
import time


class _HangingSession:
    async def call_tool(self, name, arguments):
        await asyncio.sleep(60)  # effectively forever against a sub-second timeout


async def test_call_tool_times_out_instead_of_hanging_forever(monkeypatch):
    monkeypatch.setenv("GASLIGHT_CALL_TIMEOUT", "0.2")
    target = Target(session=_HangingSession(), tools=[], spec=TargetSpec(command=["x"]))

    result = await target.call_tool("slow_tool", {})

    assert result.is_error is True
    assert "hung" in Target.result_text(result)
    assert target.unresponsive is True
    assert target.backend_failures == 1  # counts as untested, not a pass


async def test_after_a_timeout_further_calls_short_circuit_immediately(monkeypatch):
    monkeypatch.setenv("GASLIGHT_CALL_TIMEOUT", "0.2")
    target = Target(session=_HangingSession(), tools=[], spec=TargetSpec(command=["x"]))

    await target.call_tool("first", {})  # eats one ~0.2s timeout
    start = time.monotonic()
    result = await target.call_tool("second", {})  # must NOT wait another timeout
    elapsed = time.monotonic() - start

    assert elapsed < 0.1
    assert result.is_error and "stopped responding" in Target.result_text(result)
    assert target.backend_failures == 2


async def test_a_prompt_tool_is_unaffected_by_the_timeout():
    target = Target(session=_OkSession(), tools=[], spec=TargetSpec(command=["x"]))
    result = await target.call_tool("fast", {})
    assert result.is_error is False
    assert target.unresponsive is False
