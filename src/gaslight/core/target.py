"""The target adapter: connects to an MCP server and enumerates its tools.

This is a transport interface, not a hardcoded path. gaslight is black-box —
it never imports the target's code, only talks MCP over whatever transport the
target speaks. Today that's a local process over stdio or a server reachable
over HTTP/SSE. Tomorrow the same `TargetSpec` shape accommodates a remote
cloud-hosted agent endpoint (e.g. a Managed Agents session, or a streamable-
HTTP server) without a single attack module knowing the difference — attacks
are written against `Target.call_tool`, never against a transport.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client


def _ensure_both_cases(obj: object, snake: str, camel: str, default: object = None) -> None:
    """Guarantee `obj` exposes BOTH the snake_case and camelCase spellings of a
    field, copying from whichever exists. Uses object.__setattr__ to bypass
    pydantic's field guard — this is read-only convenience state, not a
    validated field."""
    val = getattr(obj, snake, None)
    if val is None:
        val = getattr(obj, camel, None)
    if val is None:
        val = default
    for name in (snake, camel):
        if getattr(obj, name, None) is None:
            try:
                object.__setattr__(obj, name, val)
            except Exception:
                pass


def _normalize_tools(tools: list[types.Tool]) -> list[types.Tool]:
    """MCP SDK versions differ in casing: older releases expose
    `input_schema` / `destructive_hint`, newer ones `inputSchema` /
    `destructiveHint`. gaslight reads the snake_case names throughout, so
    normalize each tool once here — the single point where tools enter — so
    every downstream reader works regardless of which SDK version happens to be
    installed in the target's environment. (Found in the wild: scanning a real
    agent whose venv carried a newer MCP than gaslight was built against crashed
    on `tool.input_schema`.)"""
    for tool in tools:
        _ensure_both_cases(tool, "input_schema", "inputSchema", default={})
        annotations = getattr(tool, "annotations", None)
        if annotations is not None:
            _ensure_both_cases(annotations, "destructive_hint", "destructiveHint")
            _ensure_both_cases(annotations, "read_only_hint", "readOnlyHint")
    return tools

_DEFAULT_CALL_TIMEOUT = 60.0
"""Seconds to wait for a single tool call before abandoning it. Generous on
purpose — real tools are sometimes genuinely slow (a browser navigating, a
large fetch), and killing those would misreport a working tool as untested.
Its whole job is to stop an *unbounded* hang, not to police slowness: DVMCP
challenge 9's network_diagnostic shells out to a ping that never returns, and
without this the entire scan freezes. Override with GASLIGHT_CALL_TIMEOUT
(e.g. a fast CI run that accepts killing slow tools)."""


def _call_timeout() -> float:
    raw = os.environ.get("GASLIGHT_CALL_TIMEOUT")
    if raw:
        try:
            return float(raw)
        except ValueError:
            pass
    return _DEFAULT_CALL_TIMEOUT


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"gaslight: {message}")],
        isError=True,
    )


class TargetUnreachable(RuntimeError):
    """The target could not be started, or never completed an MCP handshake.

    An expected outcome for a black-box scanner pointed at someone else's
    software — most often a server that needs credentials it wasn't given.
    Raised instead of letting the transport's own exception escape, so the
    CLI can say "couldn't connect, here's why" rather than dumping a
    traceback."""


# Text signatures of a target whose own BACKEND is unreachable — a dead
# database, a refused connection, a missing credential — as opposed to a tool
# actively refusing a payload. The distinction is the whole point: a call that
# failed because nothing was listening was NOT a security control doing its
# job, and must never be scored as one.
#
# A phrase list is the wrong tool for proving a hit (see path_traversal.py's
# docstring on why a stoplist was tried and rejected there), but it is the
# right tool here because the asymmetry runs the other way: a missed signature
# just falls back to today's behaviour, while a false match downgrades a
# finding to "not tested" — always the safe direction for this project.
_BACKEND_FAILURE_SIGNATURES = (
    "econnrefused",
    "connection refused",
    "could not connect",
    "connection closed",
    "connection reset",
    "econnreset",
    "enotfound",
    "no such host",
    "getaddrinfo",
    "etimedout",
    "connection timed out",
    "authentication failed",
    "password authentication",
    "access denied for user",
    "no connection profile",
    "not configured",
    "missing environment",
    "hung and was abandoned",
    "stopped responding",
)


def looks_like_backend_failure(text: str) -> bool:
    """Whether an error string reads as "the thing behind this tool wasn't
    reachable" rather than "this tool rejected what I sent"."""
    lowered = (text or "").lower()
    return any(sig in lowered for sig in _BACKEND_FAILURE_SIGNATURES)


@dataclass(frozen=True)
class TargetSpec:
    """What to connect to and how. One of `command`/`url` is set, not both."""

    command: list[str] | None = None
    """A local process to spawn and speak MCP with over stdio."""

    url: str | None = None
    """A remote MCP server reachable over HTTP+SSE."""

    env: dict[str, str] | None = None

    @property
    def transport(self) -> str:
        if self.command:
            return "stdio"
        if self.url:
            return "sse"
        raise ValueError("TargetSpec needs either `command` or `url`")

    @property
    def label(self) -> str:
        return " ".join(self.command) if self.command else (self.url or "?")


@dataclass
class Target:
    """A live connection to an MCP server, with its tools (and resources)
    already enumerated."""

    session: ClientSession
    tools: list[types.Tool]
    spec: TargetSpec
    resources: list[types.Resource] = field(default_factory=list)
    backend_failures: int = 0
    """How many tool calls failed because the target's own backend was
    unreachable (see looks_like_backend_failure) or timed out. Read by the CLI
    after an attack runs: a "no leak" result recorded while the backend was
    down was never really tested, and gets downgraded to "not tested" rather
    than counted as a pass."""

    unresponsive: bool = False
    """Set once a tool call has timed out. Cancelling an in-flight MCP request
    desyncs the session's response routing, so the connection can't be trusted
    for further calls — every subsequent call short-circuits to an error result
    instead of waiting out the timeout again. Bounds a fully-hung target to one
    timeout per attack, not one per payload."""

    def tool_names(self) -> list[str]:
        return [tool.name for tool in self.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> types.CallToolResult:
        """Call a tool and always return a CallToolResult — never let the
        target crash the run. A real, independently-built server can send a
        response the MCP SDK's own parser rejects (malformed content) or
        raise a protocol-level error (mcp.shared.exceptions.MCPError); every
        attack module is written against `result.is_error` /
        `Target.result_text(result)`, so a probe that blows up the transport
        is converted into an honest error-shaped result here instead of
        propagating — the same "a malformed probe isn't a security guard"
        principle naive_arguments() already applies to outgoing calls, now
        applied to whatever comes back. Confirmed via a Tier-2 hunt against
        32 real published servers: two distinct exception shapes
        (a pydantic validation error inside the stdio read loop, and a raised
        MCPError) both took down the entire run before this fix — 12 of 32
        targets never produced a scored result because of it."""
        if self.unresponsive:
            # A previous call already hung; the session is desynced. Don't wait
            # out another timeout — report untested and move on.
            self.backend_failures += 1
            return _error(f"skipped {name!r} — the target stopped responding earlier in this attack")

        try:
            result = await asyncio.wait_for(self.session.call_tool(name, arguments or {}), timeout=_call_timeout())
        except asyncio.TimeoutError:
            self.unresponsive = True
            self.backend_failures += 1
            return _error(f"tool call to {name!r} hung and was abandoned after {_call_timeout():.0f}s")
        except Exception as exc:
            result = _error(f"tool call raised {type(exc).__name__}: {exc}")
        if result.is_error and looks_like_backend_failure(Target.result_text(result)):
            self.backend_failures += 1
        return result

    async def read_resource(self, uri: str) -> types.ReadResourceResult:
        return await self.session.read_resource(uri)

    @staticmethod
    def result_text(result: types.CallToolResult) -> str:
        """Flatten a tool result's content blocks into plain text.

        Real tool results can carry images or structured content alongside
        text; for the attack surface (text an agent reads and reasons over)
        the text blocks are what matters, so this is the one place callers
        need to unwrap the union.
        """
        parts: list[str] = []
        for block in result.content:
            if isinstance(block, types.TextContent):
                parts.append(block.text)
        return "\n".join(parts)

    @staticmethod
    def resource_text(result: types.ReadResourceResult) -> str:
        """Flatten a resource read's contents into plain text — mirrors
        result_text()'s role for tool calls. Only text contents are
        meaningful for a disclosure scan; binary (blob) contents are
        skipped, matching result_text()'s own text-only focus."""
        parts: list[str] = []
        for content in result.contents:
            if isinstance(content, types.TextResourceContents):
                parts.append(content.text)
        return "\n".join(parts)


class TargetConnection:
    """Async context manager: connect, enumerate tools, yield a `Target`.

    Wraps whichever transport `spec` names behind one interface so the rest
    of gaslight — the harness, the attack modules, the scorer — never
    branches on transport.
    """

    def __init__(self, spec: TargetSpec, *, capture_stderr: bool = False) -> None:
        self._spec = spec
        self._stack: AsyncExitStack | None = None
        # When True, the target's own startup output (child stderr) is captured
        # to a temp file so the CLI can diagnose a launch failure (see
        # core/doctor.py) instead of the user seeing a raw traceback. Only worth
        # doing on the discovery connection — if that starts, the rest will too.
        self._capture_stderr = capture_stderr
        self._errlog = None
        self.stderr_text = ""

    async def __aenter__(self) -> Target:
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()

        try:
            if self._spec.transport == "stdio":
                assert self._spec.command is not None
                params = StdioServerParameters(
                    command=self._spec.command[0],
                    args=self._spec.command[1:],
                    env=self._spec.env,
                )
                errlog = sys.stderr
                if self._capture_stderr:
                    self._errlog = tempfile.NamedTemporaryFile(
                        mode="w+", prefix="gaslight-target-stderr-", delete=False
                    )
                    errlog = self._errlog
                read, write = await self._stack.enter_async_context(stdio_client(params, errlog=errlog))
            elif self._spec.transport == "sse":
                assert self._spec.url is not None
                read, write = await self._stack.enter_async_context(sse_client(self._spec.url))
            else:  # pragma: no cover - guarded by TargetSpec.transport
                raise ValueError(f"unsupported transport: {self._spec.transport}")

            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
        except Exception as exc:
            # A target that won't start (missing credentials, bad command,
            # a crash during handshake) is an ordinary, expected outcome for
            # a black-box scanner pointed at someone else's software — not a
            # bug in gaslight. Raise one clean, typed error the CLI can
            # report as "couldn't connect, here's why" instead of dumping a
            # raw traceback. Verified against a real credential-requiring
            # server (a Postgres MCP server started with no DATABASE_URL),
            # which previously killed the whole run with an unhandled
            # MCPError from session.initialize().
            await self._close_quietly(exc)
            self._read_captured_stderr()
            raise TargetUnreachable(f"could not connect to {self._spec.label}: {type(exc).__name__}: {exc}") from exc

        try:
            listed_resources = await session.list_resources()
            resources = listed_resources.resources
        except Exception:
            # MCP makes the resources capability optional. Verified
            # empirically that a FastMCP-based server with zero resources
            # returns an empty list gracefully, no exception — this guards
            # the general case of some other server implementation that
            # doesn't implement the capability at all.
            resources = []

        return Target(session=session, tools=_normalize_tools(listed.tools), spec=self._spec, resources=resources)

    async def _close_quietly(self, exc: BaseException) -> None:
        """Unwind whatever part of the connection did open, swallowing the
        teardown's own errors — a half-open broken transport re-raises on
        close (see __aexit__), and that must not mask the real reason we
        failed to connect."""
        assert self._stack is not None
        try:
            await self._stack.__aexit__(type(exc), exc, exc.__traceback__)
        except Exception:
            pass
        finally:
            self._stack = None

    def _read_captured_stderr(self) -> None:
        """Pull the target's captured startup output into `stderr_text` so the
        CLI can diagnose why it failed to launch (see core/doctor.py), then
        remove the temp file. Best-effort — a diagnosis is a nicety, never
        allowed to raise over the real connect failure."""
        if self._errlog is None:
            return
        try:
            self._errlog.flush()
            self._errlog.seek(0)
            self.stderr_text = self._errlog.read()
        except Exception:
            pass
        finally:
            self._cleanup_errlog()

    def _cleanup_errlog(self) -> None:
        if self._errlog is None:
            return
        path = self._errlog.name
        try:
            self._errlog.close()
        except Exception:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        self._errlog = None

    async def __aexit__(self, *exc: object) -> None:
        self._cleanup_errlog()  # success path: discard the captured startup log
        if self._stack is None:
            # __aenter__ already unwound after a failed connect.
            return
        try:
            await self._stack.__aexit__(*exc)
        except Exception:
            # The same broken transport that call_tool() already converted
            # into an honest error result can re-surface here: once the
            # underlying stdio read loop hits a fatal parse error, anyio's
            # structured concurrency means closing that connection re-raises
            # the same failure. By this point the attack's `run()` already
            # completed inside the `async with` block and got whatever
            # signal it needed (including the synthesized error result from
            # call_tool()) — a broken teardown of an already-served
            # connection must not crash the whole `_run()` loop and cost
            # every attack after it.
            pass
