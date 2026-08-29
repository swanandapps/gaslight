"""Remote HTTP transport auto-detection: gaslight tries the current Streamable
HTTP transport first and falls back to the older HTTP+SSE, so a `--url` caller
never has to know which one their server speaks. These test the selection logic
with fake openers — the real end-to-end path is exercised against live servers.
"""

import pytest

from gaslight.core import target as target_mod
from gaslight.core.target import TargetConnection, TargetSpec, _leaf_error


def test_url_spec_reports_http_transport():
    assert TargetSpec(url="http://host/mcp").transport == "http"
    assert TargetSpec(command=["python", "s.py"]).transport == "stdio"


def test_leaf_error_digs_through_nested_groups():
    # anyio wraps connect failures in nested (Base)ExceptionGroups; the leaf is
    # the actual cause a user should see. Uses a duck-typed group so it doesn't
    # depend on the ExceptionGroup builtin (absent before 3.11).
    class _Group(Exception):
        def __init__(self, subs):
            self.exceptions = subs

    leaf = ConnectionError("connection refused")
    grouped = _Group([_Group([leaf])])
    msg = _leaf_error(grouped)
    assert "ConnectionError" in msg and "connection refused" in msg


class _CM:
    """A stand-in for what an opener returns: an async context manager that
    either yields streams or fails on enter (a wrong transport / down server)."""

    def __init__(self, value, *, fail=False):
        self._value, self._fail = value, fail

    async def __aenter__(self):
        if self._fail:
            raise ConnectionError("refused")
        return self._value

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, read, write):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def initialize(self):
        pass


def _wire(monkeypatch, streamable_fn, sse_fn):
    monkeypatch.setattr(target_mod, "streamable_http_client", streamable_fn)
    monkeypatch.setattr(target_mod, "sse_client", sse_fn)
    monkeypatch.setattr(target_mod, "ClientSession", _FakeSession)
    target_mod._URL_TRANSPORT.clear()


async def test_streamable_is_tried_first_and_used_when_it_works(monkeypatch):
    calls = []
    _wire(
        monkeypatch,
        lambda url: (calls.append("streamable"), _CM(("r", "w", "id")))[1],
        lambda url: (calls.append("sse"), _CM(("r", "w")))[1],
    )
    conn = TargetConnection(TargetSpec(url="http://host/mcp"))
    opener = await conn._detect_http_transport("http://host/mcp")
    assert calls == ["streamable"]  # SSE never attempted
    assert target_mod._URL_TRANSPORT["http://host/mcp"] is opener


async def test_falls_back_to_sse_when_streamable_fails(monkeypatch):
    calls = []
    sse = lambda url: (calls.append("sse"), _CM(("r", "w")))[1]  # noqa: E731
    _wire(
        monkeypatch,
        lambda url: (calls.append("streamable"), _CM(None, fail=True))[1],
        sse,
    )
    conn = TargetConnection(TargetSpec(url="http://host/sse"))
    opener = await conn._detect_http_transport("http://host/sse")
    assert calls == ["streamable", "sse"]  # tried streamable, then fell back
    assert opener is not None
    assert target_mod._URL_TRANSPORT["http://host/sse"] is opener


async def test_raises_when_neither_transport_connects(monkeypatch):
    _wire(
        monkeypatch,
        lambda url: _CM(None, fail=True),
        lambda url: _CM(None, fail=True),
    )
    conn = TargetConnection(TargetSpec(url="http://host/mcp"))
    with pytest.raises(RuntimeError, match="Streamable HTTP then SSE"):
        await conn._detect_http_transport("http://host/mcp")


# --- transparent recovery: repair malformed tool schemas in flight ---

from gaslight.core.target import _normalize_tool_schemas  # noqa: E402


class _Node:
    """Mirror the SessionMessage -> .message -> .root -> .result attribute chain
    the normalizer walks, without depending on SDK internals."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _tools_msg(tools):
    return _Node(message=_Node(root=_Node(result={"tools": tools})))


def _schema_of(msg, i=0, key="inputSchema"):
    return msg.message.root.result["tools"][i][key]


def test_injects_missing_type_like_obsidian():
    # obsidian's real shape: an inputSchema that's only {"$schema": "...draft-07..."}
    m = _tools_msg([{"name": "a", "inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#"}}])
    _normalize_tool_schemas(m)
    assert _schema_of(m)["type"] == "object"


def test_never_overwrites_a_declared_type():
    m = _tools_msg([{"name": "a", "inputSchema": {"type": "array"}}])
    _normalize_tool_schemas(m)
    assert _schema_of(m)["type"] == "array"  # a compliant server's declaration is preserved


def test_normalizes_both_casings_and_output_schema():
    m = _tools_msg([{"name": "a", "input_schema": {}, "outputSchema": {}}])
    _normalize_tool_schemas(m)
    assert _schema_of(m, key="input_schema")["type"] == "object"
    assert _schema_of(m, key="outputSchema")["type"] == "object"


def test_tolerates_odd_tool_shapes_without_crashing():
    # inputSchema absent, null, or a non-dict must not raise.
    m = _tools_msg([{"name": "a"}, {"name": "b", "inputSchema": None}, {"name": "c", "inputSchema": "nope"}, "junk"])
    assert _normalize_tool_schemas(m) is m  # returns the message, no exception


def test_leaves_non_tools_messages_untouched():
    m = _Node(message=_Node(root=_Node(result={"content": [{"type": "text", "text": "hi"}]})))
    before = m.message.root.result["content"][0].copy()
    _normalize_tool_schemas(m)
    assert m.message.root.result["content"][0] == before  # a tool-call result is not a tool list


def test_handles_message_with_no_result():
    m = _Node(message=_Node(root=_Node()))  # e.g. a request/notification, no result
    assert _normalize_tool_schemas(m) is m
