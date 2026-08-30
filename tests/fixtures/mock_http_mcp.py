"""An in-process mock of an MCP server spoken over HTTP, for testing the auth
probes (core/auth_probes.py). Like core/sink.py it runs a ThreadingHTTPServer on
a background thread and hands back a URL; unlike the real transports it speaks
just enough JSON-RPC (initialize / tools/list / tools/call) for a raw probe to
exercise it, with a CONFIGURABLE auth policy so one fixture yields the matched
weak/hardened pair:

    policy="open"    — honors everything (no auth at all)            → probes fire
    policy="strict"  — requires Bearer <VALID_TOKEN>, rejects no/bad → all pass (A)
    policy="session" — accepts a bare Mcp-Session-Id with no bearer  → session probe fires

Responses are plain application/json (the spec also allows SSE; the raw client
handles both, the mock keeps it simple).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VALID_TOKEN = "valid-test-token"
_SESSION_ID = "mock-session-abc123"


def _token_ok(policy: str, auth_header: str, session_header: str) -> bool:
    """Whether this request is authorized under the mock's policy."""
    if policy == "open":
        return True
    if policy == "session":
        # A bare session id (no bearer) is (wrongly) accepted — the vuln.
        return session_header == _SESSION_ID or auth_header == f"Bearer {VALID_TOKEN}"
    # strict: only the exact valid bearer, nothing else.
    return auth_header == f"Bearer {VALID_TOKEN}"


class _Handler(BaseHTTPRequestHandler):
    server_version = "mock-mcp/1.0"

    def _send(self, code: int, body: dict, session: str | None = None) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        try:
            req = json.loads(raw)
        except ValueError:
            req = {}
        method = req.get("method", "")
        rpc_id = req.get("id", 1)
        policy = self.server.policy  # type: ignore[attr-defined]
        auth = self.headers.get("Authorization", "")
        session = self.headers.get("Mcp-Session-Id", "")

        if not _token_ok(policy, auth, session):
            self._send(401, {"jsonrpc": "2.0", "id": rpc_id,
                             "error": {"code": -32001, "message": "Unauthorized"}})
            return

        if method == "initialize":
            self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock", "version": "1.0"},
            }}, session=_SESSION_ID)
        elif method == "tools/list":
            self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": [
                {"name": "get_record", "description": "Read a record.",
                 "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
            ]}})
        elif method == "tools/call":
            self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {
                "content": [{"type": "text", "text": "record: Jane Doe, balance $4210"}],
                "isError": False,
            }})
        else:  # notifications/initialized and anything else: accept quietly
            self._send(202, {"jsonrpc": "2.0", "id": rpc_id, "result": {}})

    def log_message(self, *_a: object) -> None:
        pass  # silence


class MockHttpMcpServer:
    """Context manager: `with MockHttpMcpServer("open") as srv: srv.url`."""

    def __init__(self, policy: str = "open", *, scheme: str = "http") -> None:
        self.policy = policy
        self._scheme = scheme
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "MockHttpMcpServer":
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.policy = self.policy  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def url(self) -> str:
        assert self._server is not None
        return f"{self._scheme}://127.0.0.1:{self._server.server_address[1]}/mcp"
