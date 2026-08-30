"""Remote HTTP auth probes — the authentication layer in front of a deployed
MCP server, which the behavioral attacks can't reach (they ride the already-
authenticated MCP client). See docs/superpowers/specs/2026-08-30-remote-http-auth-probes.md.

These speak MCP-over-HTTP with RAW httpx, so every header is under our control:
we send a request that SHOULD be rejected (no token, a forged token, a bare
session id) and a finding fires only on a real HONORED response — physically
proven, never inferred. HTTP targets only; a local stdio server has no network
auth surface (the caller gates on transport before invoking this).

Tier 0 (this file, zero-config): P1 no-auth call, P2 cleartext transport.
Later tiers (forged tokens, passthrough) build on the same raw client.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx

from gaslight.core.attacks.base import Finding

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"}
_TIMEOUT = 10.0


def _parse_body(resp: httpx.Response) -> dict | None:
    """A JSON-RPC body out of either an application/json or a text/event-stream
    (SSE) response — Streamable HTTP is allowed to answer with either."""
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except ValueError:
                    continue
        return None
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _honored(resp: httpx.Response) -> bool:
    """Whether the server actually did the work — a JSON-RPC result, not a 401/403
    and not a JSON-RPC error. This is the whole verdict: the request either got a
    real answer it should not have, or it was rejected."""
    if resp.status_code in (401, 403):
        return False
    data = _parse_body(resp)
    if data is None:
        return resp.status_code < 400
    if data.get("error"):
        return False
    return "result" in data


async def _rpc(
    client: httpx.AsyncClient, url: str, method: str, *,
    headers: dict[str, str] | None = None, session: str | None = None, params: dict | None = None,
) -> httpx.Response:
    body: dict = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if headers:
        h.update(headers)
    if session:
        h["Mcp-Session-Id"] = session
    return await client.post(url, json=body, headers=h)


def _is_loopback(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in _LOOPBACK_HOSTS


def _finding(key: str, fired: bool, reason: str, severity: str | None = None) -> Finding:
    return Finding(attack_key=key, fired=fired, reason=reason, severity=severity, attempted=True)


async def _probe_no_auth_call(client: httpx.AsyncClient, url: str, read_tool: str | None) -> Finding:
    """P1: does the server serve a caller carrying NO credential? Initialize with
    no auth; if that's rejected the door is guarded (pass). If it's honored, try
    an actual tool call (or a tools/list) still with no auth — an honored answer
    is the flagship finding: a deployed server anyone can drive."""
    key = "auth-no-credential"
    init = await _rpc(client, url, "initialize", params={
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "gaslight", "version": "0"},
    })
    if not _honored(init):
        return _finding(key, False, "unauthenticated requests are rejected — the server requires a credential.")
    session = init.headers.get("mcp-session-id") or init.headers.get("Mcp-Session-Id")
    if read_tool:
        resp = await _rpc(client, url, "tools/call", session=session,
                          params={"name": read_tool, "arguments": {}})
        target = f"the tool {read_tool!r}"
    else:
        resp = await _rpc(client, url, "tools/list", session=session)
        target = "the tool catalog (tools/list)"
    if _honored(resp):
        return _finding(key, True, f"{target} was served on a request carrying NO Authorization header "
                                   f"— the server does not authenticate callers.", severity="critical")
    return _finding(key, False, "the handshake was open but tool access required a credential.")


def _probe_transport(url: str) -> Finding:
    """P2: a non-loopback endpoint served over cleartext http:// — tokens and
    tool data travel unencrypted. Loopback http is fine (dev)."""
    key = "auth-transport"
    if urlparse(url).scheme == "http" and not _is_loopback(url):
        return _finding(key, True, f"endpoint is served over cleartext http:// ({urlparse(url).hostname}) "
                                   f"— bearer tokens and tool data travel unencrypted.", severity="high")
    return _finding(key, False, "endpoint uses https (or loopback dev) — transport is encrypted.")


async def run_auth_probes(
    url: str, read_tool: str | None = None, *,
    auth_token: str | None = None, extra_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Run the remote-HTTP auth probes against `url`. `read_tool` is a harmless
    read-only tool name (from recon) to replay; None falls back to tools/list.
    Returns Findings that feed the same scorer/report as the attacks."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:  # noqa: S501 - probing, not trusting
        findings = [
            await _probe_no_auth_call(client, url, read_tool),
            _probe_transport(url),
        ]
    return findings
