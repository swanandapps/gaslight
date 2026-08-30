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

import base64
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


def _finding(key: str, fired: bool, reason: str, severity: str | None = None, attempted: bool = True) -> Finding:
    return Finding(attack_key=key, fired=fired, reason=reason, severity=severity, attempted=attempted)


def _decode_jwt_claims(token: str) -> dict | None:
    """Best-effort decode of a JWT's claims — base64 only, NO verification (that's
    the server's job, and testing whether it does its job is the point)."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad))
        return claims if isinstance(claims, dict) else None
    except (ValueError, TypeError):
        return None


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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _mint_unsigned_jwt(claims: dict | None = None) -> str:
    """A JWT with header alg:none and NO signature — the classic bypass. A server
    that verifies signatures rejects it; one that only base64-decodes the claims
    accepts it. Self-minted, so this needs no real credential."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "gaslight-probe", "aud": "gaslight", **(claims or {})}).encode())
    return f"{header}.{payload}."


async def _honored_call(client, url, headers, read_tool, session):
    """Issue the read tool call (or tools/list) with the given headers/session,
    return whether it was honored."""
    if read_tool:
        resp = await _rpc(client, url, "tools/call", headers=headers, session=session,
                          params={"name": read_tool, "arguments": {}})
    else:
        resp = await _rpc(client, url, "tools/list", headers=headers, session=session)
    return _honored(resp)


async def _probe_token_not_validated(client, url, read_tool, no_auth_fired) -> Finding:
    """P3/P4/P5: the server requires a token (no-auth was rejected) but does it
    actually VALIDATE it? Present a forged bearer — an unsigned alg:none JWT (with
    a future exp), then a garbage string. If either is honored, the server checks
    that *a* token is present but never verifies its signature or expiry."""
    key = "auth-token-not-validated"
    if no_auth_fired:
        return _finding(key, False, "not applicable — the server serves callers with no credential at all "
                                    "(see the no-credential probe).")
    forged = (("an unsigned alg:none JWT", _mint_unsigned_jwt({"exp": 9999999999})),
              ("a garbage bearer string", "not-a-real-token"))
    for label, token in forged:
        headers = {"Authorization": f"Bearer {token}"}
        init = await _rpc(client, url, "initialize", headers=headers, params={
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "gaslight", "version": "0"},
        })
        if not _honored(init):
            continue
        session = init.headers.get("mcp-session-id") or init.headers.get("Mcp-Session-Id")
        if await _honored_call(client, url, headers, read_tool, session):
            return _finding(key, True, f"the server honored {label} — it checks that a token is present but "
                                       f"never validates its signature or expiry (accepts anything).",
                            severity="critical")
    return _finding(key, False, "forged and unsigned tokens were rejected — the server validates its tokens.")


def _probe_transport(url: str) -> Finding:
    """P2: a non-loopback endpoint served over cleartext http:// — tokens and
    tool data travel unencrypted. Loopback http is fine (dev)."""
    key = "auth-transport"
    if urlparse(url).scheme == "http" and not _is_loopback(url):
        return _finding(key, True, f"endpoint is served over cleartext http:// ({urlparse(url).hostname}) "
                                   f"— bearer tokens and tool data travel unencrypted.", severity="high")
    return _finding(key, False, "endpoint uses https (or loopback dev) — transport is encrypted.")


_INIT_PARAMS = {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "gaslight", "version": "0"},
}


async def _probe_session_as_auth(client, url, read_tool, auth_token) -> Finding:
    """P6: open a session with the valid token, then make a call carrying ONLY the
    session id and no bearer. If it's honored, the server treats the session as
    authentication (spec MUST-NOT). Needs a token to open the session."""
    key = "auth-session-as-auth"
    if not auth_token:
        return _finding(key, False, "NOT TESTED — pass --auth-token so a session can be opened first.", attempted=False)
    headers = {"Authorization": f"Bearer {auth_token}"}
    init = await _rpc(client, url, "initialize", headers=headers, params=_INIT_PARAMS)
    session = init.headers.get("mcp-session-id") or init.headers.get("Mcp-Session-Id")
    if not _honored(init) or not session:
        return _finding(key, False, "NOT TESTED — the supplied token did not open a session.", attempted=False)
    if await _honored_call(client, url, {}, read_tool, session):
        return _finding(key, True, "a tool call carrying ONLY the session id (no bearer token) was honored — the "
                                   "server treats the session as authentication.", severity="critical")
    return _finding(key, False, "a bare session id with no token was rejected — sessions are not used as auth.")


async def _probe_passthrough(client, url, read_tool, auth_token) -> Finding:
    """P7: if the supplied token's audience is NOT this server, replay it here. An
    honored response = token passthrough (the server accepts a token minted for
    someone else). Needs a token minted for a different service to be meaningful."""
    key = "auth-token-passthrough"
    if not auth_token:
        return _finding(key, False, "NOT TESTED — pass --auth-token (a token minted for a DIFFERENT service).", attempted=False)
    claims = _decode_jwt_claims(auth_token)
    aud = claims.get("aud") if claims else None
    aud_str = ",".join(aud) if isinstance(aud, list) else (aud or "")
    if not aud_str:
        # Can't read the audience (opaque token, or no aud claim) — replaying it
        # and seeing it honored would just be the legit token working, not
        # passthrough. Can't assess this without a readable, foreign audience.
        return _finding(key, False, "NOT TESTED — the supplied token has no readable audience (opaque token or no "
                                    "aud claim); supply a JWT minted for a DIFFERENT service to test passthrough.",
                        attempted=False)
    host = (urlparse(url).hostname or "").lower()
    if host and host in aud_str.lower():
        return _finding(key, False, f"NOT TESTED — the supplied token's audience ({aud_str!r}) names this server; "
                                    f"supply a token for a DIFFERENT service to test passthrough.", attempted=False)
    headers = {"Authorization": f"Bearer {auth_token}"}
    init = await _rpc(client, url, "initialize", headers=headers, params=_INIT_PARAMS)
    session = init.headers.get("mcp-session-id") or init.headers.get("Mcp-Session-Id")
    if _honored(init) and await _honored_call(client, url, headers, read_tool, session):
        return _finding(key, True, f"the server honored a token whose audience is {aud_str or 'unset'!r} — not this "
                                   f"server — token passthrough / no audience binding.", severity="critical")
    return _finding(key, False, "a token minted for another audience was rejected — audience binding is enforced.")


def _probe_token_hygiene(auth_token) -> Finding:
    """P8: decode-only — judge the supplied token itself. No exp / no aud = a
    long-lived, unbound credential that stays a skeleton key if it leaks."""
    key = "auth-token-hygiene"
    if not auth_token:
        return _finding(key, False, "NOT TESTED — no --auth-token supplied.", attempted=False)
    claims = _decode_jwt_claims(auth_token)
    if claims is None:
        return _finding(key, False, "the supplied token isn't a decodable JWT — hygiene not assessed.", attempted=False)
    issues = [name for name, present in (("no expiry (exp)", "exp" in claims), ("no audience (aud)", "aud" in claims)) if not present]
    if issues:
        return _finding(key, True, f"the supplied token has {', '.join(issues)} — a leaked token like this is a "
                                   f"long-lived, unbound credential.", severity="medium")
    return _finding(key, False, "the supplied token declares an expiry and an audience.")


def _tier3_not_tested() -> Finding:
    """The OAuth-flow rules (PKCE, exact redirect-URI, CSRF state) need the
    authorization server in the loop — stated honestly, never faked."""
    return _finding("auth-oauth-flow", False,
                    "NOT TESTED — PKCE, redirect-URI matching and CSRF state need the OAuth authorization "
                    "server in the loop, out of reach of a black-box tool scan.", attempted=False)


async def run_auth_probes(
    url: str, read_tool: str | None = None, *,
    auth_token: str | None = None, extra_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Run the remote-HTTP auth probes against `url`. `read_tool` is a harmless
    read-only tool name (from recon) to replay; None falls back to tools/list.
    Returns Findings that feed the same scorer/report as the attacks."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:  # noqa: S501 - probing, not trusting
        no_cred = await _probe_no_auth_call(client, url, read_tool)
        findings = [
            no_cred,
            await _probe_token_not_validated(client, url, read_tool, no_cred.fired),
            _probe_transport(url),
        ]
        if auth_token:
            findings += [
                await _probe_session_as_auth(client, url, read_tool, auth_token),
                await _probe_passthrough(client, url, read_tool, auth_token),
                _probe_token_hygiene(auth_token),
            ]
        findings.append(_tier3_not_tested())
    return findings
