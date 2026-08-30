"""Remote HTTP auth probes — weak/hardened pairs against an in-process mock MCP
server (no real network, loopback only). See core/auth_probes.py."""

import sys
from pathlib import Path

from gaslight.core.auth_probes import run_auth_probes

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from mock_http_mcp import VALID_TOKEN, MockHttpMcpServer  # noqa: E402

from gaslight.core.auth_probes import _b64url, _mint_unsigned_jwt, _probe_token_hygiene  # noqa: E402


def _jwt(claims: dict) -> str:
    import json
    return f"{_b64url(json.dumps({'alg': 'none'}).encode())}.{_b64url(json.dumps(claims).encode())}."


def _fired(findings, key):
    return next((f for f in findings if f.attack_key == key and f.fired), None)


def _by_key(findings, key):
    return next(f for f in findings if f.attack_key == key)


async def test_no_auth_call_fires_against_open_server():
    with MockHttpMcpServer("open") as srv:
        findings = await run_auth_probes(srv.url, read_tool="get_record")
    hit = _fired(findings, "auth-no-credential")
    assert hit is not None
    assert "no authorization" in hit.reason.lower()
    assert hit.severity == "critical"


async def test_no_auth_call_does_not_fire_against_strict_server():
    with MockHttpMcpServer("strict") as srv:
        findings = await run_auth_probes(srv.url, read_tool="get_record")
    assert _fired(findings, "auth-no-credential") is None
    # it was actually tested, and reports the pass honestly
    assert _by_key(findings, "auth-no-credential").attempted is True


def test_transport_fires_on_non_loopback_http():
    # pure check on scheme+host — no network request
    from gaslight.core.auth_probes import _probe_transport

    assert _probe_transport("http://tools.acme.com/mcp").fired is True
    assert "cleartext" in _probe_transport("http://tools.acme.com/mcp").reason.lower()
    assert _probe_transport("https://tools.acme.com/mcp").fired is False


async def test_transport_does_not_fire_on_loopback_http():
    with MockHttpMcpServer("open") as srv:  # loopback http — fine for dev
        findings = await run_auth_probes(srv.url, read_tool="get_record")
    assert _by_key(findings, "auth-transport").fired is False


async def test_token_not_validated_fires_when_any_bearer_is_accepted():
    # server requires *a* bearer (no-auth rejected) but never validates it
    with MockHttpMcpServer("any_bearer") as srv:
        findings = await run_auth_probes(srv.url, read_tool="get_record")
    assert _fired(findings, "auth-no-credential") is None  # it DOES require a token
    hit = _fired(findings, "auth-token-not-validated")
    assert hit is not None
    assert "never validates" in hit.reason.lower()
    assert hit.severity == "critical"


async def test_token_not_validated_does_not_fire_against_strict():
    with MockHttpMcpServer("strict") as srv:
        findings = await run_auth_probes(srv.url, read_tool="get_record")
    assert _fired(findings, "auth-token-not-validated") is None


async def test_token_not_validated_is_na_when_fully_open():
    # if there's no auth at all, the forged-token probe is subsumed by no-credential
    with MockHttpMcpServer("open") as srv:
        findings = await run_auth_probes(srv.url, read_tool="get_record")
    tnv = _by_key(findings, "auth-token-not-validated")
    assert tnv.fired is False
    assert "not applicable" in tnv.reason.lower()


async def test_falls_back_to_tools_list_when_no_read_tool():
    with MockHttpMcpServer("open") as srv:
        findings = await run_auth_probes(srv.url, read_tool=None)
    hit = _fired(findings, "auth-no-credential")
    assert hit is not None
    assert "tools/list" in hit.reason


# --- Tier 2 (needs --auth-token) ---

async def test_session_as_auth_fires_when_bare_session_accepted():
    with MockHttpMcpServer("session") as srv:
        findings = await run_auth_probes(srv.url, "get_record", auth_token=VALID_TOKEN)
    hit = _fired(findings, "auth-session-as-auth")
    assert hit is not None and hit.severity == "critical"


async def test_session_as_auth_passes_against_strict():
    with MockHttpMcpServer("strict") as srv:
        findings = await run_auth_probes(srv.url, "get_record", auth_token=VALID_TOKEN)
    assert _fired(findings, "auth-session-as-auth") is None


async def test_passthrough_fires_on_foreign_audience_token():
    foreign = _mint_unsigned_jwt({"aud": "api.other-service.com"})
    with MockHttpMcpServer("any_bearer") as srv:
        findings = await run_auth_probes(srv.url, "get_record", auth_token=foreign)
    assert _fired(findings, "auth-token-passthrough") is not None


async def test_passthrough_not_tested_when_token_names_this_server():
    with MockHttpMcpServer("any_bearer") as srv:
        own = _mint_unsigned_jwt({"aud": "127.0.0.1"})
        findings = await run_auth_probes(srv.url, "get_record", auth_token=own)
    p7 = _by_key(findings, "auth-token-passthrough")
    assert p7.fired is False and p7.attempted is False


def test_token_hygiene_fires_without_exp_or_aud():
    f = _probe_token_hygiene(_jwt({"sub": "x"}))
    assert f.fired is True and "no expiry" in f.reason.lower()


def test_token_hygiene_passes_with_exp_and_aud():
    f = _probe_token_hygiene(_mint_unsigned_jwt({"exp": 9999999999}))
    assert f.fired is False


async def test_tier2_probes_absent_without_token():
    with MockHttpMcpServer("open") as srv:
        findings = await run_auth_probes(srv.url, "get_record")
    keys = {f.attack_key for f in findings}
    assert "auth-session-as-auth" not in keys  # only present when --auth-token given
    assert "auth-oauth-flow" in keys  # tier 3 not-tested row always present
