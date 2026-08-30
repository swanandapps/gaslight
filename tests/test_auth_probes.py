"""Remote HTTP auth probes — weak/hardened pairs against an in-process mock MCP
server (no real network, loopback only). See core/auth_probes.py."""

import sys
from pathlib import Path

from gaslight.core.auth_probes import run_auth_probes

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from mock_http_mcp import MockHttpMcpServer  # noqa: E402


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


async def test_falls_back_to_tools_list_when_no_read_tool():
    with MockHttpMcpServer("open") as srv:
        findings = await run_auth_probes(srv.url, read_tool=None)
    hit = _fired(findings, "auth-no-credential")
    assert hit is not None
    assert "tools/list" in hit.reason
