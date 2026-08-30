import urllib.request

from gaslight.core.sink import _LOOPBACK_ENCODINGS, Sink, loopback_hosts

_BASE = ("127.0.0.1", "localhost") + _LOOPBACK_ENCODINGS


def test_loopback_hosts_defaults_to_plain_loopback_then_encodings(monkeypatch):
    monkeypatch.delenv("GASLIGHT_EXTRA_SINK_HOSTS", raising=False)
    hosts = loopback_hosts()
    assert hosts == _BASE
    assert hosts[0] == "127.0.0.1"  # common case stays first, fires fast
    assert "2130706433" in hosts  # the encoded-bypass tier is present


def test_loopback_hosts_appends_extra_hosts_from_env(monkeypatch):
    monkeypatch.setenv("GASLIGHT_EXTRA_SINK_HOSTS", "gaslight-proxy, other-host")
    assert loopback_hosts() == _BASE + ("gaslight-proxy", "other-host")


def test_loopback_hosts_ignores_blank_env_value(monkeypatch):
    monkeypatch.setenv("GASLIGHT_EXTRA_SINK_HOSTS", "")
    assert loopback_hosts() == _BASE


def test_sink_captures_and_recognizes_token():
    with Sink() as sink:
        assert sink.url.startswith("http://127.0.0.1:")

        body = b"reference code: canary-deadbeef"
        request = urllib.request.Request(sink.url, data=body, method="POST")
        urllib.request.urlopen(request, timeout=5)  # noqa: S310

        found = sink.received("canary-deadbeef")
        assert found is not None
        assert found.method == "POST"
        assert "canary-deadbeef" in found.body


def test_sink_reports_no_match_for_absent_token():
    with Sink() as sink:
        urllib.request.urlopen(  # noqa: S310
            urllib.request.Request(sink.url, data=b"nothing interesting", method="POST"),
            timeout=5,
        )
        assert sink.received("canary-neverused") is None


def test_sink_matches_token_in_query_string():
    with Sink() as sink:
        urllib.request.urlopen(f"{sink.url}?ref=canary-abc12345", timeout=5)  # noqa: S310
        assert sink.received("canary-abc12345") is not None
