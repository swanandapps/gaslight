"""Deterministic secret detection — regex + entropy, no LLM involved. See
docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.
"""

from gaslight.core.secrets_scan import find_secret_like_strings, mask_secret, redact_and_truncate


def test_finds_aws_key():
    hits = find_secret_like_strings("Debug token: AKIAABCDEFGHIJKLMNOP end of message")
    assert "AKIAABCDEFGHIJKLMNOP" in hits


def test_finds_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    hits = find_secret_like_strings(f"Authorization: Bearer {jwt}")
    assert jwt in hits


def test_finds_vendor_prefixed_key():
    hits = find_secret_like_strings("API Key: sk_live_ABCDEFGHIJKLMNOPQRST1234")
    assert any("sk_live_ABCDEFGHIJKLMNOPQRST1234" in hit for hit in hits)


def test_ordinary_text_finds_nothing():
    assert find_secret_like_strings("All systems operational. Have a nice day.") == []


def test_empty_text_finds_nothing():
    assert find_secret_like_strings("") == []


def test_mask_secret_short_value_fully_masked():
    assert mask_secret("short") == "*****"


def test_mask_secret_long_value_shows_prefix_and_suffix_only():
    masked = mask_secret("AKIAABCDEFGHIJKLMNOP")
    assert masked == "AKIA...OP"
    assert "ABCDEFGHIJKLMN" not in masked


def test_ignores_redacted_placeholder_value():
    assert find_secret_like_strings("api_key: redacted") == []


def test_ignores_common_placeholder_words():
    assert find_secret_like_strings("token: unavailable") == []
    assert find_secret_like_strings("secret: anonymous") == []
    assert find_secret_like_strings("password: encrypted") == []


def test_redact_and_truncate_masks_then_truncates():
    text = "prefix api_key: sk-live-abcdef1234567890 padding"
    result = redact_and_truncate(text, 200)
    assert len(result) < len(text)  # masking shortened it even though length (200) exceeds len(text)
    assert "sk-live-abcdef1234567890" not in result


def test_redact_and_truncate_no_secret_still_truncates():
    text = "a" * 500
    result = redact_and_truncate(text, 10)
    assert result == "a" * 10


def test_redact_and_truncate_short_text_unaffected():
    result = redact_and_truncate("hello", 150)
    assert result == "hello"


def test_public_url_path_is_not_reported_as_a_secret():
    """Regression: a real Confluence MCP server's ordinary error text contained
    the PUBLICLY DOCUMENTED endpoint below. It scores 4.021 against a 4.0
    entropy threshold and was reported as a CONFIRMED secret leak — a
    confidently wrong CONFIRMED, the worst output this project can produce."""
    from gaslight.core.secrets_scan import _shannon_entropy

    path = "/wiki/rest/api/group/confluence-users/member"
    assert _shannon_entropy(path) > 4.0  # still trips raw entropy...
    assert find_secret_like_strings(path) == []  # ...but is no longer called a secret


def test_other_ordinary_paths_and_urls_are_not_secrets():
    for text in (
        "/api/v2/organizations/members/settings",
        "https://example.atlassian.net/wiki/rest/api/content/search",
        "/usr/local/lib/python3.10/site-packages/mcp/client",
    ):
        assert find_secret_like_strings(text) == [], text


def test_a_real_secret_inside_a_url_is_still_caught():
    """The path exclusion must only affect the fuzzy entropy fallback — a
    genuine credential in a query string is still matched by the token=
    pattern."""
    hits = find_secret_like_strings("GET /wiki/rest/api/search?token=sk9Kx2mQvT7bNpLw3ZaR")
    assert hits, "a real token in a URL must still be detected"


def test_known_secret_formats_still_detected_after_the_path_exclusion():
    assert find_secret_like_strings("key AKIAABCDEFGHIJKLMNOP here")
    assert find_secret_like_strings("Authorization: Bearer abcdefghijklmnop123456")


def test_long_absolute_paths_are_not_secrets():
    """Regression: the per-segment length cap misfired on a genuinely long
    real path (a 50-char directory name and a 36-char UUID), so it fell
    through to the entropy check and was reported as a secret."""
    long_path = (
        "/private/tmp/claude-501/-Users-someone-Desktop-SK-Projects-gaslight/"
        "8d47fa29-5d99-44cb-a402-17ae8bf20f62/scratchpad/sprint/testrepo"
    )
    assert find_secret_like_strings(long_path) == []


def test_high_confidence_excludes_entropy_but_keeps_patterns():
    from gaslight.core.secrets_scan import find_high_confidence_secrets

    # a build hash: entropy net flags it, high-confidence must not
    h = "commit a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    assert find_high_confidence_secrets(h) == []
    assert find_secret_like_strings(h)  # the fuzzy net still returns it

    # a real AWS key: both must catch it
    k = "AKIAABCDEFGHIJKLMNOP"
    assert find_high_confidence_secrets(k) == [k]
