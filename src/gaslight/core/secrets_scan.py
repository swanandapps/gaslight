"""Deterministic secret/credential detection — regex + entropy, the same
approach gitleaks/trufflehog use. No LLM involved; this is the mandatory
baseline every disclosure-detecting attack module runs, regardless of
whether the optional LLM-classifier layer (core/llm_secret_hints.py) is
enabled. See docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.

Known, accepted limitation shared by every regex/entropy secret scanner:
the entropy fallback will sometimes flag high-entropy non-secrets (UUIDs,
hashes). That costs a report line, not a wrong verdict — no attempt is
made to eliminate it here.
"""

from __future__ import annotations

import math
import re

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"Bearer\s+[A-Za-z0-9\-_.]{10,}", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[a-z]{2,12}[_-](?:api|live|test)[_-][A-Za-z0-9]{12,}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|secret|password|token)[\"']?\s*[:=]\s*[\"']?"
        r"(?!(?:redacted|unavailable|anonymous|encrypted|hidden|masked|none|null|n/?a|removed|omitted|withheld)\b)"
        r"[A-Za-z0-9\-_.]{8,}",
        re.IGNORECASE,
    ),
]

_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_ENTROPY_THRESHOLD = 4.0

# A URL path is not a secret, but it looks like one to an entropy test: the
# "/" separators are in the candidate character class (base64 uses them), and
# enough distinct letters across several words pushes a long path over the
# threshold. Found in the wild — a real Confluence MCP server's ordinary error
# text contained the PUBLICLY DOCUMENTED endpoint
# "/wiki/rest/api/group/confluence-users/member", which scores 4.021 against a
# 4.0 threshold and was reported as a CONFIRMED secret leak. A confidently
# wrong CONFIRMED is the worst output this project can produce, so path-shaped
# strings are excluded from the fuzzy entropy fallback.
#
# Only the fallback: every _SECRET_PATTERNS regex still runs against the whole
# text, so a genuine credential sitting inside a URL ("...?token=<real>") is
# still caught by the token=/api_key= pattern. What's given up is a secret that
# is itself shaped like a multi-segment path — a shape no real key format uses.
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~+-]+\Z")
_MAX_PATH_SEGMENT = 32


def _looks_like_path_or_url(value: str) -> bool:
    if "://" in value:
        return True
    segments = [s for s in value.split("/") if s]
    if len(segments) < 3:
        return False
    if not all(_PATH_SEGMENT.match(s) for s in segments):
        return False
    # An absolute path is conclusive on its own — no real credential format
    # starts with "/". The per-segment length cap below is only needed to stop
    # a slash-bearing base64 blob from passing as a relative path; applying it
    # to absolute paths misfired on a genuinely long one (a 50-character
    # directory name and a 36-character UUID), which then got reported as a
    # secret.
    if value.startswith("/"):
        return True
    return all(len(s) <= _MAX_PATH_SEGMENT for s in segments)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def find_high_confidence_secrets(text: str) -> list[str]:
    """Only the deterministic regex patterns — recognisable credential formats
    (AWS keys, JWTs, Bearer tokens, PEM private keys, `api_key=`/`password:`
    pairs). A hit here is a *real, named* secret, never a random-looking string
    that merely scored high on entropy.

    This is the line between guessing and proving. Use it wherever a hit must
    be trustworthy enough to CONFIRM a finding — a confidently-wrong CONFIRMED
    is the worst thing this project can emit, and every false positive found
    while testing real servers came from the entropy net below firing on an
    ordinary high-entropy string (a URL path, a build hash, a request id).
    Use find_secret_like_strings() (patterns PLUS the fuzzy entropy net) only
    where a softer 'worth a manual look' signal is acceptable.
    """
    if not text:
        return []
    found: list[str] = []
    for pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if m.group(0) not in found:
                found.append(m.group(0))
    return found


def find_secret_like_strings(text: str) -> list[str]:
    """Secret detection over free text: the deterministic patterns PLUS a fuzzy
    entropy fallback for unknown formats. Returns each match verbatim
    (unmasked), deduplicated in first-seen order — callers must mask before a
    value ever reaches a report or log; see mask_secret(). The entropy tail is
    a *guess* and will occasionally flag a high-entropy non-secret; callers
    that CONFIRM findings should use find_high_confidence_secrets() instead.
    """
    found = find_high_confidence_secrets(text)
    for candidate in _ENTROPY_CANDIDATE.findall(text or ""):
        if candidate in found or _looks_like_path_or_url(candidate):
            continue
        if _shannon_entropy(candidate) > _ENTROPY_THRESHOLD:
            found.append(candidate)
    return found


def mask_secret(value: str) -> str:
    """Never let a full secret value reach a report — same principle as
    reporter.py's autoescape=True: a security tool whose own output leaks
    what it found is not a credible security tool."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]}"


def redact_and_truncate(text: str, length: int) -> str:
    """Mask anything secret-shaped, then hard-truncate to `length` chars —
    truncation is the real protection here, since most response text from
    an untrusted target won't match any secret pattern at all. Shared by
    path_traversal.py and ssrf_probe.py, both of which call a target
    directly and must not let a real hit dump unbounded raw content into
    a Finding.
    """
    redacted = text
    for hit in find_secret_like_strings(text):
        redacted = redacted.replace(hit, mask_secret(hit))
    return redacted[:length]
