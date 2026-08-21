"""The honesty + education layer — plain words for what each check does, and
fun, true facts to sprinkle through the waits.

Two jobs:
1. Honesty. "Attack" can sound alarming — as if the tool might harm the user's
   system. It won't. Every probe is safe by construction — a benign test payload aimed at a
   dead local address gaslight controls, with destructive actions declined
   and anything sensitive masked (on the default --safe). SAFE_INTRO says this
   out loud, and each check gets one plain sentence of what it actually looks
   for, so nobody has to guess what we're doing to their system.
2. Personality + teaching. Agent security is genuinely fascinating and most
   people have never heard why an AI agent leaks. The FACTS below are short,
   true, and drawn from real 2025-26 incidents (see AGENT_SECURITY_LANDSCAPE.md
   — only the dated/verified ones). Shown during the slow beats of a run, they
   give the tool a voice and leave the user knowing more than when they started.

All static and deterministic — no model, no cost, always the same true thing.
Facts rotate by position (fact_for(index)) rather than at random, so a run is
reproducible and testable.
"""

from __future__ import annotations

SAFE_INTRO = (
    "These are safe, controlled probes. On the default safe setting, gaslight never triggers a "
    "destructive action, sends its network probes only to a local address it controls, and masks anything "
    "sensitive it sees. It checks your guardrails and leaves your real data alone."
)

# attack.key -> one honest, plain sentence of what this check actually looks
# for. Every registered attack must have an entry (a test enforces this), so the
# user is never shown a bare, scary-sounding name with no explanation.
_WHAT_IT_CHECKS: dict[str, str] = {
    "injection-exfil": "whether hidden instructions planted in data can trick the agent into leaking information to an outsider",
    "tool-authz-probe": "whether a tool that sends data out will just fire on demand, with no authorization check",
    "tool-metadata-poisoning": "whether a booby-trapped tool description can quietly steer the agent",
    "memory-poisoning": "whether a false 'fact' planted in one session survives to mislead a later one",
    "output-leakage": "whether secrets in a tool's output are shown in the clear instead of masked",
    "baseline-disclosure": "whether an ordinary, innocent request already spills a secret",
    "resource-exposure": "whether files and data the server exposes can be read with no gate at all",
    "instruction-override": "whether text claiming to be a new 'system rule' can override the agent's real limits",
    "destructive-authz-probe": "whether a destructive action — delete, reset — runs with no confirmation or guard",
    "path-traversal": "whether a file tool can be walked out of its folder into the rest of the disk",
    "ssrf-probe": "whether a URL tool can be aimed at internal addresses it should never be able to reach",
    "code-execution-probe": "whether a code or command tool will run a payload it was handed",
    "claim-integrity": "whether a tool that promises to be read-only actually keeps that promise",
    "confused-deputy": "whether data planted in one tool can be smuggled out through a different, unrelated one",
    "argument-smuggling": "whether a sneaky value hidden in an ordinary field gets used unsafely",
    "error-disclosure": "whether error messages leak file paths, secrets, or internal details",
    "denial-of-wallet": "whether one call can be made to do unbounded, expensive work with no cap",
}

# A punchy line to open a run — personality, not a claim.
OPENING = "Let's see what your agent's really made of."

# Shown at the end of a clean run — a friendly win, not a certificate.
CLEAN_LINE = "Clean run — nothing we tried got through. Your guardrails held. Nice."

# The AI-first fix loop: gaslight finds and proves it, your agent fixes it.
FIX_HINT = 'Want these fixed? Hand this report to your AI coding agent: "read the gaslight report and fix what it found."'

# Short, true, told with a bit of personality — plain words. Verified incidents only.
FACTS: tuple[str, ...] = (
    "The biggest problem in AI security has no fix yet: prompt injection. If your agent reads text, that "
    "text can try to give it orders — and the model often can't tell your instructions from an attacker's.",
    "2025: one crafted email walked data out of Microsoft Copilot. Zero clicks, no malware — just words the "
    "agent believed. They named it EchoLeak.",
    "A popular email tool for agents shipped a quiet extra: it BCC'd every message to its author. It worked "
    "perfectly — that was the whole trick.",
    "Researchers found 24,000+ secrets sitting in public AI-tool configs. Thousands still worked. Secrets "
    "love to hide in config files.",
    "The lethal trifecta: private data + untrusted text + a way out. Give an agent all three and you've "
    "built a data-leaking machine. gaslight tests exactly that.",
    "One tool was tricked into looping until it ran up 658× the normal cost. Security isn't just your data "
    "— it's your bill too.",
    "A public GitHub comment once talked an AI agent into leaking private code into a public pull request. "
    "The agent had the keys; the attacker just asked nicely.",
    "Rule one of agent security: the model is not a wall. The real guardrails live in your code — the stuff "
    "a smooth-talking prompt can't argue with.",
    "Most agent tools still use long-lived keys that never expire. A leaked key that never expires is a "
    "door that never locks.",
    "A tool that can run code can usually do everything else too — read files, hit the network. That's why "
    "'can it run code?' is the scariest question we ask.",
    "A tool can be friendly today and malicious next week — a 'rug pull.' gaslight can snapshot your tools "
    "and warn you the moment one changes.",
    "'send_email' and 'send_emai1' look identical to you. To a computer they're different tools — and one "
    "of them might not be friendly.",
    "The safest agent isn't the one that's never attacked — it's the one where a successful attack still "
    "can't reach anything that matters. That's blast radius.",
)


def what_it_checks(attack_key: str) -> str | None:
    """The plain-language description for a check, or None if unmapped."""
    return _WHAT_IT_CHECKS.get(attack_key)


def fact_for(index: int) -> str:
    """A fun fact, chosen deterministically by position so runs are reproducible."""
    return FACTS[index % len(FACTS)]
