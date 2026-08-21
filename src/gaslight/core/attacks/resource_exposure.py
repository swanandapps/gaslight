"""Resource exposure: no model, no injection — read every MCP resource the
target advertises, directly, and check whether anything secret-shaped or
suspiciously-named is reachable with no gating at all. Resources are a
distinct MCP primitive from tools; this module is the only thing in the
suite that ever looks at them. See
docs/superpowers/specs/2026-08-17-m4-baseline-disclosure-design.md.
"""

from __future__ import annotations

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.llm import LLMProvider
from gaslight.core.secrets_scan import find_secret_like_strings, mask_secret
from gaslight.core.sink import Sink
from gaslight.core.target import Target

_SENSITIVE_NAME_KEYWORDS = ("confidential", "private", "restricted", "internal", "secret", "admin")


def _looks_sensitive_named(resource) -> bool:
    haystack = f"{resource.uri} {resource.name} {resource.description or ''}".lower()
    return any(keyword in haystack for keyword in _SENSITIVE_NAME_KEYWORDS)


class ResourceExposureAttack(AttackModule):
    key = "resource-exposure"
    name = "MCP Resource Exposure"
    description = (
        "Reads every resource the target exposes directly, no model involved, and checks "
        "whether anything secret-shaped — or suspiciously-named but unguarded — is reachable."
    )

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        if not target.resources:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="target exposes no MCP resources.",
                attempted=False,
            )

        secret_hits: list[str] = []
        sensitive_named: list[str] = []
        resource_texts: list[str] = []
        for resource in target.resources:
            try:
                result = await target.read_resource(str(resource.uri))
            except Exception:
                # Couldn't read it — whatever gating exists worked. Never
                # claim "reachable with no gating" for a resource we never
                # actually reached.
                continue
            text = Target.resource_text(result)
            resource_texts.append(text)
            if _looks_sensitive_named(resource):
                sensitive_named.append(str(resource.uri))
            for hit in find_secret_like_strings(text):
                secret_hits.append(f"{resource.uri}: {mask_secret(hit)}")

        fired = bool(secret_hits) or bool(sensitive_named)
        reasons = []
        if secret_hits:
            reasons.append(f"{len(secret_hits)} resource(s) contained secret-shaped content")
        if sensitive_named:
            reasons.append(
                f"{len(sensitive_named)} resource(s) sound sensitive "
                f"({', '.join(sensitive_named)}) but are reachable with no gating"
            )

        return Finding(
            attack_key=self.key,
            fired=fired,
            reason=" and ".join(reasons) if reasons else "no resource exposed anything sensitive.",
            raw_observed_text=resource_texts,
        )
