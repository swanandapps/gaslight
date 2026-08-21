# Contributing to gaslight

Thanks for wanting to help. gaslight is a security tool, so it holds itself to a
few hard rules — most of this document is about those rules, because they're
what make the tool trustworthy. Read the discipline section before adding an
attack.

## Getting set up

gaslight uses [uv](https://docs.astral.sh/uv/).

```
git clone https://github.com/<you>/gaslight
cd gaslight
uv sync
uv run pytest            # ~397 tests; all should pass
uv run gaslight --help   # run it from source
```

Try a real run against a throwaway target:

```
uv run gaslight -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## The discipline (non-negotiable)

gaslight's entire value is that a `CONFIRMED` finding is *real*. Three rules
protect that. A change that breaks any of them will not be merged.

1. **Physical proof, never a guess.** A finding may be marked `CONFIRMED` only
   when something physically happened: a unique canary token gaslight planted
   reached the local sink it controls, a known signature was returned (e.g. a
   world-readable system file), or a tool's own state contradicted its own
   stated promise. A finding must **never** be decided by a model's opinion or a
   heuristic guess. Softer signals belong in the static surface pass as
   `info`/`warn`, and never touch the grade.

2. **Payloads are benign by construction.** Every probe may only ever:
   touch gaslight's own local sink, read an ordinary world-readable system file
   (`/etc/hosts`, `/etc/passwd`), or plant a synthetic canary. A payload must
   **never** write, delete, modify real data, spawn a persistent/background
   process, or risk unbounded resource use. This is enforced by *never writing
   such a payload*, not by a runtime check. Consequential tools
   (destructive/exfil/write-shaped) must be skipped by targeting, so a probe
   never triggers a real side effect.

3. **Deterministic core.** The attack suite must run with no API key and no LLM.
   A model is an optional lens that can *aim* a probe or *explain* a result — it
   may never decide whether an attack succeeded.

If a change can't hold these, it's out of scope for gaslight, however useful it
might be elsewhere.

## Adding an attack

Attacks are small, independent modules. To add one:

1. **Write the module** in `src/gaslight/core/attacks/`, implementing the
   `AttackModule` interface (see any existing attack, e.g. `ssrf_probe.py` for a
   sink-proof attack or `path_traversal.py` for a signature-proof one).
2. **Add a matched fixture pair** in `tests/fixtures/`: one *vulnerable* MCP
   server the attack must fire on, and one *hardened* server it must stay silent
   on. This pair is how we keep false positives at zero.
3. **Map it into a metric** in `core/metrics.py` (Network / Filesystem /
   Leakage / Authorization / Integrity) so it's scored.
4. **Register it** in `cli._build_attacks`.
5. **Write tests** that assert it fires on the vulnerable fixture, stays silent
   on the hardened one, and declines honestly (`attempted=False`) when no
   suitable tool exists.

Run `uv run pytest` and make sure everything is green.

## Style

Match the surrounding code — its naming, its comment density, its idioms. The
codebase favors small, well-documented functions and comments that explain *why*
a choice was made (especially safety and false-positive reasoning). New
user-facing copy stays plain and calm; keep alarming language out.

## Pull requests

- Fork, branch, keep the change focused.
- All tests green (`uv run pytest`), and add tests for what you changed.
- In the description, say what the change does and — for an attack — what its
  *proof* is and why it can't false-positive.

## Reporting a vulnerability in gaslight itself

If you find a security issue in gaslight (not in a target it scans), please
report it privately rather than opening a public issue — open a GitHub security
advisory on the repo, or contact the maintainer. We'll coordinate a fix and
credit you.

## Scope

gaslight tests a single MCP-based agent's runtime, black-box. Things that are
out of scope by design (see `README.md`): supply-chain/dependency analysis,
internal audit-logging, and multi-agent attacks. Contributions that fit the
black-box, physically-proven model are the ones that belong here.
```
