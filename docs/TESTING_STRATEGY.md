# Testing Strategy

How gaslight validates itself, and against what. Written down for the first
time in 2026-08 — the practice below has been running informally since M4,
this just names it and makes the gaps visible.

**Core rule for every tier below:** only test systems we own, systems we run
ourselves, or systems whose rules explicitly say testing is welcome. Public
reachability is never authorization. This rule doesn't loosen as the tiers
get more "real" — it's the same rule at every level.

## Tier 0 — gaslight's own fixtures

**What it is:** a matched pair of tiny MCP servers per attack — one
vulnerable, one fixed — living in `tests/fixtures/`. Every attack module's
true-positive/false-positive test pair is Tier 0.

**What's allowed:** anything. We wrote every line of these fixtures.

**What "done" looks like:** the attack fires against the vulnerable fixture,
stays silent against the fixed one, and the false-positive guard is a real
test, not a rubber stamp.

**Where we stand:** done, every milestone, no exceptions. M1 through M6 each
shipped with this pair for every new attack (e.g. `unguarded_destructive_server.py`
/ `guarded_destructive_server.py` for M5a, `unguarded_file_read_server.py` /
`guarded_file_read_server.py` for M6).

**Known limit:** Tier 0 only proves the *mechanism* works. It says nothing
about whether the mechanism generalizes to a real target's real code —
that's what Tier 1 is for.

## Tier 1 — real, deliberately vulnerable practice targets

**What it is:** independently-built benchmarks whose whole purpose is to be
attacked — Damn Vulnerable MCP Server (DVMCP) is the one we've used.

**What's allowed:** whatever the benchmark's own rules say. DVMCP is built
to be attacked; there's no separate permission step.

**What "done" looks like:** run gaslight against the real challenge, and
report the *actual* result — including when it's not a clean pass. This is
the discipline that's mattered most so far.

**Where we stand:** done for every recent milestone, and it's already caught
a real bug. M4 checked DVMCP's tool-poisoning and disclosure challenges
during research. M5a validated instruction-override against DVMCP and other
public benchmarks. **M6 is the clearest example of why this tier is worth
the effort**: `PathTraversalAttack` initially reported a false "CONFIRMED"
against real DVMCP Challenge 3 — its own fixtures never would have caught
this, because the false-positive shape (a target returning a friendly "file
not found" string instead of a protocol error) doesn't occur in fixtures we
wrote to be either clearly vulnerable or clearly guarded. Only a real,
independently-built target with its own idiosyncratic code surfaced it.

**M7 update:** `SsrfProbeAttack` (network egress abuse) has no Tier 1
validation yet — Damn Vulnerable MCP Server's 10 challenges were checked
during M7's design and none expose a URL-fetching tool for this attack
to probe. Ships with Tier 0 (fixture) validation only until a suitable
real target is found or built.

**M8 update:** `CodeExecutionAttack` (dangerous code execution) validated
against real Damn Vulnerable MCP Server Challenge 8 (Malicious Code
Execution) — confirmed fire via the network-trap category, matching the
challenge's own documented zero-sandboxing vulnerability. Unlike M7,
this attack has real Tier 1 coverage.

**Local setup note:** the DVMCP clone lives outside the repo in a scratch
directory, not committed — see any recent milestone's plan document for the
exact path and the one-line patch (`mcp.run(transport="stdio")`) needed to
run its challenges over real stdio transport.

## Tier 2 — self-hosted real open-source MCP servers

**What it is:** real, actively-maintained MCP server projects, run locally
under our own control — not built to be broken like Tier 1, just real code
with real (if sometimes accidental) bugs.

**What's allowed:** run it locally, on synthetic/throwaway data, in an
isolated environment. Never point at someone else's running instance.

**Isolation baseline, before running anything here:**
- one container or VM per target, never running as root
- network egress denied by default, with only gaslight's own local sink
  allowed through
- disposable, least-privilege credentials — never a real API key or a real
  database
- synthetic data only — no real emails, no real names, no real anything
- a way to snapshot/tear down cleanly between runs

**Where to look, when we get here** (not evaluated yet, just a starting
list): the [Glama MCP registry](https://glama.ai/mcp/servers), Smithery,
and mcp.so are the largest catalogs of real, runnable MCP servers. Categories
worth prioritizing, roughly in order of how much new attack surface they'd
exercise beyond what Tiers 0/1 already cover:
- a database MCP server (SQL tools, schema introspection — exercises
  over-permissioned write/read scope in a way none of our current fixtures do)
- a filesystem MCP server (a *second*, independently-built path-traversal
  surface, to cross-check `PathTraversalAttack` against code we didn't write
  and DVMCP didn't write either)
- a browser/fetch MCP server (indirect injection via real page content,
  not a fixture we scripted)

**Where we stand:** started — one data point so far. Ran `PathTraversalAttack`
against the official MCP filesystem reference server
(`@modelcontextprotocol/server-filesystem`), self-hosted locally against a
throwaway scratch directory with synthetic files, one of them planted just
outside the allowed root. Result: a clean, honest non-fire — the real server
rejected both relative (`../secret.txt`) and absolute-path traversal with an
explicit "Access denied - path outside allowed directories" error, confirmed
by a direct manual call outside the attack module too, not just the attack's
own report. No false positive, no false negative. `ToolAuthzProbeAttack` also
ran and declined honestly (no exfil-shaped tool exists on a filesystem
server) — correct behavior, not a gap.

Pushed further against four more official/reference servers (memory, git,
sqlite, fetch — all self-hosted locally, all real, independently-built
code). This is where Tier 2 earned its keep:

- `SsrfProbeAttack` **fired for real** against the official fetch reference
  server — it has no destination confinement at all. A genuine finding
  against real, currently-published code, not a fixture.
- `DestructiveActionAuthzProbeAttack` run for real (`--no-safe`, both
  targets fully disposable) against the git server's `git_reset` and the
  memory server's `delete_entities` **initially reported both as
  guarded — falsely.** Manual verification proved neither has any real
  protection. Root cause and fix: see commit `c71d461` — the probe was
  misreading "rejected because our placeholder argument was invalid" as
  "rejected by a real authorization check." Fixed by extracting real
  values leaked in the rejection's own error text and retrying with them;
  re-run after the fix now correctly reports `fired: True` for both.

This is exactly the scenario this tier exists for: a false negative in
our own shipped code, found only by testing against real software we
didn't write, that Tier 0/1 never surfaced.

**Scaled up: 53 more real, independently-built community/reference MCP
servers**, self-hosted locally across filesystem, browser, git, memory,
sqlite, calculator, terminal, and fetch categories (npm + pip). 42 of 53
connected; 11 failed for reasons that are themselves informative — not
our tool's fault: missing native binaries never built by a bare `npx`
(gitnexus), needing an interactive init step or a runtime we don't have
(toon-memory, claude-memory-hub), a malformed tool schema in the target
package itself (`@mseep/mcp-server-sqlite-npx`), dead/placeholder PyPI
packages (`mcp-server-memory`), and one real bug in a published
package's own entrypoint wiring (`mcp-server-shell`'s console script
calls an `async def` synchronously, so it never runs). Roughly 1 in 5
packages in this pool was simply broken — a real signal about ecosystem
quality, not something to paper over.

**5 real, confirmed findings against real targets**, none of them ours:
- `@redf0x1/mcp-server-filesystem` — an unscoped `run_command` tool let
  code execution reach an arbitrary outbound network address.
- `@agent-infra/mcp-server-browser` and `@mindstone/mcp-server-browser-automation`
  — both navigate to loopback/internal addresses with no restriction.
- `@wonderwhy-er/desktop-commander` — `read_file` escaped its intended
  directory via `../../../../../etc/hosts` (best-effort tier).
- `d33naz-mcp-fetch` — confirmed SSRF, canary physically received.

**Honest gaps this round also surfaced in our own coverage**, not fixed
yet: `chrome-devtools-mcp` and a generic `mcp-server-browser` package use
non-standard tool names (`set_url_tab`, `navigate_page`, `evaluate_script`)
that our keyword-based tool discovery never matched — their "declined"
results mean never fairly tested, not confirmed safe. `mssql-mcp-server`
exposes a 32-tool surface including `execute_query` that none of our
current attacks are shaped to probe (no SQL-injection-class attack
exists yet) — matches this doc's own already-noted database-category gap.

Still worth trying, not yet attempted: a database server with a live
backend, and a from-scratch server built specifically to have zero
MCP-ecosystem conventions to pattern-match against.

**Isolation baseline upgraded from "runs directly on the host" to real
per-target containment**, closing the gap against this tier's own stated
requirements above. Each target now runs non-root, with every Linux
capability dropped and a read-only root filesystem, on a Docker network
with no route to the real internet at all (confirmed: a plain internet
request from inside it fails outright). Reaching gaslight's own local
sink from a network with no route out at all is the same restriction as
reaching anywhere else — solved with a small proxy container on both
networks, forwarding only to the sink's own port, so the isolated target's
only reachable peer is that one proxy, nothing else.

Two real wrinkles surfaced building this, both fixed, not just noted:
`core/sink.py` gained `loopback_hosts()` (`GASLIGHT_EXTRA_SINK_HOSTS`,
comma-separated) so `SsrfProbeAttack`/`CodeExecutionAttack` can be told
about a reachable proxy address instead of only ever trying
`127.0.0.1`/`localhost`, which no isolated container can ever reach (see
commit `58200b6`) — and a target that needs a first-time
`npx`/`uvx` download can't run on a network with no internet route at
all, so isolated runs now pre-warm a shared package cache over a normal
connection first, then run the actual test fully offline from that cache
(`NPM_CONFIG_OFFLINE=true`). Re-validated end to end: the same real
`d33naz-mcp-fetch` SSRF finding from the non-isolated round above still
fires correctly from inside the fully locked-down container, and the
known-clean `@adpharm/mcp-server-filesystem-ro` result stays clean —
same real answers, now backed by real isolation.

## Tier 3 — permissioned real targets (the two production agents)

**What it is:** the user's own two real production agents, mentioned early
in this project as the eventual goal.

**What's allowed:** private, exploratory testing only, on infrastructure the
user owns. **Not for public release. Not for testing anyone else's agents.**
This tier requires the user's own explicit go-ahead each time — no standing
authorization is implied by this document.

**What a real run here needs, decided in advance, every time:**
- exact endpoints/environments and a time window
- which attack classes are in scope, and which are explicitly excluded
- confirmation the target is staging/synthetic data, not live customer data
- a rate limit and a way to stop the run immediately if needed

**What "done" looks like:** a report the user can actually act on — which
findings are real, which tier of confidence each one has (Tier 0/1-grade
"confirmed" vs. Tier 2/3-grade "best-effort," matching the confidence
language `PathTraversalAttack` already introduced in M6), and what to fix
first.

**Where we stand:** not scheduled. Everything in Tiers 0–2 exists to make
this tier worth running — the whole point of building Tier 0/1 discipline
first is arriving here with a tool that doesn't cry wolf.

## Tier 4 — public bug-bounty / vulnerability-disclosure programs

**What it is:** external programs that explicitly list AI agents or MCP
endpoints as in-scope for security testing.

**What's allowed:** exactly what the program's own rules say, nothing more.
A public bounty program is not blanket permission to test everything that
program's company runs — only what's explicitly in scope.

**Where we stand:** not relevant yet. Revisit once Tier 3 has actually run
and the tool's false-positive rate is proven low enough to trust against a
target we can't personally investigate line-by-line if something looks odd.

## A separate, not-yet-decided idea: structured fixture manifests

Worth naming even though it's out of scope for this document: every Tier 0
fixture pair could carry a small structured file stating what vulnerability
class it represents, what severity it maps to, and what exact condition
counts as a pass — checkable by the test suite itself, so a fixture's claim
and its actual behavior can never quietly drift apart. This is real tooling
work, not a documentation change, and hasn't been scoped or approved yet.

## What we can honestly say publicly about this, and what we can't

**Fair to say:**
- "Every finding is proven with a planted marker reaching a controlled
  sink, or a deterministic code-level check — never an LLM's opinion."
- "Validated against real, independently-built vulnerable targets (Damn
  Vulnerable MCP Server), not just our own fixtures."
- "When a real-target validation run doesn't cleanly pass, we say so and
  fix it — see M6's own history for a real example, not a hypothetical."

**Not fair to say, and won't be for a while:**
- "We scanned hundreds of public MCP servers." (We haven't. Tier 2 hasn't
  started, and Tier 4 doesn't apply.)
- Anything implying testing against systems we don't own or don't have
  explicit permission to test.
- "This tool has been validated on real production agents" — true only
  after Tier 3 actually runs, and even then, only in the private,
  non-public sense that tier is scoped to.
