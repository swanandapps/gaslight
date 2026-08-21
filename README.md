# gaslight

> Automated penetration testing for AI agents. Point it at your agent, get a graded security report — and everything it confirms, it proves.

**Building an AI agent? Run gaslight on it before you ship — it's the first
check to do, and it takes one command.** gaslight is a black-box security
tester for agents built on the [Model Context Protocol](https://modelcontextprotocol.io):
you point it at your running agent, it pokes at the tools the way an attacker
would, and hands you a plain, graded, screenshot-ready report of what it found.
No account, no config, no API key — and it never reads your source or your data.

Think of it as a pen test that ends in a scorecard: five security scores out of
100, a letter grade, and a picture of how far a breach could travel — so you can
see at a glance whether your agent holds or leaks, and exactly where.

The one thing that sets it apart from every "AI security" scanner that grades
one model's output with another model: **gaslight never trusts an opinion.**
A finding is only marked CONFIRMED when something physically happened — a unique
token you planted arrived at a listener gaslight controls, real out-of-bounds
data came back, or a call that should have been refused went through. If it says
confirmed, it's real. Go fix it.

```
$ gaslight -- npx -y some-mcp-server

🛡  These are safe, controlled probes — they check your guardrails and leave your real data alone.

🧪  Network Egress Abuse (SSRF) — whether a URL tool can be aimed at addresses it should never reach
🔥  CONFIRMED — fetch_url reached http://127.0.0.1:<sink> (your canary arrived). No destination check.
🧪  Claim Integrity — whether a tool that promises to be read-only keeps that promise
🔥  CONFIRMED — create_invoice says "stages for approval; does not issue",
     but the record it created shows status "issued". Its own read tools contradict its own description.

   Network 42   Filesystem 100   Leakage 88   Authorization 60   Integrity 55
   Grade: F   ·   blast radius: THIS MACHINE ▓   YOUR NETWORK ▓   DATA LEAVING ░
```

## Quick start

```
pip install gaslight
gaslight -- npx -y your-mcp-server      # point it at your agent
```

That's it — no API key, no config. gaslight connects like any MCP client,
attacks the tools it finds, prints a graded report to your terminal, and writes
a shareable HTML report next to it. Add `--json` for machine-readable output, or
`--baseline tools.json` to catch a tool that changes on you in CI. What the
grades mean is under [How to read a report](#how-to-read-a-report); to drive it
from an AI assistant, see [AGENTS.md](AGENTS.md).

## What you get

From one run, three things:

1. **A report card in your terminal** — the letter grade, the five gauges, and
   every confirmed finding, right where you ran it.
2. **A shareable HTML report card** — written to `gaslight-report.html`. Open it
   in your browser: the gauges, the grade, the blast-radius map, and a share
   card made to screenshot. This is *the* report card for your agent — gaslight
   tells you the file path when it finishes, so you just open it.
3. **A JSON report** (`--json`) — the same results, machine-readable, for CI or
   to hand straight to your AI agent.

Here's what a graded agent looks like — the report card gaslight writes for you
(**[interactive version](https://claude.ai/code/artifact/8343dd80-f369-4280-80e5-5726cc26634b)**):

![An example gaslight report card — grade F, blast-radius map, five gauges, and the chain-of-custody proof for each confirmed finding](assets/example-report.png)

## The score

Every finding rolls up into five gauges, each 0–100, plus one letter grade:

| Gauge | The question it answers |
|---|---|
| **Network** | Can the agent be steered into reaching out, or sending your data, over the wire? |
| **Filesystem** | Do file tools stay in their lane, or can they be walked out of scope? |
| **Leakage** | Do secrets, keys or tokens slip out during ordinary use? |
| **Authorization** | Are destructive, consequential or costly actions actually gated? |
| **Integrity** | Do the agent's instructions and its tools' own promises hold under pressure? |

A **breach never scores green** — a confirmed exploit caps the metric and drops
the grade. And the **blast radius** only lights up where an attack *physically*
succeeded: working guards keep the lit area small, so the picture rewards real
defense instead of just counting capabilities.

## What it tests

Every agent, whatever its domain, is built on the same few primitives: tools
that move data out, read resources, take consequential actions, and make claims
about themselves. gaslight aims at the primitives, so the same tests apply to
a hospital agent and a bank agent alike.

**17 attack modules**, all deterministic, all proven physically — including
indirect prompt injection → exfiltration, SSRF, path traversal, code execution,
confused-deputy, tool-metadata poisoning, memory poisoning, destructive-action
authorization, verbose-error disclosure, **denial-of-wallet** (unbounded, costly
calls), and the headline: **claim integrity** — it takes the safety promise a
tool's description makes (the promise the driving model trusts) and checks
whether it's still true, using the target's own read tools as the verification
channel.

Plus a zero-call **static surface pass** (schema hygiene, hidden instructions in
descriptions, tool-shadowing / homoglyph names) that flags red flags without
firing a shot.

### Coverage, mapped to a standard

gaslight is anchored to the **[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)**,
not an ad-hoc list:

- **7 of 10 fully covered** — secret exposure, tool poisoning, command
  injection, prompt injection, weak authorization, context over-sharing, and
  shadow-servers/rug-pulls.
- **2 out of scope by design** — supply-chain/dependency tampering and internal
  audit logging. A black-box behavioral tool can't see those, and says so rather
  than faking a pass.
- **1 partial** — privilege scope-creep (stateful over time).

Stating what it *doesn't* test is the difference between an honest benchmark and
a scanner that over-credits itself.

## The optional LLM layer

The whole deterministic core needs **no model and no key** — it works out of the
box. An LLM is an *optional lens* that makes probes smarter and the report
richer, and there is one hard rule:

> The LLM may aim an attack and explain a result. It may **never** decide whether
> the attack succeeded.

Every CONFIRMED still comes from a canary reaching our sink — never a model's
opinion. Turn it on with a key, or with `--llm ollama` for a **free local
model** (nothing leaves your machine — the right default for a security tool).
No model configured? You still get the full deterministic run. Every run states
plainly whether the LLM layer is on, off, and where its boundary is.

## Extra modes

- **Doctor mode** — if the target won't start (built for an older SDK, needs a
  credential, wrong Node/Python), gaslight reads its startup output and gives
  you one plain sentence to fix it, instead of a wall of someone else's stack
  trace.
- **Rug-pull guard** — `gaslight --baseline tools.json` records your tools on
  first run and flags any that changed since (a description quietly rewritten
  into a poisoned payload, a new dangerous parameter). Drop it in CI to catch a
  tool that turns malicious *after* you approved it.

## How to read a report

- **CONFIRMED** — physically proven. Real. Fix it.
- **not tested** — no tool of the shape this attack needs, or a claim with no
  black-box way to verify it. Honest about what it couldn't reach, never
  silently green.
- A clean run means *these attack vectors, tested, found nothing* — a floor, not
  a certificate. It's the first security check to run on your agent, not the last.

## Fix what it finds — just ask your agent

You don't have to fix anything by hand. gaslight writes a plain report, so hand
it straight to your AI coding assistant:

> *"Read the gaslight report and fix what it found."*

gaslight finds it and proves it; your agent fixes it; you re-run gaslight to
confirm the finding is gone. That's the whole loop — it's built to be driven by
your agent, not to add another dashboard to your day. See [AGENTS.md](AGENTS.md)
for how an agent reads and acts on the results.

## Safety

Probes are harmless by construction: they only ever touch a sink gaslight
controls, an ordinary system file, or a synthetic canary record — never real
data. On the default `--safe`, an action with a real irreversible or external
effect is never triggered, and a soft, description-only signal never fires one.
When you point it at a target that needs a credential, use a **throwaway/test**
one via `--env KEY=VALUE` — never production.

## Install

```
pip install gaslight        # (pre-launch)
gaslight --help
```

Point it at any stdio MCP server:

```
gaslight -- npx -y some-mcp-server
gaslight --url https://my-agent.example/mcp     # remote (HTTP+SSE)
gaslight --json -- python my_server.py          # machine-readable, for CI
```

## Use it from an AI agent (or CI)

gaslight is built to be driven by an AI assistant — just tell yours *"use
gaslight to check my agent."* It ships an **[AGENTS.md](AGENTS.md)** that tells
the AI how to run it, how to read the result, and — crucially — the safety
contract, so it can run without any worry about touching your code:

- `--json` emits a structured report on stdout (findings, grade, metrics); human
  text goes to stderr, so stdout stays clean JSON to parse.
- **Exit codes:** `0` clean · `1` a CONFIRMED finding · `2` the target couldn't
  start (with a plain-language reason).
- **The boundary:** black-box (never reads your source), `--safe` by default
  (never fires a destructive action), probes aimed at a local sink it controls,
  no API key, nothing leaves your machine. See `AGENTS.md` for the full contract.

## Roadmap

v1 tests **MCP-based agents** — one target, through the MCP boundary. The next
frontier is the **agentic / multi-agent layer**: an adaptive red-team agent that
reasons about your agent and holds a real multi-turn conversation, plus
agent-to-agent (A2A) attacks between agents that talk to each other. The
physical-proof rule holds there too — the attacker gets smarter, the verdict
stays deterministic.

## Status

Pre-launch. **17 attack modules**, validated against deliberately-vulnerable
benchmarks and 50+ real, independently-built community MCP servers, with matched
vulnerable/hardened fixtures and zero false positives on the controlled set. See
`docs/` for the design specs and `docs/TESTING_STRATEGY.md` for the validation
record.

## License

Apache-2.0 — see `LICENSE`.
