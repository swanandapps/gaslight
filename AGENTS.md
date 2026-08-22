# Using gaslight from an AI agent

This file is written for an **AI coding assistant** (Claude Code, Cursor, etc.).
It tells you how to run `gaslight` correctly, how to read its output, and — most
importantly — why it is safe to run without worrying about breaking the user's
code. If a user says *"use gaslight to check my agent,"* follow this.

`gaslight` is a black-box security scanner for MCP-based AI agents. You point it
at a running MCP server; it attacks the tools it finds and returns a graded
report. Every finding it marks CONFIRMED is physically proven — never a guess.

## TL;DR

```
uvx gaslight --json -- <command that launches the MCP server>
```

Parse the JSON on stdout. `grade` is A–F. `findings[]` with `fired: true` are
real. Exit code `1` means at least one CONFIRMED issue, `0` means clean.

## When to use it

- Before the user ships or publishes an MCP server or agent.
- In CI, to catch a tool that changed since it was approved (see `--baseline`).
- Whenever the user asks *"is my agent / MCP server secure?"*

## How to run it

**Install:** run it **isolated** — `uvx gaslight` (no install) or `pipx install gaslight`. **Do NOT `pip install gaslight` into the user's app virtualenv** — it can change the app's dependencies (e.g. the MCP SDK version) and break the app. gaslight runs the target as a separate process, so it never needs to share the app's venv. If the agent runs from a project venv, point the launch command at that venv's Python (e.g. `.venv/bin/python -m pkg.server`) so the agent keeps its own dependencies.

**Point it at a target:**
```
gaslight -- npx -y some-mcp-server        # a stdio MCP server
gaslight --url https://host/mcp           # a remote HTTP+SSE server
gaslight --json -- python server.py       # machine-readable — USE THIS to parse
```

**Flags worth knowing:**
| Flag | Use |
|---|---|
| `--json` | Machine-readable report on **stdout** (all human text goes to stderr, so stdout is clean JSON). |
| `--safe` / `--no-safe` | `--safe` is the default. Keep it. |
| `--env KEY=VALUE` | Pass a **throwaway/test** credential if the server needs one to boot. Never a production secret. |
| `--baseline FILE` | CI rug-pull guard: records the tool set on first run, flags any tool that changed on later runs. |
| `--llm ollama` | Optional free local model for richer output. Never required; never decides a verdict. |
| `--skip k1,k2` | Skip named attacks (e.g. a raw-SQL tool wired to a real warehouse). |

## What gaslight will NEVER do — the safety contract

You can run it without worrying about the user's system. On the default `--safe`
setting, gaslight:

- **Never reads the user's source code.** It is black-box — it only sees the
  tools the server exposes over MCP, exactly like any other client.
- **Never performs a destructive or irreversible action.** Delete/reset-style
  tools are probed for *authorization*, but the destructive call is not actually
  made.
- **Aims its network probes at a dead local address it controls** (its own
  listener), not at the internet or the user's infrastructure.
- **Needs no API key**, and with no model (or a local one) **sends nothing off
  the machine**.
- **Only tests the one target you point it at.**

## The ONE thing to be careful about

gaslight sends **real (but benign) attack payloads** to whatever target it is
pointed at. So:

- Point it at a **local / test / throwaway** instance — **never a production
  backend**.
- If the server needs a credential, pass a **throwaway** one via `--env` — never
  a production secret.
- Do not aim `--url` at a production endpoint.

If you are unsure whether a target is production, ask the user before running.

## How to read the result

**Exit code:**
- `0` — clean: no CONFIRMED findings.
- `1` — at least one CONFIRMED finding. The agent has a proven security issue.
- `2` — the target could not be started or reached. gaslight prints a
  plain-language reason (old SDK, needs a credential, wrong Node/Python, bad
  command). This is not a security verdict — the target never ran.

**JSON shape (`--json`):**
```json
{
  "target": "…",
  "tool_count": 6,
  "grade":   { "grade": "F", "fired_count": 2, "total_count": 17, "summary": "…" },
  "findings":[ { "attack_key": "ssrf-probe", "fired": true, "attempted": true, "reason": "…" } ],
  "metrics": { "average": 60, "scores": [ { "name": "Network", "score": 0, "band": "red", "breached": true } ] },
  "surface": [ { "severity": "warn", "category": "unconstrained-field", "tool_name": "run_sql", "message": "…" } ],
  "llm":     { "active": false, "provider": "scripted", "role": "off", "decides_verdict": false }
}
```

**What the fields mean:**
- `fired: true` → **CONFIRMED**. Physically proven — a token gaslight planted
  reached its listener, or a protected file came back. Real. Report it and help
  the user fix it.
- `attempted: false` → **NOT TESTED**. No tool of the shape this attack needs,
  or nothing verifiable black-box. This is an honest gap, **not** a pass — don't
  report it as "secure."
- `metrics.scores[].score` is 0–100 (or `null` when every check for that metric
  was N/A). `breached: true` means a confirmed exploit capped that metric.
- `surface[]` are **static warnings** (schema hygiene) — `info`/`warn` only.
  They never change the grade and are not CONFIRMED exploits. Surface them as
  "worth reviewing," not as proven vulnerabilities.

## The confidence model — why you can trust it

gaslight **never** marks something CONFIRMED on a guess or a model's opinion.
Every CONFIRMED is backed by physical proof. So:
- Trust a CONFIRMED — it really happened.
- Trust a clean gauge — those vectors were tested and nothing fired.
- A clean overall run means *"these attack vectors, tested, found nothing"* — a
  floor, not a certificate. It is the first security check to run, not the last.

The optional LLM layer only makes probes smarter and explains results. It can
**never** decide whether an attack succeeded.

## Setting up a target that needs a backend (for full coverage)

Many agents' tools only work with a live backend (a database, an API). Without
one, those tools error and gaslight honestly reports them "not tested" — partial
coverage. If you're asked for a *full* scan, wire up a **test** backend first.
You have the project context to do this; gaslight can't and won't guess it.

1. **Find how the agent connects** — look for `DATABASE_URL` / API keys in
   `.env`, `.env.example`, `docker-compose.yml`, or the project's config/settings.
2. **Provide a THROWAWAY/TEST backend — never production.** Options:
   - Point at a local/test database the project already uses for testing.
   - Spin up a disposable one (e.g. `docker compose up` a local db service, or a
     temporary Postgres/SQLite) and let the app run its migrations if it does so.
   - ⚠️ Do NOT reuse a production `DATABASE_URL` you find in `.env` — gaslight
     sends real payloads (including a SQL probe). If you're unsure whether a
     connection is production, ask the user before using it.
3. **Pass it via `--env`** (throwaway values only), launching from the repo root
   with the app's own venv Python:
   ```
   uvx gaslight -- .venv/bin/python -m pkg.server --env DATABASE_URL=postgresql://localhost/app_test
   ```
4. **Re-run and check the Coverage line** — the "couldn't run — backend
   unreachable" count should drop as the tools come alive.

## If the user asks you to fix the findings

This is the main loop: gaslight finds and proves the issue, and **you fix it.**
Each `fired: true` finding's `reason` says exactly what happened and which tool.
Typical fixes:

- **SSRF / network egress** — add an allowlist so the URL tool can't reach
  internal or loopback addresses (block `127.0.0.1`, `169.254.169.254`, private
  ranges).
- **Path traversal** — confine the file tool to an intended directory; reject
  `..` and absolute paths before opening.
- **Code / command execution** — never build a shell command or SQL from
  untrusted input; parameterize, sandbox, or drop the tool.
- **Secret / path leak** (leakage, error disclosure) — mask secrets and internal
  filesystem paths in tool output and in error messages.
- **Unconstrained field** (surface warning) — add `maxLength`, `pattern`, or
  `enum` to path/url/command fields in the tool's input schema.
- **Missing destructiveHint** (surface warning) — annotate destructive tools so
  MCP clients can gate them behind confirmation.

After you make a fix, **re-run gaslight and confirm the finding is gone** (the
attack now reports `fired: false`, and the exit code returns to `0`). Don't
claim it's fixed until gaslight agrees.

## What gaslight does NOT cover — don't overclaim

It is a black-box behavioral scanner of one MCP target's runtime. Out of scope
**by design** (it cannot see these, and says so rather than faking a pass):
- Supply-chain / dependency tampering (a source/SCA concern).
- Internal audit-logging quality.
- Multi-agent / agent-to-agent attacks (on the roadmap).

When you report results, describe them as *"gaslight tested the running tools
and found X"* — not as a complete security audit.
