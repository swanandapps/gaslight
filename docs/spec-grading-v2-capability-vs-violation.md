# Spec — Grading v2: Security Grade vs Exposure (capability vs violation)

Status: proposed · Author: Swanand Kadam · Target: gaslight core
Motivation source: the 136-server hunt + the decisive desktop-commander / markitdown
re-tests (2026-09).

---

## 1. Problem

gaslight currently collapses two fundamentally different things into one signal —
`fired → severity → letter grade`:

1. **A real security failure** — the server crossed a boundary it is expected to
   enforce. (markitdown reaching a loopback/internal address and returning the
   body; a sandboxed reader bypassing a configured root.)
2. **By-design power** — the server did exactly what it exists to do. A shell
   server ran a command. A `delete_*` tool deleted. A file tool with no configured
   restriction read a file.

Today both produce **grade F**. That is wrong, and it is the tool's biggest
credibility risk. Evidence from our own testing:

- **desktop-commander → F "path-traversal" was a false positive.** It was scanned
  in its documented default (`allowedDirectories: []` = full filesystem access).
  There was no boundary to escape. When we set a real boundary, every traversal
  attempt (`/etc/hosts`, `../../…`, traversal-from-inside) was **blocked** with
  *"Path not allowed… Must be within /private/tmp/dc_allowed."* The tool enforces
  its boundary correctly; gaslight reported an escape anyway.
- **The shell / delete / git findings are by-design.** Running a command *is* the
  shell server's purpose; deleting *is* the delete tool's purpose. "No code-level
  check exists" is inferred from the absence of an error, and the check is normally
  the caller/token — not the server.
- **markitdown SSRF was real and survived.** Canary on loopback, `convert_to_markdown`
  fetched it and returned the body. Reaching a reserved/internal range is a boundary
  a fetcher is expected to enforce. This is the shape of a true VIOLATION.

Root cause (from the code map): **no attack establishes that a boundary/policy is
declared or enforced before treating success as a violation.** `path-traversal`
infers "intended directory" from the tool merely being a file reader
(`path_traversal.py:232-235`, no confinement check). `destructive-authz-probe`
fires on `not result.is_error` with no notion of a claimed guard
(`destructive_authz_probe.py:139-149`, flagged as a known limitation in its own
docstring).

## 2. The model: two axes

Replace the single letter with **two independent, separately-reported axes.**

### Axis A — Security Grade (A / B / C / F)
Derived **only from VIOLATIONs** — a boundary the server (or an industry standard)
is expected to enforce was crossed. Same severity→letter mapping as today
(`critical→F`, `high→C`, `medium→B`, none→A), but capability-only servers no longer
land here.

### Axis B — Exposure (informational: LOW / MEDIUM / HIGH / CRITICAL)
Derived from **CAPABILITY** findings — the blast radius the server hands an agent,
by design. Arbitrary command exec, unrestricted filesystem read/write, unguarded
destructive ops, arbitrary network egress. **Never a letter downgrade on its own.**

This is the credible, and more useful, output. A shell server with no bugs becomes:

> **Security Grade: A** (no violations) · **Exposure: CRITICAL** (arbitrary command
> execution — safe only under isolation).

That is honest, unkillable, and it *is* the systemic thesis in a single line: most
servers are "A / high-exposure" — no bug, enormous blast radius — and that is the
ecosystem risk when they are wired into an agent that reads untrusted input.

### Finding disposition (the new classifier)
Every fired finding is tagged with a `disposition`:

- **`violation`** — crossed an enforced/expected boundary. Feeds Security Grade.
- **`capability`** — by-design power, no boundary in that category to cross. Feeds
  Exposure.
- **`hygiene`** — minor info leak (paths in errors) or heuristic-only (secret-shaped
  content). Caps Security Grade at B and is labelled *verify*.

**Decision rule (uniform across boundary-style attacks):**
> A powerful behavior is a **violation** only if the server **refuses something in
> that category** (a boundary exists) and our payload got past that refusal — OR it
> reached a target that is a violation by industry standard (a reserved/internal
> network range; a safety claim the tool advertised but didn't honor). If the server
> refuses *nothing* in that category, the behavior is **capability**.

## 3. Data-model changes

`src/gaslight/core/attacks/base.py` — extend `Finding` (43-99):

```python
disposition: str = "violation"   # "violation" | "capability" | "hygiene"
confidence: str = "confirmed"    # "confirmed" | "best-effort"  (promote from reason text)
control_observed: str | None = None  # what the boundary-probe saw, for the report
```

- `confidence` is promoted from free text into a field. Today "confirmed" vs
  "best-effort" lives only inside `reason` (path_traversal.py:230, ssrf_probe.py:101/117,
  code_execution.py:153/173) and never reaches the grade. Make it structured and emit it.
- Keep `severity` as-is (per-finding override → `_DEFAULT_SEVERITY`).

## 4. Per-attack changes

### 4.1 path-traversal (`core/attacks/path_traversal.py`) — add a boundary control probe
Before any traversal payload, do a **control read of an out-of-scope absolute path**
(e.g. `/etc/hosts` directly, no `../`).

- Control **succeeds** → the tool has no confinement → emit **`capability`**
  ("unrestricted filesystem read — by design"), *not* a traversal violation. Set
  `control_observed`. This alone fixes the desktop-commander false positive.
- Control **refused**, but a traversal / encoded payload then **succeeds** → a
  boundary exists and was **bypassed** → **`violation`** (the real path-traversal),
  confidence per the existing marker/well-known-file tier.
- Control refused **and** traversal refused → `fired=False` (enforces correctly).

### 4.2 destructive-authz-probe (`core/attacks/destructive_authz_probe.py`) — reclassify
`not is_error` on a tool whose declared purpose is destructive is **`capability`**
by default ("unguarded destructive tool — executes on request, no confirmation"),
feeding Exposure, not an F.

Escalate to **`violation`** only when there is a bypassed guard:
- the tool advertises a safety property it breaks (defer to / cross-reference
  `claim-integrity`), or
- a reduced-privilege probe still succeeds (future: scoped/read-only token path).

Until a bypass signal exists, this attack should not produce an F.

### 4.3 code-execution-probe (`core/attacks/code_execution.py`) — control probe
Mirror 4.1. Probe whether the tool **refuses any command** (send a sentinel that a
blocklist would reject — e.g. a commonly-blocked binary).

- Refuses nothing → arbitrary exec by design → **`capability`** (Exposure CRITICAL).
- Refuses the sentinel but our canary payload (obfuscation / substitution) executes
  anyway → blocklist **bypass** → **`violation`** (confirmed via sink as today).

The sink-received network trap stays the proof mechanism; only the disposition
changes based on whether a boundary was bypassed.

### 4.4 ssrf-probe (`core/attacks/ssrf_probe.py`) — keep as violation, tighten wording
Reaching a **reserved/internal range** (loopback, RFC1918, link-local `169.254/16`,
metadata) is a violation by industry standard — no control probe needed; keep the
sink-confirmed fire as **`violation`**. Optionally strengthen: confirm a *public*
fetch works (proves it's a functioning fetcher) so the finding reads "fetches
public URLs *and* internal ranges — no SSRF filter." markitdown is the reference
case: converter + returns the internal body = strongest violation in the corpus.

## 5. Grade / scorer changes (`core/scorer.py`)

- `grade(findings)` (89-122): filter to `disposition == "violation"` before computing
  `worst_severity`. `capability` and `hygiene` never set the letter.
- **Confidence weighting:** a `best-effort` violation caps the letter at **C** (and
  the summary says "unconfirmed — verify"); only `confirmed` violations can reach F.
  This stops a heuristic hit from driving an F alone.
- **Hygiene cap:** `hygiene` findings cap the letter at **B**.
- Add `exposure(findings) -> ExposureResult` (new): rank the `capability` findings
  into LOW/MEDIUM/HIGH/CRITICAL by category (exec/destructive/fs-write > fs-read/net).
- `GradeResult` summary text (`_fired_detail`, 125-191) updated to speak in
  violations; add a parallel exposure summary.

## 6. Report changes

### JSON (`cli.py:_report_json` 411-479)
- Per finding, emit `disposition`, `confidence`, `severity` (currently only
  `attack_key/fired/attempted/reason` — 436-444).
- Add top-level `exposure: {rating, drivers:[...]}` beside `grade`.
- Split `findings` presentation into `violations` vs `capabilities` vs `hygiene`
  (or keep one list + the disposition field; consumer groups).

### HTML (`core/reporter.py`)
- Two headline chips: Security Grade + Exposure (reuse `_GRADE_COLOR` 46; add an
  exposure palette).
- `_confirmed_view` (657-666) → "Violations" section; new "Exposure / blast radius"
  section for capabilities; "Hygiene (verify)" for the rest.

## 7. Cleanup / correctness

- **Stale docs:** `core/metrics.py:18` and `:32` still say "any confirmed fire is an
  F" — false since the severity-tiered scorer landed. Update to the two-axis model.
- Exit code (`cli.py:962`, returns 1 if `fired_count > 0`): change to return 1 only
  when a **violation** fired, so CI on a high-exposure-but-clean server passes.
  (Consider `--fail-on={violation,exposure,any}` for flexibility.)

## 8. Test plan

- **Regression fixtures (real behavior, from our tests):**
  - desktop-commander default → expect **Grade A, Exposure CRITICAL**, path-traversal
    disposition `capability`, no F. (Today: wrongly F.)
  - desktop-commander with a set `allowedDirectories` + traversal → expect
    `fired=False` (enforces).
  - markitdown → expect **Grade F**, ssrf disposition `violation`, confirmed.
  - a shell server with no blocklist → Grade A, Exposure CRITICAL, code-exec
    `capability`.
- Unit-test the decision rule for each attack (control-refuses / control-allows /
  bypass) directly against a stub target.
- Snapshot the new JSON shape.

## 9. Out of scope (later)

- Scoped/read-only-token authz bypass probing (the real test for destructive
  violations).
- Per-target policy import (letting a user declare the server's intended boundary so
  gaslight grades against it).
- Migrating `metrics.py` scoring onto the two-axis model (this spec touches the
  letter grade + exposure; the numeric metric layer can follow).

## 10. Implementation order (sectioned for incremental execution)

1. Data model — `Finding.disposition/confidence/control_observed` (§3) + emit in JSON (§6 JSON).
2. Scorer — violation-only grade + confidence/hygiene caps + `exposure()` (§5).
3. path-traversal control probe (§4.1) + its regression fixtures (§8).
4. destructive-authz reclassify (§4.2).
5. code-execution control probe (§4.3).
6. ssrf wording/strengthen (§4.4).
7. HTML report two-axis (§6 HTML).
8. Cleanup: metrics.py docs + exit-code (§7).

Each section is independently testable; land 1–2 first (they unblock honest grades),
then the per-attack precision in 3–6.
