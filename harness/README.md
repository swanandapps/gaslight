# harness/ — Tier 2 hunt tooling

Operator tooling for pointing gaslight at many real, published MCP servers
at once. Not imported by the shipped package.

## Files

- `targets.txt` — one `npx|uvx <package> [args]` per line; `#` comments.
- `hunt.py` — the driver. Runs gaslight against each target, `--json`,
  collects fired findings into `hunt_results.json`.
- `runner.Dockerfile` — the locked-down per-target runtime image
  (`gaslight-test-runner`): node + python + uv, non-root uid 10001.
- `proxy.Dockerfile` — the socat sink-reachability proxy for the two-network
  isolation model (`gaslight-sink-proxy`).
- `hunt.Dockerfile` — the single-container model (`gaslight-hunt`):
  gaslight + runtimes in one image, so sink and target share loopback.

## Two ways to run

```
# Host mode — fast, proven (the method the prior 53-server round used).
# Runs the untrusted package with your own privileges: use for curated,
# reputable packages only.
python harness/hunt.py harness/targets.txt --host

# Isolated mode (default) — each target in a no-internet, non-root,
# read-only, all-caps-dropped container.
docker build -f harness/runner.Dockerfile -t gaslight-test-runner harness
docker build -f harness/hunt.Dockerfile   -t gaslight-hunt .
python harness/hunt.py harness/targets.txt
```

## Known issue (isolated single-container model)

The `--network none` single-container path currently stalls on the
model-driven attacks (injection-exfil is the first): the second in-container
`npx` spawn appears to contend on the shared npm-cache volume lock and hangs,
where the same run on host completes in ~20-30s. Verified not DNS (fails fast
under `--network none` in both Python and Node) and not the sink (binds
loopback, reachable). The deterministic, model-free attacks — which are the
real finding-generators for a black-box scan with `--llm scripted` — are
unaffected. Resolution options: per-spawn npm cache dir, disabling cacache
locks offline, or reverting to the proxy-based model (target-in-container,
gaslight-on-host) which was validated end-to-end in an earlier round.

Until then, hunts run in `--host` mode against curated reputable targets.
