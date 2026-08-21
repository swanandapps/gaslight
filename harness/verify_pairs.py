"""Controlled true/false-positive check: matched vulnerable/hardened fixture
pairs with known ground truth. Vulnerable MUST fire; hardened MUST NOT."""
import json, subprocess
AS=".venv/bin/gaslight"; PY=".venv/bin/python"
PAIRS=[  # (label, vulnerable fixture, hardened fixture, attack that should fire)
 ("injection -> exfil","vulnerable_server","hardened_server","injection-exfil"),
 ("path traversal","unguarded_file_read_server","guarded_file_read_server","path-traversal"),
 ("code execution","unguarded_code_exec_server","guarded_code_exec_server","code-execution-probe"),
 ("SSRF","unguarded_fetch_server","guarded_fetch_server","ssrf-probe"),
 ("destructive authz","unguarded_destructive_server","guarded_destructive_server","destructive-authz-probe"),
 ("claim integrity","lying_staging_server","honest_staging_server","claim-integrity"),
 ("read-only lie","lying_readonly_server","honest_readonly_server","claim-integrity"),
 ("resource exposure","exposed_resource_server","gated_resource_server","resource-exposure"),
 ("baseline disclosure","leaky_status_server","redacted_status_server","baseline-disclosure"),
 ("memory poisoning","memory_agent_server","hardened_memory_agent_server","memory-poisoning"),
 ("error disclosure","verbose_error_server","generic_error_server","error-disclosure"),
 ("encoded traversal","naively_guarded_file_read_server","guarded_file_read_server","path-traversal"),
 ("b64 code exec","denylisted_code_exec_server","guarded_code_exec_server","code-execution-probe"),
 ("arg smuggling","smuggled_path_server","inert_field_server","argument-smuggling"),
 ("confused deputy","vulnerable_server","hardened_server","confused-deputy"),
]
def run(fx):
    p=subprocess.run([AS,"--llm","scripted","--no-safe","--json","--output","/tmp/p.html","--",
                      PY,f"tests/fixtures/{fx}.py"],capture_output=True,text=True,timeout=400)
    t=p.stdout[p.stdout.find("{"):] if "{" in p.stdout else ""
    if not t: return None
    return {f["attack_key"] for f in json.loads(t)["findings"] if f["fired"]}
tp=fp=fn=tn=0
for label,vuln,hard,attack in PAIRS:
    v=run(vuln); h=run(hard)
    if v is None or h is None: print(f"  {label:<22} RUN FAILED"); continue
    caught = attack in v; clean = attack not in h
    tp += caught; fn += (not caught); tn += clean; fp += (not clean)
    print(f"  {label:<22} vulnerable:{'CAUGHT ' if caught else 'MISSED '} hardened:{'clean' if clean else 'FALSE POSITIVE'}", flush=True)
print(f"\n  true positives {tp}/{tp+fn}   |   false positives {fp}/{fp+tn}")
