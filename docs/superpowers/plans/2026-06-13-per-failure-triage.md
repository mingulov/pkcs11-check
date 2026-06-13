# Per-Failure Triage of artifacts_base (7 Providers) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify every observed `failed`, `xfailed`, and `crashed` test outcome across the 7 in-scope providers into an actionable verdict (`PROVIDER_BUG` / `UPSTREAM_BUG` / `HARNESS_BUG` / `KNOWN_ISSUE` / `SPEC_AMBIGUITY` / `SOFT_TOKEN_CAVEAT` / `FALSE_POSITIVE`) with severity and downstream routing, so the results can feed (a) provider bug reports and (b) pkcs11-check test/fixture fixes.

**Architecture:**
- Source of truth: per-provider `artifacts_base/<provider>-pooled/report.jsonl` (per-test pytest TestReport records) reconciled against `results.json` summary counts.
- Xfails are encoded as `outcome=skipped` + `longrepr.reprcrash.message` starting with `_pytest.outcomes.XFailed:`. The XFailed message itself is structured (e.g. `"ECDSA:key-import: advertised but not operational (secp…"`), so we group by message-prefix to handle the ~95K xfails at scale; only outliers get individual deep-dive.
- A durable append-only `verdicts.jsonl` makes the loop resumable: every analysis pass reads existing verdicts, skips already-decided items, appends new ones. Loop continues until work-queue is exhausted AND a final sweep adds zero new verdicts.
- The decision tree applies the AGENTS.md classification model + cross-references `docs/module-issues.md` (already-known entries → `KNOWN_ISSUE`).

**Tech Stack:**
- Python 3.13+ (system Python is fine; no `uv` needed for analysis scripts in `/tmp`)
- Pure stdlib `json` / `pathlib` / `hashlib` / `collections` — no test-framework imports needed for extraction
- Markdown output via plain f-strings (no rich/jinja)

**Scope (locked):**

| # | Provider | F | xf | crash | Source |
|---|---|---|---|---|---|
| 1 | wolfpkcs11-master | 468 | 14065 | 4 | `artifacts_base/wolfpkcs11-master-pooled/` |
| 2 | opencryptoki-master | 215 | 2861 | 0 | `artifacts_base/opencryptoki-master-pooled/` |
| 3 | corepkcs11-main | 683 | 9818 | 0 | `artifacts_base/corepkcs11-main-pooled/` |
| 4 | kryoptic-main | 158 | 24579 | 0 | `artifacts_base/kryoptic-main-pooled/` |
| 5 | nss-main | 130 | 2121 | 9 | `artifacts_base/nss-main-pooled/` |
| 6 | softhsm2-main | 67 | 5667 | 0 | `artifacts_base/softhsm2-main-pooled/` |
| 7 | tpm2 | 49 | 25562 | 0 | `artifacts_base/tpm2-pooled/` |
| **Total** | | **1770** | **94673** | **5 files / 13 tests** | |

**Excluded per user:** bouncyhsm (dev-only, drop), kryoptic-fips (= kryoptic FIPS mode, covered by kryoptic-main), pkcs11-mock (canned mock), wolfpkcs11 release (superseded by master), other release/main duplicates.

**Outputs (created by this plan):**

```
docs/findings/per-failure-triage/
├── workqueue/
│   ├── <provider>-failures.jsonl      # 1 record per failed TestReport
│   ├── <provider>-xfails.jsonl        # 1 record per XFailed TestReport
│   └── <provider>-crashes.jsonl       # 1 record per crashed unit (file-level)
├── groups/
│   └── <provider>-<bucket>-groups.json  # signature→[nodeids] rollup
├── verdicts.jsonl                     # append-only durable verdict store
├── reports/
│   ├── <provider>-report.md           # 7 per-provider findings reports
│   ├── _universal.md                  # cross-cutting (same test, N providers)
│   ├── _harness-fixes.md              # pkcs11-check test bugs to fix
│   └── _summary.md                    # top-level rollup
└── scripts/
    ├── extract.py                     # build workqueue/*.jsonl
    ├── group.py                       # build groups/*.json
    ├── classify.py                    # decision tree + verdicts.jsonl append
    ├── reconcile.py                   # cross-ref module-issues.md / existing docs
    └── report.py                      # render reports/*.md
```

**Verdict JSONL schema** (one record per analyzed nodeid-or-group):

```json
{
  "provider": "wolfpkcs11-master",
  "nodeid": "src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc45]",
  "signature": "sha1:7f3a...",
  "outcome": "failed",
  "message": "AES-dec-tc45: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)",
  "category": "PROVIDER_BUG",
  "severity": "LOW",
  "direction": "REJECT_VALID",
  "evidence": "Master build rejects tc1-valid of every CCM variant with CKR_ENCRYPTED_DATA_INVALID. Per §9.5 of artifacts-base-analysis-2026-06-13.md, reject-valid on AEAD is a functional bug (false negative, clean CKR), not a Type A forgery. NOT an oracle.",
  "spec_ref": "PKCS#11 v3.0 §2.13.2 (CKM_AES_CCM); v3.2 validation-policy",
  "routing": "PROVIDER_REPORT(wolfpkcs11-master)",
  "group_id": "wolfpkcs11-master/REJECT_VALID/ccm-decrypt",
  "group_size": 44,
  "analyzed_at": "2026-06-13T14:22:01Z",
  "analyzer": "manual"
}
```

**Classification model (from AGENTS.md, applied per verdict):**

| What module did | Direction | Default category | Default severity |
|---|---|---|---|
| Crash (SIGSEGV/SIGABRT/...) on valid input | CRASH | PROVIDER_BUG | HIGH (CRITICAL if auth/op was correct beforehand) |
| CKR_OK + wrong output (forgery, mismatched digest) | WRONG_OUTPUT | PROVIDER_BUG | CRITICAL (Type A) |
| CKR_OK on input that must be rejected (oracle) | ACCEPT_INVALID | PROVIDER_BUG | CRITICAL/HIGH |
| Claimed protection (CKA_SENSITIVE=TRUE) then violated it | TYPE_B | PROVIDER_BUG | CRITICAL |
| Claimed success (CKR_OK) then didn't honor it | TYPE_C | PROVIDER_BUG | HIGH |
| Some clean CKR other than the spec-mandated one | CLEAN_ERROR | PROVIDER_BUG | MEDIUM (deviation, noted) |
| Rejects valid input with clean CKR | REJECT_VALID | PROVIDER_BUG | LOW (functional, "advertised but not operational") |
| Mechanism not advertised / v3.x function absent | CAPABILITY_GAP | FALSE_POSITIVE | INFO (test should have skipped) |
| Same outcome across 5+ providers | CROSS_PROVIDER | HARNESS_BUG (candidate) or SOFT_TOKEN_CAVEAT | case-by-case |
| Failure matches entry in `docs/module-issues.md` | KNOWN | KNOWN_ISSUE | INFO (already documented) |
| Root cause in dependency (e.g. OpenSSL) | UPSTREAM | UPSTREAM_BUG | per upstream severity |

---

## Loop / Continuation Contract (READ BEFORE ANY TASK)

This plan is a **loop**, not a one-shot. The loop does not stop until ALL of these hold:

1. `workqueue/*.jsonl` for every provider has been built and reconciled against `results.json` summary counts (Phase 0 + Phase 2 + Phase 4).
2. `verdicts.jsonl` contains a verdict for every `crashed` record, every `failed` record, and a verdict for every **xfail group** (the individual xfails inside a group inherit the group verdict — they don't each get their own verdict record).
3. A final sweep (Phase 9) re-scans `workqueue/` looking for any nodeid lacking a verdict and any group with `verdict="UNKNOWN"` or empty `evidence` — and adds at most zero new verdicts.
4. `reports/_summary.md` declares `exhausted: true`.

**Stop conditions** (any one is sufficient to PAUSE, not terminate — surface to user):
- Work-queue 100% classified AND final sweep adds zero new verdicts → DONE.
- Three consecutive Phase-5 batches yield <2% novel findings (rest are `KNOWN_ISSUE` or `FALSE_POSITIVE`) → surface "diminishing returns" to user before continuing.
- New evidence contradicts a previously-written verdict → PAUSE, surface contradiction, await confirmation before overwriting (append a `superseded_by` field — never delete).

**Resume mechanism:** Every task is idempotent. `verdicts.jsonl` is append-only. Each task starts by reading existing verdicts and skipping items already decided. If a session is interrupted mid-task, re-running the task continues from the last checkpoint.

**No premature termination.** Do not declare the analysis "mostly done" or "good enough" before the work-queue is empty. The user has explicitly asked for exhaustive per-failure coverage. When in doubt, do another sweep.

---

## File Structure (locked before any task runs)

| Path | Purpose | Created in |
|---|---|---|
| `docs/findings/per-failure-triage/scripts/extract.py` | Walk `report.jsonl`, emit `workqueue/*.jsonl` per provider | Task 0.2 |
| `docs/findings/per-failure-triage/scripts/group.py` | Read workqueue, emit `groups/*.json` (signature rollup) | Task 0.4 |
| `docs/findings/per-failure-triage/scripts/classify.py` | Apply decision tree, append to `verdicts.jsonl` | Task 5.1 |
| `docs/findings/per-failure-triage/scripts/reconcile.py` | Cross-ref `docs/module-issues.md`, mark `KNOWN_ISSUE` | Task 5.2 |
| `docs/findings/per-failure-triage/scripts/report.py` | Render `reports/*.md` from verdicts | Task 8.1 |
| `docs/findings/per-failure-triage/workqueue/*.jsonl` | Per-provider enumerated failures/xfails/crashes | Phase 0/2/4 |
| `docs/findings/per-failure-triage/groups/*.json` | Signature-grouped rollups | Phase 4 |
| `docs/findings/per-failure-triage/verdicts.jsonl` | Append-only durable verdict store | Phase 1+ |
| `docs/findings/per-failure-triage/reports/*.md` | 7 provider reports + universal + harness-fixes + summary | Phase 8 |

---

## Phase 0: Scaffolding & Verdict Store

### Task 0.1: Create directory tree

**Files:**
- Create: `docs/findings/per-failure-triage/{workqueue,groups,reports,scripts}/` (directories)
- Create: `docs/findings/per-failure-triage/verdicts.jsonl` (empty file)

- [ ] **Step 1: Create the directory structure**

```bash
mkdir -p /home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/{workqueue,groups,reports,scripts}
touch /home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl
```

- [ ] **Step 2: Verify**

```bash
ls -la /home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/
```

Expected: directories `workqueue/ groups/ reports/ scripts/` and file `verdicts.jsonl` (0 bytes).

- [ ] **Step 3: Commit**

```bash
git add docs/findings/per-failure-triage/
git commit -m "docs(triage): scaffold per-failure-triage directory tree"
```

### Task 0.2: Build `extract.py` — workqueue builder

**Files:**
- Create: `docs/findings/per-failure-triage/scripts/extract.py`

- [ ] **Step 1: Write the extractor**

```python
#!/usr/bin/env python3
"""Extract per-test outcome records from a provider's pooled report.jsonl.

Emits three JSONL files per provider:
  <provider>-failures.jsonl  -- outcome=failed in call phase
  <provider>-xfails.jsonl    -- outcome=skipped + _pytest.outcomes.XFailed: prefix
  <provider>-crashes.jsonl   -- file-level crashed units (from results.json units)

Reconciles counts against results.json summary; exits non-zero on mismatch.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ARTIFACTS = Path("/home/user/src/m/pkcs11-check/artifacts_base")
OUTDIR = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue")

XFAIL_PREFIX = "_pytest.outcomes.XFailed:"

PROVIDERS = [
    "wolfpkcs11-master",
    "opencryptoki-master",
    "corepkcs11-main",
    "kryoptic-main",
    "nss-main",
    "softhsm2-main",
    "tpm2",
]


def extract_message(longrepr: object) -> str:
    if not isinstance(longrepr, dict):
        return ""
    rc = longrepr.get("reprcrash") or {}
    msg = rc.get("message") or ""
    if msg:
        return msg
    rt = longrepr.get("reprtraceback") or {}
    for entry in rt.get("reprentries", []):
        data = entry.get("data") or {}
        for line in data.get("lines", []):
            if line and not line.startswith(" "):
                return line
    return ""


def extract_provider(provider: str) -> dict:
    pooled = ARTIFACTS / f"{provider}-pooled"
    rj = pooled / "results.json"
    rj_data = json.loads(rj.read_text())
    summary = rj_data["summary"]

    crashes: list[dict] = []
    for unit in rj_data.get("units", []):
        if unit.get("status") == "crashed":
            crashes.append({
                "provider": provider,
                "target": unit["target"],
                "status": "crashed",
                "returncode": unit.get("returncode"),
                "counts": unit.get("counts", {}),
                "stdout_tail": (unit.get("stdout") or "")[-4000:],
            })

    failures: list[dict] = []
    xfails: list[dict] = []
    report = pooled / "report.jsonl"
    with report.open() as f:
        for line in f:
            r = json.loads(line)
            if r.get("$report_type") != "TestReport":
                continue
            if r.get("when") != "call":
                continue
            outcome = r.get("outcome")
            nodeid = r.get("nodeid")
            if not nodeid:
                continue
            msg = extract_message(r.get("longrepr"))
            rec = {
                "provider": provider,
                "nodeid": nodeid,
                "location": r.get("location"),
                "outcome": outcome,
                "message": msg,
            }
            if outcome == "failed":
                failures.append(rec)
            elif outcome == "skipped" and msg.startswith(XFAIL_PREFIX):
                rec["xfail_reason"] = msg[len(XFAIL_PREFIX):].strip()
                xfails.append(rec)

    # Reconcile counts
    found = {
        "failed": len(failures),
        "xfailed": len(xfails),
        "crashed_units": len(crashes),
    }
    expected = {
        "failed": summary.get("failed", 0),
        "xfailed": summary.get("xfailed", 0),
        "crashed_units": summary.get("crashed", 0),
    }
    drift = {k: (found[k], expected[k]) for k in found if found[k] != expected[k]}

    # Write
    for bucket, records in (("failures", failures), ("xfails", xfails), ("crashes", crashes)):
        out = OUTDIR / f"{provider}-{bucket}.jsonl"
        with out.open("w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    return {
        "provider": provider,
        "found": found,
        "expected": expected,
        "drift": drift,
        "files": {
            "failures": str(OUTDIR / f"{provider}-failures.jsonl"),
            "xfails": str(OUTDIR / f"{provider}-xfails.jsonl"),
            "crashes": str(OUTDIR / f"{provider}-crashes.jsonl"),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("providers", nargs="*", default=PROVIDERS)
    args = ap.parse_args()

    OUTDIR.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    for provider in args.providers:
        result = extract_provider(provider)
        print(f"=== {provider} ===")
        print(f"  found:    {result['found']}")
        print(f"  expected: {result['expected']}")
        if result["drift"]:
            print(f"  DRIFT:    {result['drift']}")
            exit_code = 1
        print()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it**

```bash
python3 /home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/scripts/extract.py
```

Expected: prints 7 provider blocks. `found` and `expected` match for all (drift empty). If drift is non-empty, fix `extract.py` before continuing — most likely cause is a record-type variant we haven't accounted for.

- [ ] **Step 3: Verify file sizes match counts**

```bash
for p in wolfpkcs11-master opencryptoki-master corepkcs11-main kryoptic-main nss-main softhsm2-main tpm2; do
  echo "$p:"
  wc -l /home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue/${p}-*.jsonl
done
```

Expected: failures line counts match table in plan header; xfails match; crashes match (4, 0, 0, 0, 9, 0, 0).

- [ ] **Step 4: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/extract.py docs/findings/per-failure-triage/workqueue/
git commit -m "docs(triage): extract workqueue from artifacts_base for 7 providers"
```

### Task 0.3: Inspect a sample to confirm encoding

- [ ] **Step 1: Read first 3 records from each bucket for wolfpkcs11-master**

```bash
head -3 docs/findings/per-failure-triage/workqueue/wolfpkcs11-master-failures.jsonl | python3 -m json.tool --json-lines
head -3 docs/findings/per-failure-triage/workqueue/wolfpkcs11-master-xfails.jsonl | python3 -m json.tool --json-lines
cat docs/findings/per-failure-triage/workqueue/wolfpkcs11-master-crashes.jsonl | python3 -m json.tool --json-lines
```

Expected: 3 well-formed JSON records per bucket. The xfail records have an `xfail_reason` field with the structured reason string.

- [ ] **Step 2: If anything looks malformed, fix `extract.py` and re-run Task 0.2 Step 2.**

---

## Phase 1: Crash Deep-Dive (5 crashed files covering 13 per-test crashes — full manual attention)

Smallest bucket, highest signal. Each crashed FILE gets its own verdict record. The per-test crash count inside the file is captured via `counts.crashed`.

### Task 1.1: Build crash dossiers

**Files:**
- Create (transient, in `/tmp/p11analysis/triage/crashes/`): one markdown dossier per crash

- [ ] **Step 1: For each crash record, fetch full stdout from the original shard**

The pooled `results.json` `stdout` for a crashed unit may be from a SUCCESSFUL retry. The crashing attempt's stdout lives in the **shard**-level results.json for that file. Build a locator:

```bash
python3 << 'EOF'
import json
from pathlib import Path
ART = Path('/home/user/src/m/pkcs11-check/artifacts_base')
OUT = Path('/tmp/p11analysis/triage/crashes')
OUT.mkdir(parents=True, exist_ok=True)

crashes = []
for prov in ['wolfpkcs11-master', 'nss-main']:
    cj = json.loads((ART / f'{prov}-pooled/results.json').read_text())
    for unit in cj.get('units', []):
        if unit.get('status') != 'crashed':
            continue
        crashes.append({'provider': prov, **{k: unit[k] for k in ('target','returncode','counts') if k in unit}})

for c in crashes:
    prov = c['provider']
    target = c['target']
    # find every shard dir
    best = None
    for sd in sorted(ART.glob(f'{prov}-shard-*')):
        sj = sd / 'results.json'
        if not sj.exists(): continue
        d = json.loads(sj.read_text())
        for u in d.get('units', []):
            if u.get('target') == target and u.get('status') == 'crashed':
                # Prefer the shard attempt with the largest stdout from a CRASHED unit
                if best is None or len(u.get('stdout','')) > len(best.get('stdout','')):
                    best = u | {'shard': sd.name}
    c['crashed_unit'] = best
    c['stdout_tail'] = (best or {}).get('stdout', '')[-6000:] if best else ''

for c in crashes:
    safe = c['target'].replace('/', '__')
    out = OUT / f"{c['provider']}__{safe}.md"
    out.write_text(
        f"# Crash: {c['provider']} / {c['target']}\n\n"
        f"- returncode: {c['returncode']} (signal {abs(c['returncode'])}: "
        f"{'SIGSEGV' if abs(c['returncode'])==11 else 'SIGABRT' if abs(c['returncode'])==6 else 'SIGTRAP' if abs(c['returncode'])==5 else '?'})\n"
        f"- shard: {c.get('crashed_unit',{}).get('shard','?')}\n"
        f"- counts: {c['counts']}\n\n"
        f"## stdout tail (last 6000 chars)\n\n```\n{c['stdout_tail']}\n```\n"
    )
print(f"Wrote {len(crashes)} dossiers to {OUT}")
EOF
```

Expected: 5 dossiers (2 wolf-master: wycheproof_hkdf.py + x509/test_identity.py; 3 nss-main: test_mech_flags.py + test_mech_negative.py + test_operation_termination.py). Each dossier's `counts.crashed` shows per-test impact (total 13 across the 5 files).

- [ ] **Step 2: List the dossiers**

```bash
ls -la /tmp/p11analysis/triage/crashes/
```

Expected: 13 `.md` files.

### Task 1.2: Classify each crash

For each of the 5 crash dossiers, decide: was the crash triggered by (a) valid PKCS#11 input the module must handle → `PROVIDER_BUG`, (b) provably-UB input the test should not have sent → `HARNESS_BUG`, (c) a test-script-side assertion/abort → `FALSE_POSITIVE`.

**Decision rules:**

| Crash site context | Category |
|---|---|
| Crash during a normal op (encrypt/sign/etc.) with valid mechanism + key | `PROVIDER_BUG` |
| Crash after `ulDataLen = 0x7fffffffffffffff` or similar UB-provoker | `HARNESS_BUG` if test is in `security/test_ffi_*.py`, else `PROVIDER_BUG` (module should still not crash) |
| Crash after `pytest.fail` / `sys.exit` / explicit abort in test code | `FALSE_POSITIVE` (test aborted cleanly, not the module) |
| Crash during mechanism not advertised by the module | `HARNESS_BUG` (test should have skipped) |

**Severity:** crashes are always at least HIGH. If the test that crashed was about to demonstrate a Type A/B/C bug, severity = CRITICAL.

- [ ] **Step 1: Process each dossier and append verdict to `verdicts.jsonl`**

For each dossier file in `/tmp/p11analysis/triage/crashes/`, read it, apply the decision rule, and append a verdict. Use this Python helper:

```bash
python3 << 'EOF'
import json, datetime
from pathlib import Path

VERDICTS = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl')
DOSSIERS = Path('/tmp/p11analysis/triage/crashes')

# MANUAL TABLE: edit verdicts per dossier. Below is the STARTING POINT based on prior analysis
# (see docs/findings/artifacts-base-analysis-2026-06-13.md §2/§9). Verify against the dossier
# before keeping.
KNOWN = {
    # wolfpkcs11-master
    ('wolfpkcs11-master', 'src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py'):
        ('PROVIDER_BUG', 'HIGH', 'CRASH', 'SIGABRT in HKDF wycheproof replay'),
    ('wolfpkcs11-master', 'src/pkcs11_check/testcases/x509/test_identity.py'):
        ('PROVIDER_BUG', 'HIGH', 'CRASH', 'SIGTRAP in x509 identity test'),
    # nss-main (3 files × repeated per variant — nss-main only has 9 = 3 files; each file may have
    # multiple crashing subtests; classify at file level for now, refine in Phase 6)
    ('nss-main', 'src/pkcs11_check/testcases/test_mech_flags.py'):
        ('PROVIDER_BUG', 'HIGH', 'CRASH', 'NSS SIGSEGV on mech-flags probe'),
    ('nss-main', 'src/pkcs11_check/testcases/test_mech_negative.py'):
        ('PROVIDER_BUG', 'HIGH', 'CRASH', 'NSS SIGSEGV on mech-negative op'),
    ('nss-main', 'src/pkcs11_check/testcases/test_operation_termination.py'):
        ('PROVIDER_BUG', 'HIGH', 'CRASH', 'NSS SIGSEGV on operation-termination op'),
}

now = datetime.datetime.now(datetime.timezone.utc).isoformat()
for d in sorted(DOSSIERS.glob('*.md')):
    # parse provider + target from filename
    name = d.stem
    provider, target_rel = name.split('__', 1)
    target = target_rel.replace('__', '/')
    key = (provider, target)
    if key not in KNOWN:
        print(f"WARN: no known verdict for {key}, skipping (manual fill needed)")
        continue
    cat, sev, direction, evidence = KNOWN[key]
    rec = {
        'provider': provider,
        'nodeid': target,  # file-level crash, use target as nodeid placeholder
        'signature': f'crash:{provider}:{target}',
        'outcome': 'crashed',
        'message': f'file-level crash; see dossier {d}',
        'category': cat,
        'severity': sev,
        'direction': direction,
        'evidence': evidence,
        'spec_ref': '',
        'routing': f'PROVIDER_REPORT({provider})',
        'group_id': f'{provider}/CRASH/{Path(target).stem}',
        'group_size': 1,
        'analyzed_at': now,
        'analyzer': 'manual',
    }
    with VERDICTS.open('a') as f:
        f.write(json.dumps(rec) + '\n')
print(f"Appended crash verdicts. Run: wc -l {VERDICTS}")
EOF
```

- [ ] **Step 2: Verify count**

```bash
wc -l docs/findings/per-failure-triage/verdicts.jsonl
```

Expected: ≥5 lines (one per crashed file). If the WARN branch fired, fill missing entries manually before continuing.

- [ ] **Step 3: Commit**

```bash
git add docs/findings/per-failure-triage/verdicts.jsonl
git commit -m "docs(triage): classify all 5 crashed files (wolf-master + nss-main)"
```

---

## Phase 2: Per-Provider FAIL Enumeration & Reconciliation

Already done by Task 0.2 for the records. This phase just verifies the enumeration is complete and there's no surprise drift.

### Task 2.1: Verify no drift in any provider

- [ ] **Step 1: Re-run extract and watch for drift**

```bash
python3 docs/findings/per-failure-triage/scripts/extract.py 2>&1 | grep -A2 DRIFT
```

Expected: no output (no drift). If drift appears, investigate before proceeding.

### Task 2.2: Sample-inspect FAIL records per provider

For each of the 7 providers, eyeball 5 random FAIL records to confirm `message` field is informative (not empty, not a stack trace dump).

- [ ] **Step 1: For each provider, print 5 random failures**

```bash
for p in wolfpkcs11-master opencryptoki-master corepkcs11-main kryoptic-main nss-main softhsm2-main tpm2; do
  echo "=== $p ==="
  shuf -n 5 docs/findings/per-failure-triage/workqueue/${p}-failures.jsonl | python3 -c "
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    print(f\"  {r['nodeid']}\")
    print(f\"    {r['message'][:200]}\")"
done
```

Expected: each failure has a meaningful message. If many have empty/truncated messages, revisit `extract.py:extract_message`.

---

## Phase 3: xpassed Audit (CRITICAL signals)

`results.json.summary.xpassed` counts tests marked `xfail` that actually passed — i.e. tests that expected the module to fail but the module did the right thing. **Each xpassed is either a test bug (false xfail marker) or a module improvement.** These are tiny in N but high-signal.

### Task 3.1: Enumerate xpassed tests per provider

- [ ] **Step 1: Extend `extract.py` to also emit `<provider>-xpassed.jsonl`**

Edit `extract.py`: add a fourth bucket. xpassed tests appear in `report.jsonl` as `outcome=passed` with `longrepr` containing `"wasxfail"` (pytest internal marker).

```python
# Add inside extract_provider, alongside failures/xfails:
xpassed: list[dict] = []
# ... in the per-line loop, after the existing outcome checks:
elif outcome == "passed" and isinstance(r.get("longrepr"), str) and "wasxfail" in r["longrepr"]:
    xpassed.append({
        "provider": provider,
        "nodeid": nodeid,
        "location": r.get("location"),
        "outcome": "xpassed",
        "message": r["longrepr"],
    })
```

Also extend the file-write loop and the `found`/`expected` reconciliation to include `xpassed: summary.get('xpassed', 0)`.

- [ ] **Step 2: Re-run extract, verify xpassed counts**

```bash
python3 docs/findings/per-failure-triage/scripts/extract.py
wc -l docs/findings/per-failure-triage/workqueue/*-xpassed.jsonl
```

Expected: all 7 files exist; counts match each provider's `results.json.summary.xpassed` (per Task 0.2 we saw wolf-master = 0; verify the others).

- [ ] **Step 3: For each non-empty xpassed bucket, write a verdict per item**

xpassed tests are usually few (0–10 per provider). Process each manually:

```bash
python3 << 'EOF'
import json, datetime
from pathlib import Path

VERDICTS = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl')
WQ = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue')
now = datetime.datetime.now(datetime.timezone.utc).isoformat()

total = 0
for xp in sorted(WQ.glob('*-xpassed.jsonl')):
    provider = xp.stem.replace('-xpassed', '')
    records = [json.loads(l) for l in xp.read_text().splitlines() if l.strip()]
    if not records:
        continue
    print(f"=== {provider}: {len(records)} xpassed ===")
    for r in records:
        print(f"  {r['nodeid']}")
        # default verdict — analyzer must review each one
        rec = {
            'provider': provider,
            'nodeid': r['nodeid'],
            'signature': f"xpassed:{provider}:{r['nodeid']}",
            'outcome': 'xpassed',
            'message': r['message'][:500],
            'category': 'HARNESS_BUG',  # default: xfail marker is stale, test should be unmarked
            'severity': 'LOW',
            'direction': 'XPASSED',
            'evidence': 'UNREVIEWED — analyzer must inspect test source to decide: (a) module improved → remove xfail marker, OR (b) xfail was for a different reason and this pass is incidental → keep marker',
            'spec_ref': '',
            'routing': 'HARNESS_FIX',
            'group_id': f'{provider}/XPASSED/{r["nodeid"]}',
            'group_size': 1,
            'analyzed_at': now,
            'analyzer': 'unreviewed',
        }
        with VERDICTS.open('a') as f:
            f.write(json.dumps(rec) + '\n')
        total += 1
print(f"Wrote {total} xpassed verdicts (UNREVIEWED — Phase 6 must audit)")
EOF
```

- [ ] **Step 4: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/extract.py docs/findings/per-failure-triage/workqueue/ docs/findings/per-failure-triage/verdicts.jsonl
git commit -m "docs(triage): extract +初步 verdict xpassed tests"
```

---

## Phase 4: Signature Grouping (the volume-scaling step)

Per-failure records (1770 F + ~95K xf) are too many to analyze individually. Group by **signature** = normalized (test file + message-prefix + outcome direction). Within a group, all members share root cause.

### Task 4.1: Write `group.py`

**Files:**
- Create: `docs/findings/per-failure-triage/scripts/group.py`

- [ ] **Step 1: Write the grouping script**

```python
#!/usr/bin/env python3
"""Group workqueue records by signature.

Signature = sha1(provider + bucket + test_file + message_prefix + direction_tag)

  test_file    = nodeid without parametrize suffix and without line number
  message_prefix = first 60 chars of normalized message (whitespace-collapsed)
  direction_tag  = heuristic from message text:
                   ACCEPT_INVALID / REJECT_VALID / WRONG_OUTPUT / CLEAN_ERROR / CRASH / CAPABILITY_GAP / OTHER

The signature collapses e.g. 210 wycheproof RSA-OAEP tc-failed cases into ONE group.
Output: groups/<provider>-<bucket>-groups.json
  { "signature": {"signature":..., "size":N, "test_file":..., "direction":...,
                   "example_nodeid":..., "messages_sample":[...], "nodeids":[...] } }
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

WQ = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue")
OUTDIR = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/groups")

DIR_PATTERNS = [
    (r"accept(ing|ed)?\s+(an?\s+)?invalid|invalid\s+(ciphertext|signature|tag|key|padding).*CKR_OK|CKR_OK.*invalid|decrypt\s+successfully|encrypt\s+successfully", "ACCEPT_INVALID"),
    (r"reject(ing|ed)?\s+(a\s+)?valid|valid.*rejected|valid-tag.*rejected|valid\s+sig(nature)?\s+rejected|tc\d+-valid.*Unexpected\s+CK_RV", "REJECT_VALID"),
    (r"wrong\s+(output|digest|signature|ciphertext)|mismatch|expected\s+\S+\s+got\s+\S+|InvalidSignature|did\s+not\s+match", "WRONG_OUTPUT"),
    (r"crash|SIGSEGV|SIGABRT|signal\s+\d+|returncode", "CRASH"),
    (r"CK_RV\s+CKR_\w+|Unexpected\s+CK_RV|CKR_\w+", "CLEAN_ERROR"),
    (r"advertised\s+but\s+not\s+operational|not\s+operational|operability\s+probe|mechanism\s+operational\s+but|not\s+advertised|CAPABILITY_GAP|capability\s+absent", "CAPABILITY_GAP"),
]

def direction_of(msg: str) -> str:
    m = msg.lower()
    for pat, tag in DIR_PATTERNS:
        if re.search(pat, m, re.IGNORECASE):
            return tag
    return "OTHER"


def test_file_of(nodeid: str) -> str:
    # nodeid = "path/to/test_x.py::TestCls::test_y[param]"
    return nodeid.split("::", 1)[0]


def message_prefix(msg: str, n: int = 60) -> str:
    collapsed = re.sub(r"\s+", " ", msg or "").strip()
    return collapsed[:n]


def signature(provider: str, bucket: str, test_file: str, msg_prefix: str, direction: str) -> str:
    h = hashlib.sha1()
    h.update(f"{provider}|{bucket}|{test_file}|{msg_prefix}|{direction}".encode())
    return f"sha1:{h.hexdigest()[:16]}"


def group_bucket(provider: str, bucket: str) -> dict:
    path = WQ / f"{provider}-{bucket}.jsonl"
    if not path.exists():
        return {}
    by_sig: dict[str, dict] = defaultdict(lambda: {
        "size": 0, "nodeids": [], "messages_sample": set(), "test_file": "", "direction": "",
        "provider": provider, "bucket": bucket, "signature": "",
    })
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        test_file = test_file_of(r["nodeid"])
        msg = r.get("message", "")
        msg_prefix = message_prefix(msg)
        direction = direction_of(msg)
        sig = signature(provider, bucket, test_file, msg_prefix, direction)
        g = by_sig[sig]
        g["signature"] = sig
        g["size"] += 1
        g["nodeids"].append(r["nodeid"])
        if len(g["messages_sample"]) < 3:
            g["messages_sample"].add(msg[:300])
        g["test_file"] = test_file
        g["direction"] = direction
        g["provider"] = provider
        g["bucket"] = bucket
    # convert sets to lists for json
    for g in by_sig.values():
        g["messages_sample"] = sorted(g["messages_sample"])
        g["example_nodeid"] = g["nodeids"][0]
    return by_sig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("providers", nargs="*")
    ap.add_argument("--buckets", nargs="*", default=["failures", "xfails", "xpassed"])
    args = ap.parse_args()
    providers = args.providers or [
        "wolfpkcs11-master", "opencryptoki-master", "corepkcs11-main",
        "kryoptic-main", "nss-main", "softhsm2-main", "tpm2",
    ]

    OUTDIR.mkdir(parents=True, exist_ok=True)
    grand_total = 0
    for provider in providers:
        for bucket in args.buckets:
            groups = group_bucket(provider, bucket)
            if not groups:
                continue
            out = OUTDIR / f"{provider}-{bucket}-groups.json"
            payload = {
                "provider": provider,
                "bucket": bucket,
                "group_count": len(groups),
                "total_records": sum(g["size"] for g in groups.values()),
                "groups": sorted(groups.values(), key=lambda g: -g["size"]),
            }
            out.write_text(json.dumps(payload, indent=2))
            grand_total += payload["total_records"]
            print(f"{provider}/{bucket}: {payload['group_count']} groups, {payload['total_records']} records → {out.name}")
    print(f"Grand total: {grand_total} records grouped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run it**

```bash
python3 docs/findings/per-failure-triage/scripts/group.py
```

Expected: prints per-(provider,bucket) line counts; grand total ≈ 1770 failures + 94673 xfails + however-many xpassed = ~96000 records. Number of distinct groups should be much smaller (target: hundreds, not thousands, for failures; low thousands for xfails).

- [ ] **Step 3: Inspect top-10 groups per provider-bucket to verify grouping quality**

```bash
for p in wolfpkcs11-master opencryptoki-master corepkcs11-main kryoptic-main nss-main softhsm2-main tpm2; do
  echo "=== $p FAILURES top groups ==="
  python3 -c "
import json
d = json.load(open('docs/findings/per-failure-triage/groups/${p}-failures-groups.json'))
for g in d['groups'][:10]:
    print(f\"  size={g['size']:4d}  {g['direction']:18s}  {g['test_file']}\")
    print(f\"           msg: {g['messages_sample'][0][:150] if g['messages_sample'] else ''}\")"
done
```

Expected: top groups have meaningful sizes (not all size=1). If most are size=1, message-prefix is too specific — widen `message_prefix` slice from 60 to 40 chars and re-run.

- [ ] **Step 4: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/group.py docs/findings/per-failure-triage/groups/
git commit -m "docs(triage): group failures + xfails by signature"
```

---

## Phase 5: The Classification Loop (core)

The loop. Applies the decision tree to each group, appends verdicts. Runs **per provider, per bucket, in batches of 20 groups**. After each batch: checkpoint + continue.

### Task 5.1: Write `classify.py` — automated first-pass classifier

**Files:**
- Create: `docs/findings/per-failure-triage/scripts/classify.py`

- [ ] **Step 1: Write the classifier**

```python
#!/usr/bin/env python3
"""Apply decision tree to groups, append verdicts to verdicts.jsonl.

First pass: automated rules. Anything not confidently classified gets
category=UNKNOWN and routed to Phase 6 manual deep-dive.

Idempotent: skips signatures already present in verdicts.jsonl.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

GROUPS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/groups")
VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")

# Automated direction → category/severity table (per AGENTS.md classification model)
AUTO_RULES = [
    # (regex against group's combined test_file+messages_sample, category, severity, routing, evidence_template)
    (r"security/test_ffi_length_boundary|security/test_arithmetic_overflow|0x7fff{3,}|0xffff{4,}|0x7fffffffffffffff",
     "SOFT_TOKEN_CAVEAT", "MEDIUM", "DOCS_ONLY",
     "UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens."),
    (r"advertised\s+but\s+not\s+operational|mechanism\s+operational\s+but",
     "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
     "Mechanism advertised but not operational — clean refusal. Per §9.5 severity-direction principle, reject-valid is functional (LOW), not oracle/forgery."),
    (r"ML-DSA|ML_KEM|MLKEM|SLH-DSA|SLHDSA",  # PQC + harness-vector caveat
     "UNKNOWN", "MEDIUM", "MANUAL_REVIEW",
     "PQC mechanism. Possible harness-vector bug PC-2 (see findings-summary-2026-06-10.md). Manual review required."),
    (r"rsa_pkcs1_decrypt.*accept|PKCS#?1.*accept.*invalid|PKCS1.*Bleichenbacher",
     "SOFT_TOKEN_CAVEAT", "HIGH", "DOCS_ONLY",
     "Bleichenbacher-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access)."),
    (r"AES-CBC.*PAD|CBC.*padding\s+oracle|Vaudenay|tc\d+-invalid.*decrypt\s+successfully",
     "PROVIDER_BUG", "HIGH", "PROVIDER_REPORT",
     "Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug."),
    (r"OAEP.*Manger|OAEP.*accept.*invalid|Manger",
     "PROVIDER_BUG", "HIGH", "PROVIDER_REPORT",
     "Manger oracle: RSA-OAEP non-uniform errors. Real provider bug."),
    (r"reject.*valid.*tag|valid-tag.*rejected|valid.*CCM.*reject|valid.*GCM.*reject",
     "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
     "Reject-valid on AEAD: false negative (clean CKR error). Per §9.5, LOW severity — functional bug, not oracle."),
]


def load_existing_signatures() -> set[str]:
    if not VERDICTS.exists():
        return set()
    sigs: set[str] = set()
    for line in VERDICTS.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            if r.get("signature"):
                sigs.add(r["signature"])
        except json.JSONDecodeError:
            continue
    return sigs


def classify_group(g: dict) -> dict | None:
    """Return a verdict dict, or None if no rule matched (UNKNOWN will be assigned by caller)."""
    text = g["test_file"] + " " + " ".join(g.get("messages_sample") or [])
    for pat, cat, sev, routing, evidence in AUTO_RULES:
        if re.search(pat, text, re.IGNORECASE):
            return {
                "category": cat,
                "severity": sev,
                "routing": routing,
                "evidence": evidence,
                "analyzer": "auto-classifier",
            }
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--bucket", required=True, choices=["failures", "xfails", "xpassed"])
    ap.add_argument("--limit", type=int, default=0, help="max groups to process (0 = all)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    gf = GROUPS / f"{args.provider}-{args.bucket}-groups.json"
    if not gf.exists():
        print(f"no groups file: {gf}", file=sys.stderr)
        return 1
    data = json.loads(gf.read_text())

    existing = load_existing_signatures()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    n_new = n_unknown = n_skipped = 0
    out_lines: list[str] = []
    for g in data["groups"]:
        if g["signature"] in existing:
            n_skipped += 1
            continue
        if args.limit and n_new >= args.limit:
            break

        verdict = classify_group(g)
        if verdict is None:
            verdict = {
                "category": "UNKNOWN",
                "severity": "MEDIUM",
                "routing": "MANUAL_REVIEW",
                "evidence": "No auto-rule matched. Phase 6 manual deep-dive required.",
                "analyzer": "auto-classifier:unmatched",
            }
            n_unknown += 1

        rec = {
            "provider": args.provider,
            "nodeid": f"<group:{g['signature']}>",
            "signature": g["signature"],
            "outcome": args.bucket.rstrip("s"),  # failure / xfail / xpassed
            "message": (g.get("messages_sample") or [""])[0][:500],
            "test_file": g["test_file"],
            "direction": g["direction"],
            "group_id": f"{args.provider}/{g['direction']}/{g['test_file']}#{g['signature'][:8]}",
            "group_size": g["size"],
            "example_nodeid": g.get("example_nodeid"),
            "analyzed_at": now,
            **verdict,
        }
        out_lines.append(json.dumps(rec))
        n_new += 1

    if not args.dry_run and out_lines:
        with VERDICTS.open("a") as f:
            for line in out_lines:
                f.write(line + "\n")

    print(f"{args.provider}/{args.bucket}: new={n_new} unknown={n_unknown} skipped(already-done)={n_skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run for one provider/bucket as smoke test**

```bash
python3 docs/findings/per-failure-triage/scripts/classify.py --provider softhsm2-main --bucket failures
```

Expected: `new=... unknown=... skipped=0`. Read the new verdict lines to sanity-check:

```bash
tail -20 docs/findings/per-failure-triage/verdicts.jsonl | python3 -m json.tool --json-lines
```

- [ ] **Step 3: Run for all 7 providers × 3 buckets**

```bash
for p in wolfpkcs11-master opencryptoki-master corepkcs11-main kryoptic-main nss-main softhsm2-main tpm2; do
  for b in failures xfails xpassed; do
    python3 docs/findings/per-failure-triage/scripts/classify.py --provider $p --bucket $b
  done
done
```

Expected: 21 runs, each prints a `new=N unknown=M skipped=K` line. Track the unknown count — that's Phase 6's work-queue.

- [ ] **Step 4: Tally UNKNOWN vs classified**

```bash
python3 -c "
import json, collections
counts = collections.Counter()
unknown_groups = []
for line in open('docs/findings/per-failure-triage/verdicts.jsonl'):
    r = json.loads(line)
    counts[r['category']] += 1
    if r['category'] == 'UNKNOWN':
        unknown_groups.append((r['provider'], r.get('test_file','?'), r['direction'], r.get('group_size',1)))
print('Category tally:', dict(counts))
print(f'UNKNOWN groups: {len(unknown_groups)}')
# sort by group_size desc
print('Top UNKNOWN by group_size:')
for p, tf, d, n in sorted(unknown_groups, key=lambda x:-x[3])[:30]:
    print(f'  size={n:5d}  {p:22s}  {d:18s}  {tf}')"
```

- [ ] **Step 5: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/classify.py docs/findings/per-failure-triage/verdicts.jsonl
git commit -m "docs(triage): auto-classify all groups, identify UNKNOWNs for Phase 6"
```

### Task 5.2: Cross-reference `docs/module-issues.md` — mark KNOWN_ISSUE

Many findings are already documented. This pass scans `verdicts.jsonl` and re-tags any verdict whose `test_file` + `provider` matches an existing `module-issues.md` entry.

**Files:**
- Create: `docs/findings/per-failure-triage/scripts/reconcile.py`

- [ ] **Step 1: Write the reconciler**

```python
#!/usr/bin/env python3
"""Cross-reference verdicts.jsonl against docs/module-issues.md.

For any verdict whose (provider, test_file, message_keyword) matches an existing
module-issues entry, append a follow-up verdict record with category=KNOWN_ISSUE
and severity ≤ INFO, pointing at the doc section.

This does NOT delete the original verdict — it appends a superseding record with
`supersedes` pointing back. Loop continuation rule: never delete.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")
MODULE_ISSUES = Path("/home/user/src/m/pkcs11-check/docs/module-issues.md")


def parse_module_issues() -> list[dict]:
    """Parse module-issues.md into a list of {providers:[...], keywords:[...], section:...}."""
    entries: list[dict] = []
    if not MODULE_ISSUES.exists():
        return entries
    current_providers: list[str] = []
    current_section: str = ""
    for line in MODULE_ISSUES.read_text().splitlines():
        if line.startswith("## "):
            current_section = line.lstrip("# ").strip()
            current_providers = []
            # detect "provider: foo" or known provider names in title
            for p in ["softhsm2", "kryoptic", "nss", "opencryptoki", "tpm2", "wolfpkcs11", "corepkcs11", "bouncyhsm"]:
                if p in current_section.lower():
                    current_providers.append(p)
        elif line.startswith("### ") or line.startswith("- "):
            text = line.lstrip("#- ").strip()
            entries.append({
                "providers": list(current_providers),
                "section": current_section,
                "text": text,
                "keywords": [w for w in re.split(r"\W+", text.lower()) if len(w) > 4][:8],
            })
    return entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    entries = parse_module_issues()
    print(f"Loaded {len(entries)} module-issues entries")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    new_lines: list[str] = []
    n_marked = 0

    for line in VERDICTS.read_text().splitlines():
        if not line.strip():
            continue
        v = json.loads(line)
        if v.get("category") == "KNOWN_ISSUE":
            continue  # already marked
        provider_base = v["provider"].replace("-main", "").replace("-master", "")
        test_file = v.get("test_file", "")
        msg = (v.get("message") or "").lower()

        # match: any entry whose providers include provider_base AND any keyword is in msg or test_file
        for e in entries:
            if e["providers"] and provider_base not in e["providers"]:
                continue
            if not any(k in msg or k in test_file.lower() for k in e["keywords"]):
                continue
            # match!
            superseded = dict(v)
            new_v = {
                **v,
                "category": "KNOWN_ISSUE",
                "severity": "INFO",
                "evidence": f"Already documented in docs/module-issues.md §'{e['section']}': \"{e['text'][:120]}\"",
                "routing": "DOCS_ONLY",
                "analyzed_at": now,
                "analyzer": "auto-reconcile",
                "supersedes": v["signature"],
                "signature": v["signature"] + "#known",
            }
            new_lines.append(json.dumps(new_v))
            n_marked += 1
            break

    print(f"Marked {n_marked} verdicts as KNOWN_ISSUE")
    if not args.dry_run and new_lines:
        with VERDICTS.open("a") as f:
            for line in new_lines:
                f.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run it**

```bash
python3 docs/findings/per-failure-triage/scripts/reconcile.py
```

Expected: prints "Marked N verdicts as KNOWN_ISSUE". N may be anywhere from 10 to 200.

- [ ] **Step 3: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/reconcile.py docs/findings/per-failure-triage/verdicts.jsonl
git commit -m "docs(triage): reconcile verdicts against module-issues.md"
```

---

## Phase 6: Manual Deep-Dive of UNKNOWNs

For every group with `category=UNKNOWN` from Phase 5.1: read the test source + a representative failure detail, apply manual judgment, write a proper verdict.

### Task 6.1: Extract deep-dive work-list

- [ ] **Step 1: Generate the UNKNOWN work-list**

```bash
python3 -c "
import json, collections
by_provider = collections.defaultdict(list)
for line in open('docs/findings/per-failure-triage/verdicts.jsonl'):
    r = json.loads(line)
    if r.get('category') != 'UNKNOWN': continue
    if r.get('supersedes'): continue  # ignore if it's been superseded
    by_provider[r['provider']].append(r)
for p, recs in sorted(by_provider.items()):
    recs.sort(key=lambda r: -r.get('group_size',1))
    print(f'=== {p}: {len(recs)} UNKNOWN groups ===')
    for r in recs[:30]:
        print(f\"  size={r.get('group_size',1):5d}  {r.get('direction','?'):18s}  {r.get('test_file','?')}\")
        if r.get('message'):
            print(f\"           msg: {r['message'][:160]}\")"
```

- [ ] **Step 2: Save the work-list to a file**

```bash
python3 -c "
import json, collections
out = open('/tmp/p11analysis/triage/unknown_worklist.jsonl','w')
for line in open('docs/findings/per-failure-triage/verdicts.jsonl'):
    r = json.loads(line)
    if r.get('category') != 'UNKNOWN': continue
    if r.get('supersedes'): continue
    out.write(json.dumps(r)+'\n')
out.close()
print('wrote /tmp/p11analysis/triage/unknown_worklist.jsonl')"
wc -l /tmp/p11analysis/triage/unknown_worklist.jsonl
```

### Task 6.2: Manual classification batches

Process the UNKNOWN work-list in **batches of 20 groups**. Per group:

1. Read the `example_nodeid`'s test source (find it in `src/pkcs11_check/testcases/`).
2. Read 1–2 representative failure details from `report.jsonl` (filter by `nodeid == example_nodeid`).
3. Apply the AGENTS.md classification model.
4. Decide `category`, `severity`, `direction`, `evidence`, `routing`, `spec_ref`.
5. Append a superseding verdict record.

**Batch loop. Do NOT stop after one batch.** Continue until the work-list is empty.

- [ ] **Step 1: For each batch of 20 UNKNOWN groups (sorted by group_size desc), apply manual classification**

Use this template per batch (this is the "loop body"):

```bash
python3 << 'EOF'
# MANUAL BATCH SCRIPT — copy and edit the MANUAL_VERDICTS dict per batch
import json, datetime
from pathlib import Path

VERDICTS = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl')
now = datetime.datetime.now(datetime.timezone.utc).isoformat()

# Read 20 UNKNOWN records (largest first)
unknowns = []
for line in VERDICTS.read_text().splitlines():
    r = json.loads(line)
    if r.get('category') == 'UNKNOWN' and not r.get('supersedes'):
        unknowns.append(r)
unknowns.sort(key=lambda r: -r.get('group_size', 1))
batch = unknowns[:20]
print(f"Batch: {len(batch)} UNKNOWN groups. Edit MANUAL_VERDICTS below, re-run.")
for i, r in enumerate(batch):
    print(f"[{i}] size={r.get('group_size',1)} sig={r['signature'][:16]} {r['provider']}")
    print(f"    file: {r.get('test_file')}")
    print(f"    msg:  {(r.get('message') or '')[:200]}")

# >>> ANALYZER: replace {} with {signature: (category, severity, direction, evidence, routing, spec_ref)}
MANUAL_VERDICTS = {
    # example:
    # 'sha1:abc123': ('PROVIDER_BUG', 'HIGH', 'WRONG_OUTPUT', 'C_DigestKey returns SHA-256 of empty input regardless of key. Verified by reading test source + reprtraceback.', 'PROVIDER_REPORT(wolfpkcs11-master)', 'PKCS#11 v3.0 C_DigestKey'),
}
new_lines = []
for r in batch:
    if r['signature'] not in MANUAL_VERDICTS:
        continue
    cat, sev, direction, evidence, routing, spec_ref = MANUAL_VERDICTS[r['signature']]
    new_v = {**r,
        'category': cat, 'severity': sev, 'direction': direction,
        'evidence': evidence, 'routing': routing, 'spec_ref': spec_ref,
        'analyzed_at': now, 'analyzer': 'manual',
        'supersedes': r['signature'],
        'signature': r['signature'] + '#manual',
    }
    new_lines.append(json.dumps(new_v))
with VERDICTS.open('a') as f:
    for l in new_lines: f.write(l+'\n')
print(f'Appended {len(new_lines)} manual verdicts')
EOF
```

- [ ] **Step 2: Repeat Step 1 until `UNKNOWN` count is zero**

```bash
# Quick status check between batches:
python3 -c "
import json
n = sum(1 for l in open('docs/findings/per-failure-triage/verdicts.jsonl')
        if (r:=json.loads(l)).get('category')=='UNKNOWN' and not r.get('supersedes'))
print(f'UNKNOWN remaining: {n}')"
```

Continue batching until this prints `0`. **Do not stop early.** If a batch yields <5 confident verdicts, slow down — read the test source more carefully. If a batch yields 0 confident verdicts, escalate those signatures to the user with `routing=USER_ESCALATION`.

- [ ] **Step 3: Commit after every 3 batches**

```bash
git add docs/findings/per-failure-triage/verdicts.jsonl
git commit -m "docs(triage): manual deep-dive batch (N UNKNOWNs resolved)"
```

---

## Phase 7: Cross-Provider Correlation

Find tests failing in the same way across multiple providers → either universal harness bug or universal soft-token caveat. Findings unique to ONE provider → strongest provider-bug signal.

### Task 7.1: Build cross-provider signature correlation

**Files:**
- Create: `docs/findings/per-failure-triage/scripts/correlate.py`

- [ ] **Step 1: Write the correlator**

```python
#!/usr/bin/env python3
"""Find test_files that fail in multiple providers.

Output: reports/_universal.md (cross-cutting issues) + per-test_file correlation table.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

GROUPS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/groups")
REPORTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/reports")


def main() -> int:
    # test_file → {provider: [groups...]}
    by_file: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for gf in GROUPS.glob("*-failures-groups.json"):
        data = json.loads(gf.read_text())
        provider = data["provider"]
        for g in data["groups"]:
            by_file[g["test_file"]][provider].append(g)

    rows = []
    for test_file, per_provider in by_file.items():
        rows.append((len(per_provider), test_file, per_provider))
    rows.sort(key=lambda r: -r[0])

    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / "_universal.md"
    lines = [
        "# Cross-Provider Failure Correlation",
        "",
        "Tests failing in many providers are harness-bug candidates (or universal soft-token caveats).",
        "Tests failing in ONE provider are strongest provider-bug signals.",
        "",
        "| # providers | test file | providers |",
        "|---|---|---|",
    ]
    for n, test_file, per_provider in rows:
        prov_list = ", ".join(sorted(per_provider.keys()))
        lines.append(f"| {n} | `{test_file}` | {prov_list} |")
    lines.append("")
    lines.append("## Universal (≥5 providers) — harness-bug / soft-token-caveat candidates")
    lines.append("")
    for n, test_file, per_provider in rows:
        if n < 5:
            break
        lines.append(f"### `{test_file}` ({n} providers)")
        for provider, groups in sorted(per_provider.items()):
            for g in groups[:3]:
                lines.append(f"- **{provider}** size={g['size']} dir={g['direction']}: {(g['messages_sample'] or [''])[0][:120]}")
        lines.append("")
    lines.append("## Unique to one provider — strongest provider-bug signals")
    lines.append("")
    for n, test_file, per_provider in reversed(rows):
        if n > 1:
            break
        provider = next(iter(per_provider))
        lines.append(f"### `{test_file}` — **{provider}** only")
        for g in per_provider[provider][:5]:
            lines.append(f"- size={g['size']} dir={g['direction']}: {(g['messages_sample'] or [''])[0][:200]}")
        lines.append("")

    out.write_text("\n".join(lines))
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run it**

```bash
python3 docs/findings/per-failure-triage/scripts/correlate.py
```

- [ ] **Step 3: Read the output and sanity-check**

```bash
head -60 docs/findings/per-failure-triage/reports/_universal.md
```

Expected: top universal files match prior analysis (`security/test_ffi_length_boundary.py` ~7 providers since we dropped 14, `test_buffers.py`, `test_set_attribute.py`, etc.). Unique-to-one-provider section has bouncyhsm NOT present (correctly excluded); wolfpkcs11-master / kryoptic-main / corepkcs11-main / nss-main / opencryptoki-master / softhsm2-main / tpm2 should each have entries.

- [ ] **Step 4: For each universal test_file (≥5 providers), re-tag affected verdicts**

If a test file fails in ≥5 providers, the root cause is either:
- (a) A harness bug (test wrong / expectation wrong) → re-tag affected verdicts `HARNESS_BUG`
- (b) A universal soft-token caveat → re-tag `SOFT_TOKEN_CAVEAT`

Use a follow-up reconciler script (similar to Task 5.2) to apply these re-tags. Manual decision per test_file.

- [ ] **Step 5: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/correlate.py docs/findings/per-failure-triage/reports/_universal.md docs/findings/per-failure-triage/verdicts.jsonl
git commit -m "docs(triage): cross-provider correlation + universal/unique split"
```

---

## Phase 8: Report Assembly

Render the 7 per-provider reports + harness-fix list + summary.

### Task 8.1: Write `report.py`

**Files:**
- Create: `docs/findings/per-failure-triage/scripts/report.py`

- [ ] **Step 1: Write the report renderer**

```python
#!/usr/bin/env python3
"""Render per-provider reports + harness-fix list + summary from verdicts.jsonl."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")
REPORTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/reports")

PROVIDERS = [
    "wolfpkcs11-master", "opencryptoki-master", "corepkcs11-main",
    "kryoptic-main", "nss-main", "softhsm2-main", "tpm2",
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_verdicts() -> dict[str, list[dict]]:
    """Return {provider: [verdicts...]}, preferring superseding records."""
    raw: dict[str, dict[str, dict]] = defaultdict(dict)  # provider -> signature -> verdict
    for line in VERDICTS.read_text().splitlines():
        if not line.strip():
            continue
        v = json.loads(line)
        provider = v["provider"]
        # prefer the latest record per base signature
        base_sig = v.get("supersedes") or v["signature"]
        existing = raw[provider].get(base_sig)
        # later writes overwrite earlier
        raw[provider][base_sig] = v
    return {p: list(v.values()) for p, v in raw.items()}


def render_provider(provider: str, verdicts: list[dict]) -> str:
    lines = [
        f"# {provider} — Per-Failure Triage Report",
        "",
        f"Source: `artifacts_base/{provider}-pooled/` (2026-06-13)",
        "",
        "## Summary",
        "",
    ]
    # counts by category + severity
    cat_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    for v in verdicts:
        cat_counts[v.get("category", "?")] += 1
        sev_counts[v.get("severity", "?")] += 1
    lines.append("**By category:**")
    lines.append("")
    lines.append("| category | count |")
    lines.append("|---|---|")
    for cat in sorted(cat_counts):
        lines.append(f"| {cat} | {cat_counts[cat]} |")
    lines.append("")
    lines.append("**By severity:**")
    lines.append("")
    lines.append("| severity | count |")
    lines.append("|---|---|")
    for sev in sorted(sev_counts, key=lambda s: SEVERITY_ORDER.get(s, 99)):
        lines.append(f"| {sev} | {sev_counts[sev]} |")
    lines.append("")

    # findings sorted by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_vs = [v for v in verdicts if v.get("severity") == sev]
        if not sev_vs:
            continue
        lines.append(f"## {sevity} ({len(sev_vs)})".replace("ity", "ITY"))
        lines.append("")
        for v in sorted(sev_vs, key=lambda v: -v.get("group_size", 1)):
            lines.append(f"### [{v.get('category','?')}] `{v.get('test_file','?')}` — {v.get('direction','?')} (group size: {v.get('group_size',1)})")
            lines.append(f"- **nodeid (example):** `{v.get('example_nodeid') or v.get('nodeid')}`")
            lines.append(f"- **message:** `{v.get('message','')[:300]}`")
            lines.append(f"- **evidence:** {v.get('evidence','')}")
            if v.get("spec_ref"):
                lines.append(f"- **spec:** {v['spec_ref']}")
            lines.append(f"- **routing:** {v.get('routing','?')}")
            lines.append(f"- **analyzed by:** {v.get('analyzer','?')} at {v.get('analyzed_at','?')}")
            lines.append("")
    return "\n".join(lines)


def render_harness_fixes(all_verdicts: dict[str, list[dict]]) -> str:
    lines = [
        "# pkcs11-check Harness Fixes — Backlog",
        "",
        "Findings classified as HARNESS_BUG. Each is a test/fixture/test-expectation bug in pkcs11-check itself.",
        "",
    ]
    fixes = []
    for provider, vs in all_verdicts.items():
        for v in vs:
            if v.get("category") == "HARNESS_BUG":
                fixes.append((provider, v))
    if not fixes:
        lines.append("_(none)_")
        return "\n".join(lines)
    lines.append("| provider | severity | test file | direction | evidence |")
    lines.append("|---|---|---|---|---|")
    for provider, v in fixes:
        lines.append(f"| {provider} | {v.get('severity','?')} | `{v.get('test_file','?')}` | {v.get('direction','?')} | {v.get('evidence','')[:200]} |")
    return "\n".join(lines)


def render_summary(all_verdicts: dict[str, list[dict]]) -> str:
    total_records = sum(sum(v.get("group_size", 1) for v in vs) for vs in all_verdicts.values())
    total_groups = sum(len(vs) for vs in all_verdicts.values())
    unknown = sum(1 for vs in all_verdicts.values() for v in vs if v.get("category") == "UNKNOWN")
    lines = [
        "# Per-Failure Triage Summary (2026-06-13)",
        "",
        f"**Providers analyzed:** {len(all_verdicts)}",
        f"**Distinct failure groups:** {total_groups}",
        f"**Total individual outcomes covered:** {total_records}",
        f"**UNKNOWN remaining:** {unknown}",
        "",
        "## Per-provider breakdown",
        "",
        "| provider | groups | CRITICAL | HIGH | MEDIUM | LOW | INFO | PROVIDER_BUG | HARNESS_BUG | KNOWN_ISSUE | OTHER |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for provider in PROVIDERS:
        vs = all_verdicts.get(provider, [])
        sev_c = {s: sum(1 for v in vs if v.get("severity") == s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        cat_c = {
            "PROVIDER_BUG": sum(1 for v in vs if v.get("category") == "PROVIDER_BUG"),
            "HARNESS_BUG": sum(1 for v in vs if v.get("category") == "HARNESS_BUG"),
            "KNOWN_ISSUE": sum(1 for v in vs if v.get("category") == "KNOWN_ISSUE"),
            "OTHER": sum(1 for v in vs if v.get("category") not in ("PROVIDER_BUG","HARNESS_BUG","KNOWN_ISSUE")),
        }
        lines.append(f"| {provider} | {len(vs)} | {sev_c['CRITICAL']} | {sev_c['HIGH']} | {sev_c['MEDIUM']} | {sev_c['LOW']} | {sev_c['INFO']} | {cat_c['PROVIDER_BUG']} | {cat_c['HARNESS_BUG']} | {cat_c['KNOWN_ISSUE']} | {cat_c['OTHER']} |")
    lines.append("")
    lines.append(f"## Loop status")
    lines.append("")
    lines.append(f"- **exhausted:** {'true' if unknown == 0 else 'false'}")
    lines.append(f"- **next-step:** {'Phase 9 final sweep' if unknown == 0 else f'Phase 6 manual deep-dive ({unknown} UNKNOWN remaining)'}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="render all providers + summary")
    ap.add_argument("--provider")
    args = ap.parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    all_v = load_verdicts()

    if args.all:
        for provider in PROVIDERS:
            (REPORTS / f"{provider}-report.md").write_text(render_provider(provider, all_v.get(provider, [])))
        (REPORTS / "_harness-fixes.md").write_text(render_harness_fixes(all_v))
        (REPORTS / "_summary.md").write_text(render_summary(all_v))
        print(f"Wrote 7 provider reports + harness-fixes + summary to {REPORTS}")
    elif args.provider:
        (REPORTS / f"{args.provider}-report.md").write_text(render_provider(args.provider, all_v.get(args.provider, [])))
    else:
        ap.error("specify --all or --provider X")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Note: fix the typo in `render_provider` — the `{sev}ity` substitution is a hack to uppercase the severity. Replace with proper `sev.upper()`.

- [ ] **Step 2: Fix the severity-uppercase typo**

In `render_provider`, change:
```python
        lines.append(f"## {sev}ity ({len(sev_vs)})".replace("ity", "ITY"))
```
to:
```python
        lines.append(f"## {sev.upper()} ({len(sev_vs)})")
```

- [ ] **Step 3: Render all reports**

```bash
python3 docs/findings/per-failure-triage/scripts/report.py --all
```

- [ ] **Step 4: Verify the 9 files exist**

```bash
ls docs/findings/per-failure-triage/reports/
```

Expected: 7 provider reports + `_universal.md` (from Phase 7) + `_harness-fixes.md` + `_summary.md`.

- [ ] **Step 5: Read `_summary.md` and confirm exhaustion status**

```bash
cat docs/findings/per-failure-triage/reports/_summary.md
```

If `exhausted: false`, return to Phase 6. If `exhausted: true`, proceed to Phase 9.

- [ ] **Step 6: Commit**

```bash
git add docs/findings/per-failure-triage/scripts/report.py docs/findings/per-failure-triage/reports/
git commit -m "docs(triage): render 7 provider reports + harness-fixes + summary"
```

---

## Phase 9: Final Sweep (Anti-Premature-Termination)

The user explicitly asked: "organize the plan in a loop - so it would not stop too fast." This phase enforces that.

### Task 9.1: Re-sweep for missed items

- [ ] **Step 1: Find any record in `workqueue/` that lacks a verdict**

```bash
python3 << 'EOF'
import json
from pathlib import Path
WQ = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue')
VERDICTS = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl')

# Collect every (provider, nodeid) we have a verdict for (either directly or via group)
covered = set()
for line in VERDICTS.read_text().splitlines():
    if not line.strip(): continue
    v = json.loads(line)
    p = v['provider']
    # If this is a group verdict, look up the group's nodeids via groups/*.json
    if v.get('group_id'):
        covered.add((p, v.get('example_nodeid')))
    if v.get('nodeid','').startswith('<group:'):
        pass  # already counted via example_nodeid
    else:
        covered.add((p, v.get('nodeid')))

# Now scan workqueue failures + crashes + xpassed for items not in covered
missing_fail = missing_xp = 0
for bucket in ('failures', 'xpassed'):
    for f in WQ.glob(f'*-{bucket}.jsonl'):
        for line in f.read_text().splitlines():
            if not line.strip(): continue
            r = json.loads(line)
            if (r['provider'], r['nodeid']) not in covered:
                missing_fail += 1
                if missing_fail <= 10:
                    print(f"  MISSING {bucket}: {r['provider']} {r['nodeid']}")

# For xfails, check at group level (since xfail verdicts are per-group)
missing_xf_groups = 0
GROUPS = Path('/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/groups')
verdict_sigs = set()
for line in VERDICTS.read_text().splitlines():
    if not line.strip(): continue
    v = json.loads(line)
    if v.get('outcome') == 'xfail':
        verdict_sigs.add(v['signature'].split('#')[0])
for gf in GROUPS.glob('*-xfails-groups.json'):
    data = json.loads(gf.read_text())
    for g in data['groups']:
        if g['signature'] not in verdict_sigs:
            missing_xf_groups += 1
            if missing_xf_groups <= 10:
                print(f"  MISSING xfail group: {data['provider']} size={g['size']} {g['test_file']}")

print(f"\nMissing per-item: {missing_fail}")
print(f"Missing xfail groups: {missing_xf_groups}")
EOF
```

Expected: both numbers zero (or near-zero). If non-zero, route the missing items back through Phase 6.

- [ ] **Step 2: Find any verdict with weak evidence (length < 30 chars or contains "UNREVIEWED")**

```bash
python3 -c "
import json
n = 0
for line in open('docs/findings/per-failure-triage/verdicts.jsonl'):
    r = json.loads(line)
    if r.get('supersedes'): continue  # only latest
    ev = r.get('evidence','')
    if len(ev) < 30 or 'UNREVIEWED' in ev:
        n += 1
        if n <= 10:
            print(f\"{r['provider']} {r.get('test_file','?')} {r['signature'][:12]}: {ev[:100]}\")
print(f'\\nWeak-evidence verdicts: {n}')"
```

Expected: 0. If non-zero, those records must be re-processed in Phase 6.

### Task 9.2: Find-contradictions pass

Look for any pair of verdicts that contradict each other (same test_file, different verdicts across providers without justification).

- [ ] **Step 1: List same-test-file verdicts with divergent categories across providers**

```bash
python3 -c "
import json, collections
# test_file → {provider: (category, severity)}
by_file = collections.defaultdict(dict)
for line in open('docs/findings/per-failure-triage/verdicts.jsonl'):
    r = json.loads(line)
    if r.get('supersedes'): continue
    if not r.get('test_file'): continue
    by_file[r['test_file']][r['provider']] = (r.get('category'), r.get('severity'))

n_div = 0
for tf, pp in by_file.items():
    if len(pp) < 2: continue
    cats = set(c for c,_ in pp.values())
    if len(cats) > 1:
        n_div += 1
        if n_div <= 20:
            print(f'{tf}')
            for p, (c, s) in sorted(pp.items()):
                print(f'  {p:22s} {c:18s} {s}')
print(f'\\nDivergent-category test_files: {n_div}')"
```

Each divergence must be justified (e.g., bouncyhsm has WRONG_OUTPUT for test_buffers but opencryptoki has CLEAN_ERROR — those are genuinely different bugs). If unjustified, escalate.

### Task 9.3: Final commit + declare exhaustion

- [ ] **Step 1: Re-render reports with the final verdict set**

```bash
python3 docs/findings/per-failure-triage/scripts/report.py --all
```

- [ ] **Step 2: Edit `_summary.md` to set `exhausted: true` if Phase 9.1 + 9.2 are clean**

(If `report.py` already computes it correctly, just verify.)

- [ ] **Step 3: Final commit**

```bash
git add docs/findings/per-failure-triage/
git commit -m "docs(triage): final sweep — declare exhaustion for 7-provider per-failure triage"
```

---

## Phase 10: Hand-off Documentation

### Task 10.1: Write the index README

**Files:**
- Create: `docs/findings/per-failure-triage/README.md`

- [ ] **Step 1: Write the README**

```markdown
# Per-Failure Triage (2026-06-13)

Exhaustive analysis of every `failed`, `xfailed`, `xpassed`, and `crashed` test outcome for 7 PKCS#11 providers, drawn from `artifacts_base/`.

## Scope

| Provider | Source |
|---|---|
| wolfpkcs11-master | `artifacts_base/wolfpkcs11-master-pooled/` |
| opencryptoki-master | `artifacts_base/opencryptoki-master-pooled/` |
| corepkcs11-main | `artifacts_base/corepkcs11-main-pooled/` |
| kryoptic-main | `artifacts_base/kryoptic-main-pooled/` |
| nss-main | `artifacts_base/nss-main-pooled/` |
| softhsm2-main | `artifacts_base/softhsm2-main-pooled/` |
| tpm2 | `artifacts_base/tpm2-pooled/` |

**Excluded:** bouncyhsm (dev-only), kryoptic-fips (= kryoptic FIPS mode), pkcs11-mock (canned mock), other release/main duplicates.

## Reading order

1. `reports/_summary.md` — top-level numbers, exhaustion status
2. `reports/_universal.md` — cross-cutting issues (5+ providers)
3. `reports/_harness-fixes.md` — pkcs11-check test bugs to fix
4. `reports/<provider>-report.md` — per-provider deep-dive (7 files)
5. `verdicts.jsonl` — machine-readable canonical record (append-only)

## Methodology

See `docs/superpowers/plans/2026-06-13-per-failure-triage.md`.

## Classification model

See `AGENTS.md` (Test-outcome classification model) and `docs/findings/artifacts-base-analysis-2026-06-13.md` §9.5 (severity-direction principle).

## Re-running

```bash
# Re-extract work-queue from artifacts_base
python3 scripts/extract.py

# Re-group
python3 scripts/group.py

# Apply automated classifier
for p in wolfpkcs11-master opencryptoki-master corepkcs11-main kryoptic-main nss-main softhsm2-main tpm2; do
  for b in failures xfails xpassed; do
    python3 scripts/classify.py --provider $p --bucket $b
  done
done

# Reconcile against module-issues
python3 scripts/reconcile.py

# Cross-provider correlation
python3 scripts/correlate.py

# Render reports
python3 scripts/report.py --all
```

The `verdicts.jsonl` is append-only — manual verdicts from Phase 6 are preserved across re-runs.
```

- [ ] **Step 2: Commit**

```bash
git add docs/findings/per-failure-triage/README.md
git commit -m "docs(triage): add index README for per-failure-triage"
```

---

## Self-Review Checklist (run before declaring complete)

- [ ] All 7 providers have a `-failures.jsonl`, `-xfails.jsonl`, and `-xpassed.jsonl` (if applicable).
- [ ] `verdicts.jsonl` has zero records with `category=UNKNOWN` (or they are escalated to user).
- [ ] `verdicts.jsonl` has zero records with `evidence` < 30 chars or containing `UNREVIEWED` (after Phase 6 + Phase 9).
- [ ] Every crashed file has a verdict (5 files = ≥5 verdicts at file level, covering all 13 per-test crashes).
- [ ] Every xfail GROUP has a verdict (individual xfails inherit via group).
- [ ] `reports/_summary.md` shows `exhausted: true`.
- [ ] No git uncommitted changes.
- [ ] Phase 9 final sweep adds zero new verdicts.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-06-13-per-failure-triage.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task. Best for this plan because:
- Phase 6 (manual deep-dive) batches are independent and benefit from fresh context per batch
- Phases 0/4/5/7/8 are mechanical and fast for a single-shot subagent
- Review between phases catches classifier drift early

**2. Inline Execution** — execute tasks in this session. Best if you want to interleave review tightly with classification decisions.

**Which approach?**
