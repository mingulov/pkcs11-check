# Per-Failure Triage — 2026-06-13

Per-failure classification of every test failure/xfail/crash across 7 PKCS#11
providers from the `artifacts_base/` pool. Output is structured verdict records
that can feed (a) upstream provider bug reports, (b) pkcs11-check harness
fixes, (c) `docs/module-issues.md` updates.

> **Status:** 9 of 10 plan phases complete. Per user directive (m0213-m0214),
> classification extension stopped on 2026-06-13. ~465 UNKNOWN xfail groups
> (across 161 buckets / 4844 tests) are deferred to a different in-tool
> workflow. See [§Status](#status) and [scripts/workqueue.py](scripts/workqueue.py)
> for the deferred work-queue.

## Layout

```
docs/findings/per-failure-triage/
├── README.md                  (this file)
├── verdicts.jsonl             (append-only classification database)
├── reports/                   (Phase 7+8 output — START HERE)
│   ├── _index.md              (executive summary + top-priority findings)
│   ├── _universal.md          (cross-provider theme correlation)
│   ├── wolfpkcs11-master.md   (per-provider findings)
│   ├── opencryptoki-master.md
│   ├── corepkcs11-main.md
│   ├── kryoptic-main.md
│   ├── nss-main.md
│   ├── softhsm2-main.md
│   └── tpm2.md
├── scripts/                   (regenerable tooling)
│   ├── extract.py             (Phase 0: build per-provider JSONL)
│   ├── group.py               (Phase 4: signature grouping)
│   ├── classify.py            (Phase 5.1: auto-classify via regex rules)
│   ├── reconcile.py           (Phase 5.2: cross-ref vs module-issues.md)
│   ├── workqueue.py           (Phase 6: emit prioritized bucket list)
│   ├── emit_phase6_verdict.py (Phase 6: idempotent verdict appender)
│   ├── bulk_classify.py       (Phase 6 bulk: regex rules for vector-replay xfails)
│   └── report.py              (Phase 7+8: render reports)
├── workqueue/                 (Phase 6 work-queue state)
└── groups/                    (Phase 4 group JSON files)
```

## Scope

**In scope (from `artifacts_base/`, no fresh docker):**

| Provider | Failures | Xfails | Crashed files |
|---|---:|---:|---:|
| wolfpkcs11-master | 468 | 14064 | 2 |
| opencryptoki-master | 215 | 2861 | 0 |
| corepkcs11-main | 683 | 9818 | 0 |
| kryptic-main | 158 | 24579 | 0 |
| nss-main | 130 | 2121 | 3 |
| softhsm2-main | 67 | 5667 | 0 |
| tpm2 | 49 | 25562 | 0 |
| **Total** | **1770** | **84672** | **5** |

**Out of scope (per user direction):**
- `bouncyhsm` — dev-only reference, dropped entirely
- `kryptic-fips` — separate FIPS build of kryptic
- `pkcs11-mock` — canned mock, not a real provider
- Release/main duplicates where master/main variant exists

## Effective verdict counts (Phase 7+8 reports basis)

| Category | Count | Notes |
|---|---:|---|
| PROVIDER_BUG | 1429 | File as upstream bug report |
| KNOWN_ISSUE | 857 | Already in `docs/module-issues.md` |
| SOFT_TOKEN_CAVEAT | 270 | UB-provoked or Bleichenbacher-class; severity lowered |
| UNKNOWN | 465 | **Deferred** — see status below |
| HARNESS_BUG | 16 | Fix in pkcs11-check test code |
| UPSTREAM_BUG | 1 | OpenSSL PR #30663 (AES-KWP buffer overwrite) |
| SPEC_AMBIGUITY | 1 | Atomicity of `C_SetAttributeValue` not mandated by PKCS#11 |

| Severity | Count |
|---|---:|
| CRITICAL | 2 |
| HIGH | 381 |
| MEDIUM | 591 |
| LOW | 1156 |
| INFO | 904 |

**The 2 CRITICAL findings:**
1. `kryptic-main` `CKM_AES_CBC_ENCRYPT_DATA` KDF ignores IV — byte-identical
   derived keys for different IVs (Type-A crypto-correctness break).
   See [reports/kryoptic-main.md](reports/kryoptic-main.md) F066.
2. `tpm2` `C_GetAttributeValue` leaks `CKA_VALUE` of imported
   `CKA_SENSITIVE=True` AES key (Type-B sensitivity claim violated).
   See [reports/tpm2.md](reports/tpm2.md) F179.

## Status

Per user direction (m0213-m0214):

> "do not extend classification for remaining reports!"
> "it will be done by different way, so just continue with known."

- **Phases 0–8:** COMPLETE.
- **Phase 6 (manual deep-dive):** 2572 of 3037 effective records classified
  (85%). Remaining 465 UNKNOWN are mostly bulk vector-replay xfails
  (wycheproof / ACVP / CCTV) where each xfail encodes a clean CKR rejection.
  Top deferred buckets:
  - 486 ECDSA secp256r1_sha512 wycheproof (kryptic-main)
  - 405 CKM_AES_CTS CBC-CS decrypt failures (kryptic-main)
  - 288 SigVer-pkcs15 SHA-1 (multiple providers)
  - 162×4 HMAC tc82-valid not verified (kryptic)
- **Phase 9 (final sweep):** Skipped — the deferred UNKNOWNs are the only
  remaining work and they are explicitly out of scope.
- **Phase 10 (README):** THIS FILE.

## How to regenerate

All scripts idempotent and append-safe.

```bash
# Phase 0: extract per-provider records from artifacts_base/ (already committed)
python3 docs/findings/per-failure-triage/scripts/extract.py

# Phase 4: group by signature (already committed)
python3 docs/findings/per-failure-triage/scripts/group.py

# Phase 5: auto-classify (idempotent — skips already-done)
python3 docs/findings/per-failure-triage/scripts/classify.py
python3 docs/findings/per-failure-triage/scripts/reconcile.py

# Phase 7+8: render reports (this is what's most useful to re-run)
python3 docs/findings/per-failure-triage/scripts/report.py
```

## Verdict JSONL schema

```jsonc
{
  "provider": "wolfpkcs11-master",          // provider key
  "signature": "sha1:1b28b74f983d6400",     // unique group identifier
  "outcome": "failure|xfail|crashed",       // test outcome
  "message": "...",                          // first 500 chars of group sample
  "test_file": "src/pkcs11_check/testcases/...",
  "direction": "ACCEPT_INVALID|REJECT_VALID|WRONG_OUTPUT|CLEAN_ERROR|CRASH|...",
  "category": "PROVIDER_BUG|UPSTREAM_BUG|HARNESS_BUG|KNOWN_ISSUE|SPEC_AMBIGUITY|SOFT_TOKEN_CAVEAT|UNKNOWN|...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "evidence": "...",                         // free-text justification
  "routing": "PROVIDER_REPORT|USER_ESCALATION|HARNESS_FIX|DOCS_ONLY|MANUAL_REVIEW",
  "group_id": "provider/direction/test_file#sig8",
  "group_size": 12,                          // how many tests this group covers
  "example_nodeid": "...",                   // first test nodeid
  "analyzed_at": "2026-06-13T...",
  "analyzer": "manual|auto-classifier|auto-reconcile|bulk-classifier",
  "supersedes": "<base signature>"          // optional: present on superseding records
}
```

## Classification model

Applies the AGENTS.md model: classify by **what the module did vs what is correct**.

| Direction | Severity |
|---|---|
| accept-invalid (lax) on auth/AEAD/RSA-PAD | Critical/High (oracle/forgery/Bleichenbacher/Manger/Vaudenay) |
| reject-valid (over-strict) on same | Low (functional bug, "advertised but not operational") |
| wrong-output on successful operation | Critical (Type-A crypto-correctness break) |
| crash | High (always — "a segfault IS the finding") |
| clean error on advertised mechanism | Low (capability gap) |

Self-contradiction classes (Type A/B/C/D) → fail (not xfail):
- **A** crypto-correctness (wrong/forgeable result)
- **B** attribute/permission (claimed a protection then violated it)
- **C** lifecycle/state (claimed success then didn't honor it)
- **D** derived-attribute invariant

See `docs/classification-model-design.md` for the full model.

## Plan reference

`docs/superpowers/plans/2026-06-13-per-failure-triage.md` — the 10-phase plan
that produced this directory.
