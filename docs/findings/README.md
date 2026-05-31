# Artifact Findings Analysis (2026-05-27 artifact set)

Deep analysis of every crash and failure in the `artifacts/` provider runs.
**Goal of this phase: investigate + store root causes only — no source fixes yet.**
Fixes and Docker reruns happen in a later batch.

## Scope

- **In scope (12 targets):** softhsm2, softhsm2-main, kryoptic, kryoptic-main,
  kryoptic-fips, nss, nss-main, nss-pqc, opencryptoki, opencryptoki-master,
  tpm2, pkcs11-mock.
- **Out of scope:** `bouncyhsm` (7,692 failures; long-tail simulator, excluded by request).
- Intermediate Docker re-runs (for confirmation) must write to **new** folder
  names under `artifacts/` — never overwrite the existing result dirs.

## Method

Failures parsed from each `artifacts/<target>/report.jsonl` (`outcome=failed`),
grouped by `(test function, normalized message)` into **classes**. File-level
crashes parsed from `results.json` units (`status=crashed`). Machine-readable:
- [`failure-inventory.json`](failure-inventory.json) — 729 failure classes, counts, per-provider, example nodeid.
- [`crash-inventory.json`](crash-inventory.json) — 10 file-level crashes.

## Failure landscape (2,969 failures, excl. bouncyhsm → 729 classes)

| Category | Failures | Notes |
|---|--:|---|
| OTHER | 1,868 | pkcs11-mock cert round-trip (~559), opencryptoki AES-CBC (288), RSA-PSS/ML-DSA sig (sigver), … |
| ACCEPT_INVALID | 581 | accepted invalid sig/ciphertext/key — **RSA PKCS#1 v1.5 decrypt = 546** |
| WRONG_CKR | 254 | unexpected CK_RV vs expected |
| CRASH_signal | 162 | module crashed with a signal (isize::MAX, template_count overflow) |
| ABORT_exit | 104 | subprocess aborted (GCM NULL-AAD nonzero len, KWP bit-flip) |

### Crashes (file-level, 10) and signal crash-findings

| Provider | rc | Crashing file |
|---|---|---|
| kryoptic-fips | 6 (SIGABRT) | acvp/aes/test_ccm.py |
| kryoptic-fips | 6 | test_mech_derive.py |
| kryoptic-fips | 6 | test_mech_encrypt.py |
| kryoptic-fips | 6 | test_misc_kdf.py |
| kryoptic-fips | 6 | wycheproof/test_wycheproof_aes.py |
| nss | 11 (SIGSEGV) | test_mech_flags.py |
| nss-main | 11 | test_mech_flags.py |
| nss-main | 11 | test_mech_negative.py |
| nss-pqc | 11 | test_mech_flags.py |
| nss-pqc | 11 | test_mech_negative.py |

Plus test-level "module crashed with signal" findings (recorded as failures):
isize::MAX `C_Sign`/`C_Digest` and `C_FindObjectsInit(template_count)` overflow
on kryoptic/nss/opencryptoki/tpm2.

## Status

- [x] Failure + crash inventory built and persisted.
- [x] Per-class root-cause investigation + classification → [`catalog.md`](catalog.md) (findings PC-1..6, PV-1..15, CR-1..6, EX-1..2).
- [x] Per-provider findings docs → `provider-<target>.md` (one per in-scope target).
- [ ] Fix phase (separate) → see [`fix-plan.md`](fix-plan.md): resolve PKCS11-CHECK bugs **without hiding findings** (+ regression tests), route CKR changes through `_ckr_spec.py` per the classification plan, gate pkcs11-mock, confirm NEEDS-CONFIRM via Docker reruns into NEW artifact folders, re-measure.

## Headline classifications (see catalog.md for detail)

**PKCS11-CHECK bugs (our code — fix these):**
- **PC-1** GCM NULL-AAD probe: ctypes `pIv` assignment error → dies in setup on all 10 providers.
- **PC-5** KWP bit-flip: KWP-wrap setup unguarded → Python traceback (nss ×15).
- **PC-2** ML-DSA sigVer rejects valid on 3 providers (likely our context/encoding) — NEEDS-CONFIRM.
- **PC-3/PC-6** tpm2 RSA-PSS MD5 + negative-path CKR sets too narrow (`CKR_FUNCTION_NOT_SUPPORTED`) — NEEDS-CONFIRM.
- **PC-4** assorted WRONG_CKR: widen to specific additional valid CKRs.

**PROVIDER findings (real, mostly hard-fail by design):**
- **PV-1** RSA PKCS#1 v1.5 lenient decrypt (546, all but tpm2) · **PV-2** opencryptoki AES-CBC padding (288)
  · **PV-3** EdDSA accepts invalid keys (all) · **PV-7** kryoptic ML-DSA/AES-CTS `DEVICE_ERROR`
  · **PV-10..15** access-control/Tookan, padding oracles, message-API IV, AES-CTR/KCV, buffer-state.
- Crashes (all PROVIDER, mostly KNOWN in module-issues.md): **CR-1** kryoptic-fips FIPS SIGABRT,
  **CR-2** NSS NULL-param SIGSEGV cluster, **CR-3** isize::MAX, **CR-4** template_count overflow.

**EXPECTED:** **EX-1/EX-2** pkcs11-mock (~1,353) — mock returns canned values; suite not meaningful there.

> Nothing in pkcs11-check or any provider has been modified in this phase.

> Classification legend used per finding: **PROVIDER** (real module defect),
> **PKCS11-CHECK** (our test/harness bug), **KNOWN** (already in
> `docs/module-issues.md`), **EXPECTED** (correct behavior, e.g. mock provider).
