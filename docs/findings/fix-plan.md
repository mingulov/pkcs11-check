# Fix-phase plan & guard-rails

How to act on [`catalog.md`](catalog.md) in the **later** fix phase. Nothing here is
implemented yet. Driven by the user's constraints (2026-05-27) + the existing
classification plan.

## Non-negotiable guard-rails

1. **A pkcs11-check change must NEVER hide a real crash or bug.** Several "PKCS11-CHECK"
   findings (PC-1 GCM NULL-AAD, PC-5 KWP) are *intended probes blocked by a harness bug*.
   Fixing the harness must make the probe **actually run** and surface the real provider
   behavior (crash → `fail`/finding; clean reject → pass; wrong accept → finding). It must
   not convert the probe into a no-op or a blanket pass.
2. **Every harness fix gets a dedicated regression test that re-triggers the original issue**
   so it is *always* exercised and cannot silently regress. Use
   `superpowers:test-driven-development` (write the failing test first) and, for multi-step
   work, `superpowers:subagent-driven-development` / `superpowers:executing-plans`.
   - Prefer an offline **mock-`raw` meta-test** in `tests/*_runtime_classification.py` (drive a
     fake `raw` returning a chosen `CK_RV`/crash; assert the classification) — runs with no
     provider, matching the classification plan's per-flip acceptance gate.
3. **Verify the effect, not the return code** (classification model). Crash = `fail`;
   accept-invalid-crypto / self-contradiction = `fail`; honest single deviation = `xfail`;
   missing capability = `skip`. No per-provider config.
4. **Doc-sync:** any flip of a finding documented in `docs/module-issues.md` updates that entry
   in the same change; NEW provider findings get added there.

## The fix phase EXECUTES the classification plan (backbone)

**Decision (2026-05-27):** the CKR-common-storage / table-centric classification plan
([`../classification-model-plan.md`](../classification-model-plan.md)) is **part of this goal**
and must be **executed**, not just referenced. Status: **0 / 46 tasks done** — only the *ad-hoc*
per-test classification shipped in v0.1.1; the table-centric refactor (the `kind` field, 3-way
`assert_ckr`, mock-`raw` meta-tests) is unimplemented.

The classification plan is the **backbone** of the fix phase; the per-finding fixes (PC-*) are
implemented as rows/migrations on top of it, never ad-hoc. Run it with
`superpowers:executing-plans` (or `superpowers:subagent-driven-development`), incrementally —
each phase is one revertible change gated on its meta-tests. **Phase 1** (foundation) enables
the PC-4/PC-6 CKR work; **Phase 2** (invalid-vector A/B classification) is Phase-1-independent
and may land first and directly covers PV-1/PV-2/PV-3/PV-9 accept-invalid findings.

## CKR changes go through the common storage (do NOT widen ad-hoc)

The "CKR common storage" is **`src/pkcs11_check/testcases/ckr/_ckr_spec.py`**:
`CkrExpectation` (the table) + the single `assert_ckr()`. Per
[`../classification-model-plan.md`](../classification-model-plan.md) (table-centric, 6 phases):
- **Tests declare intent; `assert_ckr` decides pass/xfail/fail.** Add the planned `kind` field
  to `CkrExpectation` and make `assert_ckr` 3-way (expected→pass, other clean reject→`xfail`,
  `CKR_OK`/crash→`fail`).
- The **PC-4 / PC-6 CKR-widenings** (e.g. accepting `CKR_FUNCTION_NOT_SUPPORTED` for tpm2's
  limited surface, the RO-wrap `CKR_TEMPLATE_INCOMPLETE`, etc.) must be expressed as
  `CkrExpectation` rows / spec-vs-compat sets — **not** scattered per-test `in {...}` edits
  (that ad-hoc style is exactly what the plan rejects, and how today's asymmetries arose).
- Only ever widen to **specific** additional CKRs (never a catch-all), per `CLAUDE.md`.

## Suggested fix order (each = one revertible change + its regression test)

1. **PC-1** (GCM NULL-AAD `pIv` cast) — unblock probe; rerun GCM targets into a new artifact
   folder; record real behavior; regression meta-test. *Highest value: clarifies a real probe.*
2. **PC-5** (KWP wrap setup classification) — capture real wrap `rv`; skip/xfail honestly.
3. **Phase 1 of the classification plan** (add `kind`, 3-way `assert_ckr` + meta-tests), then
   **PC-4 / PC-6** CKR rows on top of it.
4. **PC-2** (ML-DSA sigVer encoding) — **RESOLVED 2026-05-28**: loader filters
   `signatureInterface == "internal"` groups (the 9 false-fails per provider were ACVP
   internal-interface vectors with no PKCS#11 mechanism equivalent). Regression test
   `tests/test_acvp_mldsa_sigver_loader.py`. **PC-3 / PV-8** split — partially resolved:
   - **PC-3 (security probes, 7 tpm2 false-fails)** RESOLVED — `gen_*_keypair` setup
     now skips on capability-class CKRs (`_KEYGEN_CAPABILITY_REJECT_RVS`). Regression
     test `tests/test_security_rsa_pss_md5_setup_skip.py` (5 cases).
   - **PV-8 (39 invalid-accepted tpm2 rows)** confirmed PROVIDER — already source-
     reviewed in `docs/module-issues.md` (auto-salt-length detection in OpenSSL path).
     No harness change.
   - **PC-3 REMAINING — 43 wycheproof "valid SHA-1 PSS rejected" on tpm2:** verify
     returns `verified=False` with no exception (current `is_known_error` path does
     not apply). Needs a self-roundtrip-probe helper for `test_wycheproof_rsa_pss.py`:
     if a known-valid sig is rejected, generate a fresh keypair and try sign+verify
     with the same (mech, hash, mgf); roundtrip-fails → "advertised not operational"
     → `xfail`, roundtrip-passes → real `fail`.
5. **EX-2** (pkcs11-mock) — gate the functional/security/KAT suites off the mock provider
   (capability/identity guard), leaving smoke/diagnostic only. Not a bug.
6. **CR-6 / timing** — make timeouts/timing-variance non-gating or confirm as provider hangs.

## Rerun review — softhsm2 (2026-05-28, `artifacts/softhsm2-recheck-20260528/`)

First valid post-fix rerun (full suite, ~82k). Net vs baseline: passed −259, **failed +57**,
xfailed +147 — findings stopped hiding (former passes → real fails + documented xfails). Total
~stable (82,014). **GCM NULL-AAD SIGSEGV surfaced as `fail`** (FP-1 confirmed end-to-end);
KWP no longer exit-1 crashes (FP-2). The +58 new failures reviewed:
- **~55 legitimate surfaced findings**: ECDH invalid-point accepted (×42), GCM weak tag/IV +
  IV-reuse, PSS sLen=0, bad EC-curve OID, wrong-key-type sign/verify accepted, CBC-PAD oracle.
- **3 false-fails — RESOLVED:** the module's correct refusal had been flagged "unexpected".
  Fixed by 718a429 (destroyed-handle reads now classified by raw rv → `test_destroyed_handle`
  and `test_ckr_object_handle_invalid_after_destroy` accept `CKR_OBJECT_HANDLE_INVALID`) and
  33b5f0e (refused wrap of protected key now counts as the attack being blocked →
  `test_wrap_decrypt_extraction_attempt` accepts `CKR_KEY_UNEXTRACTABLE`). Both fixes are
  narrow / per-test; the broader Phase-4 N2 follow-up (push these into the
  table/`classify_negative_rv`) still stands as part of the classification rework.

## Goal additions (2026-05-28)

- **Refresh the result/size docs after FP-8 reruns** (they are stale vs the classification
  fixes; numbers only become accurate post-rerun): `docs/docker-provider-results.md`
  (per-provider pass/fail/skip/xfail matrix), `docs/provider-crash-failure-findings.md`
  (crash/timeout/failure classification + new findings: GCM NULL-AAD SIGSEGV, NSS MAC-RSA),
  `docs/test-universe.md` (suite size/group breakdown — collection is ~stable at ~109k).
- **Source audit/review of pkcs11-check while Docker runs** (idle compute): review the raw
  ctypes binding, `recipes.py`, `core/file_runner.py`, the conftest classifiers, and testcase
  patterns for *other* possible issues (bugs, masking, unsafe ctypes, error-handling gaps) —
  use the code-review agents. Separate from provider findings; store in `docs/findings/`.

## Re-measurement (Docker reruns)

- Allowed, but **write to NEW folder names** under `artifacts/` (e.g. `artifacts/<target>-recheck-YYYYMMDD/`)
  — never overwrite the 2026-05-27 baseline result dirs (backup: `/home/user/src/m/artifacts.tar.xz`).
- **Safe rerun command** (override the per-service `PKCS11_CHECK_ARTIFACT_DIR` env so output
  lands in a new folder, baseline untouched):
  ```
  docker compose -f docker/docker-compose.test.yml run --rm \
    -v /home/user/.local/share/pkcs11-check/data:/app/data:ro \
    -e PKCS11_CHECK_ARTIFACT_DIR=/artifacts/<target>-recheck-20260528 \
    --build test-<target>
  ```
  **CRITICAL:** the repo `data/` has NO vectors (they live in XDG `~/.local/share/pkcs11-check/data`,
  847M); the compose default mount `../data:/app/data:ro` therefore gives the container an EMPTY
  vector dir → only ~3.3k non-vector tests run instead of the full ~82k. The `-v` override above
  mounts the XDG vectors over `/app/data` so the full suite runs. (First softhsm2 recheck without
  it ran only 3,317 tests — do not compare those numbers.)
  In-scope targets (excl. bouncyhsm) + approx test-exec time: softhsm2 ~10m, softhsm2-main ~10m,
  kryoptic ~15m, kryoptic-main ~16m, kryoptic-fips ~18m, nss ~9m, nss-main ~10m, nss-pqc ~9m,
  opencryptoki ~2h, opencryptoki-master ~1.5h, tpm2 ~25m, pkcs11-mock ~3m. Run fast ones first;
  opencryptoki are the long tail. After each: parse `quality.json` summary, compare deltas vs
  baseline `artifacts/_matrix/provider-summary.json`, regenerate the matrix summary, refresh the
  three docs (rounded ~Xk), update `module-issues.md` for NEW findings (e.g. cross-provider GCM
  NULL-AAD SIGSEGV).
- After fixes, re-run only the **affected** targets and compare `passed/failed/xfailed/skipped`
  deltas vs `artifacts/_matrix/provider-summary.json`. "Better" = no new signal/crash `fail`,
  no finding demoted to silent pass/skip; every `fail→xfail` offset by an `xfail` gain.

## PROVIDER findings — no pkcs11-check change

PV-1 (RSA PKCS#1 lenient decrypt), PV-2 (opencryptoki AES-CBC), PV-3 (EdDSA invalid keys),
PV-7/10..15, and all crashes (CR-1..4) are **real module behavior**. The only action is to
confirm KNOWN vs NEW against `module-issues.md` and document NEW ones. Do **not** soften the
tests to make these pass.
