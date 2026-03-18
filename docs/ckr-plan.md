# CKR Error Coverage Implementation Plan

Systematic PKCS#11 CKR return code compliance testing.

Spec: `docs/superpowers/specs/2026-03-18-ckr-error-coverage-design.md`
OASIS spec: https://github.com/oasis-tcs/pkcs11.git (`working/doc/spec/`)

---

## How to use

Each task is designed to be completed in **one iteration** of the Ralph loop.
**Use local builds** (`local-builds/test.sh`) for fast iteration. Docker images are for final validation only.

### Quick reference

```bash
# Test CKR suite only
bash local-builds/test.sh softhsm2 -k "ckr" -v
bash local-builds/test.sh kryoptic -k "ckr" -v

# Full suite (verify no regressions)
bash local-builds/test.sh softhsm2 -q
bash local-builds/test.sh kryoptic -q

# Strict mode
bash local-builds/test.sh softhsm2 -k "ckr" --ckr-strict -v
```

## Completion promise

All tasks marked `[x]` and zero regressions on SoftHSM2 + Kryoptic (local builds).

---

## Tier 0 — Prerequisites

Fix issues from gap-analysis.md that block CKR work.

- [x] **0.1** Fix fixture logout catch — `fixtures.py` has broad `except PKCS11Error: pass` on logout. Replace with `except (UserNotLoggedIn, SessionClosed, FunctionFailed):`. Verify: `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`.
- [x] **0.2** Register missing markers — add `thread_safe`, `subprocess`, `subprocess_per_test` to `markers.py`. Verify: `uv run pytest --strict-markers src/p11test/testcases/ --collect-only -q 2>&1 | tail -5`.
- [x] **0.3** Migrate existing CKR tests — move tests from `test_ckr_spec_compliance.py` and `test_ckr_codes.py` into seed files in `testcases/ckr/`. Delete originals. Verify same test count.

## Tier 1 — Infrastructure

Build the shared data model, assertion helpers, and conftest before any test files.

- [x] **1.1** Create `testcases/ckr/__init__.py` and `testcases/ckr/conftest.py` — register `--ckr-strict` option, define `ckr_strict` fixture. Verify: `uv run pytest src/p11test/testcases/ckr/ --co -q` collects 0 tests (no test files yet) without errors.
- [x] **1.2** Create `testcases/ckr/_ckr_spec.py` — `CkrExpectation` dataclass, `assert_ckr()` helper, `full_compat()`, universal CKR tuples. Start with `CKR_ENCRYPT` dict (4-5 entries) as the first family. Import from `_error_tuples.py`. Verify: `uv run python -c "from p11test.testcases.ckr._ckr_spec import CKR_ENCRYPT, assert_ckr; print(len(CKR_ENCRYPT))"`.
- [x] **1.3** Create `test_ckr_encrypt.py` — first real CKR test file. 5-8 tests covering: unsupported mechanism, key missing CKA_ENCRYPT, key type inconsistent, non-aligned ECB data, empty data, RSA too-long data. Verify: `bash local-builds/test.sh softhsm2 -k "test_ckr_encrypt" -v && bash local-builds/test.sh kryoptic -k "test_ckr_encrypt" -v`.
- [x] **1.4** Fix issues from 1.3 — Kryoptic ArgumentsBad for mechanism param (added to compat). Zero regressions: SoftHSM2 22706, Kryoptic 21620. — any unexpected CKR codes or crashes found on real tokens. Document module-specific deviations in `docs/module-issues.md` with `compliance.note()`, NOT with silent `pass`. Do NOT change expected error codes to match broken modules — use `xfail` or compliance notes.

## Tier 2 — Core Crypto Operations

One file per operation family. After each pair, validate on both tokens.

- [x] **2.1** Add `CKR_DECRYPT` entries to `_ckr_spec.py`. Create `test_ckr_decrypt.py` — key missing CKA_DECRYPT, key type inconsistent, encrypted data invalid/len range, wrong ciphertext length. Verify on both tokens.
- [x] **2.2** Add `CKR_SIGN` entries. Create `test_ckr_sign.py` — key missing CKA_SIGN, wrong mechanism, key type inconsistent, data too long for mechanism. Verify on both tokens.
- [x] **2.3** Add `CKR_VERIFY` entries. Create `test_ckr_verify.py` — key missing CKA_VERIFY, signature invalid, signature len range, tampered data. Verify on both tokens.
- [x] **2.4** Add `CKR_DIGEST` entries. Create `test_ckr_digest.py` — invalid mechanism, mechanism param invalid, operation not initialized. Verify on both tokens.
- [x] **2.5** Validation checkpoint — SoftHSM2: 22727 passed / 0 failed. Kryoptic: 21640 passed / 0 failed. CKR tests: 30 new (12 encrypt + 10 decrypt + 4 sign + 4 verify + 3 digest) minus 3 skipped. — run full suite on SoftHSM2 + Kryoptic. Fix any regressions. Record pass counts: `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`.

## Tier 3 — Key Management & Object Operations

- [ ] **3.1** Add `CKR_KEYGEN` entries. Create `test_ckr_keygen.py` — bad key size, template incomplete, template inconsistent, invalid attribute type/value, attribute read-only, curve not supported, domain params invalid, session read-only. Verify on both tokens.
- [ ] **3.2** Add `CKR_WRAP` entries. Create `test_ckr_wrap.py` — key unextractable, key not wrappable, wrapping key type inconsistent, wrong mechanism, wrapped key invalid on unwrap, wrapped key len range. Verify on both tokens.
- [ ] **3.3** Add `CKR_DERIVE` entries. Create `test_ckr_derive.py` — base key type inconsistent, template incomplete, domain params invalid, mechanism invalid. Verify on both tokens.
- [ ] **3.4** Add `CKR_KEM` entries. Create `test_ckr_kem.py` — key missing CKA_ENCAPSULATE/DECAPSULATE, key type inconsistent, ciphertext invalid. Mark `@pytest.mark.requires_v32`. Verify on Kryoptic (v3.2 support).
- [ ] **3.5** Add `CKR_OBJECT` entries. Create `test_ckr_object.py` — missing CKA_CLASS, conflicting attrs, action prohibited (CKA_COPYABLE/MODIFIABLE/DESTROYABLE=False), get sensitive value, set read-only attr, object handle invalid, find not initialized. Verify on both tokens.
- [ ] **3.6** Validation checkpoint — full suite on both tokens. Fix regressions. Update pass counts.

## Tier 4 — Session, Slot, Token, General

- [ ] **4.1** Add `CKR_SESSION` entries. Create `test_ckr_session.py` — invalid slot ID, session count exhaustion, CKF_SERIAL_SESSION missing, login wrong PIN, login already logged in, login another user, logout not logged in, close invalid handle. Verify on both tokens.
- [ ] **4.2** Add `CKR_SLOT_TOKEN` entries. Create `test_ckr_slot_token.py` — invalid slot ID for GetSlotInfo/GetTokenInfo/GetMechanismList/GetMechanismInfo, unsupported mechanism in GetMechanismInfo, WaitForSlotEvent non-blocking. Verify on both tokens.
- [ ] **4.3** Add `CKR_GENERAL` entries. Create `test_ckr_general.py` — double C_Initialize, C_Finalize when not initialized, GetInterfaceList. Run in subprocess (post-Finalize calls). Verify on both tokens.
- [ ] **4.4** Add `CKR_RANDOM` entries. Create `test_ckr_random.py` — SeedRandom support check, GenerateRandom after seed. Verify on both tokens.
- [ ] **4.5** Add `CKR_STATE` entries. Create `test_ckr_state.py` — GetOperationState with no active op, SetOperationState with invalid state, key needed/not needed. Verify on both tokens.
- [ ] **4.6** Validation checkpoint — full suite on both tokens. Fix regressions. Update pass counts.

## Tier 5 — State Machine & Priority Tests

- [ ] **5.1** Create `test_ckr_dual.py` — cross-operation state machine conflicts: EncryptInit then SignInit (OPERATION_ACTIVE), Encrypt without EncryptInit (OPERATION_NOT_INITIALIZED), EncryptUpdate after Encrypt (OPERATION_NOT_INITIALIZED), interleaved multipart operations. Verify on both tokens.
- [ ] **5.2** Create `test_ckr_priority.py` — error priority ordering when 2+ conditions overlap: invalid handle + wrong mechanism (handle takes priority per spec), data len range + data invalid (len range takes priority), session handle invalid + operation not initialized (session takes priority). Verify on both tokens.
- [ ] **5.3** Validation checkpoint — full CKR suite on both tokens. Record total CKR test count.

## Tier 6 — ctypes NULL Parameter Tests

- [ ] **6.1** Create `testcases/ckr/_ctypes_raw.py` — `RawPkcs11` class using ctypes CDLL, extracts CK_FUNCTION_LIST v2.40 from C_GetFunctionList, provides `call(func_name, *args) -> CK_RV`. Verify: `uv run python -c "from p11test.testcases.ckr._ctypes_raw import RawPkcs11; print('OK')"`.
- [ ] **6.2** Create `test_ckr_null_params.py` — mark all tests `@pytest.mark.subprocess`. Tests run in subprocess via `subprocess.run()`. Cover: C_GetInfo(NULL), C_GetSlotList(NULL count), C_OpenSession(NULL phSession), C_EncryptInit(NULL mechanism), C_Encrypt(NULL data). Each expects CKR_ARGUMENTS_BAD or segfault (both recorded). Verify on SoftHSM2.
- [ ] **6.3** Run NULL param tests on Kryoptic. Document any segfaults vs proper CKR codes in `docs/module-issues.md`.
- [ ] **6.4** Run NULL param tests on pkcs11-mock. pkcs11-mock should return proper CKR codes (it's a stub designed for validation).

## Tier 7 — Fault Injection Proxy

- [ ] **7.1** Create `local-builds/fault-proxy/fault-proxy.c` — ~300 line C proxy that loads real module via `PKCS11_REAL_MODULE`, delegates all calls, injects error from `PKCS11_INJECT_FUNCTION` + `PKCS11_INJECT_ERROR` env vars. Create `local-builds/providers/fault-proxy.sh` with build(). Verify: `bash local-builds/build.sh fault-proxy`.
- [ ] **7.2** Create `test_ckr_fault_inject.py` — mark all tests `@pytest.mark.subprocess`. Tests use env vars + subprocess to load fault proxy. Cover: CKR_DEVICE_REMOVED on C_Encrypt, CKR_DEVICE_ERROR on C_Sign, CKR_DEVICE_MEMORY on C_GenerateKey, CKR_TOKEN_NOT_PRESENT on C_OpenSession, CKR_TOKEN_NOT_RECOGNIZED on C_GetTokenInfo. Verify proxy with SoftHSM2 as real module.
- [ ] **7.3** Process-kill tests — add to `test_ckr_session.py`: kill BouncyHSM server mid-session (if available), kill swtpm mid-session (if available). Skip gracefully if services not running.

## Tier 8 — Per-Target Validation

Run full CKR suite on every available target. Fix issues, document module deviations.

- [ ] **8.1** **SoftHSM2 2.7.0** — `bash local-builds/test.sh softhsm2 -k "ckr" -v`. Record results. Fix issues.
- [ ] **8.2** **Kryoptic 1.5.0+PQC** — `bash local-builds/test.sh kryoptic -k "ckr" -v`. Record results. Fix issues.
- [ ] **8.3** **pkcs11-mock 2.0.0** — `bash local-builds/test.sh pkcs11-mock -k "ckr" -v`. Record results (mock returns limited CKR set).
- [ ] **8.4** **Strict mode audit** — run `bash local-builds/test.sh softhsm2 -k "ckr" --ckr-strict -v`. Record all compliance deviations. Run on Kryoptic too.
- [ ] **8.5** Full suite regression — `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`. Confirm zero regressions in the entire 29K+ test suite.

## Tier 8b — Deep Gap Analysis & Completeness Audit

After per-target validation, audit what's actually covered vs what the spec requires.

- [ ] **8b.1** Run gap analysis — for each CKR test file, count (function, condition) pairs actually tested vs entries in `_ckr_spec.py` vs OASIS spec total. Produce a coverage matrix: `docs/ckr-coverage.md` with per-function counts. Identify missing conditions.
- [ ] **8b.2** Compare against OASIS spec — clone `/tmp/pkcs11/` if needed, parse each function's "Return values:" list and prose conditions. List every (function, condition) pair NOT yet in `_ckr_spec.py`. Add missing entries.
- [ ] **8b.3** Implement missing tests — for each gap found in 8b.2, add tests to the appropriate `test_ckr_*.py` file. Verify on SoftHSM2 + Kryoptic.
- [ ] **8b.4** Quality review — run `--ckr-strict` on both tokens. Audit all compliance notes. Document spec deviations per module in `docs/module-issues.md`. Decide which deviations need upstream bug reports.
- [ ] **8b.5** Update `_ckr_spec.py` condition counts — verify total matches spec expectation (~487). Update `ckr-plan.md` with actual coverage numbers.
- [ ] **8b.6** Final regression — `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`. Zero failures.

## Tier 9 — Cleanup & Handoff

- [ ] **9.1** Update `docs/module-issues.md` — add CKR deviation summary per module.
- [ ] **9.2** Update `docs/test-coverage.md` — add CKR error coverage section.
- [ ] **9.3** Update CLAUDE.md — add `testcases/ckr/` to architecture section, document `--ckr-strict` flag.
- [ ] **9.4** Update `docs/master-plan.md` — mark 7c.3 (crash isolation) partially done (adaptive runner designed, not yet wired into CLI). Add CKR coverage as completed tier.
- [ ] **9.5** **Switch to master-plan.md** — resume Ralph loop with `docs/master-plan.md` as the task source. Pick highest-priority unfinished task from there.

---

## Recommended loop prompt

```
/ralph-loop:ralph-loop "/using-superpowers Pick the highest-priority unfinished task from docs/ckr-plan.md. Implementation rules: (1) Use local builds (local-builds/test.sh) for fast iteration — avoid Docker unless required. (2) Read the OASIS spec (working/doc/spec/ in /tmp/pkcs11/) for exact CKR return values per function. (3) Use _error_tuples.py for compat tuples — NEVER add generic PKCS11Error catches. (4) When a module returns unexpected CKR: document in docs/module-issues.md with compliance.note(), do NOT silently pass. Use xfail for known module bugs. (5) Verify zero regressions: bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q. (6) Commit with descriptive message referencing the task ID, then mark done in the plan." --completion-promise "All tasks in docs/ckr-plan.md are marked done"
```
