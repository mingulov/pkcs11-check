# CKR Error Coverage Implementation Plan

Systematic PKCS#11 CKR return code compliance testing.

Spec: `docs/superpowers/specs/2026-03-18-ckr-error-coverage-design.md`
OASIS spec: https://github.com/oasis-tcs/pkcs11.git (`working/doc/spec/`)

---

## How to use

Each task is designed to be completed in **one iteration** of the Ralph loop.
**Use local builds** (`local-builds/test.sh`) for fast iteration. Docker images are for final validation only.

### Task execution discipline

**Before implementing any medium or large task** (new test file, new infrastructure module, C code):
1. **Plan first** — read the relevant OASIS spec section, check existing code patterns, identify what exception types/imports are needed, list the exact test cases you'll write. Don't start coding until you have a clear mental model.
2. **Implement** — write the code following the plan.
3. **Verify** — run on all 3 local targets (SoftHSM2 + Kryoptic + NSS softokn). Fix failures. **Every 3rd task** (or at checkpoints), also rebuild and run Docker OpenCryptoki CKR-only. If Docker fails, skip with a note and continue.
4. **Gap-check after** — after the task passes, ask: "Did I cover all the conditions the spec lists for this function? Are there edge cases I missed?" If yes, add them in the same iteration. If it needs a separate task, add a new checkbox entry to this plan.
5. **Commit** — with task ID reference.

**For small tasks** (fix a compat tuple, add one test, update docs): just do it, verify, commit.

**When a test fails on a real token:** investigate before "fixing" — the module may have a real bug. Document in `docs/module-issues.md`. Use `compliance.note()` for spec deviations, `pytest.xfail()` for known bugs, `allow_success=True` in CkrExpectation for permissive modules. NEVER silently `pass`.

### Quick reference

```bash
# Test CKR suite only (fast validation — run after every change)
bash local-builds/test.sh softhsm2 -k "ckr" -v
bash local-builds/test.sh kryoptic -k "ckr" -v
bash local-builds/test.sh nss-softokn -k "ckr" -v    # NSS slot 0, no PIN

# Full suite (verify no regressions)
bash local-builds/test.sh softhsm2 -q
bash local-builds/test.sh kryoptic -q

# Strict mode
bash local-builds/test.sh softhsm2 -k "ckr" --ckr-strict -v

# Docker OpenCryptoki — CKR only (slow, run at checkpoints)
docker compose -f docker/docker-compose.test.yml run --rm test-opencryptoki sh -c \
  'pkcsslotd && sleep 2 && \
   echo "p11test" | pkcsconf -I -c 0 -S 87654321 2>&1 || true && \
   printf "87654321\n1234\n1234\n" | pkcsconf -u -c 0 2>&1 || true && \
   uv run pytest src/p11test/testcases/ckr/ \
     --p11-module=/usr/lib64/pkcs11/libopencryptoki.so \
     --p11-pin=1234 -v --tb=line --timeout=60; \
   RC=$?; killall pkcsslotd 2>/dev/null; exit $RC'
```

## Completion promise

All tasks marked `[x]` and zero regressions on SoftHSM2 + Kryoptic + NSS softokn (local builds).

### Validation targets

| Target | Type | When | Command |
|--------|------|------|---------|
| SoftHSM2 | Local | Every change | `bash local-builds/test.sh softhsm2 -k "ckr" -v` |
| Kryoptic | Local | Every change | `bash local-builds/test.sh kryoptic -k "ckr" -v` |
| NSS softokn | Local | Every change | `bash local-builds/test.sh nss-softokn -k "ckr" -v` |
| OpenCryptoki | Docker | Checkpoints (3.6, 4.6, 5.3, 8.x) | See quick reference above |

**NSS softokn notes:** Uses slot 0 (crypto services, no PIN). PIN/login tests will skip — this is expected. 72/79 pass baseline.
**OpenCryptoki notes:** Docker only (needs pkcsslotd). Slow — run only at validation checkpoints. Rebuild image before testing: `docker compose -f docker/docker-compose.test.yml build test-opencryptoki`. **If Docker build/run fails, skip OpenCryptoki with a note and continue. Don't loop on Docker failures.**

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

- [x] **3.1** Add `CKR_KEYGEN` entries. Create `test_ckr_keygen.py` — bad key size, template incomplete, template inconsistent, invalid attribute type/value, attribute read-only, curve not supported, domain params invalid, session read-only. Verify on both tokens.
- [x] **3.2** Add `CKR_WRAP` entries. Create `test_ckr_wrap.py` — key unextractable, key not wrappable, wrapping key type inconsistent, wrong mechanism, wrapped key invalid on unwrap, wrapped key len range. Verify on both tokens.
- [x] **3.3** Add `CKR_DERIVE` entries. Create `test_ckr_derive.py` — base key type inconsistent, template incomplete, domain params invalid, mechanism invalid. Verify on both tokens.
- [x] **3.4** Add `CKR_KEM` entries. Create `test_ckr_kem.py` — key missing CKA_ENCAPSULATE/DECAPSULATE, key type inconsistent, ciphertext invalid. Mark `@pytest.mark.requires_v32`. **KEM is v3.2 only — verify on Kryoptic only. SoftHSM2 and NSS don't support KEM, skip them for this task.** Use ML-KEM-768 parameter set. See `test_kem.py` for existing KEM test patterns.
- [x] **3.5** Add `CKR_OBJECT` entries. Create `test_ckr_object.py` — missing CKA_CLASS, conflicting attrs, action prohibited (CKA_COPYABLE/MODIFIABLE/DESTROYABLE=False), get sensitive value, set read-only attr, object handle invalid, find not initialized. Verify on both tokens.
- [x] **3.6** Validation checkpoint — SoftHSM2: 78p/0f/6s. Kryoptic: 80p/0f/3s/1x. NSS: 72p/5f(expected)/7s. OpenCryptoki: 77p/0f/6s. Zero regressions on all 4 targets.

## Tier 4 — Session, Slot, Token, General

- [x] **4.1** Add `CKR_SESSION` entries. Create `test_ckr_session.py` — invalid slot ID, session count exhaustion, CKF_SERIAL_SESSION missing, login wrong PIN, login already logged in, login another user, logout not logged in, close invalid handle. Verify on both tokens.
- [x] **4.2** Add `CKR_SLOT_TOKEN` entries. Create `test_ckr_slot_token.py` — invalid slot ID for GetSlotInfo/GetTokenInfo/GetMechanismList/GetMechanismInfo, unsupported mechanism in GetMechanismInfo, WaitForSlotEvent non-blocking. Verify on both tokens.
- [ ] **4.3** Add `CKR_GENERAL` entries. Create `test_ckr_general.py` — double C_Initialize, C_Finalize when not initialized, GetInterfaceList. **All tests MUST run in subprocess** — follow pattern from `test_subprocess_safety.py`: each test calls `subprocess.run([sys.executable, '-c', script], capture_output=True, timeout=10)` and checks `result.returncode` and stdout. Mark with `@pytest.mark.subprocess`. Verify on SoftHSM2 + Kryoptic + NSS softokn.
- [x] **4.4** Add `CKR_RANDOM` entries. Create `test_ckr_random.py` — SeedRandom support check, GenerateRandom after seed. Verify on both tokens.
- [ ] **4.5** Add `CKR_STATE` entries. Create `test_ckr_state.py` — GetOperationState with no active op, SetOperationState with invalid state, key needed/not needed. Verify on both tokens.
- [ ] **4.6** Validation checkpoint — CKR suite on SoftHSM2 + Kryoptic + NSS softokn + Docker OpenCryptoki. Fix regressions. Update pass counts.

## Tier 5 — State Machine & Priority Tests

- [ ] **5.1** Create `test_ckr_dual.py` — cross-operation state machine conflicts. **python-pkcs11 manages multipart state internally, so test only conditions observable through the wrapper.** Concrete tests: (a) call `key.encrypt()` for block-aligned data, then immediately call `key.encrypt()` again — second call should work (single-shot resets state); (b) call `session.digest(data)` twice — should work; (c) use subprocess to test raw C_Encrypt without C_EncryptInit → CKR_OPERATION_NOT_INITIALIZED. **If wrapper blocks a test, skip with explanation and defer to Tier 6 ctypes.** Verify on SoftHSM2 + Kryoptic + NSS softokn.
- [ ] **5.2** Create `test_ckr_priority.py` — error priority ordering when 2+ conditions overlap. **Concrete test cases:** (a) Destroyed key handle + SHA256 for encrypt: both KEY_HANDLE_INVALID and MECHANISM_INVALID apply. Spec says handle errors have priority → expect ObjectHandleInvalid or KeyHandleInvalid. (b) AES-ECB encrypt with 15 bytes AND wrong key type: KEY_TYPE_INCONSISTENT has priority over DATA_LEN_RANGE. (c) Generate RSA key size 0 with bad mechanism: MECHANISM_INVALID should take priority. Each test asserts the higher-priority CKR is returned. Verify on SoftHSM2 + Kryoptic + NSS softokn.
- [ ] **5.3** Validation checkpoint — CKR suite on SoftHSM2 + Kryoptic + NSS softokn + Docker OpenCryptoki. Record total CKR test count.

## Tier 6 — ctypes NULL Parameter Tests

**Approach:** Don't build a full CK_FUNCTION_LIST struct wrapper. Instead, each test runs a self-contained subprocess script that uses `ctypes.CDLL` to load the module, calls `C_GetFunctionList`, and invokes individual C_* functions via the function list pointer at known offsets. **The subprocess script is the test** — if it segfaults (returncode < 0), that's recorded as "module doesn't validate NULL params." If it returns a CKR code, check it's CKR_ARGUMENTS_BAD (0x00000007).

- [ ] **6.1** Create `testcases/ckr/_ctypes_raw.py` — helper that generates subprocess scripts for NULL param tests. Key function: `run_null_test(module_path: str, c_code: str) -> tuple[int, str]` that runs a Python script via `subprocess.run()`. The script uses `ctypes.CDLL(module_path)` to load the module and calls the specified C function with NULL. Returns `(returncode, stdout)`. Verify: `uv run python -c "from p11test.testcases.ckr._ctypes_raw import run_null_test; print('OK')"`.
- [ ] **6.2** Create `test_ckr_null_params.py` — mark all tests `@pytest.mark.subprocess`. Each test calls `run_null_test()` with a script that passes NULL to one C_* function. Cover: `C_GetInfo(NULL)`, `C_GetSlotList(1, NULL, NULL)`, `C_OpenSession(0, flags, NULL, NULL, NULL)`, `C_GenerateRandom(session, NULL, 32)`. Each expects CKR_ARGUMENTS_BAD (0x7) or segfault (returncode < 0). **Both outcomes are valid test results** — segfault means module fails to validate. Verify on SoftHSM2.
- [ ] **6.3** Run NULL param tests on Kryoptic + NSS softokn. Document segfaults vs proper CKR codes in `docs/module-issues.md`.
- [ ] **6.4** Run NULL param tests on pkcs11-mock. pkcs11-mock should return proper CKR codes (it's a stub designed for validation).

## Tier 7 — Fault Injection Proxy

**Architecture:** A C shared library that wraps a real PKCS#11 module. It loads the real module via `PKCS11_REAL_MODULE` env var, delegates all calls, but can inject a specific error on one function. Set `PKCS11_INJECT_FUNCTION=C_Encrypt` and `PKCS11_INJECT_ERROR=0x00000032` (CKR_DEVICE_REMOVED) to make the next C_Encrypt call return that error instead of delegating.

- [ ] **7.1a** Create `local-builds/fault-proxy/fault-proxy.c` — start with minimal proxy: just `C_GetFunctionList`, `C_Initialize`, `C_Finalize`, and `C_Encrypt` with injection support. ~100 lines. Create `local-builds/providers/fault-proxy.sh` with `build()` function that compiles to `.so`. Verify: `bash local-builds/build.sh fault-proxy && ls local-builds/fault-proxy/fault-proxy.so`.
- [ ] **7.1b** Extend `fault-proxy.c` with remaining functions — add `C_Sign`, `C_GenerateKey`, `C_OpenSession`, `C_GetTokenInfo`, and all other standard C_* functions that just delegate. ~300 lines total. Verify: build succeeds, `PKCS11_REAL_MODULE=/usr/lib/softhsm/libsofthsm2.so uv run python -c "import pkcs11; lib = pkcs11.lib('local-builds/fault-proxy/fault-proxy.so'); ..."` loads and works.
- [ ] **7.2** Create `test_ckr_fault_inject.py` — mark all tests `@pytest.mark.subprocess`. Tests use env vars + subprocess to load fault proxy. Cover: CKR_DEVICE_REMOVED on C_Encrypt, CKR_DEVICE_ERROR on C_Sign, CKR_DEVICE_MEMORY on C_GenerateKey, CKR_TOKEN_NOT_PRESENT on C_OpenSession. **If fault-proxy.so doesn't exist (not built), skip all tests gracefully** with `pytest.skip("fault-proxy not built")`. Verify proxy with SoftHSM2 as real module.
- [ ] **7.3** Process-kill tests — add to `test_ckr_session.py`: kill BouncyHSM server mid-session (if available), kill swtpm mid-session (if available). **Skip gracefully if services not running** — check with `subprocess.run(['pgrep', ...])` before attempting.

## Tier 8 — Per-Target Validation

Run full CKR suite on every available target. Fix issues, document module deviations.

- [ ] **8.1** **SoftHSM2 2.7.0** — `bash local-builds/test.sh softhsm2 -k "ckr" -v`. Record results. Fix issues.
- [ ] **8.2** **Kryoptic 1.5.0+PQC** — `bash local-builds/test.sh kryoptic -k "ckr" -v`. Record results. Fix issues.
- [ ] **8.3** **NSS softokn** — `bash local-builds/test.sh nss-softokn -k "ckr" -v`. Record results. PIN/login tests expected to skip.
- [ ] **8.4** **Docker OpenCryptoki** — CKR-only run. Rebuild image, run CKR tests. Record results.
- [ ] **8.5** **pkcs11-mock 2.0.0** — `bash local-builds/test.sh pkcs11-mock -k "ckr" -v`. Record results (mock returns limited CKR set).
- [ ] **8.6** **Strict mode audit** — run `--ckr-strict` on SoftHSM2, Kryoptic, NSS softokn. Record all compliance deviations.
- [ ] **8.7** Full suite regression — `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`. Confirm zero regressions in the entire 29K+ test suite.

## Tier 8b — Deep Gap Analysis & Completeness Audit

After per-target validation, audit what's actually covered vs what the spec requires. Gaps found here get added as NEW tasks in this plan (the plan grows).

- [ ] **8b.1** Run gap analysis — for each CKR test file, count (function, condition) pairs actually tested vs entries in `_ckr_spec.py` vs OASIS spec total. Produce a coverage matrix: `docs/ckr-coverage.md` with per-function counts. Identify missing conditions.
- [ ] **8b.2** Compare against OASIS spec — clone `/tmp/pkcs11/` if needed, parse each function's "Return values:" list and prose conditions. List every (function, condition) pair NOT yet in `_ckr_spec.py`. Add missing entries to `_ckr_spec.py`.
- [ ] **8b.3** Add new tasks to ckr-plan.md — for each gap found in 8b.2, add a checkbox entry below this line (e.g., `- [ ] **8b.3a** Add CKR_KEYGEN domain_params_invalid test`). Mark 8b.3 done AFTER all new entries are written. Then continue to next iteration to implement them one by one.
- [ ] **8b.4** Implement all gap tasks added in 8b.3 — pick the first unchecked `8b.3x` task, implement it, test on SoftHSM2 + Kryoptic + NSS softokn, commit, mark done. **This task is done when ALL 8b.3x sub-tasks are marked `[x]`.** If no 8b.3x tasks exist yet, mark 8b.4 done immediately.
- [ ] **8b.5** Quality review — run `--ckr-strict` on both tokens. Audit all compliance notes. Document spec deviations per module in `docs/module-issues.md`. Decide which deviations need upstream bug reports.
- [ ] **8b.6** Update `_ckr_spec.py` condition counts — verify total matches spec expectation (~487). Update `ckr-plan.md` with actual coverage numbers.
- [ ] **8b.7** Final regression — `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`. Zero failures.

## Tier 9 — Cleanup & Handoff

- [ ] **9.1** Update `docs/module-issues.md` — add CKR deviation summary per module.
- [ ] **9.2** Update `docs/test-coverage.md` — add CKR error coverage section.
- [ ] **9.3** Update CLAUDE.md — add `testcases/ckr/` to architecture section, document `--ckr-strict` flag.
- [ ] **9.4** Update `docs/master-plan.md` — mark 7c.3 (crash isolation) partially done (adaptive runner designed, not yet wired into CLI). Add CKR coverage as completed tier.
- [ ] **9.5** **Switch to master-plan.md** — mark this task done. The completion promise will fire, ending this loop. **To continue:** start a new Ralph loop with `docs/master-plan.md` manually.

---

## Recommended loop prompt

```
/ralph-loop:ralph-loop "/using-superpowers Pick the highest-priority unfinished task from docs/ckr-plan.md. Implementation rules: (1) Use local builds for fast iteration. (2) If /tmp/pkcs11/ doesn't exist, clone it: git clone --depth 1 https://github.com/oasis-tcs/pkcs11.git /tmp/pkcs11. Read OASIS spec (working/doc/spec/) for exact CKR return values. (3) Use _error_tuples.py — NEVER generic PKCS11Error catches. (4) Unexpected CKR: document in module-issues.md with compliance.note(), NOT silent pass. (5) After each new test file: verify on SoftHSM2 + Kryoptic + NSS softokn (all local). (6) At checkpoints (3.6, 4.6, 5.3): also run Docker OpenCryptoki CKR-only (rebuild image first). If Docker fails, skip OpenCryptoki with a note and continue — don't loop on Docker failures. (7) Commit with task ID, mark done." --completion-promise "All tasks in docs/ckr-plan.md are marked done"
```
