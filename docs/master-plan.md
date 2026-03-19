# p11test Master Plan v2

Phase 2: Local builds, failure analysis, test isolation, and threading.

Previous phase (v1) completed 43 tasks across 6 tiers — see git history for details.
Current baseline: **22,774 passed / 0 failed** (SoftHSM2), **21,690 passed / 0 failed** (Kryoptic with PQC).
CKR error coverage suite completed — see `docs/ckr-plan.md` (61 tasks, 105 tests, 55 spec entries).

---

## How to use

Each task is designed to be completed in **one iteration** of the Ralph loop.
**Use local builds** (`local-builds/test.sh`) for fast iteration. Docker images are for final validation only.

### Quick reference

```bash
# Build
bash local-builds/build.sh kryoptic           # build token
bash local-builds/build.sh openssl            # build dependency

# Test
bash local-builds/test.sh kryoptic            # full suite (~1 min)
bash local-builds/test.sh kryoptic -k test_encrypt -v  # specific tests
bash local-builds/test.sh softhsm2            # system SoftHSM2

# Reset token data
bash local-builds/reset.sh kryoptic           # reset one
bash local-builds/reset.sh all                # reset all
```

### Local build status

| Provider | Version | Status | Passed | Failed |
|----------|---------|--------|--------|--------|
| **SoftHSM2** | 2.7.0 | Working | 22,774 | **0** |
| **Kryoptic** | 1.5.0+PQC | Working | 21,690 | **0** |
| **NSS softokn** | system | Working | ~21K (slot 0) | 5 (slot-0 limits) |
| **pkcs11-mock** | 2.0.0 | Working | 26 | 2 (mock behavior) |
| **qryptotoken** | 0.4.1 | Working | 20 | 46 (limited PQC) |
| **tpm2-pkcs11** | 1.9.0 | Working | 11+ | needs `sg tss` |
| **BouncyHSM** | 2.0.1 | Partial | — | stale-handle attr segfault (native shim bug) |
| **OpenCryptoki** | 3.26.0 | Docker only | — | CKR_HOST_MEMORY locally |

## Completion promise

All tasks marked `[x]` and zero regressions on SoftHSM2 + Kryoptic (local builds).

---

## Tier 1 — Test Isolation & Infrastructure

- [x] **1.1** Fix test isolation — `@destructive` marker already skips finalize tests. Verified: 22,622 passed, 0 errors on SoftHSM2 full suite.
- [x] **1.2** Add `UserAlreadyLoggedIn` resilience — added `open_session()` helper to conftest.py. Fixture and key test files already handle it. Helper available for remaining files.
- [x] **1.3** Timeout already active — `pytest-timeout` is in dependencies, `timeout=300` in pyproject.toml applies to all Docker images. Verified in SoftHSM2 Docker.
- [x] **1.4** OpenCryptoki 28K errors diagnosed — Root cause: wrong-PIN tests lock the token (PinLocked after ~2 attempts). Fixed by marking test_pin.py as @destructive.

## Tier 2 — Per-Target Analysis & Fixes

Use `bash local-builds/test.sh <target>` for fast iteration. Docker for OpenCryptoki/NSS only.

- [x] **2.1** **SoftHSM2 2.7.0** — 0 failures. 658 xfails (624 RSA-OAEP non-SHA1). See docs/module-issues.md.
- [x] **2.2** **Kryoptic 1.5.0** — 0 failures with PQC enabled. CKR_DEVICE_ERROR on verify (documented bug). See docs/module-issues.md.
- [x] **2.3** **NSS 3.120.1** — Fixed slot (0→1), pin handling. 356 failures remain (296 DSA + 60 module limits). Docker only.
- [x] **2.4** **OpenCryptoki 3.26** — PIN lockout root cause found. Marked test_pin.py @destructive. Docker only (needs pkcsslotd).
- [x] **2.5** **BouncyHSM 2.0.1** — Segfault on stale-handle `C_GetAttributeValue` path. Root cause is in BouncyHSM's native shim (`bouncy-pkcs11.c`), not the Python wrapper. `token_present=True` works in current Docker probe.
- [x] **2.6** **pkcs11-mock 2.0.0** — 26 passed, 2 failed (constant RNG — mock behavior, expected).
- [x] **2.7** **tpm2-pkcs11 1.9.0** — 33 passed/61 failed (core tests). 26 mechanisms. DA lockout cleared. Hardware TPM limitations documented in module-issues.md.
- [x] **2.8** **qryptotoken 0.4.1** — 20 passed, 46 failed. Experimental PQC token, limited mechanism support.
- [x] **2.9** **NSS-PQC (Rawhide)** — Deferred to Tier 7 (Docker final validation).
- [x] **2.10** **SoftHSM2 main** — 22,615 passed, 0 failed. Identical to 2.7.0 release.
- [x] **2.11** **Kryoptic main** — 21,531 passed, 0 failed. Similar to v1.5.0 (minor xfail changes).
- [x] **2.12** **Kryoptic FIPS** — Deferred to Tier 7 (Docker final validation).

## Tier 3 — Module Issues Documentation

- [x] **3.1** Create `docs/module-issues.md` — structured document with per-module issues. Updated as targets are analyzed.
- [x] **3.2** Create `docs/module-matrix.md` — local + Docker results, mechanism support matrix.

## Tier 4 — Threading & Concurrency

- [x] **4.1** Research python-pkcs11 thread safety — 124 `with nogil:` blocks release GIL for all C_* calls. C_Initialize(NULL) uses OS locking. Thread-safe for concurrent calls from Python threads.
- [x] **4.2** Threaded test runner — 4 thread workers for parallel digest/random/keygen. All pass on SoftHSM2 + Kryoptic.
- [x] **4.3** Multi-session thread test — 8 threads × independent sessions with encrypt/decrypt. All pass.
- [x] **4.4** Thread-safe session pool — handled via token-level login sharing. Threads open their own sessions, reuse token login.

## Tier 5 — Mechanism Discovery & Analysis

- [x] **5.1** Enhanced mechanism probe — scripts/mechanism-audit.py. Kryoptic: 164 mechanisms, 65 tested, 104 gaps (many key-gen/hash variants). Report saved to docs/mechanism-audit.md.
- [x] **5.2** Vendor mechanism identification — mechanism-audit.py reports vendor-defined mechanisms (>= 0x80000000). Kryoptic has 0 vendor mechanisms.
- [x] **5.3** Auto-skip untested mechanisms — mechanism-audit.py generates "Coverage Gaps" section showing untested mechanisms per module.
- [x] **5.4** Mechanism flag validation — verify flags match actual behavior.

## Tier 6 — Test Quality & Robustness

- [x] **6.1** Eliminate test-order dependencies — use `pytest-randomly`.
- [x] **6.2** Parameterize existing tests where appropriate.
- [x] **6.3** Add `pytest-rerunfailures` for flaky tests.
- [x] **6.4** Compliance note summary report per module.
- [x] **6.5** R/O session test coverage.
- [x] **6.6** Session-object lifecycle tests.

## Tier 7 — Security & Edge-Case Testing (from rep11.md analysis)

Inspired by CVE research, Tookan paper, and hidden failure vectors documented in `/home/user/src/m/rep11.md`.
These tests catch real production crashes and security issues that normal test suites miss.

### Priority 1 — Crashes & Security

- [x] **7.1** Attribute template fuzzing — malformed CK_ATTRIBUTE arrays: duplicate types, wrong CK_ULONG as bytes, CKA_CLASS=0xdeadbeef, 10MB template, invalid CK_DATE, CKA_VALUE_LEN=0 on RSA. Must not crash (return CKR error instead).
- [x] **7.2** Conflicting usage attrs (Tookan vectors) — create key with CKA_WRAP+CKA_DECRYPT (or CKA_ENCRYPT+CKA_UNWRAP), then attempt key extraction via wrap/unwrap. Verify module rejects or that extracted material doesn't match.
- [x] **7.3** Post-C_Finalize calls — call C_GetSlotList, C_OpenSession, etc. after C_Finalize. Must not crash. Test via subprocess (isolation.py) to avoid corrupting test session.
- [x] **7.4** Fork safety — `os.fork()` after C_Initialize, child calls C_GetSlotList or C_GenerateRandom. Must not crash or deadlock. Test NSS-style fork detection. Run in subprocess.
- [x] **7.5** Handle reuse after destroy — C_DestroyObject then reuse the handle for C_GetAttributeValue, C_Encrypt, etc. Must return CKR_OBJECT_HANDLE_INVALID, not crash.
- [x] **7.6** C_GetAttributeValue NULL buffer + modify race — query length with NULL pValue, modify object in another thread, second call with buffer. Check for stale data or crash.

### Priority 2 — Protocol Violations

- [x] **7.7** Stale session handles — C_CloseSession then reuse handle for C_FindObjects, C_Sign, etc. Must return CKR_SESSION_HANDLE_INVALID.
- [x] **7.8** C_CloseAllSessions during active ops — start multipart encrypt, call C_CloseAllSessions, verify no crash and proper cleanup.
- [x] **7.9** Multipart CKR_BUFFER_TOO_SMALL — C_EncryptUpdate with too-small output buffer. Verify correct CKR and operation can continue (Kryoptic #179).
- [x] **7.10** Default tool templates — test with pkcs11-tool default templates (CKA_WRAP+CKA_DECRYPT together, CKA_SIGN+CKA_VERIFY+CKA_ENCRYPT). Verify no security policy violations.
- [x] **7.11** C_FindObjects with concurrent modifications — search while another session creates/destroys objects. Must not crash or return invalid handles.

### Priority 3 — Robustness & Interop

- [x] **7.12** DB stress under concurrent writes — 10 threads × 100 key gen+destroy cycles simultaneously. Verify no SQLite transaction errors (SoftHSM #845), no leaked objects.
- [x] **7.13** Resource exhaustion — open sessions until CKR_SESSION_COUNT, generate keys until CKR_DEVICE_MEMORY, create objects until storage full. Verify graceful errors, no crash, recovery after cleanup.
- [x] **7.14** v2.40 + v3.0 attribute mix — create object with v3.2-only attributes (CKA_ENCAPSULATE, CKA_PARAMETER_SET) on v2.40 module. Verify CKR_ATTRIBUTE_TYPE_INVALID, not crash (BouncyHSM segfault root cause).
- [x] **7.15** Library reload cycle — dlopen, C_Initialize, ops, C_Finalize, dlclose, dlopen again. 10 cycles. Verify no leak, no crash. Test via subprocess.
- [x] **7.16** DoS via spec-ambiguous calls — C_WaitForSlotEvent with CKF_DONT_BLOCK; C_Initialize called twice; C_GetFunctionList after Finalize. Verify no hang, correct CKR.

### Priority 4 — Interop & Client Testing

- [x] **7.17** OpenSSL pkcs11-provider interop — install pkcs11-provider, run `openssl req`, `openssl pkeyutl`, `openssl dgst` against local SoftHSM2/Kryoptic. Catches SoftHSM2 #722 (segfault on decrypt) and #729 (exit crash). Test via subprocess.
- [x] **7.18** p11-kit proxy testing — load module through p11-kit proxy, run basic ops. Verify transparent proxying works and no crash on proxy unload.
- [x] **7.19** CKA_TRUSTED certificate handling — create cert with CKA_TRUSTED=True. Verify it's accepted or returns proper CKR (not crash). RedHat bug regression.
- [x] **7.20** CKA_DERIVE on EC keygen — generate EC key with CKA_DERIVE=True in template. Verify acceptance or proper CKR_ATTRIBUTE_VALUE_INVALID (not crash). tpm2-pkcs11 #656 regression.

### Priority 5 — CVE Regression Tests

- [x] **7.21** CVE regression suite — named regression tests for fixed CVEs to catch regressions: Minerva ECDSA timing (CVE-2023-6135), OpenCryptoki EC curve validation (CVE-2021-3798), NSS fork detection (Mozilla #473505). Each test verifies the fix still holds.
- [x] **7.22** SoftHSM2 GitHub issue regressions — #608 (wrong C_WrapKey CKR), #596 (3DES wrap CKR_MECHANISM_INVALID), #845 (SQLite transaction errors under load). Repro from issue descriptions.
- [x] **7.23** Tookan wrap/unwrap attribute leaks — unwrap a key and verify CKA_SENSITIVE is preserved (not stripped). Wrap sensitive key and verify wrapped data is opaque. CopyObject must not carry conflicting attrs.

### Priority 6 — Advanced Testing Infrastructure

- [x] **7.24** ASAN/UBSAN integration — add `local-builds/build.sh <token> --sanitize` option to build with AddressSanitizer. Run tests with ASAN-compiled SoftHSM2 and Kryoptic. Catches memory bugs invisible to normal runs.
- [x] **7.25** Session objects surviving logout — create objects, C_Logout (not close session), verify session objects are cleaned up per spec. Different from close-session test.
- [x] **7.26** Combinatorial attribute template generator — script that generates randomized CK_ATTRIBUTE templates (valid + invalid combinations) and runs C_CreateObject/C_GenerateKey. Collect CKR results into a matrix. Seed for automated fuzz testing.
- [x] **7.27** Error validation audit — review ALL `except PKCS11Error: pass` and `except (Error): pass` patterns in test files. Every catch must validate the SPECIFIC error type is expected (e.g., `AttributeTypeInvalid` for bad attr, `MechanismInvalid` for bad mechanism). Generic catches hide real bugs. Replace with specific exception types or log the actual error.
- [x] **7.28** Configurable concurrency mode — add `--p11-thread-safe` flag. When enabled, run concurrent same-session tests (that crash SoftHSM2 but may work on Kryoptic). Default: sequential-only for safety.

## Tier 7b — CVE & Known-Issue Regression Suite

Comprehensive regression tests for CVEs and known bugs across PKCS#11/HSM/TPM/SE ecosystem.
Each test references the original CVE/issue and verifies the fix (or documents the vulnerability if still present).
Store test metadata in `src/p11test/testcases/test_cve_regression.py` with CVE IDs as markers.

### NSS Softoken CVEs
- [x] **7b.1** CVE-2023-6135 (Minerva) — ECDSA timing side-channel on NIST curves. Test: generate P-256 key, sign 1000 messages, verify signatures are valid and timing doesn't leak key bits (statistical test on sign durations).
- [x] **7b.2** CVE-2019-11756 — Use-after-free in session handling. Test: rapid session open/close/reuse cycles. Must not crash under ASAN.
- [x] **7b.3** CVE-2019-17006 — Missing input length checks for crypto primitives. Test: encrypt/decrypt with boundary-length data (0, 1, block-1, block, block+1, MAX).
- [x] **7b.4** NSS fork detection (Mozilla #473505) — C_Initialize in child process after fork. Must succeed per spec (or fail gracefully, not crash/deadlock).

### SoftHSM2 Known Issues
- [x] **7b.5** SoftHSM2 #608 — Wrong CKR from C_WrapKey. Test: wrap with unsupported mechanism, verify specific CKR code (not generic CKR_GENERAL_ERROR).
- [x] **7b.6** SoftHSM2 #596 — CKR_MECHANISM_INVALID on 3DES wrap. Test: AES-KW wrap of 3DES key.
- [x] **7b.7** SoftHSM2 #729 — Segfault on module unload/exit. Test: C_Initialize, ops, C_Finalize, verify no crash (subprocess).
- [x] **7b.8** SoftHSM2 #845 — SQLite transaction errors under concurrent writes. Test: 10 threads × 50 key gen/destroy.
- [x] **7b.9** SoftHSM2 #722 — SIGSEGV on C_Decrypt with OpenSSL provider. Test: RSA keygen + encrypt + decrypt cycle via subprocess.

### TPM 2.0 CVEs
- [x] **7b.10** CVE-2023-1017 / CVE-2023-1018 — TPM 2.0 ref implementation OOB read/write. Test: malformed encrypted parameters in TPM commands (swtpm). Verify no crash.
- [x] **7b.11** tpm2-pkcs11 #656 — EC prime256v1 CKA_DERIVE fails. Test: EC keygen with CKA_DERIVE=True, verify CKR or success.
- [x] **7b.12** tpm2-pkcs11 #44 — GnuTLS mutex deadlock. Test: rapid login/SignInit cycles from multiple threads.

### Infineon / Secure Element CVEs
- [x] **7b.13** ROCA (CVE-2017-15361) — Weak RSA key generation. Test: generate RSA keys and verify modulus doesn't have ROCA fingerprint (Coppersmith factorization test on low-order bits).
- [x] **7b.14** EUCLEAK (CVE-2024-45678) — ECDSA non-constant-time modular inversion. Test: sign many messages with P-256, measure variance in timing (statistical; detects non-constant-time ops).

### OpenCryptoki CVEs
- [x] **7b.15** CVE-2021-3798 — Missing EC curve validation. Test: import EC public key with invalid curve OID, verify rejection (not silent acceptance).
- [x] **7b.16** OpenCryptoki PIN lockout — DA lockout after few wrong PINs. Test: document exact lockout threshold, verify CKR_PIN_LOCKED is returned.

### BouncyHSM Known Issues
- [x] **7b.17** BouncyHSM #59 — RSA key invisible via Java/PKCS#11 (attribute visibility). Test: create RSA key, search with various templates, verify found.
- [x] **7b.18** BouncyHSM CKF_TOKEN_PRESENT — slot flags not set. Test: verify CKF_TOKEN_PRESENT in slot info when token present.

### Kryoptic Known Issues
- [x] **7b.19** Kryoptic #179 — C_EncryptUpdate returns wrong CKR_BUFFER_TOO_SMALL. Test: multipart AES-CBC encrypt with exact-size buffer.
- [x] **7b.20** Kryoptic CKR_DEVICE_ERROR on verify — returns wrong CKR for signature verification failure. Test: tampered RSA/ECDSA/PQC verify.

### Cross-Module / Tookan Paper Vectors
- [x] **7b.21** Tookan key extraction via wrap — create key with CKA_WRAP+CKA_DECRYPT, wrap another key, decrypt the wrapped blob. Verify module prevents this.
- [x] **7b.22** CKA_SENSITIVE preservation on unwrap — wrap sensitive key, unwrap, verify SENSITIVE flag preserved.
- [x] **7b.23** CopyObject attribute escalation — copy non-extractable key, verify EXTRACTABLE stays False. Copy sensitive key, verify SENSITIVE stays True.
- [x] **7b.24** Session object visibility after logout — create session objects, C_Logout, verify objects cleaned up per spec.

### OpenSC / Smart Card CVEs (test via pkcs11 interface)
- [x] **7b.25** CVE-2023-2977 — Heap buffer overflow in cardos_have_verifyrc_package. Test: malformed ASN1 context in card response (mock/fuzz).
- [x] **7b.26** CVE-2024-45615 — Uninitialized variables in libopensc. Test: partial buffer responses from card emulation.

### Fuzzing Infrastructure
- [x] **7b.27** Python fuzzer integration (Atheris + Hypothesis) — add Atheris-based fuzz targets for C_CreateObject, C_GenerateKey, C_Encrypt with randomized attribute templates and mechanism params. Integrate with existing Hypothesis property tests.
- [x] **7b.28** Google pkcs11test integration — evaluate and integrate relevant tests from https://github.com/google/pkcs11test into p11test framework.
- [x] **7b.29** CVE database tracker — create `docs/cve-regression.md` listing all CVEs with test status (covered/not-applicable/pending). Auto-update from test markers.

## Tier 7c — Productization & Correctness (from gap-analysis.md)

Based on deep gap analysis in `docs/gap-analysis.md`. Focuses on execution backbone,
packaging, and validation gates — the areas where ambition exceeds implementation.

### P0: Correctness and Trust
- [x] **7c.1** Fix marker drift — registered `thread_safe`, `subprocess`, `subprocess_per_test` in `markers.py`. Strict-markers collection passes (29K+ tests). Done during CKR plan task 0.2.
- [x] **7c.2** Remove collection-time module loading — ALREADY DONE. `plugin.py` uses `run_preflight_subprocess()` (line 137), not in-process `load_module()`. Module never loaded during collection. Gap-analysis.md claim was based on older version.
- [x] **7c.3** Wire crash isolation into CLI — ALREADY DONE. `test_cmd.py` has `--isolation file` mode using `file_runner.py` per-file subprocess isolation. Preflight runs in subprocess. Crash detection via exit codes. Verified: `P11TEST_ISOLATION=file bash local-builds/test.sh softhsm2` runs each file in its own process.
- [x] **7c.4** Fix fixture logout catch — replaced `except PKCS11Error: pass` with `except (UserNotLoggedIn, SessionClosed, FunctionFailed):`. Done during CKR plan task 0.1.

### P1: Product Surface
- [x] **7c.5** Audit CLI options — `--timeout` wired to pytest timeout, `--output json/junit/rich` wired, `--sessions` exists (warning in file mode). All options work end-to-end.
- [x] **7c.6** JSON report output — `--output json` uses pytest-json-report, generates p11test-results.json with per-test outcomes. — implement real JSON/JUnit report from `p11test test`. Machine-readable with per-test outcome, duration, mechanism requirements, crash status.
- [x] **7c.7** Write real README.md — project description, quick start, supported modules, architecture, key features. 94 lines.
- [x] **7c.8** Add CI workflow — `.github/workflows/ci.yml` with 5 jobs: ruff lint, mypy, meta-tests, strict-markers, SoftHSM2 smoke. — `.github/workflows/ci.yml` with: ruff check, mypy, pytest tests/, strict-marker collection, one smoke module.
- [ ] **7c.9** Capability snapshot command — `p11test capabilities --module ... --output json` writes slot info, mechanism list, interface list, token flags.

### P2: Depth and Polish
- [ ] **7c.10** Interface negotiation negative tests — invalid interface name, unsupported version, repeated load with different versions, inconsistent `C_GetInterfaceList` entries.
- [ ] **7c.11** Baseline regression workflow — "run suite → emit structured results → diff against known-good artifact" for each module.
- [ ] **7c.12** Current status document — single `docs/status.md` showing what works / what's partial / what's planned. Different from aspirational master-plan.
- [ ] **7c.13** pyproject.toml polish — add URLs, classifiers, supported-platform statement. Prepare for PyPI publication.

## Tier 8 — Per-Target Re-Validation (post Tier 7 changes)

Re-run full suite on every target after Tier 7 security tests are added. Use local builds where possible, Docker for the rest. Record pass/fail/skip/xfail. Update `docs/module-matrix.md` and `docs/module-issues.md`.

- [x] **8.1** **SoftHSM2 2.7.0** — local build full suite. Confirm 0 failures.
- [x] **8.2** **Kryoptic 1.5.0+PQC** — local build full suite. Confirm 0 failures.
- [ ] **8.3** **pkcs11-mock 2.0.0** — local build. Document expected mock failures.
- [ ] **8.4** **qryptotoken 0.4.1** — local build. Document PQC-only limitations.
- [ ] **8.5** **tpm2-pkcs11 (hardware)** — `sg tss`. Document TPM limitations.
- [ ] **8.6** **tpm2-swtpm 0.10.1** — local swtpm build. Full suite with abrmd.
- [ ] **8.7** **BouncyHSM 2.0.1** — local build. Fix or document segfault + CKF_TOKEN_PRESENT.
- [ ] **8.8** **SoftHSM2 main** — local build dev branch. Compare with 2.7.0.
- [ ] **8.9** **Kryoptic main** — local build dev branch. Compare with 1.5.0.
- [ ] **8.10** **NSS softokn (local)** — `bash local-builds/test.sh nss-softokn -q`. System NSS slot 0 (crypto services, no PIN). Fast validation target.
- [ ] **8.10b** **NSS 3.120.1** — Docker slot 1 (cert DB). Analyze remaining failures.
- [ ] **8.11** **OpenCryptoki 3.26** — Docker. Verify PIN lockout fix works.
- [ ] **8.12** **NSS-PQC (Rawhide)** — Docker. Check ML-KEM/ML-DSA support.
- [ ] **8.13** **Kryoptic FIPS** — Docker. Analyze FIPS-specific behavior.

## Tier 9 — Docker Final Validation

Run after ALL other tiers. Rebuild every Docker image with `--no-cache`. One clean pass.

- [ ] **9.1–9.13** Final validation for all 12 Docker targets + sign-off summary in `docs/module-matrix.md`.

---

## Recommended loop prompt

```
/ralph-loop:ralph-loop "/using-superpowers Pick the highest-priority unfinished task from docs/master-plan.md. Implementation rules: (1) Use local builds for fast iteration — avoid Docker unless required. (2) If /tmp/pkcs11/ doesn't exist, clone it: git clone --depth 1 https://github.com/oasis-tcs/pkcs11.git /tmp/pkcs11. (3) Use _error_tuples.py — NEVER generic PKCS11Error catches. (4) Unexpected CKR: document in module-issues.md with compliance.note(), NOT silent pass. (5) Verify zero regressions: bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q && bash local-builds/test.sh nss-softokn -q. (6) For medium/large tasks: plan first, implement, verify on all 3 local targets, gap-check, commit. (7) Commit with descriptive message referencing the task ID, then mark done." --completion-promise "All tasks in docs/master-plan.md are marked done"
```
