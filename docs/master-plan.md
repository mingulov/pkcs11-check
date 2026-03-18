# p11test Master Plan v2

Phase 2: Local builds, failure analysis, test isolation, and threading.

Previous phase (v1) completed 43 tasks across 6 tiers — see git history for details.
Current baseline: **22,615 passed / 0 failed** (SoftHSM2), **21,533 passed / 0 failed** (Kryoptic with PQC).

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
| **SoftHSM2** | 2.7.0 | Working | 22,615 | **0** |
| **Kryoptic** | 1.5.0+PQC | Working | 21,533 | **0** |
| **pkcs11-mock** | 2.0.0 | Working | 26 | 2 (mock behavior) |
| **qryptotoken** | 0.4.1 | Working | 20 | 46 (limited PQC) |
| **tpm2-pkcs11** | 1.9.0 | Working | 11+ | needs `sg tss` |
| **BouncyHSM** | 2.0.1 | Partial | — | segfault + CKF_TOKEN_PRESENT bug |
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
- [x] **2.5** **BouncyHSM 2.0.1** — Segfaults on v3.2 attr query (python-pkcs11 fork bug). CKF_TOKEN_PRESENT not set (BouncyHSM bug).
- [x] **2.6** **pkcs11-mock 2.0.0** — 26 passed, 2 failed (constant RNG — mock behavior, expected).
- [ ] **2.7** **tpm2-pkcs11 1.9.0** — Hardware TPM working (`sg tss`). 26 mechanisms. Run full suite, document limitations.
- [x] **2.8** **qryptotoken 0.4.1** — 20 passed, 46 failed. Experimental PQC token, limited mechanism support.
- [ ] **2.9** **NSS-PQC (Rawhide)** — Docker only. Check ML-KEM/ML-DSA support.
- [ ] **2.10** **SoftHSM2 main** — Build locally: `bash local-builds/build.sh softhsm2 master`. Compare with 2.7.0.
- [ ] **2.11** **Kryoptic main** — Build locally: `bash local-builds/build.sh kryoptic main`. Compare with 1.5.0.
- [ ] **2.12** **Kryoptic FIPS** — Needs special OpenSSL FIPS build. Docker for now.

## Tier 3 — Module Issues Documentation

- [x] **3.1** Create `docs/module-issues.md` — structured document with per-module issues. Updated as targets are analyzed.
- [ ] **3.2** Create `docs/module-matrix.md` — summary table from local build test results.

## Tier 4 — Threading & Concurrency

- [ ] **4.1** Research python-pkcs11 thread safety — check `with nogil:` blocks in Cython.
- [ ] **4.2** Threaded test runner — ThreadPoolExecutor for parallel AES/digest/keygen.
- [ ] **4.3** Multi-session thread test — separate sessions in separate threads.
- [ ] **4.4** Thread-safe session pool — handle login state correctly.

## Tier 5 — Mechanism Discovery & Analysis

- [ ] **5.1** Enhanced mechanism probe — enumerate ALL mechanisms per module, generate coverage gap report.
- [ ] **5.2** Vendor mechanism identification — decode vendor-defined IDs.
- [ ] **5.3** Auto-skip untested mechanisms — coverage gap report.
- [ ] **5.4** Mechanism flag validation — verify flags match actual behavior.

## Tier 6 — Test Quality & Robustness

- [ ] **6.1** Eliminate test-order dependencies — use `pytest-randomly`.
- [ ] **6.2** Parameterize existing tests where appropriate.
- [ ] **6.3** Add `pytest-rerunfailures` for flaky tests.
- [ ] **6.4** Compliance note summary report per module.
- [ ] **6.5** R/O session test coverage.
- [ ] **6.6** Session-object lifecycle tests.

## Tier 7 — Final Validation (Docker)

Run after ALL other tiers. Rebuild every Docker image with `--no-cache`. Record final counts.

- [ ] **7.1–7.13** Final validation for all 12 Docker targets + summary in `docs/module-matrix.md`.

---

## Recommended loop prompt

```
/ralph-loop:ralph-loop "/using-superpowers Pick the highest-priority unfinished task from docs/master-plan.md. Use local builds (local-builds/test.sh) for fast iteration. Fix bugs on our side (p11test or python-pkcs11 fork), document module-side issues in docs/module-issues.md, commit, and mark done. Verify zero regressions on SoftHSM2 + Kryoptic." --completion-promise "All tasks in docs/master-plan.md are marked done"
```
