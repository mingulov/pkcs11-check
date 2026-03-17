# p11test Master Plan

Iterative improvement plan for the PKCS#11 test suite.
Each task should pass on **SoftHSM2** (v2.40) and **Kryoptic** (v3.2) before being marked done.

## Verification targets

- **SoftHSM2 2.6.1** (local, v2.40): `SOFTHSM2_CONF=/tmp/p11test-softhsm2.conf uv run pytest src/p11test/testcases/ --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234 -q --benchmark-disable`
- **SoftHSM2 2.7.0** (Docker, v2.40): `docker compose -f docker/docker-compose.test.yml run --rm test-softhsm2`
- **Kryoptic 1.5.0** (Docker, v3.2): `docker compose -f docker/docker-compose.test.yml run --rm test-kryoptic`

Note: Local SoftHSM2 is 2.6.1 (Ubuntu package). Docker builds 2.7.0 from source (latest release).

---

## Tier 1 — PKCS#11 Compliance Fundamentals

- [x] **1.1** Wrong-PIN / PIN-locked tests — 7 tests: wrong PIN, empty PIN, recovery after bad attempt, no object leak, long/unicode/null PIN edge cases
- [x] **1.2** Token (persistent) objects — 6 tests: create, survive session, use across sessions, session obj disappears, destroy, flag check
- [x] **1.3** `C_SetAttributeValue` — 7 tests: change label/ID, keypair labels, reject CKA_CLASS/KEY_TYPE/MODULUS/VALUE (compliance notes for silent ignore)
- [x] **1.4** SO login / `C_SetPIN` — 3 tests: SO wrong PIN, user+SO coexist rejected, PIN change+restore (@destructive)
- [x] **1.5** Multipart streaming — 20 tests: AES-ECB/CBC multiblock, SHA-256/512 large data, RSA sign 10KB, HMAC 64KB cross-verify
- [x] **1.6** Interface negotiation tests — test v2.40 fallback when v3.x unavailable, test `interface="auto"` vs explicit

## Tier 2 — Object & Type Coverage

- [x] **2.1** `CKO_DATA` objects — create, search by label/app, read value, destroy
- [x] **2.2** `CKO_CERTIFICATE` — import X.509 DER cert, search by subject/issuer, extract fields
- [x] **2.3** Classic DH key agreement — `CKM_DH_PKCS_DERIVE` with parameter generation
- [x] **2.4** RSA key wrapping — wrap AES key with RSA-OAEP, unwrap, verify material matches

## Tier 3 — Adversarial & Security Testing

- [x] **3.1** Concurrent session attacks — two sessions racing on same object (create/destroy/use)
- [x] **3.2** Object visibility across sessions — create in session A, find in session B (same token) [covered by 3.1]
- [x] **3.3** Attribute sensitivity enforcement — read CKA_VALUE on SENSITIVE=True key, must return error
- [x] **3.4** Key usage policy enforcement — use encrypt-only key for signing, must fail
- [x] **3.5** Mechanism parameter fuzzing — random bytes as mechanism_param, must not crash (segfault survival)
- [x] **3.6** Large object stress — 1MB CKO_DATA, 100KB random generation, very large plaintext encrypt
- [x] **3.7** Session exhaustion — open sessions until CKR_SESSION_COUNT, verify graceful error
- [x] **3.8** Duplicate label handling — two objects with same label, search returns both
- [x] **3.9** Slot re-initialization — C_Finalize + C_Initialize cycle, verify clean state
- [x] **3.10** CKR return code coverage — map all standard CKR codes, verify we trigger each reachable one

## Tier 4 — Module Differential & Reporting

- [ ] **4.1** Cross-module differential — same test on SoftHSM2 vs Kryoptic, flag behavioral differences (deferred: infrastructure task)
- [ ] **4.2** Module mechanism matrix report — generate CSV: module × mechanism × pass/skip/fail/xfail (deferred: infrastructure task)
- [x] **4.3** Vendor extension detection — probe CKM_VENDOR_DEFINED range for hidden mechanisms
- [x] **4.4** FIPS mode detection — check CKF_FIPS_APPROVED flag, adjust test expectations

## Tier 5 — Infrastructure & Quality

- [x] **5.1** Add pytest-timeout to Docker images — prevent hangs (OpenCryptoki took 33 min)
- [ ] **5.2** NSS + NSS-PQC Docker test run — rebuild and test with expanded suite
- [x] **5.3** Test result archival — save pytest JSON/JUnit output per module per run
- [ ] **5.4** Mechanism coverage report — auto-generate docs/test-coverage.md from test metadata

---

## Recommended loop prompt

```
/using-superpowers Pick the highest-priority unfinished task from docs/master-plan.md, implement it with tests passing on SoftHSM2 and Kryoptic (use Docker for Kryoptic), commit, then update the plan marking it done. If all tasks are done, do a gap analysis and add new tasks. Focus on test quality over quantity — each test should catch real bugs in real PKCS#11 modules.
```
