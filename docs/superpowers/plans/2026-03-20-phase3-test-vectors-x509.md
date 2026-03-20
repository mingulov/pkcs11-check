# Phase 3: Test Vectors & X.509 Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete X.509 test hardening, add ACVP-based tests for FIPS algorithms, integrate CCTV edge-case vectors, add RSA signature generation tests, and refresh documentation.

**Architecture:** Each task creates or modifies one test file, verifies on SoftHSM2 + Kryoptic (local builds), and commits. Wycheproof tests follow the existing loader pattern (`WYCHEPROOF_DIR / filename`). ACVP tests use `acvp_loader.py`. All tests skip gracefully when vectors or mechanisms are unavailable.

**Tech Stack:** Python 3.11+, pytest, python-pkcs11, cryptography, uv

**Existing coverage note:** The current Wycheproof test files ALREADY have comprehensive multi-curve/multi-hash coverage (ECDSA 68 configs, ECDH 28 files, RSA all key sizes, PSS auto-glob, HMAC all SHA-2/3, HKDF all variants, PBKDF2 all variants, RSA-OAEP 3072/4096). Do NOT create tasks to "expand" what is already there.

**Verification commands:**
```bash
# Fast iteration (use for every task)
bash local-builds/test.sh softhsm2 -- <test-file> -v --tb=short
bash local-builds/test.sh kryoptic -- <test-file> -v --tb=short

# Full suite regression (use after each section)
bash local-builds/test.sh softhsm2 -q
bash local-builds/test.sh kryoptic -q

# Lint + type check (run after every task)
uv run ruff check src/ tests/
uv run mypy src/
```

**Ralph loop prompt:**
```
Execute the plan at docs/superpowers/plans/2026-03-20-phase3-test-vectors-x509.md task by task.

For each task:
1. Read the task steps
2. Implement the code changes described
3. Run the verification commands shown in each task
4. Run `uv run ruff check src/ tests/ && uv run mypy src/` to ensure no lint/type errors
5. If tests pass on both SoftHSM2 and Kryoptic, commit with the suggested message
6. If tests fail, debug and fix before committing
7. Move to the next task

Use `bash local-builds/test.sh softhsm2 -- <file> -v --tb=short` and
`bash local-builds/test.sh kryoptic -- <file> -v --tb=short` for verification.

IMPORTANT: Never use generic `except PKCS11Error: pass`. Always catch specific CKR codes.
IMPORTANT: All tests must skip cleanly when mechanisms are unavailable.
IMPORTANT: Follow existing patterns in the wycheproof/ and x509/ directories.
IMPORTANT: The existing ACVP SLH-DSA test is a parsing skeleton that never calls PKCS#11.
           Rewrite it to actually import keys and call C_Verify/C_Sign.
```

---

## Section A — X.509 Hardening (Tasks 1–2)

### Task 1: Add x509 `__init__.py` and fix bare except

**Files:**
- Create: `src/pkcs11_check/testcases/x509/__init__.py`
- Modify: `src/pkcs11_check/testcases/x509/conftest.py`

- [ ] **Step 1:** Create empty `__init__.py`

```python
# src/pkcs11_check/testcases/x509/__init__.py
```

- [ ] **Step 2:** Fix bare `except:` in `get_crl_class()` (conftest.py line 193)

Replace `except:` with `except Exception:`. This is a probing function that tries multiple CKO class values — broad catch is acceptable here, but bare `except:` catches `SystemExit`/`KeyboardInterrupt`.

- [ ] **Step 3:** Verify tests still pass

```bash
bash local-builds/test.sh softhsm2 -- src/pkcs11_check/testcases/x509/ -q --tb=short
bash local-builds/test.sh kryoptic -- src/pkcs11_check/testcases/x509/ -q --tb=short
```

- [ ] **Step 4:** Commit

```bash
git add src/pkcs11_check/testcases/x509/__init__.py src/pkcs11_check/testcases/x509/conftest.py
git commit -m "fix(x509): add __init__.py, fix bare except in get_crl_class"
```

---

### Task 2: Expand v3.0+ attribute matrix with HASH_OF_SUBJECT/ISSUER_PUBLIC_KEY

**Files:**
- Modify: `src/pkcs11_check/testcases/x509/test_core_ops.py`

The v3.0+ matrix currently tests PUBLIC_KEY_INFO, SKID, AKID. PKCS#11 v3.0 also defines `CKA_HASH_OF_SUBJECT_PUBLIC_KEY` (0x8A) and `CKA_HASH_OF_ISSUER_PUBLIC_KEY` (0x8B). Add these to the parametrized matrix.

**Note:** Per PKCS#11 v3.0 spec, these are SHA-1 hashes of the SubjectPublicKeyInfo BIT STRING value (the public key content), NOT the full SPKI DER encoding.

- [ ] **Step 1:** Add hash attributes to `_build_v30_attr()` and parametrize list

Add cases for `HASH_OF_SUBJECT_PUBLIC_KEY` and `HASH_OF_ISSUER_PUBLIC_KEY`. Use `cryptography` to extract the public key bytes and compute SHA-1 hash.

- [ ] **Step 2:** Verify on both modules

```bash
bash local-builds/test.sh softhsm2 -- src/pkcs11_check/testcases/x509/test_core_ops.py::TestV30CertAttributes -v
bash local-builds/test.sh kryoptic -- src/pkcs11_check/testcases/x509/test_core_ops.py::TestV30CertAttributes -v
```

Expected: SoftHSM2 skips all 5 (v2.40), Kryoptic xfails all 5.

- [ ] **Step 3:** Commit

```bash
git commit -am "feat(x509): expand v3.0+ attr matrix with HASH_OF_*_PUBLIC_KEY"
```

---

## Section B — Wycheproof RSA Signature Generation (Task 3)

### Task 3: Add Wycheproof RSA PKCS#1 signature generation tests

**Files:**
- Create: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_siggen.py`

New file — tests RSA signature *generation* via `C_Sign` (NOT verification). Import the private key from Wycheproof `rsa_pkcs1_2048_sig_gen_test.json` vectors, sign the message with `CKM_SHA256_RSA_PKCS`, compare output to expected signature. PKCS#1 v1.5 signatures are deterministic, so the output MUST match.

**Note:** The existing `test_wycheproof_rsa.py` already loads `rsa_pkcs1_*_sig_gen_test.json` but only uses them for *verification* (C_Verify). This test file tests the *signing* path (C_Sign) which is a fundamentally different operation.

- [ ] **Step 1:** Create test file

Import private key components (n, e, d, p, q) from vector, create `CKO_PRIVATE_KEY` with `CKM_RSA_PKCS`, sign the message, compare to expected signature bytes. Use `has_mechanism()` skip pattern.

- [ ] **Step 2:** Verify on SoftHSM2 and Kryoptic
- [ ] **Step 3:** Add 3072/4096 vectors if 2048 works
- [ ] **Step 4:** Commit

```bash
git commit -am "feat(wycheproof): add RSA PKCS#1 signature generation tests (C_Sign path)"
```

---

## Section C — ACVP Integration (Tasks 4–9)

### Task 4: Rewrite ACVP SLH-DSA test to actually call PKCS#11

**Files:**
- Modify: `src/pkcs11_check/testcases/test_acvp_slhdsa.py`

**Critical:** The existing implementation is a parsing skeleton that counts vectors but never calls PKCS#11. It must be rewritten to actually import keys and call C_Verify/C_Sign.

- [ ] **Step 0:** Read the existing test_acvp_slhdsa.py — understand it's a skeleton
- [ ] **Step 1:** Rewrite sigVer test to actually import the public key and call `C_Verify`

Load vectors from `SLH-DSA-sigVer-FIPS205`. For each vector: import public key as `CKO_PUBLIC_KEY` with `CKA_PARAMETER_SET`, call `session.verify()` with `CKM_SLH_DSA`, check result matches expected pass/fail.

- [ ] **Step 2:** Add sigGen test function

Load `SLH-DSA-sigGen-FIPS205`. Import private key, sign the message, compare output to expected signature.

- [ ] **Step 3:** Add keyGen test function if vectors support it

Load `SLH-DSA-keyGen-FIPS205`. Generate key pair, verify public key matches expected. This may not be possible if the module doesn't accept seed-based generation.

- [ ] **Step 4:** Verify on Kryoptic (only module with SLH-DSA support)

```bash
bash local-builds/test.sh kryoptic -- src/pkcs11_check/testcases/test_acvp_slhdsa.py -v --tb=short
```

- [ ] **Step 5:** Commit

```bash
git commit -am "feat(acvp): rewrite SLH-DSA tests to call PKCS#11 C_Verify/C_Sign"
```

---

### Task 5: Add ACVP SHA-3 digest tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_acvp_sha3.py`

Load ACVP `SHA3-256-2.0`, `SHA3-384-2.0`, `SHA3-512-2.0` vectors. Test `C_Digest` with `CKM_SHA3_*`. Skip gracefully if ACVP not cloned or mechanism unavailable.

- [ ] **Step 1:** Create test file using `acvp_loader.py`

```python
from pkcs11_check.testcases.data.acvp_loader import load_acvp_vectors, ACVP_AVAILABLE
```

- [ ] **Step 2:** Parametrize by algorithm variant (224/256/384/512)
- [ ] **Step 3:** Verify on Kryoptic (has SHA-3), note SoftHSM2 may lack SHA-3

```bash
bash local-builds/test.sh kryoptic -- src/pkcs11_check/testcases/test_acvp_sha3.py -v --tb=short
```

- [ ] **Step 4:** Commit

```bash
git commit -am "feat(acvp): add SHA-3 digest tests from NIST ACVP vectors"
```

---

### Task 6: Add ACVP HMAC tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_acvp_hmac.py`

Load ACVP `HMAC-SHA2-256-2.0`, `HMAC-SHA2-384-2.0`, `HMAC-SHA2-512-2.0`. Cross-verify with PKCS#11 `CKM_SHA256_HMAC` etc.

- [ ] **Step 1:** Create test file, load HMAC-SHA2-256 vectors
- [ ] **Step 2:** Import the HMAC key as `CKO_SECRET_KEY` with `CKA_KEY_TYPE = CKK_SHA256_HMAC`
- [ ] **Step 3:** Call `session.sign()` with `CKM_SHA256_HMAC`, compare MAC output to expected
- [ ] **Step 4:** Parametrize across SHA-2 variants (256/384/512) and SHA-3 if supported
- [ ] **Step 5:** Verify on both modules, commit

```bash
git commit -am "feat(acvp): add HMAC tests from NIST ACVP vectors"
```

---

### Task 7: Add ACVP ECDSA signature verification tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_acvp_ecdsa.py`

Load `ECDSA-SigVer-FIPS186-5`. Test signature verification with imported public keys across P-256/P-384/P-521.

- [ ] **Step 1:** Create test file with ECDSA SigVer
- [ ] **Step 2:** For each vector: import EC public key, call `session.verify()` with `CKM_ECDSA`, check pass/fail matches expected
- [ ] **Step 3:** Parametrize by curve (P-256, P-384, P-521)
- [ ] **Step 4:** Verify on both modules, commit

```bash
git commit -am "feat(acvp): add ECDSA SigVer tests from FIPS 186-5 vectors"
```

---

### Task 8: Add ACVP EdDSA tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_acvp_eddsa.py`

Load `EDDSA-SigVer-1.0` and `EDDSA-SigGen-1.0`. Test Ed25519 and Ed448 via `CKM_EDDSA`.

- [ ] **Step 1:** Create test file with SigVer (import public key, verify signature)
- [ ] **Step 2:** Add SigGen if supported (Ed25519 is deterministic — sign and compare)
- [ ] **Step 3:** Verify on Kryoptic (has EdDSA), SoftHSM2 may skip

```bash
bash local-builds/test.sh kryoptic -- src/pkcs11_check/testcases/test_acvp_eddsa.py -v --tb=short
```

- [ ] **Step 4:** Commit

```bash
git commit -am "feat(acvp): add EdDSA SigVer/SigGen from NIST ACVP vectors"
```

---

### Task 9: Add ACVP AES-GCM tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_acvp_aes.py`

Load `ACVP-AES-GCM-1.0`. Cross-verify PKCS#11 AES-GCM encrypt/decrypt against NIST vectors. Complements existing Wycheproof AES-GCM coverage with official FIPS test vectors.

- [ ] **Step 1:** Create test file loading AES-GCM vectors from ACVP
- [ ] **Step 2:** Test encrypt (import key → set IV → encrypt plaintext → compare ciphertext + tag) and decrypt
- [ ] **Step 3:** Verify on both modules, commit

```bash
git commit -am "feat(acvp): add AES-GCM encrypt/decrypt from NIST ACVP vectors"
```

---

## Section D — CCTV Integration (Tasks 10–11)

### Task 10: Add CCTV ML-DSA benchmark message signing tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_cctv_mldsa.py`

**Data format note:** The CCTV `ML-DSA/benchmark/ML-DSA-44.json` files contain lists of ASCII message strings designed as benchmark signing inputs. They are NOT known-answer test vectors — there are no expected signatures. Use them for sign/verify round-trip testing: sign each message, then verify the signature, confirming internal consistency.

- [ ] **Step 1:** Read `ML-DSA/benchmark/ML-DSA-44.json` to confirm format (list of message strings)
- [ ] **Step 2:** Create test file that generates an ML-DSA key pair, signs each message, then verifies
- [ ] **Step 3:** Parametrize across ML-DSA-44/65/87
- [ ] **Step 4:** Skip if mechanism unavailable, limit to first 20 messages for speed
- [ ] **Step 5:** Verify on Kryoptic (only module with ML-DSA), commit

```bash
bash local-builds/test.sh kryoptic -- src/pkcs11_check/testcases/test_cctv_mldsa.py -v --tb=short
git commit -am "feat(cctv): add ML-DSA round-trip signing tests from benchmark messages"
```

---

### Task 11: Investigate CCTV RFC 6979 directory

**Files:**
- Possibly create: `src/pkcs11_check/testcases/test_cctv_rfc6979.py`

**Data note:** The `data/cctv/RFC6979/` directory contains only a `README.md` with a single P-256 test vector embedded in markdown text. No structured JSON or data files exist. Most PKCS#11 modules do NOT produce deterministic ECDSA (they use random k for side-channel resistance).

- [ ] **Step 1:** Read `data/cctv/RFC6979/README.md` to confirm there's only one embedded vector
- [ ] **Step 2:** If the vector is usable: extract it, create a minimal test that signs with `CKM_ECDSA` and compares. Mark as `@pytest.mark.xfail` since most modules use random nonces.
- [ ] **Step 3:** If no usable data: skip this task, document in commit message
- [ ] **Step 4:** Commit (or skip)

```bash
git commit -am "docs: CCTV RFC6979 has no structured test vectors — skipped"
```

---

## Section E — Documentation & Regression (Tasks 12–16)

### Task 12: Run full regression on SoftHSM2

**Files:** None (verification only)

- [ ] **Step 1:** Run full suite

```bash
bash local-builds/test.sh softhsm2 -q 2>&1 | tail -5
```

- [ ] **Step 2:** Compare against baseline (22,800+ passed, 0 failed)
- [ ] **Step 3:** Document any new skips/xfails in `docs/module-issues.md`
- [ ] **Step 4:** Commit doc updates if needed

---

### Task 13: Run full regression on Kryoptic

**Files:** None (verification only)

- [ ] **Step 1:** Run full suite

```bash
bash local-builds/test.sh kryoptic -q 2>&1 | tail -5
```

- [ ] **Step 2:** Compare against baseline (21,690+ passed, 0 failed)
- [ ] **Step 3:** Document any new results, commit

---

### Task 14: Update test-coverage.md

**Files:**
- Modify: `docs/test-coverage.md`

- [ ] **Step 1:** Run coverage report

```bash
uv run python scripts/generate-coverage-report.py
```

- [ ] **Step 2:** Update `docs/test-coverage.md` with new vector counts
- [ ] **Step 3:** Add X.509 section and ACVP section if missing
- [ ] **Step 4:** Commit

```bash
git commit -am "docs: update test coverage with Phase 3 additions"
```

---

### Task 15: Update status.md and module-issues.md

**Files:**
- Modify: `docs/status.md`
- Modify: `docs/module-issues.md`

- [ ] **Step 1:** Add X.509 parity, ACVP tests, CCTV ML-DSA to "What Works" in status.md
- [ ] **Step 2:** Update test counts across both modules
- [ ] **Step 3:** Add any new module quirks discovered during Phase 3
- [ ] **Step 4:** Commit

```bash
git commit -am "docs: update status and module issues for Phase 3 completion"
```

---

### Task 16: Final lint and type check pass

**Files:** Various (fix any issues found)

- [ ] **Step 1:** Run full lint and type check

```bash
uv run ruff check src/ tests/
uv run mypy src/
```

- [ ] **Step 2:** Fix any new issues introduced during Phase 3
- [ ] **Step 3:** Commit fixes

```bash
git commit -am "fix: resolve lint and type issues from Phase 3"
```

---

## Summary

| Section | Tasks | Focus |
|---------|-------|-------|
| A: X.509 Hardening | 1–2 | `__init__.py`, bare except fix, v3.0+ HASH attr matrix |
| B: Wycheproof RSA SigGen | 3 | New RSA signature generation test (C_Sign deterministic path) |
| C: ACVP Integration | 4–9 | SLH-DSA rewrite, SHA-3, HMAC, ECDSA, EdDSA, AES-GCM |
| D: CCTV Integration | 10–11 | ML-DSA round-trip, RFC 6979 investigation |
| E: Docs & Regression | 12–16 | Full regression both modules, coverage docs, lint pass |

**Expected outcome:** ACVP vectors integrated for 5+ FIPS algorithms, SLH-DSA tests actually calling PKCS#11, CCTV ML-DSA edge cases covered, X.509 suite fully hardened with 5-attribute v3.0+ matrix, clean documentation.
