# Deep Artifact Analysis — Test Bug Fixes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Opus 4.6** for analysis/investigation tasks, **Sonnet 4.6** for fix implementation.

**Goal:** Fix test bugs causing ~35,000 false failures across 4 providers. The failures are in pkcs11-check test code itself, not module bugs.

**Architecture:** 7 independent fix tasks targeting specific test files. Each fix addresses a well-understood root cause found via cross-provider failure analysis. After fixes, remaining failures are genuine module findings.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw

**Artifacts analyzed:** `/home/user/src/m/pkcs11-check/artifacts/` — softhsm2-main, kryoptic-main, nss-pqc, opencryptoki-master

---

## Failure Triage

| Priority | Test File | Failures | Root Cause | Type |
|----------|-----------|----------|-----------|------|
| **P0** | test_wycheproof_ecdh.py | **~30,000** | Missing `CKA_CLASS: CKO_SECRET_KEY` in derive template | Test bug |
| **P0** | test_wycheproof_x25519.py | **~4,100** | Same missing `CKA_CLASS` in derive template | Test bug |
| **P1** | test_wycheproof_rsa_pss.py | **~870** | PSS params: mismatched MGF hash (mgf1sha1 vs mgf1sha256) | Test bug |
| **P1** | test_wycheproof_pbkdf2.py | **~65** | PBKDF2 derive template missing `CKA_CLASS` | Test bug |
| **P2** | test_wycheproof_ecdh.py | N/A | Error messages hide actual CKR codes | UX bug |
| **P2** | test_mech_sign_recover.py | **8** | Output buffer size 237 vs expected 256 — padding issue | Test bug |
| **P2** | test_wycheproof_aes.py | **82** | AES ciphertext mismatch (NSS+OCK) | Investigate |

**Estimated fix impact:** ~35,000 of ~40,000 total cross-provider failures (87%)

---

### Task 1: Fix ECDH derive template — missing CKA_CLASS (P0, -30,000 failures)

**Root cause:** `test_wycheproof_ecdh.py` line 155 passes derive attrs without `CKA_CLASS: CKO_SECRET_KEY`. SoftHSM2 returns `CKR_TEMPLATE_INCOMPLETE`, Kryoptic returns `CKR_TEMPLATE_INCONSISTENT`, OpenCryptoki similar. ALL valid vectors fail across ALL providers.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py`

- [ ] **Step 1:** Read the file. Find the `derive_key` call around line 150-162. The `attrs` dict is:
```python
attrs={
    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
    CKA_VALUE_LEN: key_bits // 8,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}
```

- [ ] **Step 2:** Add `CKA_CLASS: CKO_SECRET_KEY` to the attrs dict:
```python
attrs={
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
    CKA_VALUE_LEN: key_bits // 8,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}
```

Add `CKA_CLASS` and `CKO_SECRET_KEY` to imports from `types_std`.

- [ ] **Step 3:** Also fix the error message to include the actual CKR code:
```python
# Change line 178 from:
pytest.fail(f"Valid ECDH derive failed for {vec_id}")
# To:
pytest.fail(f"Valid ECDH derive failed for {vec_id}: {exc_msg}")
```

- [ ] **Step 4:** Test:
```bash
bash local-builds/test.sh softhsm2 -k "test_ecdh[ecdh_secp256r1_ecpoint_test.json:tc1-valid]" -v
```
Expected: PASS

- [ ] **Step 5:** Test broader:
```bash
bash local-builds/test.sh softhsm2 -k "test_ecdh" -x --no-header 2>&1 | tail -5
```

- [ ] **Step 6:** Commit:
```bash
git commit -m 'fix: add CKA_CLASS to ECDH derive template — fixes ~30,000 Wycheproof failures'
```

---

### Task 2: Fix X25519/X448 derive template — same CKA_CLASS issue (P0, -4,100 failures)

**Root cause:** Same missing `CKA_CLASS` pattern.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py`

- [ ] **Step 1:** Read the file, find the `derive_key` call. Add `CKA_CLASS: CKO_SECRET_KEY` to the attrs dict.

- [ ] **Step 2:** Also fix the error message to include the actual CKR code (same pattern as Task 1).

- [ ] **Step 3:** Test:
```bash
bash local-builds/test.sh softhsm2 -k "test_x25519" -v --no-header 2>&1 | tail -5
```
SoftHSM2 may not support X25519 — skip is fine. Test on Kryoptic if possible:
```bash
LD_LIBRARY_PATH=/home/user/src/m/pkcs11-check/local-builds/openssl/install/lib64 P11TEST_MODULE=/home/user/src/m/pkcs11-check/local-builds/kryoptic/lib/libkryoptic_pkcs11.so P11TEST_PIN=1234 uv run python -m pytest src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py -x -v --no-header 2>&1 | tail -10
```

- [ ] **Step 4:** Commit:
```bash
git commit -m 'fix: add CKA_CLASS to X25519/X448 derive template — fixes ~4,100 Wycheproof failures'
```

---

### Task 3: Fix RSA-PSS Wycheproof verify — MGF hash mismatch (P1, -870 failures)

**Root cause:** The failure message says "sLen=20: CKR_ARGUMENTS_BAD". Looking at the test vector filenames: `rsa_pss_2048_sha256_mgf1sha1_20` — this means the vector uses SHA-256 for signing but MGF1-SHA1 for masking, with salt length 20. The test may be building the PSS params with a mismatched MGF hash.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py`

- [ ] **Step 1:** Read the file. Find how PSS params are built — does it extract the MGF hash from the vector/group metadata?

- [ ] **Step 2:** The Wycheproof vector groups have fields like `sha: "SHA-256"`, `mgf: "MGF1"`, `mgfSha: "SHA-1"`, `sLen: 20`. Check if the test uses `mgfSha` for the MGF parameter, or if it defaults to the same hash as the signing hash.

- [ ] **Step 3:** The PKCS#11 PSS params need:
```
hashAlg = CKM_SHA256     (from sha field)
mgf = CKG_MGF1_SHA1      (from mgfSha field, NOT from sha field)
salt_len = 20             (from sLen field)
```
If the test uses the signing hash for MGF, it would pass `CKG_MGF1_SHA256` instead of `CKG_MGF1_SHA1` — causing the module to reject.

- [ ] **Step 4:** Fix the MGF hash resolution to use the vector's `mgfSha` field.

- [ ] **Step 5:** Test:
```bash
bash local-builds/test.sh softhsm2 -k "test_rsa_pss_verify[rsa_pss_2048_sha256_mgf1sha1_20" -v --no-header 2>&1 | tail -10
```

- [ ] **Step 6:** Commit:
```bash
git commit -m 'fix: use vector mgfSha for RSA-PSS MGF parameter — fixes ~870 Wycheproof failures'
```

---

### Task 4: Fix PBKDF2 derive template (P1, -65 failures)

**Root cause:** `test_wycheproof_pbkdf2.py` likely has the same missing `CKA_CLASS` issue in its derive key template. Kryoptic returns `CKR_TEMPLATE_INCONSISTENT`.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py`

- [ ] **Step 1:** Read the file, find the `derive_key` or `C_DeriveKey` call. Check if `CKA_CLASS: CKO_SECRET_KEY` is in the template.

- [ ] **Step 2:** If missing, add it. Also add `CKA_CLASS` to the error message.

- [ ] **Step 3:** Test and commit:
```bash
git commit -m 'fix: add CKA_CLASS to PBKDF2 derive template — fixes ~65 Wycheproof failures'
```

---

### Task 5: Fix sign_recover output size assertion (P2, -8 failures)

**Root cause:** `test_mech_sign_recover.py` asserts `len(recovered) == 256` but gets 237 bytes. RSA sign-recover with PKCS#1 v1.5 padding produces output shorter than the modulus (256 bytes) because it strips the leading zero. The test should compare the recovered MESSAGE, not expect modulus-length output.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_sign_recover.py`

- [ ] **Step 1:** Read the file. Find the assertion that fails.

- [ ] **Step 2:** The sign-recover output includes padding. The assertion should check that the recovered data ENDS WITH the original input, not that it's exactly 256 bytes. Or use `unpad_pkcs1_type1()` to strip padding. Check the PKCS#11 spec for C_SignRecover and C_VerifyRecover to understand what output to expect.

- [ ] **Step 3:** Fix and commit.

---

### Task 6: Investigate AES Wycheproof ciphertext mismatches (P2, -82 failures)

**Root cause:** AES Wycheproof tests on NSS-PQC and OpenCryptoki show ciphertext mismatches (diff output). This could be:
- Wrong IV handling
- Wrong padding mode
- Endianness issue
- Module bug (different AES implementation)

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`

- [ ] **Step 1:** Read the test file. Understand how AES vectors are processed.

- [ ] **Step 2:** Check sample failures from artifacts — what AES mode (GCM, CBC, etc.) and what the actual vs expected ciphertexts look like.

- [ ] **Step 3:** If the issue is in the test (wrong mode selection, wrong IV), fix it. If the issue is in the module (wrong AES output), document as finding.

- [ ] **Step 4:** Fix or document.

---

### Task 7: Improve error messages across Wycheproof tests

**Goal:** All Wycheproof tests that catch `AssertionError` and re-raise as `pytest.fail` should include the original error message (which contains the CKR code). Currently, failures show generic "Valid X failed for vector_id" without the CKR code, making diagnosis impossible.

**Files to fix:**
- `test_wycheproof_ecdh.py` — line 178 (already in Task 1, but ensure consistency)
- `test_wycheproof_x25519.py` — similar pattern
- `test_wycheproof_rsa_pss.py` — if it has the pattern
- `test_wycheproof_pbkdf2.py` — if it has the pattern
- Any other Wycheproof test with `pytest.fail(f"... failed for {vec_id}")` without `{exc_msg}`

- [ ] **Step 1:** Search all Wycheproof tests for the pattern:
```bash
grep -rn "pytest.fail.*failed for" src/pkcs11_check/testcases/wycheproof/
```

- [ ] **Step 2:** For each match, change from:
```python
pytest.fail(f"Valid X failed for {vec_id}")
```
To:
```python
pytest.fail(f"Valid X failed for {vec_id}: {exc_msg}")
```

- [ ] **Step 3:** Lint and commit:
```bash
git commit -m 'fix: include CKR code in Wycheproof failure messages for diagnosis'
```

---

## Expected Impact

| Task | Fix | Failures Fixed |
|------|-----|----------------|
| 1 | ECDH CKA_CLASS | **~30,000** |
| 2 | X25519 CKA_CLASS | **~4,100** |
| 3 | RSA-PSS MGF hash | **~870** |
| 4 | PBKDF2 CKA_CLASS | **~65** |
| 5 | Sign-recover size | **~8** |
| 6 | AES investigate | **~82** (TBD) |
| 7 | Error messages | 0 (UX improvement) |
| **Total** | | **~35,125** |

Post-fix, the remaining ~5,000 failures across 4 providers should be genuine module findings (CKR_DEVICE_ERROR, CKR_CURVE_NOT_SUPPORTED, CKR_MECHANISM_INVALID, etc.).
