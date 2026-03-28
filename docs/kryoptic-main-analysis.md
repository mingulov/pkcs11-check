# Kryoptic-Main Deep Analysis (2026-03-27)

**Source:** `artifacts/kryoptic-main/` from Docker run
**Baseline:** 165,340 passed / 29 failed / 40,254 skipped / 11,418 xfailed

## Critical Finding: Wycheproof xfails Hide Real Failures

All Wycheproof test files use `pytest.xfail()` instead of `pytest.fail()` for valid
vectors that fail. This means every PKCS#11 module bug found by Wycheproof vectors
is hidden as "expected failure" instead of reported as a real failure.

**Two bugs in the test pattern:**

1. **CKR rejections on valid vectors use xfail instead of fail.** When a module
   advertises a mechanism but returns an error CKR on a valid vector, that IS a module
   bug. The test should fail, not xfail. CLAUDE.md says: "Do not add pytest.xfail()
   for crashes, segfaults, or unexpected errors."

2. **Wrong-output assertions caught by the same `except AssertionError`.** The
   data-validation `assert actual == expected` raises `AssertionError`, same type as
   `expect_rv()`. The catch block treats both identically. A module that produces
   WRONG cryptographic output (the most dangerous kind of bug) gets xfailed.

**Affected files (26+ xfail sites):**
- test_wycheproof_ecdh.py (line 190) — only file with partial mismatch guard
- test_wycheproof_x25519.py (line 149)
- test_wycheproof_pbes2.py (lines 148, 163) — unconditional xfail, no result check
- test_wycheproof_pbkdf2.py (line 155)
- test_wycheproof_aes.py (lines 104, 177, 251, 257, 328, 387, 448)
- test_wycheproof_hkdf.py (line 153)
- test_wycheproof_ecdsa.py, test_wycheproof_dsa.py, test_wycheproof_mldsa.py,
  test_wycheproof_mldsa_sign.py, test_wycheproof_mlkem.py, test_wycheproof_chacha.py

**Fix pattern:** Replace `pytest.xfail()` with `pytest.fail()` for valid vectors.
Keep xfail ONLY for known, documented, CKR-specific module bugs (using
`xfail_if_known_ckr()` from conftest.py).

## Xfail Breakdown (11,418 total → should become failures)

| Count | Category | Root Cause |
|------:|----------|-----------|
| 6,918 | Valid ECDH derive failed | Kryoptic ECDH1_DERIVE incomplete |
| 2,069 | X25519/X448 derive failed | Kryoptic Montgomery ECDH incomplete |
| 1,260 | PBES2 key derivation | CKM_PKCS5_PBKD2 advertised but broken |
| 467 | ECDSA SHAKE256 rejected | No SHAKE ECDSA support in kryoptic |
| 298 | PBKDF2 key gen failed | Same CKM_PKCS5_PBKD2 issue |
| 236 | HKDF derive failed | HKDF incomplete |
| 123 | AES-CCM wrong ciphertext | AES-CCM implementation bugs |
| 18 | ML-DSA CKR_DEVICE_ERROR | Wrong CKR code |
| 6 | ML-DSA valid sig rejected | ML-DSA verify bugs |
| 23 | Other | Mixed |

## ECDH Parameter Format: Test is Correct

OASIS spec (elliptic_curves.md) says pPublicData for CK_ECDH1_DERIVE_PARAMS:
- MUST accept raw octet string (0x04||x||y) — this is what the test uses
- MAY accept DER-encoded ECPoint
- This is DIFFERENT from CKA_EC_POINT (which IS DER-encoded)

The test uses the mandatory format. Kryoptic failure is a kryoptic issue.

## Coverage Gaps

### Uncalled Functions (42 of 104)

**Actually called in subprocess but invisible to tracker (35):**
Multi-part streaming, message-based v3.0, dual-function, lifecycle —
all run in `subprocess.run([sys.executable, "-c", script])` which
creates its own RawPKCS11 that dies with the subprocess.

**Genuinely untested (4):**
C_SignRecover, C_VerifyRecover, C_VerifyRecoverInit, C_UnwrapKeyAuthenticated

**Behind destructive flag (3):**
C_InitToken, C_InitPIN, C_SetPIN

### Not-Invoked Mechanisms (49 of 168)

**No tests exist (real gaps):**
- 12 `*_HMAC_GENERAL` variants
- ~15 `*_KEY_DERIVATION` variants
- ~12 `*_KEY_GEN` variants (SHA-based HMAC key gen)
- 4 SHA3_*_RSA_PKCS_PSS variants
- 2 ECDSA hash variants (SHA384, SHA512)
- CKM_PUB_KEY_FROM_PRIV_KEY

**Blocked by missing bindings:**
- CKM_HASH_ML_DSA — needs CK_HASH_SIGN_ADDITIONAL_CONTEXT params
- CKM_HASH_SLH_DSA — same

**Alias (functionally covered):**
- CKM_ECDSA_KEY_PAIR_GEN (alias for CKM_EC_KEY_PAIR_GEN, which has 100 calls)

## ML-KEM invoked_detail Gap

ML-KEM uses `mech_simple(CKM_ML_KEM)` which produces `sub_mechanisms=None`.
No `mech_kem` packer exists. The "encapsulated AES" detail comes from template
attributes (CKA_KEY_TYPE), not mechanism parameters, so it cannot be captured
by the current sub_mechanisms tracking.

Options:
1. Create a `mech_kem` packer that extracts key type from template
2. Add template-based detail tracking alongside mechanism-based tracking

## Subprocess Call Tracking Gap

35 functions invisible because they run in bare `subprocess.run -c` scripts.
File-runner isolation (--isolation file) does NOT have this issue — plugin.py
runs inside each file subprocess and emits CoverageReport to JSONL.

Fix: Extend subprocess_session_preamble's cleanup() to dump call_log and
mechanism_counts to a temp file, have parent _run() read it back.

## Skip Analysis

All 40,254 skips are legitimate:
- 28,836 unsupported EC curves (secp256k1, brainpool, secp224r1, etc.)
- 1,511 DSA mechanisms not available
- 414 AES_GMAC not available
- 325 ChaCha20_Poly1305 not available
- etc.

Zero wrong skips found.
