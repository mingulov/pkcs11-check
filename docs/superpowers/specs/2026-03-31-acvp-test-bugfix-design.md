# ACVP Test Suite Bug Fix Design

**Date:** 2026-03-31
**Scope:** Fix 19 confirmed bugs in `src/pkcs11_check/testcases/acvp/` test code
**Approach:** Mix (C) — fix all mechanical bugs now, skip structural ones needing missing infrastructure (C_DigestXof), implement what's feasible

## Problem

The ACVP test suite has bugs in the test code itself (not in ACVP data or module behavior). These cause:
- ~18,000 false failures across BouncyHSM and Kryoptic
- Real module bugs hidden by overly broad error handling
- Wrong PKCS#11 attributes that may work on lenient modules but are spec-incorrect
- Missing validation that lets incorrect results pass silently

Analysis method: all 27 ACVP test files cross-referenced with OASIS PKCS#11 v3.2 specs, BouncyHSM and Kryoptic test artifacts (`artifacts2/`), and module source code.

## Phase 1: Fix crash/AttributeError bugs

**Model:** Sonnet 4.6
**Impact:** Unblocks ~18 multiblock CFB/OFB tests + ~5,400 wrap tests per module

### 1a. `mech.mech` AttributeError in multiblock runner

**File:** `aes/base_runner_simple.py` lines 192, 265
**Bug:** `mech.mech` does not exist on `PackedMechanism`. The class has `self.ck` (CK_MECHANISM struct) and `self.byref()` (for C function calls).
**Evidence:** All multiblock CFB128/CFB8/CFB1/OFB tests crash with AttributeError on both BouncyHSM and Kryoptic (18 failures each).
**Spec ref:** `recipes.py:642` uses `mech.byref()` for `C_EncryptInit`.
**Fix:** Change `mech.mech` to `mech.byref()` at both lines.

### 1b. `CKK_AES` for arbitrary-size wrap payload

**File:** `aes/test_wrap.py` lines 74, 194
**Bug:** ACVP key wrap vectors have payloads of various sizes (multiples of 8 bytes, 16-512+ bytes). Using `CKK_AES` enforces valid AES key sizes only (16/24/32 bytes). All non-AES-sized vectors fail with `CKR_KEY_SIZE_RANGE`.
**Evidence:** 5,400 failures on Kryoptic, all `CKR_KEY_SIZE_RANGE`.
**Fix:** Change `CKK_AES` to `CKK_GENERIC_SECRET` for the key-to-wrap at both locations. Keep `CKK_AES` for the wrapping key itself.

## Phase 2: Fix wrong PKCS#11 attributes

**Model:** Sonnet 4.6
**Impact:** ML-KEM tests use spec-correct attributes; strict modules will no longer reject

### 2a. ML-KEM public key: `CKA_ENCRYPT` → `CKA_ENCAPSULATE`

**File:** `test_acvp_mlkem.py` lines 94, 164
**Bug:** Uses `CKA_ENCRYPT` for ML-KEM public keys.
**Spec ref:** OASIS `ml-kem.md:76` shows `{CKA_ENCAPSULATE, &true, sizeof(true)}` in example template. `CKA_ENCAPSULATE` exists in `types_std.py:2428`.
**Fix:** Replace `CKA_ENCRYPT: True` with `CKA_ENCAPSULATE: True`.

### 2b. ML-KEM private key: `CKA_DERIVE` → `CKA_DECAPSULATE`

**File:** `test_acvp_mlkem.py` lines 95, 224
**Bug:** Uses `CKA_DERIVE` for ML-KEM private keys.
**Spec ref:** OASIS `ml-kem.md:133` shows `{CKA_DECAPSULATE, &true, sizeof(true)}`. `CKA_DECAPSULATE` exists in `types_std.py:2429`.
**Fix:** Replace `CKA_DERIVE: True` with `CKA_DECAPSULATE: True`.

## Phase 3: Fix overly broad error handling

**Model:** Sonnet 4.6
**Impact:** Real module bugs no longer hidden; test failures become visible findings

### 3a. Remove `CKR_DEVICE_ERROR` from `_UNSUPPORTED_ERRORS`

**Files:** 6 files contain `_UNSUPPORTED_ERRORS` tuples with `CKR_DEVICE_ERROR`:
- `test_acvp_mldsa.py:68`
- `test_acvp_mlkem.py:56`
- `test_acvp_eddsa.py:59`
- `test_acvp_ecdsa.py:244` (inline tuple, not named)
- `test_acvp_rsa_keygen.py:106,175,232`

**Bug:** `CKR_DEVICE_ERROR` indicates a real module failure, not "unsupported mechanism." Skipping on it hides bugs.
**Fix:** Remove `"CKR_DEVICE_ERROR"` from all these tuples.

### 3b. Tighten verify CKR acceptance lists

**Files and lines:**
- `test_acvp_mldsa.py:258-263` — accepts `CKR_SIGNATURE_INVALID`, `CKR_SIGNATURE_LEN_RANGE`, `CKR_DATA_INVALID`, `CKR_FUNCTION_FAILED`, `CKR_DEVICE_ERROR`
- `test_acvp_ecdsa.py:243-244` — accepts `CKR_FUNCTION_FAILED`, `CKR_DEVICE_ERROR`
- `test_acvp_eddsa.py:202-203` — accepts `CKR_FUNCTION_FAILED`, `CKR_DEVICE_ERROR`

**Bug:** Per OASIS spec (`functions_for_verifying_signatures_and_macs.md:67-72`), C_Verify returns `CKR_OK`, `CKR_SIGNATURE_INVALID`, or `CKR_SIGNATURE_LEN_RANGE` for signature verification results. `CKR_FUNCTION_FAILED` and `CKR_DEVICE_ERROR` are unexpected errors that should not be treated as "invalid signature."
**Fix:** Keep only `CKR_SIGNATURE_INVALID` and `CKR_SIGNATURE_LEN_RANGE` in verify error lists. For `CKR_DATA_INVALID` in ML-DSA: remove it (it means the input data is malformed, not that the signature is invalid).

### 3c. RSA verify exception fall-through

**File:** `test_acvp_rsa.py` lines 170-175 (PKCS#1.5) and 219-224 (PSS)
**Bug:** When `expected_pass=False` and the exception isn't a signature error, execution silently falls through the `except` block. The `elif expected_pass: raise` doesn't cover the case where `expected_pass=False` AND the error is unexpected.
**Fix:** Add `else: raise` after each `elif expected_pass: raise`.

### 3d. ML-DSA: `xfail` suppresses real errors

**File:** `test_acvp_mldsa.py`
- Line 185: sign failure → `pytest.xfail(...)` — should raise
- Line 204-205: generated sig fails verify → `pytest.xfail(...)` — should raise
- Line 274: valid sig rejected → `pytest.xfail(...)` — should be `pytest.fail()`

**Bug:** Per project philosophy (CLAUDE.md): "NEVER skip, disable, or suppress real failures or crashes."
**Fix:** Line 185 → `raise`. Lines 204-205 → `pytest.fail(...)`. Line 274 → `pytest.fail(...)`.

### 3e. SLH-DSA: hardcoded "known Kryoptic issue" xfail

**File:** `test_acvp_slhdsa.py:292`
**Bug:** `pytest.xfail(f"... known Kryoptic issue")` — module-specific, hides the same bug on other modules.
**Fix:** → `pytest.fail(f"{vec_id}: rejected VALID SLH-DSA signature")`.

## Phase 4: Fix wrong mechanism/vector selection

**Model:** Opus 4.6
**Impact:** Tests use correct mechanisms; wrong vectors no longer loaded

### 4a. ML-DSA preHash mechanism check

**File:** `test_acvp_mldsa.py` lines 156, 225
**Bug:** `_get_mech_name(vec["pre_hash"])` is called where `vec["pre_hash"]` can be the literal string `"preHash"`. This falls through `hash_suffix_map` and returns `"ML_DSA"` instead of the hash-specific mechanism name. The signing/verify path at lines 177-179 and 245-247 correctly resolves `"preHash"` → `hash_alg`, but the mechanism availability CHECK doesn't.
**Fix:** Resolve `"preHash"` → `hash_alg` before calling `_get_mech_name()`:
```python
pre_hash = vec["pre_hash"]
if pre_hash == "preHash":
    pre_hash = vec.get("hash_alg", "pure")
mech_name = _get_mech_name(pre_hash)
```

### 4b. RSA ansx9.31 vectors loaded as PSS

**File:** `rsa/base_loader.py` lines 182, 303
**Bug:** Both `load_siggen_pss_vectors()` and `load_sigver_pss_vectors()` accept `sig_type in ("pss", "ansx9.31")`. ANSI X9.31 is a different signature scheme (`CKM_SHA1_RSA_X9_31`), not PSS.
**Fix:** Change both filters to `if sig_type != "pss": continue`.

### 4c. AES-XPN uses wrong IV

**File:** `aes/test_gcm.py` line 293
**Bug:** XPN test vectors build `extended_nonce = salt + iv` but store it as `vec["extended_nonce"]`. The GCM runner functions use `vec["iv"]` (the IV portion only), not the full extended nonce.
**Evidence:** Both Kryoptic and BouncyHSM produce identical "wrong" ciphertext, proving the input is wrong.
**Fix:** In `run_gcm_encrypt_test()` and `run_gcm_decrypt_test()` (in `base_runner_aead.py`), use `vec.get("extended_nonce", vec["iv"])` for the IV parameter.

### 4d. CBC-CS variant mapping

**File:** `aes/test_other.py` lines 223, 253
**Bug:** ACVP defines CBC-CS1, CBC-CS2, and CBC-CS3 as distinct modes. The test uses `CKM_AES_CTS` for all three. PKCS#11 `CKM_AES_CTS` corresponds to NIST CS3 only.
**Evidence:** CBC-CS2 mismatches show last two ciphertext blocks in opposite order — classic CS variant confusion.
**Fix:** Only run CS3 vectors with `CKM_AES_CTS`. Skip CS1 and CS2 with `pytest.skip("CBC-CS{n} not mappable to CKM_AES_CTS (CS3 only)")`.

## Phase 5: Add missing validation

**Model:** Opus 4.6
**Impact:** Tests actually verify correctness instead of just checking handles are non-zero

### 5a. ML-KEM shared secret validation

**File:** `test_acvp_mlkem.py` lines 175, 240
**Bug:** Encap/decap tests only check `secret_handle != 0`. Never extract and compare the actual shared secret against the vector's expected `k` value.
**Fix:** After encapsulate/decapsulate, read `CKA_VALUE` from the secret handle (requires `CKA_EXTRACTABLE: True` + `CKA_SENSITIVE: False` on the output key template) and assert equality with `vec["k"]`. Update the `attrs` dict for encap/decap output keys to include extractability.

### 5b. ECDH: replace ad-hoc DER stripping

**File:** `test_acvp_ecdh.py` lines 236-246
**Bug:** Manual byte stripping of DER OCTET STRING wrapper using heuristic that checks `data[0] == 0x04`. The same file at line 362 correctly uses `decode_ec_point()`.
**Fix:** Replace lines 236-246 with `point_data = decode_ec_point(peer_public_data)`.

### 5c. EdDSA dummy signature size

**File:** `test_acvp_eddsa.py` line 140
**Bug:** `dummy_sig = b"\x00" * 64` — correct for Ed25519 (64 bytes) but wrong for Ed448 (114 bytes).
**Fix:** Compute from curve metadata. The `_eddsa_helpers.py` CURVE_MAP already has this info. Pass signature length in the vector dict, or compute: `sig_len = 64 if "25519" in vec["curve"] else 114`.

## Phase 6: Skip vectors needing missing infrastructure

**Model:** Sonnet 4.6
**Impact:** Clean skips instead of wrong results

### 6a. SHAKE: skip until C_DigestXof available

**File:** `test_acvp_hash.py` lines 203-229
**Bug:** Uses `digest_single()` (C_Digest) for SHAKE-128/256. Per OASIS spec, SHAKE requires C_DigestXof functions, which are not in the vendored PKCS#11 headers or `pkcs11_check.raw`.
**Fix:** Add at the top of `test_acvp_shake`:
```python
pytest.skip("SHAKE requires C_DigestXof (not yet in pkcs11_check.raw headers)")
```

### 6b. ML-DSA context: document TODO

**File:** `test_acvp_mldsa.py`
**Bug:** Context field loaded from vectors (`_mldsa_helpers.py:135,271`) but never passed to sign/verify. Per spec, context must be provided via `CK_SIGN_ADDITIONAL_CONTEXT` mechanism parameter.
**Impact:** Low — most ACVP vectors have empty context for pure ML-DSA. Hash-ML-DSA vectors with non-empty context may produce wrong results, but the mechanism param builder doesn't exist yet.
**Fix:** Add TODO comment near the signing/verify calls documenting the gap. No skip needed since empty context works correctly for pure ML-DSA.

## Verification

After all phases, run:
```bash
bash local-builds/test.sh kryoptic -m acvp -v
```

Expected: dramatic reduction in failures and xfails. Remaining failures should be genuine module bugs (Kryoptic RSA PSS CKR_DEVICE_ERROR, EdDSA keyver accepting invalid keys, etc.).

If BouncyHSM Docker is available:
```bash
bash docker/test.sh bouncyhsm -- src/pkcs11_check/testcases/acvp/
```

## Dependencies

- Phase 1 must complete first (unblocks multiblock and wrap tests)
- Phases 2-4 are independent of each other
- Phase 5 depends on Phase 2 (ML-KEM attributes must be correct first)
- Phase 6 is independent
