# ACVP Test Suite Bug Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 19 confirmed bugs in the ACVP test code that cause ~18K false failures and hide real module bugs.

**Architecture:** Pure test-code fixes — no new modules or APIs. Each task edits specific lines in existing ACVP test files. Changes are mechanical (wrong constant, wrong CKR code) or semantic (wrong mechanism logic, missing validation).

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw (ctypes PKCS#11 binding)

**Spec:** `docs/superpowers/specs/2026-03-31-acvp-test-bugfix-design.md`

**CRITICAL project rules (from CLAUDE.md):**
- NEVER use bare `except Exception: pass` or catch-all CKR checks
- NEVER skip/disable/suppress real failures — failures ARE findings
- `pytest.xfail()` only for known module bugs with evidence, never to suppress unexpected errors
- Always use `uv run` prefix for tools — NEVER bare `ruff`, `mypy`, `pytest`
- `CKR_DEVICE_ERROR` is a real module failure, not "unsupported"

---

## File Map

**Files modified (no new files created):**

| File | Tasks | Changes |
|------|-------|---------|
| `src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py` | 1 | Fix `mech.mech` → `mech.byref()` |
| `src/pkcs11_check/testcases/acvp/aes/test_wrap.py` | 1 | Fix `CKK_AES` → `CKK_GENERIC_SECRET` for payload |
| `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py` | 2, 5 | Fix attributes, add shared secret validation |
| `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py` | 3, 4, 6 | Fix CKR lists, xfail→fail, preHash check, TODO |
| `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py` | 3 | Fix CKR list |
| `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py` | 3, 5 | Fix CKR list, fix dummy sig size |
| `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py` | 3 | Fix xfail → fail |
| `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py` | 3 | Fix exception fall-through |
| `src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py` | 3 | Remove CKR_DEVICE_ERROR from skip lists |
| `src/pkcs11_check/testcases/acvp/rsa/base_loader.py` | 4 | Filter out ansx9.31 vectors |
| `src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py` | 4 | Fix XPN IV handling |
| `src/pkcs11_check/testcases/acvp/aes/test_other.py` | 4 | Skip CBC-CS1/CS2 |
| `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py` | 5 | Replace ad-hoc DER stripping |
| `src/pkcs11_check/testcases/acvp/test_acvp_hash.py` | 6 | Skip SHAKE tests |

---

## Task 1: Fix crash bugs (Phase 1)

**Model:** Sonnet 4.6
**Blocks:** Tasks 2, 3, 4, 5, 6

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py:192,265`
- Modify: `src/pkcs11_check/testcases/acvp/aes/test_wrap.py:16-24,74,194`

- [ ] **Step 1: Fix `mech.mech` → `mech.byref()` in base_runner_simple.py**

In `src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py`, change line 192 from:
```python
        rv = rs.raw.C_EncryptInit(rs.sh, mech.mech, key)
```
to:
```python
        rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
```

And change line 265 from:
```python
        rv = rs.raw.C_DecryptInit(rs.sh, mech.mech, key)
```
to:
```python
        rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
```

- [ ] **Step 2: Fix `CKK_AES` → `CKK_GENERIC_SECRET` in test_wrap.py**

In `src/pkcs11_check/testcases/acvp/aes/test_wrap.py`, update the import to add `CKK_GENERIC_SECRET`. Change lines 16-24 from:
```python
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
)
```
to:
```python
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
)
```

Then change line 74 from:
```python
            CKK_AES,
```
to:
```python
            CKK_GENERIC_SECRET,
```

And change line 194 from:
```python
            CKK_AES,
```
to:
```python
            CKK_GENERIC_SECRET,
```

(Both occurrences are inside `import_secret_key()` calls for the key-to-wrap. The wrapping key import at lines 70/190 uses `_import_aes_key()` and stays unchanged.)

- [ ] **Step 3: Lint check**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py src/pkcs11_check/testcases/acvp/aes/test_wrap.py`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py src/pkcs11_check/testcases/acvp/aes/test_wrap.py
git commit -m "fix(acvp): fix crash bugs in multiblock runner and key wrap tests

- base_runner_simple.py: mech.mech → mech.byref() for C_EncryptInit/C_DecryptInit
- test_wrap.py: CKK_AES → CKK_GENERIC_SECRET for wrap payload (arbitrary sizes)"
```

---

## Task 2: Fix ML-KEM attributes (Phase 2)

**Model:** Sonnet 4.6
**Blocked by:** Task 1

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py:29-34,94,95,164,224`

- [ ] **Step 1: Update imports**

In `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`, change the imports from:
```python
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_PARAMETER_SET,
    CKK_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
)
```
to:
```python
from pkcs11_check.raw.types_std import (
    CKA_DECAPSULATE,
    CKA_DERIVE,
    CKA_ENCAPSULATE,
    CKA_PARAMETER_SET,
    CKK_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
)
```

(Keep `CKA_DERIVE` — it's still used on encap/decap output secret keys.)

- [ ] **Step 2: Fix public key attribute at line 94**

Change:
```python
                public_attrs={CKA_ENCRYPT: True},
```
to:
```python
                public_attrs={CKA_ENCAPSULATE: True},
```

- [ ] **Step 3: Fix private key attribute at line 95**

Change:
```python
                private_attrs={CKA_DERIVE: True},
```
to:
```python
                private_attrs={CKA_DECAPSULATE: True},
```

- [ ] **Step 4: Fix imported public key attribute at line 164**

Change:
```python
                attrs={CKA_ENCRYPT: True},
```
to:
```python
                attrs={CKA_ENCAPSULATE: True},
```

- [ ] **Step 5: Fix imported private key attribute at line 224**

Change:
```python
                attrs={CKA_DERIVE: True},
```
to:
```python
                attrs={CKA_DECAPSULATE: True},
```

- [ ] **Step 6: Lint check**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`
Expected: no errors (CKA_ENCRYPT may become unused — if ruff flags it, remove it from the import)

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py
git commit -m "fix(acvp): use CKA_ENCAPSULATE/CKA_DECAPSULATE for ML-KEM keys

Per OASIS PKCS#11 v3.2 ml-kem.md, ML-KEM public keys use CKA_ENCAPSULATE
and private keys use CKA_DECAPSULATE, not CKA_ENCRYPT/CKA_DERIVE."
```

---

## Task 3: Fix overly broad error handling (Phase 3)

**Model:** Sonnet 4.6
**Blocked by:** Task 1

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py:63-70,185,204-205,255-263,274`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py:51-59`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py:53-60,196-205`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py:237-245`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py:292`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py:170-175,219-224`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py:99-107,168-176,227-233`

- [ ] **Step 1: Remove CKR_DEVICE_ERROR from _UNSUPPORTED_ERRORS in test_acvp_mldsa.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`, change:
```python
_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_KEY_SIZE_RANGE",
    "CKR_DEVICE_ERROR",
    "CKR_MECHANISM_PARAM_INVALID",
)
```
to:
```python
_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_KEY_SIZE_RANGE",
    "CKR_MECHANISM_PARAM_INVALID",
)
```

- [ ] **Step 2: Remove CKR_DEVICE_ERROR from _UNSUPPORTED_ERRORS in test_acvp_mlkem.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`, change:
```python
_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_KEY_SIZE_RANGE",
    "CKR_DEVICE_ERROR",
    "CKR_MECHANISM_PARAM_INVALID",
    "CKR_FUNCTION_NOT_SUPPORTED",
)
```
to:
```python
_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_KEY_SIZE_RANGE",
    "CKR_MECHANISM_PARAM_INVALID",
    "CKR_FUNCTION_NOT_SUPPORTED",
)
```

- [ ] **Step 3: Remove CKR_DEVICE_ERROR from _UNSUPPORTED_ERRORS in test_acvp_eddsa.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`, change:
```python
_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_CURVE_NOT_SUPPORTED",
    "CKR_KEY_SIZE_RANGE",
    "CKR_DEVICE_ERROR",  # Kryoptic may return this for unsupported Ed25519
)
```
to:
```python
_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_CURVE_NOT_SUPPORTED",
    "CKR_KEY_SIZE_RANGE",
)
```

- [ ] **Step 4: Tighten verify CKR list in test_acvp_mldsa.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`, change the verify error list (around lines 255-263) from:
```python
            if any(
                    name in exc_msg
                    for name in (
                        "CKR_SIGNATURE_INVALID",
                        "CKR_SIGNATURE_LEN_RANGE",
                        "CKR_DATA_INVALID",
                        "CKR_FUNCTION_FAILED",
                        "CKR_DEVICE_ERROR",
                    )
                ):
```
to:
```python
            if any(
                    name in exc_msg
                    for name in (
                        "CKR_SIGNATURE_INVALID",
                        "CKR_SIGNATURE_LEN_RANGE",
                    )
                ):
```

- [ ] **Step 5: Tighten verify CKR list in test_acvp_ecdsa.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py`, change (around lines 237-245) from:
```python
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID",
                    "CKR_SIGNATURE_LEN_RANGE",
                    "CKR_DATA_INVALID",
                    "CKR_FUNCTION_FAILED",
                    "CKR_DEVICE_ERROR",
                )
            ):
```
to:
```python
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID",
                    "CKR_SIGNATURE_LEN_RANGE",
                )
            ):
```

- [ ] **Step 6: Tighten verify CKR list in test_acvp_eddsa.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`, change (around lines 196-205) from:
```python
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID",
                    "CKR_SIGNATURE_LEN_RANGE",
                    "CKR_DATA_INVALID",
                    "CKR_FUNCTION_FAILED",
                    "CKR_DEVICE_ERROR",
                )
            ):
```
to:
```python
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID",
                    "CKR_SIGNATURE_LEN_RANGE",
                )
            ):
```

- [ ] **Step 7: Fix RSA PKCS#1.5 verify fall-through in test_acvp_rsa.py**

In `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py`, change the PKCS#1.5 except block (around lines 170-175) from:
```python
            if not expected_pass and any(
                c in exc_msg for c in ("CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE")
            ):
                pass  # Expected
            elif expected_pass:
                raise
```
to:
```python
            if not expected_pass and any(
                c in exc_msg for c in ("CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE")
            ):
                pass  # Expected
            elif expected_pass:
                raise
            else:
                raise  # Unexpected error for invalid-sig vector
```

- [ ] **Step 8: Fix RSA PSS verify fall-through in test_acvp_rsa.py**

In the same file, change the PSS except block (around lines 219-224) from:
```python
            if not expected_pass and any(
                c in exc_msg for c in ("CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE")
            ):
                pass  # Expected
            elif expected_pass:
                raise
```
to:
```python
            if not expected_pass and any(
                c in exc_msg for c in ("CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE")
            ):
                pass  # Expected
            elif expected_pass:
                raise
            else:
                raise  # Unexpected error for invalid-sig vector
```

- [ ] **Step 9: Fix ML-DSA xfail → raise/fail in test_acvp_mldsa.py**

At line 185, change:
```python
                pytest.xfail(f"{vec_id}: ML-DSA sign raised unexpected error: {e}")
```
to:
```python
                raise

```

At lines 204-205, change:
```python
                if not verified:
                    pytest.xfail(f"{vec_id}: Generated signature failed verification")
```
to:
```python
                if not verified:
                    pytest.fail(f"{vec_id}: Generated signature failed verification")
```

At line 274, change:
```python
                pytest.xfail(f"{vec_id}: module rejected a VALID ML-DSA signature")
```
to:
```python
                pytest.fail(f"{vec_id}: module rejected a VALID ML-DSA signature")
```

- [ ] **Step 10: Fix SLH-DSA xfail → fail in test_acvp_slhdsa.py**

At line 292, change:
```python
            pytest.xfail(f"{vec_id}: rejected VALID SLH-DSA signature - known Kryoptic issue")
```
to:
```python
            pytest.fail(f"{vec_id}: rejected VALID SLH-DSA signature")
```

- [ ] **Step 11: Remove CKR_DEVICE_ERROR from test_acvp_rsa_keygen.py (3 locations)**

At lines 99-107, change:
```python
            if any(
                name in exc_msg
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_TEMPLATE_INCOMPLETE",
                    "CKR_KEY_SIZE_RANGE",
                    "CKR_DEVICE_ERROR",
                )
            ):
```
to:
```python
            if any(
                name in exc_msg
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_TEMPLATE_INCOMPLETE",
                    "CKR_KEY_SIZE_RANGE",
                )
            ):
```

Apply the same removal at lines 168-176 (same tuple with same `"CKR_DEVICE_ERROR"` entry).

At lines 227-233, change:
```python
            if any(
                name in str(exc)
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_KEY_SIZE_RANGE",
                    "CKR_DEVICE_ERROR",
                )
            ):
```
to:
```python
            if any(
                name in str(exc)
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_KEY_SIZE_RANGE",
                )
            ):
```

- [ ] **Step 12: Lint check all modified files**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py src/pkcs11_check/testcases/acvp/test_acvp_rsa.py src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py`
Expected: no errors

- [ ] **Step 13: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py src/pkcs11_check/testcases/acvp/test_acvp_rsa.py src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py
git commit -m "fix(acvp): tighten error handling across all ACVP tests

- Remove CKR_DEVICE_ERROR from _UNSUPPORTED_ERRORS in 5 files
- Tighten verify CKR lists to only CKR_SIGNATURE_INVALID + CKR_SIGNATURE_LEN_RANGE
- Fix RSA verify exception fall-through for unexpected errors
- Replace xfail with fail/raise in ML-DSA and SLH-DSA tests"
```

---

## Task 4: Fix wrong mechanism/vector selection (Phase 4)

**Model:** Opus 4.6
**Blocked by:** Task 1

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py:156,225`
- Modify: `src/pkcs11_check/testcases/acvp/rsa/base_loader.py:182,303`
- Modify: `src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py:81`
- Modify: `src/pkcs11_check/testcases/acvp/aes/test_other.py:278-292,299-309`

- [ ] **Step 1: Fix ML-DSA preHash mechanism check at line 156**

In `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`, change line 156 from:
```python
        mech_name = _get_mech_name(vec["pre_hash"])
```
to:
```python
        pre_hash = vec["pre_hash"]
        if pre_hash == "preHash":
            pre_hash = vec.get("hash_alg", "pure")
        mech_name = _get_mech_name(pre_hash)
```

- [ ] **Step 2: Fix ML-DSA preHash mechanism check at line 225**

In the same file, change line 225 from:
```python
        mech_name = _get_mech_name(vec["pre_hash"])
```
to:
```python
        pre_hash = vec["pre_hash"]
        if pre_hash == "preHash":
            pre_hash = vec.get("hash_alg", "pure")
        mech_name = _get_mech_name(pre_hash)
```

- [ ] **Step 3: Filter out ansx9.31 in RSA siggen PSS loader**

In `src/pkcs11_check/testcases/acvp/rsa/base_loader.py`, change line 182 from:
```python
            if sig_type not in ("pss", "ansx9.31"):
```
to:
```python
            if sig_type != "pss":
```

- [ ] **Step 4: Filter out ansx9.31 in RSA sigver PSS loader**

In the same file, change line 303 from:
```python
            if sig_type not in ("pss", "ansx9.31"):
```
to:
```python
            if sig_type != "pss":
```

- [ ] **Step 5: Fix XPN IV in GCM runner**

In `src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py`, change line 81 from:
```python
    iv = vec["iv"]
```
to:
```python
    iv = vec.get("extended_nonce", vec["iv"])
```

Also find the corresponding line in `run_gcm_decrypt_test()` (same file, similar offset in the decrypt function) and apply the same change.

- [ ] **Step 6: Skip CBC-CS1 and CBC-CS2 tests**

In `src/pkcs11_check/testcases/acvp/aes/test_other.py`, change the CS1 test functions. Replace:
```python
def test_acvp_aes_cbc_cs1_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 encryption from NIST ACVP vectors.

    SoftHSM2: Advertises CKM_AES_CTS but may not be operational - skip expected.
    Kryoptic: Supports CTS modes.
    """
    _run_cbc_cs_encrypt_test(p11_raw_session, vec_id, vec)
```
with:
```python
def test_acvp_aes_cbc_cs1_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 encryption from NIST ACVP vectors."""
    pytest.skip("CBC-CS1 not mappable to CKM_AES_CTS (CS3 only per PKCS#11 spec)")
```

Do the same for `test_acvp_aes_cbc_cs1_decrypt`:
```python
def test_acvp_aes_cbc_cs1_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 decryption from NIST ACVP vectors."""
    pytest.skip("CBC-CS1 not mappable to CKM_AES_CTS (CS3 only per PKCS#11 spec)")
```

Do the same for `test_acvp_aes_cbc_cs2_encrypt`:
```python
def test_acvp_aes_cbc_cs2_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS2 encryption from NIST ACVP vectors."""
    pytest.skip("CBC-CS2 not mappable to CKM_AES_CTS (CS3 only per PKCS#11 spec)")
```

Do the same for `test_acvp_aes_cbc_cs2_decrypt`:
```python
def test_acvp_aes_cbc_cs2_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS2 decryption from NIST ACVP vectors."""
    pytest.skip("CBC-CS2 not mappable to CKM_AES_CTS (CS3 only per PKCS#11 spec)")
```

- [ ] **Step 7: Lint check**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py src/pkcs11_check/testcases/acvp/rsa/base_loader.py src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py src/pkcs11_check/testcases/acvp/aes/test_other.py`
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py src/pkcs11_check/testcases/acvp/rsa/base_loader.py src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py src/pkcs11_check/testcases/acvp/aes/test_other.py
git commit -m "fix(acvp): correct mechanism and vector selection

- ML-DSA: resolve preHash → hash_alg before mechanism availability check
- RSA: filter out ansx9.31 vectors from PSS loaders (different scheme)
- AES-XPN: use extended_nonce instead of iv for GCM runner
- CBC-CS: skip CS1/CS2 (CKM_AES_CTS maps to CS3 only per PKCS#11 spec)"
```

---

## Task 5: Add missing validation (Phase 5)

**Model:** Opus 4.6
**Blocked by:** Task 2

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py:102-103,115,170-180,235-240`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py:234-246`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py:140`

- [ ] **Step 1: Add shared secret validation to ML-KEM encapsulation test**

In `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`, the encapsulation test (class `TestMlKemEncapsulate`) needs the output key to be extractable. First add `read_attributes` to the imports from `pkcs11_check.raw.recipes`:
```python
from pkcs11_check.raw.recipes import (
    decapsulate_key,
    destroy_quietly,
    encapsulate_key,
    gen_keypair,
    import_pqc_private_key,
    import_pqc_public_key,
    read_attributes,
)
```

Also add `CKA_EXTRACTABLE`, `CKA_SENSITIVE`, and `CKA_VALUE` to the types_std imports:
```python
from pkcs11_check.raw.types_std import (
    CKA_DECAPSULATE,
    CKA_DERIVE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKK_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
)
```

Then change the encapsulate call at line 171-172 from:
```python
            secret_handle, ciphertext = encapsulate_key(
                rs.raw, rs.sh, pub_key, mech, attrs={CKA_DERIVE: True}
            )
```
to:
```python
            secret_handle, ciphertext = encapsulate_key(
                rs.raw, rs.sh, pub_key, mech,
                attrs={CKA_DERIVE: True, CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
```

After line 180 (`f"got {len(ciphertext)}"`), add shared secret validation:
```python

            # Validate shared secret matches expected value
            if "k" in vec:
                attrs = read_attributes(rs.raw, rs.sh, secret_handle, [CKA_VALUE])
                secret_value = attrs.get(CKA_VALUE, b"")
                assert secret_value == vec["k"], (
                    f"{vec_id}: shared secret mismatch: "
                    f"expected {vec['k'][:16].hex()}..., got {secret_value[:16].hex()}..."
                )
```

- [ ] **Step 2: Add shared secret validation to ML-KEM decapsulation test**

Change the decapsulate call at lines 231-238 from:
```python
            decap_handle = decapsulate_key(
                rs.raw,
                rs.sh,
                priv_key,
                mech,
                vec["c"],
                attrs={CKA_DERIVE: True},
            )
```
to:
```python
            decap_handle = decapsulate_key(
                rs.raw,
                rs.sh,
                priv_key,
                mech,
                vec["c"],
                attrs={CKA_DERIVE: True, CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
```

After line 240 (`assert decap_handle != 0`), add:
```python

            # Validate recovered shared secret matches expected value
            if "k" in vec:
                attrs = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])
                secret_value = attrs.get(CKA_VALUE, b"")
                assert secret_value == vec["k"], (
                    f"{vec_id}: shared secret mismatch: "
                    f"expected {vec['k'][:16].hex()}..., got {secret_value[:16].hex()}..."
                )
```

- [ ] **Step 3: Replace ad-hoc DER stripping in ECDH test**

In `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`, replace lines 234-246 from:
```python
        peer_public_data = vec["ec_point_der"]
        # Strip the DER OCTET STRING wrapper for the mechanism params
        if peer_public_data[0] == 0x04:
            if peer_public_data[1] < 0x80:
                point_data = peer_public_data[2:]
            elif peer_public_data[1] == 0x81:
                point_data = peer_public_data[3:]
            elif peer_public_data[1] == 0x82:
                point_data = peer_public_data[4:]
            else:
                point_data = peer_public_data
        else:
            point_data = peer_public_data
```
with:
```python
        # Strip DER OCTET STRING wrapper — ECDH1_DERIVE needs raw point
        point_data = decode_ec_point(vec["ec_point_der"])
```

(The `decode_ec_point` import already exists at line 18.)

- [ ] **Step 4: Fix EdDSA dummy signature size**

In `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`, change line 140 from:
```python
                dummy_sig = b"\x00" * 64
```
to:
```python
                sig_len = 64 if "25519" in vec["curve"] else 114
                dummy_sig = b"\x00" * sig_len
```

- [ ] **Step 5: Lint check**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py
git commit -m "fix(acvp): add missing validation and fix encoding

- ML-KEM: validate shared secret from encap/decap against expected value
- ECDH: replace ad-hoc DER stripping with decode_ec_point()
- EdDSA: fix dummy signature size for Ed448 (114 bytes, not 64)"
```

---

## Task 6: Skip vectors needing missing infrastructure (Phase 6)

**Model:** Sonnet 4.6
**Independent — no blockers**

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_hash.py:203-229`
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py` (add TODO comment)

- [ ] **Step 1: Skip SHAKE tests**

In `src/pkcs11_check/testcases/acvp/test_acvp_hash.py`, change the `test_acvp_shake` function (lines 203-229). Add a skip at the top of the function body. Change:
```python
def test_acvp_shake(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SHAKE XOF (extendable-output function) from NIST ACVP vectors.

    SHAKE produces variable-length output based on the requested output length.
    The ACVP vectors specify outLen in bits, which we convert to bytes for
    the PKCS#11 digest operation.
    """
    rs = p11_raw_session
    mech_name: str = vec["mech_name"]
```
to:
```python
def test_acvp_shake(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SHAKE XOF (extendable-output function) from NIST ACVP vectors.

    SHAKE produces variable-length output based on the requested output length.
    The ACVP vectors specify outLen in bits, which we convert to bytes for
    the PKCS#11 digest operation.
    """
    # TODO: SHAKE requires C_DigestXof functions (not yet in pkcs11_check.raw headers)
    pytest.skip("SHAKE requires C_DigestXof (not yet in pkcs11_check.raw)")
    rs = p11_raw_session
    mech_name: str = vec["mech_name"]
```

- [ ] **Step 2: Add ML-DSA context TODO**

In `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`, add a TODO comment before the sign call at line 183. Change:
```python
            # Sign the message
            try:
                sig = sign_single(rs.raw, rs.sh, priv_key, mech, vec["msg"])
```
to:
```python
            # Sign the message
            # TODO: pass vec["context"] via CK_SIGN_ADDITIONAL_CONTEXT when
            # mechanism param builder is available (context is empty for most
            # pure ML-DSA vectors, so this works correctly for now)
            try:
                sig = sign_single(rs.raw, rs.sh, priv_key, mech, vec["msg"])
```

And similarly before the verify call at line 252:
```python
            # Verify the signature
            try:
                verified = verify_single(rs.raw, rs.sh, pub_key, mech, vec["msg"], vec["sig"])
```
to:
```python
            # Verify the signature
            # TODO: pass vec["context"] via CK_SIGN_ADDITIONAL_CONTEXT when available
            try:
                verified = verify_single(rs.raw, rs.sh, pub_key, mech, vec["msg"], vec["sig"])
```

- [ ] **Step 3: Lint check**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/test_acvp_hash.py src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_hash.py src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py
git commit -m "fix(acvp): skip SHAKE tests and document ML-DSA context gap

- SHAKE: skip until C_DigestXof available in pkcs11_check.raw
- ML-DSA: add TODO for CK_SIGN_ADDITIONAL_CONTEXT parameter"
```

---

## Task 7: Verification run

**Model:** Opus 4.6
**Blocked by:** Tasks 1-6

- [ ] **Step 1: Run ruff on all modified files**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/`
Expected: no errors

- [ ] **Step 2: Run mypy on ACVP test code**

Run: `uv run mypy src/pkcs11_check/testcases/acvp/`
Expected: no new errors (existing type issues may remain)

- [ ] **Step 3: Run ACVP tests against Kryoptic**

Run: `bash local-builds/test.sh kryoptic -m acvp -v 2>&1 | tail -30`
Expected: dramatic reduction in failures. Remaining failures should be genuine module bugs only.

---

## Parallelism Guide

```
Task 1 (crash bugs) ──────► Task 2 (ML-KEM attrs) ──► Task 5 (validation)
                    ├─────► Task 3 (error handling) ──► Task 4 (mechanism/vector)
                    │                                    └──► Task 6 (skip/TODO)
Task 7 (verification) ───► (after all others)
```

**IMPORTANT: File conflict avoidance.** `test_acvp_mldsa.py` is modified by Tasks 3, 4, and 6. `test_acvp_mlkem.py` is modified by Tasks 2, 3, and 5. These tasks MUST run sequentially for those files: Task 3 first, then Task 4, then Task 6. Task 2 before Task 5.

**Model assignments:**
- Sonnet 4.6: Tasks 1, 2, 3, 6
- Opus 4.6: Tasks 4, 5, 7
