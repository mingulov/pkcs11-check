# Test Quality Audit Report

**Date:** 2026-03-27
**Scope:** pkcs11_check.raw (library) + pkcs11_check/testcases/ (test suite)
**Status:** Complete — findings documented, fixes pending

---

## Executive Summary

The pkcs11_check codebase has strong foundational design: CKR-as-data, expect_rv()
enforcement, typed constants, comprehensive mechanism coverage. However, the audit
found **3 critical correctness issues** in the raw library, **6 critical security
test classification errors**, and a **pervasive anti-pattern** (95+ `except
(AssertionError, Exception): xfail`) that silently converts real test failures into
expected failures.

---

## Part 1: pkcs11_check.raw Library Audit

### CRITICAL Issues

**C-1. `api.py:155` — Silent swallow of interface negotiation errors**

The `C_GetInterface` probe catches `(AttributeError, OSError, TypeError, ValueError)`.
`TypeError` and `ValueError` are programming errors in the negotiation code and should
propagate. Only `AttributeError` (missing symbol) and `OSError` (linker failure) are
legitimate fallthrough cases.

**C-2. `recipes.py:447` — `C_DigestKey` CKR_FUNCTION_NOT_SUPPORTED continues to C_DigestFinal**

When `C_DigestKey` returns `CKR_FUNCTION_NOT_SUPPORTED`, the spec says the operation
is terminated. Yet the code proceeds to `C_DigestFinal`, which will fail with
`CKR_OPERATION_NOT_INITIALIZED`, masking the real error.

**C-3. `recipes.py:472` — `read_attributes` rejects spec-mandated partial success codes**

`C_GetAttributeValue` may return `CKR_ATTRIBUTE_SENSITIVE` or `CKR_ATTRIBUTE_TYPE_INVALID`
as partial success. The current code accepts only `CKR_OK`, which means any template
containing a sensitive attribute causes `AssertionError`.

### IMPORTANT Issues

| ID | File:Line | Issue |
|----|-----------|-------|
| I-3 | recipes.py:692-714 | `_multipart_output` calls update function twice per chunk (double-apply) |
| I-4 | recipes.py:1148 | `wrap_key_authenticated` CKR check pattern misleading |
| I-7 | api.py:11 | Star import `from .types_std import *` pollutes namespace |

### SUGGESTIONS

| ID | File:Line | Issue |
|----|-----------|-------|
| S-1 | bootstrap.py | `user_type` should be typed as `CKU`, not `int` |
| S-3 | faults.py | 3 unused exported functions (retained for future tests) |
| S-5 | extensions.py:46 | `_EXTENSIONS` mutable dict has no thread safety |
| S-6 | recipes.py:100 | `quick_session` uses magic literal `1` for CKU_USER |

---

## Part 2: testcases/ Test Suite Audit

### CRITICAL: Security Findings Classified as xfail (6 locations)

**These tests correctly detect security vulnerabilities but mark them as `pytest.xfail()`
instead of `pytest.fail()`. A module with a genuine vulnerability produces a green
"expected failure" in the report instead of a red failure.**

| File | Line | Security Issue | Current | Should Be |
|------|------|---------------|---------|-----------|
| test_padding_oracle.py | 83 | RSA PKCS#1 v1.5 padding oracle | xfail | **fail** |
| test_padding_oracle.py | 123 | RSA-OAEP oracle | xfail | **fail** |
| test_padding_oracle.py | 190 | AES-CBC Vaudenay oracle | xfail | **fail** |
| test_padding_oracle.py | 252 | RSA decrypt timing side-channel | xfail | **fail** |
| test_api_security.py | 96,161,179,208,232 | Wrap-decrypt oracle, extractable escalation, sensitive downgrade | xfail | **fail** |
| test_nonce_quality.py | 177,186 | ECDSA nonce bias (lattice attack) | xfail | **fail** |

### IMPORTANT: xfail Used for Missing Capabilities (~35 locations)

Should be `pytest.skip()`, not `pytest.xfail()`:

- **test_pbe.py** (17 locations): `_pbe_derive` returns None on any error → xfail
- **test_otp.py** (12 locations): Mechanisms unconditionally xfailed after has_mechanism check
- **test_kdf.py:174**: Broad except → xfail on HKDF failure

### CRITICAL: `except (AssertionError, Exception): xfail` Anti-Pattern (~95 locations)

This pattern catches ALL errors including Python coding bugs and wrong-output
assertions, converting them to expected failures. Found in 18+ files:

| File | Count | Mechanisms Affected |
|------|-------|-------------------|
| test_sp800_108_kdf.py | 11 | SP800-108 counter/feedback/pipeline KDF |
| test_ike.py | 16 | IKE PRF/PRF+/2PRF |
| test_ssl3.py | 13 | SSL3 master key derive, key material |
| test_tls12.py | 14 | TLS1.2 master key, key material, PRF |
| test_misc_kdf.py | 12 | Concatenate, XOR, extract key KDFs |
| test_hkdf_extended.py | 4 | HKDF derive/data variants |
| test_pbe.py | 17 | PBE mechanisms |
| Others | ~8 | Various |

**Reference pattern (VALID):** `test_tls12.py` uses `_is_known_error(exc, _TLS_ERROR_RVS)`
to check if the exception matches specific CKR codes, and re-raises if not. This is
the correct approach.

### IMPORTANT: Tautological Assertions (zero verification value)

| File:Line | Code | Issue |
|-----------|------|-------|
| test_resource.py:113 | `assert rv != CKR_OK or rv == CKR_OK` | Always True |
| test_remaining_gaps.py:427,436,446 | `assert rv != 0 or True` | Always True |
| test_session_edge_cases.py:125 | `assert rv == CKR_OK or rv != 0` | Always True |

### IMPORTANT: `assert rv != CKR_OK` Without Specific CKR Check

| File | Count | Issue |
|------|-------|-------|
| test_key_usage_policy.py | 5 | Should check `CKR_KEY_FUNCTION_NOT_PERMITTED` specifically |
| test_so_pin.py | 2 | Should check `CKR_PIN_INCORRECT` |
| test_pin.py | 2 | Tautological `or` branch |

### IMPORTANT: Test Isolation (Missing Finally Blocks)

- **test_token_objects.py:88-91** — Token object creation without `finally:` cleanup.
  If `gen_aes_key` raises, `CKA_TOKEN=True` object persists across tests.
- **test_token_objects.py:117-132** — Session 1 failure leaves token key behind.

### IMPORTANT: Skip on Module Bug (Should Be fail/xfail)

- **test_ecdh_known_answer.py:114** — `except AssertionError: pytest.skip("ECDH derivation failed")` — mechanism advertised but fails, this is a module bug
- **test_seed.py:79,97** — `"Mechanism advertised but rejected at use"` — skip hides a real bug
- **test_des.py:91** — Same pattern

### IMPORTANT: `except Exception: pass` Makes Test a No-Op

- **test_token_flags.py:91-92** — Entire test body wrapped in `except Exception: pass`. RNG test never actually validates anything.

---

## Recommended Fix Priorities

### Priority 1: Security test classification (CRITICAL)

Convert `pytest.xfail("SECURITY: ...")` to `pytest.fail("SECURITY: ...")` in:
- test_padding_oracle.py (4 locations)
- test_api_security.py (5 locations)
- test_nonce_quality.py (2 locations)

### Priority 2: Raw library correctness (CRITICAL)

- C-1: Narrow api.py exception catch to `(AttributeError, OSError)`
- C-2: Handle `CKR_FUNCTION_NOT_SUPPORTED` from `C_DigestKey` properly
- C-3: Accept `CKR_ATTRIBUTE_SENSITIVE`/`CKR_ATTRIBUTE_TYPE_INVALID` in `read_attributes`
- I-3: Fix `_multipart_output` double-apply bug

### Priority 3: Replace `except (AssertionError, Exception): xfail` pattern (~95 sites)

Create a shared helper (similar to `test_tls12.py`'s `_is_known_error`):
```python
def _xfail_if_known_ckr(exc: Exception, known_ckrs: set[int], msg: str) -> None:
    """xfail if exc is from a known CKR code, otherwise re-raise."""
    for ckr in known_ckrs:
        if ckr_name(ckr) in str(exc):
            pytest.xfail(msg)
    raise  # Not a known CKR — let it fail as a real error
```

### Priority 4: Fix tautological assertions and missing CKR specificity

- Replace `assert rv != CKR_OK or ...` tautologies with real checks
- Add specific CKR codes to key-policy and PIN tests

### Priority 5: Fix xfail→skip conversions and test isolation

- Convert ~35 missing-capability xfails to skips
- Add `finally:` blocks for token object cleanup
- Fix test_token_flags.py to actually validate
