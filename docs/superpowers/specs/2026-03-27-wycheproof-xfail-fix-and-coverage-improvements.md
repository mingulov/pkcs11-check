# Wycheproof xfail→fail Fix & Coverage Tracking Improvements

**Date:** 2026-03-27
**Status:** Design approved, pending implementation

## Problem Statement

### Problem 1: Wycheproof tests hide module bugs behind pytest.xfail()

All Wycheproof test files use `pytest.xfail()` when a valid test vector fails. This means:
- Module bugs that reject valid cryptographic operations are hidden as "expected failures"
- Wrong cryptographic output (the most dangerous bug class) is caught by the same `except AssertionError` as CKR rejections and silently xfailed

pkcs11-check exists to FIND bugs. Hiding them as xfails defeats its purpose.

**Scope:** 31 xfail call sites across 16 Wycheproof test files. 11,418 xfails on kryoptic-main that should be real failures.

**Two distinct sub-bugs:**

1. **CKR rejections on valid vectors:** Module advertises mechanism, `has_mechanism()` passes, but the PKCS#11 operation returns error CKR. The test calls `pytest.xfail()` instead of letting it fail. This should be `pytest.fail()` or simply `raise`.

2. **Wrong-output caught by same except:** `assert actual == expected` raises `AssertionError`, same type as `expect_rv()`. The blanket `except AssertionError` catches both. A module that produces wrong AES ciphertext, wrong ECDH shared secret, or wrong HMAC gets xfailed.

### Problem 2: Subprocess test calls invisible to coverage

35 PKCS#11 functions are called in subprocess-based tests (`subprocess.run([sys.executable, "-c", script])`) where the subprocess creates its own `RawPKCS11` instance. The `_call_log` dies with the subprocess. Coverage reports these as "uncalled".

## Component 1: Replace xfail with fail in Wycheproof Tests

### Pattern to fix

**Current (broken):**
```python
try:
    ct = encrypt_single(rs.raw, rs.sh, key, mechanism, plaintext, ...)
    assert ct == expected_ct  # Wrong output → AssertionError
except AssertionError:
    if result == "valid":
        pytest.xfail(f"Operation failed for valid vector {vec_id}")  # HIDES THE BUG
    return  # acceptable for invalid vectors
```

**Fixed:**
```python
try:
    ct = encrypt_single(rs.raw, rs.sh, key, mechanism, plaintext, ...)
except AssertionError as exc:
    if result == "valid":
        pytest.fail(f"Valid vector {vec_id} rejected: {exc}")
    return  # acceptable: module rejected invalid vector
# If we get here, operation succeeded — check output
assert ct == expected_ct, f"Wrong output for {vec_id}"
```

Key changes:
1. **Separate CKR rejection (except) from output validation (assert after try).** The `assert actual == expected` moves OUTSIDE the try/except block so it cannot be caught.
2. **`pytest.fail()` instead of `pytest.xfail()`** for valid vectors that get rejected. This is a real finding.
3. **Keep `return` for invalid vectors** where rejection is acceptable.

### Files to modify

Every Wycheproof test file with the xfail pattern. Complete list from investigation:

| File | xfail sites | Notes |
|------|------------|-------|
| `test_wycheproof_ecdh.py` | 1 (line 190) | Already has partial mismatch guard |
| `test_wycheproof_x25519.py` | 1 (line 149) | Also catches TypeError |
| `test_wycheproof_pbes2.py` | 2 (lines 148, 163) | Unconditional xfail — no result check |
| `test_wycheproof_pbkdf2.py` | 1 (line 155) | |
| `test_wycheproof_aes.py` | 7 (lines 104, 177, 251, 257, 328, 387, 448) | CMAC, KW, KWP(2), CCM, GMAC, XTS |
| `test_wycheproof_hkdf.py` | 1 (line 153) | |
| `test_wycheproof_ecdsa.py` | ~2 | Check actual count |
| `test_wycheproof_dsa.py` | ~1 | Check actual count |
| `test_wycheproof_chacha.py` | ~1 | Check actual count |
| `test_wycheproof_mldsa.py` | ~1 | Check actual count |
| `test_wycheproof_mldsa_sign.py` | ~1 | Check actual count |
| `test_wycheproof_mlkem.py` | ~1 | Check actual count |

Each site needs individual attention — the exact code structure varies per file.

### Gap Analysis Findings

**Complete file list (31 sites across 16 files):**

| File | xfail sites | Exception types | Notes |
|------|------------|-----------------|-------|
| `test_wycheproof.py` | 5 | `AssertionError` | Main file — has `"acceptable"` handling |
| `test_wycheproof_aes.py` | 7 | `AssertionError` | CMAC, KW, KWP(2), CCM, GMAC, XTS |
| `test_wycheproof_ecdh.py` | 1 | `AssertionError` | Has partial mismatch guard |
| `test_wycheproof_ecdsa.py` | 1 | `AssertionError` | Line 205 uses bare `except Exception` |
| `test_wycheproof_x25519.py` | 1 | `(AssertionError, TypeError)` | |
| `test_wycheproof_pbes2.py` | 2 | `AssertionError` | Unconditional — no result check |
| `test_wycheproof_pbkdf2.py` | 1 | `AssertionError` | |
| `test_wycheproof_hkdf.py` | 1 | `AssertionError` | |
| `test_wycheproof_chacha.py` | 1 | `AssertionError` | |
| `test_wycheproof_hmac.py` | 2 | `AssertionError` | Import-phase xfails |
| `test_wycheproof_rsa.py` | 1 | `AssertionError` | |
| `test_wycheproof_rsa_oaep.py` | 1 | `AssertionError` | |
| `test_wycheproof_rsa_decrypt.py` | 1 | `AssertionError` | |
| `test_wycheproof_rsa_pss.py` | 1 | `AssertionError` | |
| `test_wycheproof_mldsa.py` | 1 | `AssertionError` | |
| `test_wycheproof_mldsa_sign.py` | 1 | `AssertionError` | Import-phase xfail |
| `test_wycheproof_mlkem.py` | 2 | `(AssertionError, Exception)` | Bare Exception! |
| `test_wycheproof_ed25519.py` | 1 | `AssertionError` | |

**Additional patterns to handle:**

1. **"acceptable" result type:** `test_wycheproof.py` treats `result == "acceptable"` same as `"valid"`. Fix must handle all three result types: valid→fail, acceptable→fail, invalid→return.

2. **Bare `except Exception` catches** in `test_wycheproof_mlkem.py` and `test_wycheproof_ecdsa.py:205`. These hide ANY Python error. Must be narrowed to `AssertionError` only.

3. **Import-phase xfails** (3 sites in `test_wycheproof_hmac.py` and `test_wycheproof_mldsa_sign.py`). Key import failure on valid vectors is also a finding — should become `pytest.fail()`.

4. **Unconditional xfails** in `test_wycheproof_pbes2.py` (no `if result == "valid"` check). Both sites xfail regardless of vector validity.

### Impact

After this fix, the 11,418 xfails on kryoptic-main become real failures, properly exposing module bugs. Other modules will also see their Wycheproof xfails become failures. This is the correct behavior — pkcs11-check should report what it finds.

### Exception: known CKR-specific module bugs

For genuinely known, documented, module-specific CKR bugs (e.g., "Kryoptic returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID"), use `xfail_if_known_ckr()` from `testcases/conftest.py` — but this must be targeted to specific CKR codes and specific documented bugs, not a blanket catch-all.

## Component 2: Subprocess Call Tracking

### Problem

Tests in `testcases/ckr/` that use `subprocess.run([sys.executable, "-c", script])` create their own `RawPKCS11` in the subprocess. The subprocess's `_call_log` and `_used_mechanisms` die with the process. 35 functions appear "uncalled" despite having tests that exercise them.

### Solution

Extend the subprocess test preamble to dump coverage data to a temp file on cleanup, and have the parent test merge it.

**In `testcases/ckr/_subprocess_preamble.py`** (the shared preamble for subprocess tests):

The `cleanup()` function currently does:
```python
def cleanup():
    close_session_quietly(raw, sh)
    raw.C_Finalize(None)
```

Change to also dump call_log:
```python
def cleanup():
    import json, os
    coverage_path = os.environ.get("_P11CHECK_SUBPROCESS_COVERAGE")
    if coverage_path:
        json.dump({
            "call_log": raw.call_log,
            "mechanism_counts": {str(k): v for k, v in raw.mechanism_counts.items()},
        }, open(coverage_path, "w"))
    close_session_quietly(raw, sh)
    raw.C_Finalize(None)
```

**In the parent test's `_run()` helper** (e.g., `ckr/test_ckr_raw_args_bad.py`):

Before launching subprocess, create a temp file path and pass via env. After subprocess completes, read the coverage file and merge into the session's `RawPKCS11`:

```python
import tempfile
coverage_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
coverage_path = coverage_file.name
coverage_file.close()

env = {**os.environ, "_P11CHECK_SUBPROCESS_COVERAGE": coverage_path}
result = subprocess.run([sys.executable, "-c", script], env=env, ...)

# Merge subprocess coverage into parent
try:
    data = json.load(open(coverage_path))
    # Store for plugin to pick up
except (FileNotFoundError, json.JSONDecodeError):
    pass
finally:
    os.unlink(coverage_path)
```

**In `plugin.py` teardown:** Check for subprocess coverage data attached to the test item and merge it into cumulative counters.

### Scope

Two subprocess frameworks exist:

**Framework 1: `_subprocess_preamble.py`** (generates setup code string)
Consumers: `ckr/test_ckr_raw_args_bad.py`, `ckr/test_ckr_raw_attrs.py`, `ckr/test_ckr_raw_buffer.py`, `test_remaining_gaps.py`, `test_cve_regression.py`

**Framework 2: `_raw_subprocess.py`** (`run_raw_script()` function)
Consumers: `test_operation_state.py`, `test_sign_recover.py`, `test_dual_function.py`, `test_protocol_edge_cases.py`

**Additional subprocess users** (build own scripts, ~10 CKR files):
`ckr/test_ckr_universal.py`, `ckr/test_ckr_destructive.py`, `ckr/test_ckr_dual.py`,
`ckr/test_ckr_general.py`, `ckr/test_ckr_null_params.py`, `ckr/test_ckr_raw_multipart.py`,
`ckr/test_ckr_raw_state.py`, `ckr/test_ckr_v30_raw.py`, `ckr/test_ckr_v32_raw.py`

Total: ~20 test files using subprocess.

**Segfault handling:** CKR tests intentionally trigger segfaults. When subprocess crashes, `cleanup()` never runs. The coverage file won't be written — handle gracefully with `try/except FileNotFoundError`.

### Expected improvement

Function coverage: ~62/104 → ~97/104 (the remaining 7 are behind `--p11-destructive` flag or genuinely untested).

## Component 3: Mechanism Detail Tracking Enhancements

### Problem

Several mechanism packers don't populate `sub_mechanisms`, so their parameter details are invisible in `invoked_detail`. Adding detail to high-value mechanisms improves coverage visibility.

### Changes

Add `sub_mechanisms` to these packers in `pack_mechanisms.py`:

| Packer | New sub_mechanisms | Example detail string |
|--------|-------------------|----------------------|
| `mech_gcm` | `{"tagBits": tag_bits}` | `CKM_AES_GCM[tagBits=128]` |
| `mech_ccm` | `{"tagLen": tag_len, "nonceLen": nonce_len}` | `CKM_AES_CCM[nonceLen=12,tagLen=16]` |
| `mech_eddsa` | `{"phFlag": ph_flag}` | `CKM_EDDSA[phFlag=0]` |
| `mech_ctr` | `{"bits": bits}` | `CKM_AES_CTR[bits=128]` |

**Not adding sub_mechanisms to `mech_simple`**: ML-KEM, ML-DSA, AES-ECB, SHA-*, HMAC, keygen mechanisms genuinely have no parameters. They already appear in `invoked_names`/`invoked_counts`. Adding them to `invoked_detail` would just duplicate without additional granularity.

**ML-KEM "encapsulated AES" detail**: The encapsulated key type comes from template attributes (`CKA_KEY_TYPE=CKK_AES`), not mechanism parameters. This needs template-based tracking — noted as future enhancement, out of scope for this spec.

## Testing

1. **Wycheproof fix verification:** Run kryoptic-main Docker — the 11,418 xfails should become failures
2. **SoftHSM2 regression:** Run SoftHSM2 — existing pass/fail/skip counts should not change (SoftHSM2 has no Wycheproof xfails on non-ChaCha/HKDF mechanisms)
3. **Subprocess coverage:** After fix, run with coverage and verify previously-uncalled functions appear in called_names
4. **Detail tracking:** Verify `CKM_AES_GCM[tagBits=128]` appears in invoked_detail after fix
5. **Meta-tests:** `uv run python -m pytest tests/ -x -q` must pass

## Out of Scope

- Mechanism-driven parametrized tests (separate spec)
- ML-KEM template-based invoked_detail (needs template attribute inspection)
- Non-Wycheproof xfails (NSS-PQC Phase 2-8 xfails are targeted and correct)
