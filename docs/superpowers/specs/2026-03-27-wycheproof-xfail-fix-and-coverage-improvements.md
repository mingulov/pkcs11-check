# Wycheproof xfail→fail Fix & Coverage Tracking Improvements

**Date:** 2026-03-27
**Status:** Design approved, pending implementation

## Problem Statement

### Problem 1: Wycheproof tests hide module bugs behind pytest.xfail()

All Wycheproof test files use `pytest.xfail()` when a valid test vector fails. This means:
- Module bugs that reject valid cryptographic operations are hidden as "expected failures"
- Wrong cryptographic output (the most dangerous bug class) is caught by the same `except AssertionError` as CKR rejections and silently xfailed

pkcs11-check exists to FIND bugs. Hiding them as xfails defeats its purpose.

**Scope:** 26+ xfail call sites across 15+ Wycheproof test files. 11,418 xfails on kryoptic-main that should be real failures.

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

This affects the shared preamble and the `_run()` helpers in:
- `ckr/_subprocess_preamble.py`
- `ckr/test_ckr_raw_args_bad.py`
- `ckr/test_ckr_raw_attrs.py`
- `ckr/test_ckr_raw_buffer.py`
- `ckr/test_ckr_universal.py`
- Any other test using `subprocess_session_preamble()`

### Expected improvement

Function coverage: ~62/104 → ~97/104 (the remaining 7 are behind `--p11-destructive` flag or genuinely untested).

## Testing

1. **Wycheproof fix verification:** Run kryoptic-main Docker — the 11,418 xfails should become failures
2. **SoftHSM2 regression:** Run SoftHSM2 — existing pass/fail/skip counts should not change (SoftHSM2 has no Wycheproof xfails)
3. **Subprocess coverage:** After fix, run with coverage and verify C_EncryptInit, C_DecryptInit etc. appear in called_names from CKR tests
4. **Meta-tests:** `uv run python -m pytest tests/ -x -q` must pass

## Out of Scope

- Mechanism-driven parametrized tests (separate spec)
- ML-KEM invoked_detail tracking (separate spec — needs template-based tracking)
