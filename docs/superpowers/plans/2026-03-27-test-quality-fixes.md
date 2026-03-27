# Test Quality Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all findings from the test quality audit: security test classification, raw library correctness, broad-except anti-pattern, tautological assertions, and test isolation issues.

**Architecture:** 7 tasks in priority order. Each task is independently committable and testable. Task 3 creates a shared helper used by Task 4.

**Tech Stack:** Python 3.11+, pytest, ruff

**Audit report:** `docs/reports/2026-03-27-test-quality-audit.md`

---

### Task 1: Security xfail→fail (Priority 1 — CRITICAL)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_padding_oracle.py`
- Modify: `src/pkcs11_check/testcases/test_api_security.py`
- Modify: `src/pkcs11_check/testcases/test_nonce_quality.py`

- [ ] **Step 1: Fix test_padding_oracle.py**

Find all `pytest.xfail("SECURITY:` calls (4 locations, around lines 83, 123, 190, 252)
and change each to `pytest.fail("SECURITY:` — same message, just `fail` instead of `xfail`.

These detect real security vulnerabilities (padding oracles, timing channels) that
should be red failures in the report, not green expected-failures.

- [ ] **Step 2: Fix test_api_security.py**

Find all `pytest.xfail("SECURITY:` calls (5 locations, around lines 96, 161, 179, 208, 232)
and change each to `pytest.fail("SECURITY:` — wrap-decrypt oracle, extractable escalation,
sensitive downgrade are real security violations.

- [ ] **Step 3: Fix test_nonce_quality.py**

Find all `pytest.xfail("SECURITY:` calls (2 locations, around lines 177, 186)
and change each to `pytest.fail("SECURITY:` — nonce bias enables lattice attacks.

- [ ] **Step 4: Lint, format, commit**

```bash
uv run ruff format src/pkcs11_check/testcases/test_padding_oracle.py \
  src/pkcs11_check/testcases/test_api_security.py \
  src/pkcs11_check/testcases/test_nonce_quality.py
git add src/pkcs11_check/testcases/test_padding_oracle.py \
  src/pkcs11_check/testcases/test_api_security.py \
  src/pkcs11_check/testcases/test_nonce_quality.py
git commit -m "fix: convert security xfail to fail -- vulnerabilities must be red

Padding oracles, timing channels, extractable escalation, and nonce
bias are real security findings that should fail tests, not produce
green expected-failure results."
```

---

### Task 2: Raw library correctness (Priority 2 — CRITICAL)

**Files:**
- Modify: `src/pkcs11_check/raw/api.py`
- Modify: `src/pkcs11_check/raw/recipes.py`

- [ ] **Step 1: Narrow api.py exception catch (C-1)**

In `src/pkcs11_check/raw/api.py`, find the `C_GetInterface` probe block
(around line 137-156). Change:
```python
except (AttributeError, OSError, TypeError, ValueError):
    pass
```
To:
```python
except (AttributeError, OSError):
    pass  # Module does not export C_GetInterface or library load failed
```

`TypeError` and `ValueError` are programming errors that should propagate.

- [ ] **Step 2: Fix C_DigestKey CKR_FUNCTION_NOT_SUPPORTED handling (C-2)**

In `src/pkcs11_check/raw/recipes.py`, find the `digest_single_with_key` function.
The current code accepts `CKR_FUNCTION_NOT_SUPPORTED` from `C_DigestKey` and then
proceeds to call `C_DigestFinal` on a terminated operation.

Change it to raise immediately when `C_DigestKey` returns `CKR_FUNCTION_NOT_SUPPORTED`:
```python
rv = raw.C_DigestKey(session, key)
if rv == CKR_FUNCTION_NOT_SUPPORTED:
    # C_DigestKey not supported terminates the operation per spec
    raise NotImplementedError("C_DigestKey not supported by this module")
expect_rv(rv, CKR_OK)
```

Add `CKR_FUNCTION_NOT_SUPPORTED` to the imports from types_std if not already present.

- [ ] **Step 3: Fix read_attributes partial success codes (C-3)**

In `src/pkcs11_check/raw/recipes.py`, find the `read_attributes` function.
On both the size-query call and the value-read call, change:
```python
expect_rv(rv, CKR_OK)
```
To:
```python
expect_rv(rv, CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID)
```

After the value-read call, add filtering to skip attributes whose `ulValueLen` was
set to the "unavailable" sentinel (`0xFFFFFFFF` on 32-bit, `~0` on 64-bit):
```python
CK_UNAVAILABLE = 0xFFFFFFFFFFFFFFFF if ctypes.sizeof(ctypes.c_ulong) == 8 else 0xFFFFFFFF
```

Then in the value-decoding loop, add:
```python
if tmpl[i].ulValueLen == CK_UNAVAILABLE:
    continue  # Attribute sensitive or invalid — skip
```

Add `CKR_ATTRIBUTE_SENSITIVE` and `CKR_ATTRIBUTE_TYPE_INVALID` to the types_std imports.

- [ ] **Step 4: Fix _multipart_output double-apply (I-3)**

In `src/pkcs11_check/raw/recipes.py`, find the `_multipart_output` helper function
(or equivalent multipart encrypt/decrypt functions). The issue is that calling the
update function with `None` output buffer to get the size, then calling again with
a buffer, feeds the same chunk data twice.

Fix: allocate a conservatively-sized buffer upfront for update calls. For
`C_EncryptUpdate`/`C_DecryptUpdate`, use `len(chunk) + 256` as the buffer size.
Do NOT use the two-call pattern for Update functions — it only works for Final calls.

Read the current implementation carefully before making changes. The multipart
functions may be `encrypt_multipart`, `decrypt_multipart`, `sign_multipart`, etc.

- [ ] **Step 5: Lint, format, test, commit**

```bash
uv run ruff check src/pkcs11_check/raw/api.py src/pkcs11_check/raw/recipes.py --fix
uv run ruff format src/pkcs11_check/raw/api.py src/pkcs11_check/raw/recipes.py
uv run python -m pytest tests/ -x -q -k "not sdist"
git add src/pkcs11_check/raw/api.py src/pkcs11_check/raw/recipes.py
git commit -m "fix: raw library correctness -- negotiation, DigestKey, read_attributes, multipart

C-1: Narrow interface negotiation catch to (AttributeError, OSError)
C-2: Raise NotImplementedError when C_DigestKey returns NOT_SUPPORTED
C-3: Accept CKR_ATTRIBUTE_SENSITIVE/TYPE_INVALID in read_attributes
I-3: Fix multipart update double-apply (don't two-call for Update)"
```

---

### Task 3: Create shared _xfail_if_known_ckr helper (Priority 3 foundation)

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py`

- [ ] **Step 1: Add helper to conftest.py**

In `src/pkcs11_check/testcases/conftest.py`, add:

```python
def xfail_if_known_ckr(
    exc: Exception,
    known_ckrs: set[int] | tuple[int, ...],
    msg: str,
) -> None:
    """xfail if the exception message contains a known CKR name, otherwise re-raise.

    Use this instead of ``except (AssertionError, Exception): pytest.xfail(...)``
    to ensure that only specific CKR failures become expected failures, while
    Python coding bugs and wrong-output assertions propagate as real failures.
    """
    from pkcs11_check.raw.rv import ckr_name

    exc_str = str(exc)
    for ckr in known_ckrs:
        if ckr_name(ckr) in exc_str:
            pytest.xfail(f"{msg}: {ckr_name(ckr)}")
    raise  # Not a known CKR — propagate as real failure
```

- [ ] **Step 2: Lint, format, test, commit**

```bash
uv run ruff format src/pkcs11_check/testcases/conftest.py
uv run python -m pytest tests/ -x -q -k "not sdist"
git add src/pkcs11_check/testcases/conftest.py
git commit -m "feat: add xfail_if_known_ckr helper for targeted xfail

Replaces broad 'except (AssertionError, Exception): xfail' with
specific CKR-aware conditional xfail that re-raises non-CKR errors."
```

---

### Task 4: Replace broad except+xfail anti-pattern (Priority 3 — ~95 sites)

**Files (18+ test files):**
- Modify: `src/pkcs11_check/testcases/test_sp800_108_kdf.py` (11 sites)
- Modify: `src/pkcs11_check/testcases/test_ike.py` (16 sites)
- Modify: `src/pkcs11_check/testcases/test_ssl3.py` (13 sites)
- Modify: `src/pkcs11_check/testcases/test_misc_kdf.py` (12 sites)
- Modify: `src/pkcs11_check/testcases/test_hkdf_extended.py` (4 sites)
- Modify: `src/pkcs11_check/testcases/test_trust_objects.py` (2 sites)
- Modify: `src/pkcs11_check/testcases/test_domain_params.py`
- Modify: `src/pkcs11_check/testcases/test_profiles.py`
- Modify: Other files with the same pattern

- [ ] **Step 1: Define common CKR error sets**

Each test file needs a set of CKR codes that are acceptable "not operational" errors
for the mechanism being tested. Common sets:

For KDF/derive tests: `{CKR_MECHANISM_INVALID, CKR_FUNCTION_NOT_SUPPORTED, CKR_TEMPLATE_INCONSISTENT, CKR_KEY_SIZE_RANGE, CKR_MECHANISM_PARAM_INVALID, CKR_DEVICE_ERROR}`

For TLS/SSL tests: already defined as `_TLS_ERROR_RVS` in test_tls12.py

For each file, read the existing xfail messages to understand which CKR codes are
expected, then define a `_KNOWN_CKRS` set at the top of each file.

- [ ] **Step 2: Replace the pattern in each file**

For each `except (AssertionError, Exception) as exc: pytest.xfail(msg)` occurrence:

Change from:
```python
except (AssertionError, Exception) as exc:
    pytest.xfail(f"CKM_SOMETHING not operational: {exc}")
```

To:
```python
except (AssertionError, Exception) as exc:
    xfail_if_known_ckr(exc, _KNOWN_CKRS, "CKM_SOMETHING not operational")
```

Add `from pkcs11_check.testcases.conftest import xfail_if_known_ckr` to each file.

Process files in batches, running ruff after each batch.

- [ ] **Step 3: Lint, format, test, commit**

```bash
uv run ruff check src/pkcs11_check/testcases/ --fix
uv run ruff format src/pkcs11_check/testcases/
uv run python -m pytest tests/ -x -q -k "not sdist"
git add src/pkcs11_check/testcases/
git commit -m "refactor: replace broad except+xfail with xfail_if_known_ckr

~95 sites converted from 'except (AssertionError, Exception): xfail'
to 'xfail_if_known_ckr(exc, _KNOWN_CKRS, msg)'. Python coding bugs
and wrong-output assertions now propagate as real failures instead
of being silently promoted to expected failures."
```

---

### Task 5: Fix tautological assertions and CKR specificity (Priority 4)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_resource.py`
- Modify: `src/pkcs11_check/testcases/test_remaining_gaps.py`
- Modify: `src/pkcs11_check/testcases/test_session_edge_cases.py`
- Modify: `src/pkcs11_check/testcases/test_key_usage_policy.py`
- Modify: `src/pkcs11_check/testcases/test_so_pin.py`
- Modify: `src/pkcs11_check/testcases/test_pin.py`

- [ ] **Step 1: Fix tautological assertions**

In `test_resource.py:113`, change:
```python
assert rv != CKR_OK or rv == CKR_OK  # any result, just no crash
```
To a comment explaining this is a crash-only check (no assertion needed), or remove it.

In `test_remaining_gaps.py:427,436,446`, change `assert rv != 0 or True` to either
remove the assertion (if crash-only is the intent) or add the actual expected CKR codes.

In `test_session_edge_cases.py:125`, change `assert rv == CKR_OK or rv != 0` similarly.

- [ ] **Step 2: Add specific CKR codes to key-policy tests**

In `test_key_usage_policy.py`, find the 5 locations with:
```python
assert rv != CKR_OK, "Key with DECRYPT=False should not allow decrypt"
```
Change to check the spec-correct CKR code:
```python
assert rv in (CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD), \
    f"Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got {ckr_name(rv)}"
```
(Include `CKR_FUNCTION_NOT_SUPPORTED` and `CKR_ARGUMENTS_BAD` as some modules return these.)

- [ ] **Step 3: Fix PIN test assertions**

In `test_so_pin.py`, change `assert rv != CKR_OK` to check for specific CKR codes
(`CKR_PIN_INCORRECT`, `CKR_PIN_LOCKED`, `CKR_ARGUMENTS_BAD`).

In `test_pin.py`, fix the tautological `or` branches.

- [ ] **Step 4: Lint, format, test, commit**

```bash
uv run ruff format src/pkcs11_check/testcases/test_resource.py \
  src/pkcs11_check/testcases/test_remaining_gaps.py \
  src/pkcs11_check/testcases/test_session_edge_cases.py \
  src/pkcs11_check/testcases/test_key_usage_policy.py \
  src/pkcs11_check/testcases/test_so_pin.py \
  src/pkcs11_check/testcases/test_pin.py
uv run python -m pytest tests/ -x -q -k "not sdist"
git add src/pkcs11_check/testcases/
git commit -m "fix: replace tautological assertions with specific CKR checks

Remove always-true assertions. Add spec-correct CKR codes for
key-function-not-permitted and PIN tests."
```

---

### Task 6: xfail→skip conversions, test isolation, no-op tests (Priority 5)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_pbe.py`
- Modify: `src/pkcs11_check/testcases/test_otp.py`
- Modify: `src/pkcs11_check/testcases/test_kdf.py`
- Modify: `src/pkcs11_check/testcases/test_ecdh_known_answer.py`
- Modify: `src/pkcs11_check/testcases/test_seed.py`
- Modify: `src/pkcs11_check/testcases/test_des.py`
- Modify: `src/pkcs11_check/testcases/test_token_objects.py`
- Modify: `src/pkcs11_check/testcases/test_token_flags.py`

- [ ] **Step 1: Convert missing-capability xfails to skips**

In `test_pbe.py` (17 locations): where `_pbe_derive` returns None and the test
calls `pytest.xfail("... not operational")`, change to `pytest.skip("... not supported")`.

In `test_otp.py` (12 locations): where mechanisms are unconditionally xfailed after
`has_mechanism` check, change to `pytest.skip()`.

In `test_kdf.py:174`: change `pytest.xfail("HKDF derive failed")` to
`pytest.skip("HKDF derivation not operational")`.

- [ ] **Step 2: Fix skip-on-module-bug to xfail**

In `test_ecdh_known_answer.py:114`: change `pytest.skip("ECDH derivation failed")`
to `pytest.xfail("ECDH derivation failed — mechanism advertised but rejected")`.

In `test_seed.py:79,97`: change `pytest.skip("Mechanism advertised but rejected")`
to `pytest.xfail("Mechanism advertised but rejected at use")`.

In `test_des.py:91`: same change.

- [ ] **Step 3: Fix test isolation in test_token_objects.py**

Wrap the token object creation paths in `finally:` blocks:
```python
s1 = raw_open_session(rs.raw, rs.slot_id, flags)
try:
    login_user(rs.raw, s1, CKU_USER, pin_bytes)
    key = gen_aes_key(rs.raw, s1, 256, attrs={CKA_LABEL: label, CKA_TOKEN: True})
    # ... test logic ...
finally:
    close_session_quietly(rs.raw, s1)
```

- [ ] **Step 4: Fix test_token_flags.py no-op test**

In `test_token_flags.py:91-92`, the test wraps the body in `except Exception: pass`,
making it a no-op. Remove the `try/except` and let the test actually validate:
```python
data = generate_random(rs.raw, rs.sh, 32)
assert len(data) == 32, f"RNG returned {len(data)} bytes, expected 32"
# Now check the flag
```

- [ ] **Step 5: Lint, format, test, commit**

```bash
uv run ruff check src/pkcs11_check/testcases/ --fix
uv run ruff format src/pkcs11_check/testcases/
uv run python -m pytest tests/ -x -q -k "not sdist"
git add src/pkcs11_check/testcases/
git commit -m "fix: xfail→skip for missing capabilities, test isolation, no-op tests

Convert ~35 missing-capability xfails to skips. Fix skip-on-module-bug
to xfail. Add finally blocks for token object cleanup. Fix
test_token_flags no-op test."
```

---

### Task 7: Final verification

- [ ] **Step 1: Run meta-tests**

```bash
uv run python -m pytest tests/ -x -q -k "not sdist"
```

- [ ] **Step 2: Run SoftHSM2 smoke tests**

```bash
bash local-builds/test.sh softhsm2 -m smoke
```

- [ ] **Step 3: Run full lint**

```bash
uv run ruff check src/ tests/
```

- [ ] **Step 4: Verify audit findings are addressed**

Grep for remaining anti-patterns:
```bash
rg 'except \(AssertionError, Exception\)' src/pkcs11_check/testcases/ | grep -v xfail_if_known_ckr
rg 'pytest\.xfail\("SECURITY' src/pkcs11_check/testcases/
rg 'assert rv != CKR_OK or' src/pkcs11_check/testcases/
```
Expected: zero matches for all three.
