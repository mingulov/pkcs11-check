# raw Module Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove ~4,500 unnecessary `int()` conversions, split pack.py mechanism packers, and tighten exception handling across the pkcs11_check.raw module and test suite.

**Architecture:** Layered approach -- raw/ core first, then testcases/ in batches, then structural changes. Each layer is independently testable. CK_CONSTANT(int) subclass instances work natively as dict keys, in sets, and in comparisons without explicit int() conversion. RawPKCS11._call() already returns plain int.

**Tech Stack:** Python 3.11+, ctypes, pytest, ruff, mypy

**Spec:** `docs/superpowers/specs/2026-03-26-raw-module-cleanup-design.md`

---

## Replacement Rules (shared by all tasks)

All tasks apply the same mechanical transformations. Subagents MUST follow these rules:

### Safe to remove `int()` from:

1. **CK_CONSTANT subclass instances** used as dict keys, set members, tuple members, or values:
   - `int(CKA_*)` -- CKA is int subclass
   - `int(CKM_*)` -- CKM is int subclass
   - `int(CKR_*)` -- CKR is int subclass
   - `int(CKO_*)` -- CKO is int subclass
   - `int(CKK_*)` -- CKK is int subclass
   - `int(CKF_*)` -- CKF is int subclass
   - `int(CKU_*)` -- CKU is int subclass
   - `int(CKC_*)` -- CKC is int subclass (certificate types)
   - `int(CKD_*)`, `int(CKG_*)`, `int(CKP_*)`, `int(CKZ_*)` etc.

2. **Return values from `raw.C_*()`** -- `_call()` already returns int:
   - `int(rv)` where rv = `raw.C_Something(...)` -- remove int()
   - `expect_rv(int(rv), ...)` -> `expect_rv(rv, ...)`
   - `expect_rv(int(raw.C_Something(...)), ...)` -> `expect_rv(raw.C_Something(...), ...)`

3. **ctypes `.value` accessors** on simple types:
   - `int(count.value)` where count is `CK_ULONG()` -- .value returns int
   - `int(session.value)` where session is `CK_SESSION_HANDLE()` -- same
   - `int(handle.value)` where handle is `CK_OBJECT_HANDLE()` -- same
   - `int(size.value)` -- same
   - `int(found.value)` -- same

4. **ctypes array indexing** on simple types:
   - `int(slots[i])` where slots is `(CK_SLOT_ID * n)()` -- indexing returns int
   - `int(mechs[i])` where mechs is `(CK_MECHANISM_TYPE * n)()` -- same
   - `int(handles[i])` -- same

### DO NOT remove `int()` from:

- `int(self)` in `types_std.py __getnewargs__` (serialization)
- `int(func(*args))` in `api.py _call()` line 179 (ctypes boundary)
- `int(value)` in `pack.py attr_auto()` line 350 (value is Any, intentional coercion)
- `int(hex_string, 16)` -- hex parsing, unrelated
- `int.from_bytes(...)` -- byte conversion, unrelated
- `int()` inside f-strings or format expressions on non-CK values
- `int()` inside subprocess script strings (string context, different scope)

### Verification after each task:

```bash
uv run ruff check src/ tests/     # lint
uv run ruff format --check src/ tests/  # format check
```

---

### Task 1: Remove int() in raw/ core files

**Files:**
- Modify: `src/pkcs11_check/raw/api.py`
- Modify: `src/pkcs11_check/raw/bootstrap.py`
- Modify: `src/pkcs11_check/raw/attr_metadata.py`
- Modify: `src/pkcs11_check/raw/recipes.py`
- Modify: `src/pkcs11_check/raw/pack.py`
- Modify: `src/pkcs11_check/raw/inspect.py`

- [ ] **Step 1: Remove int() in api.py (~5 removals)**

In `api.py`, remove `int()` wrapping on these lines:
- Line 105: `return int(version.major), int(version.minor)` -> `return version.major, version.minor`
- Line 125: `rv = int(get_interface(...))` -> `rv = get_interface(...)`
- Line 131: `return int(function_list_ptr)` -> `return function_list_ptr`
- Line 161: `rv = int(get_function_list(...))` -> `rv = get_function_list(...)`
- **KEEP** line 179: `return int(func(*args))` -- this is the ctypes boundary

- [ ] **Step 2: Remove int() in bootstrap.py (~10 removals)**

Remove all `int()` wrapping on raw.C_*() returns and ctypes .value accesses. Also add `import ctypes` and narrow the except clause in `close_session_quietly`:

Change:
```python
except Exception:
```
To:
```python
except (AttributeError, OSError, ctypes.ArgumentError):
```

- [ ] **Step 3: Remove int() in attr_metadata.py (~170 removals)**

All dict keys change from `int(CKA_*):` to `CKA_*:`. This is the largest single file -- every line in the ATTR_VALUE_TYPES dict. Use replace_all with pattern `int(CKA_` -> `CKA_` then clean up trailing `)`.

- [ ] **Step 4: Remove int() in recipes.py (~80 removals)**

Remove `int()` wrapping on:
- `expect_rv(int(rv), ...)` -> `expect_rv(rv, ...)`
- `int(handle.value)` -> `handle.value`
- `int(count.value)` -> `count.value`
- `{int(CKA_*)}` -> `{CKA_*}` in sets
- `int(CKR_*)` -> `CKR_*` in tuples
- `attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY))` -> `attr_ulong(CKA_CLASS, CKO_SECRET_KEY)`
- `int(CKA_*)` -> `CKA_*` everywhere
- `int(mechs[i])` -> `mechs[i]`
- `int(handles[i])` -> `handles[i]`
- `int(key_handle.value)` -> `key_handle.value`

- [ ] **Step 5: Remove int() in pack.py (~1 removal)**

Line 345: `ATTR_VALUE_TYPES.get(int(attr_type))` -> `ATTR_VALUE_TYPES.get(attr_type)`
**KEEP** line 350: `attr_ulong(attr_type, int(value))` -- value is Any.

- [ ] **Step 6: Remove int() in inspect.py (~2 removals)**

- `int(attribute.attribute.type)` -> `attribute.attribute.type`
- `int(mechanism.ck.mechanism)` -> `mechanism.ck.mechanism`

- [ ] **Step 7: Lint and format**

Run: `uv run ruff check src/pkcs11_check/raw/ && uv run ruff format --check src/pkcs11_check/raw/`
Fix any issues.

- [ ] **Step 8: Run meta-tests**

Run: `uv run python -m pytest tests/ -x -q`
Expected: all tests pass.

- [ ] **Step 9: Type check**

Run: `uv run mypy src/pkcs11_check/raw/`
Expected: no new errors.

- [ ] **Step 10: Commit**

```bash
git add src/pkcs11_check/raw/api.py src/pkcs11_check/raw/bootstrap.py \
  src/pkcs11_check/raw/attr_metadata.py src/pkcs11_check/raw/recipes.py \
  src/pkcs11_check/raw/pack.py src/pkcs11_check/raw/inspect.py
git commit -m "refactor: remove unnecessary int() conversions in raw/ core

CK_CONSTANT is an int subclass -- explicit int() wrapping is redundant
for dict keys, set members, comparisons, and CK_RV returns from _call().
Also narrow close_session_quietly to specific exception types."
```

---

### Task 2: Remove int() in fixtures, CLI, and core/loader

**Files:**
- Modify: `src/pkcs11_check/raw_fixtures.py`
- Modify: `src/pkcs11_check/fixtures.py`
- Modify: `src/pkcs11_check/cli/test_cmd.py`
- Modify: `src/pkcs11_check/cli/info_cmd.py`
- Modify: `src/pkcs11_check/core/loader.py`

- [ ] **Step 1: Remove int() in raw_fixtures.py (~8 removals)**

Remove `int()` on: `int(slot_opt)`, `int(flags)`, `int(CKU_USER)`,
`int(raw.C_GetMechanismList(...))`, `int(count.value)`, `int(mechs[i])`.

- [ ] **Step 2: Remove int() in fixtures.py (~2 removals)**

Remove `int(CKF_*)` and `int(CKU_USER)`.

- [ ] **Step 3: Remove int() in cli/ files (~2 removals)**

Check `cli/test_cmd.py` and `cli/info_cmd.py` for CK constant int() wrapping.
Only remove int() on CK_CONSTANT subclass instances and ctypes .value accesses.

- [ ] **Step 4: Remove int() in core/loader.py (~30 removals)**

Remove `int()` on CKR_* constants, raw.C_*() returns, count.value, etc.
Apply same safe removal patterns as raw/ core.

- [ ] **Step 5: Lint, format, meta-tests**

```bash
uv run ruff check src/pkcs11_check/ && uv run ruff format --check src/pkcs11_check/
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw_fixtures.py src/pkcs11_check/fixtures.py \
  src/pkcs11_check/cli/test_cmd.py src/pkcs11_check/cli/info_cmd.py \
  src/pkcs11_check/core/loader.py
git commit -m "refactor: remove unnecessary int() in fixtures, CLI, and core/loader"
```

---

### Task 3: Remove int() in testcases/ckr/ and shared helpers

**Files (22 files):**
- Modify: `src/pkcs11_check/testcases/_error_tuples.py`
- Modify: `src/pkcs11_check/testcases/ckr/_ckr_spec.py`
- Modify: all `test_ckr_*.py` files in `src/pkcs11_check/testcases/ckr/`

- [ ] **Step 1: Remove int() in _error_tuples.py (~39 removals)**

This file defines CKR error tuples. Remove `int()` from all CKR_* constants.

- [ ] **Step 2: Remove int() in ckr/_ckr_spec.py (~5 removals)**

Remove `int()` from CK constant references.

- [ ] **Step 3: Remove int() in all test_ckr_*.py files (~200 removals)**

Process ALL `test_ckr_*.py` files in `ckr/` (use glob `src/pkcs11_check/testcases/ckr/test_ckr_*.py`).
Known files include but are not limited to:
test_ckr_codes.py, test_ckr_decrypt.py, test_ckr_derive.py, test_ckr_digest.py,
test_ckr_dual.py, test_ckr_encrypt.py, test_ckr_fault_inject.py, test_ckr_general.py,
test_ckr_kem.py, test_ckr_keygen.py, test_ckr_object.py, test_ckr_priority.py,
test_ckr_random.py, test_ckr_session.py, test_ckr_sign.py, test_ckr_slot_token.py,
test_ckr_spec_compliance.py, test_ckr_state.py, test_ckr_universal.py,
test_ckr_v30_raw.py, test_ckr_v32_raw.py, test_ckr_verify.py, test_ckr_wrap.py

Apply all safe removal patterns from the rules above.

- [ ] **Step 4: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/ckr/ src/pkcs11_check/testcases/_error_tuples.py
uv run ruff format --check src/pkcs11_check/testcases/ckr/ src/pkcs11_check/testcases/_error_tuples.py
```

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/_error_tuples.py src/pkcs11_check/testcases/ckr/
git commit -m "refactor: remove unnecessary int() in ckr/ tests and error tuples"
```

---

### Task 4: Remove int() in testcases/wycheproof/

**Files (20 files):**
- Modify: all files in `src/pkcs11_check/testcases/wycheproof/`

- [ ] **Step 1: Remove int() in all wycheproof test files (~350 removals)**

Process all 20 files: test_wycheproof.py, test_wycheproof_aes.py,
test_wycheproof_chacha.py, test_wycheproof_dsa.py, test_wycheproof_ecdh.py,
test_wycheproof_ecdsa.py, test_wycheproof_ed25519.py, test_wycheproof_hkdf.py,
test_wycheproof_hmac.py, test_wycheproof_mldsa.py, test_wycheproof_mldsa_sign.py,
test_wycheproof_mlkem.py, test_wycheproof_pbes2.py, test_wycheproof_pbkdf2.py,
test_wycheproof_rsa.py, test_wycheproof_rsa_decrypt.py, test_wycheproof_rsa_oaep.py,
test_wycheproof_rsa_pss.py, test_wycheproof_rsa_siggen.py, test_wycheproof_x25519.py

Apply all safe removal patterns.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/wycheproof/
uv run ruff format --check src/pkcs11_check/testcases/wycheproof/
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/wycheproof/
git commit -m "refactor: remove unnecessary int() in wycheproof/ tests"
```

---

### Task 5: Remove int() in testcases/x509/

**Files (9 files):**
- Modify: `src/pkcs11_check/testcases/x509/conftest.py`
- Modify: all `test_*.py` files in `src/pkcs11_check/testcases/x509/`

- [ ] **Step 1: Remove int() in all x509 test files (~130 removals)**

Process all 9 files: conftest.py, test_attribute_parity.py, test_attributes.py,
test_core_ops.py, test_identity.py, test_lifecycle.py, test_limbo_import.py,
test_limbo_stress.py, test_search.py

Apply all safe removal patterns.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/x509/
uv run ruff format --check src/pkcs11_check/testcases/x509/
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/x509/
git commit -m "refactor: remove unnecessary int() in x509/ tests"
```

---

### Task 6: Remove int() in testcases/ (A-E batch)

**Files (~25 files):**
- Modify: `src/pkcs11_check/testcases/test_access.py`
- Modify: `src/pkcs11_check/testcases/test_access_control.py`
- Modify: `src/pkcs11_check/testcases/test_access_levels.py`
- Modify: `src/pkcs11_check/testcases/test_acvp_aes.py`
- Modify: `src/pkcs11_check/testcases/test_acvp_ecdsa.py`
- Modify: `src/pkcs11_check/testcases/test_acvp_eddsa.py`
- Modify: `src/pkcs11_check/testcases/test_acvp_hmac.py`
- Modify: `src/pkcs11_check/testcases/test_acvp_sha3.py`
- Modify: `src/pkcs11_check/testcases/test_acvp_slhdsa.py`
- Modify: `src/pkcs11_check/testcases/test_aead.py`
- Modify: `src/pkcs11_check/testcases/test_aes_kdf.py`
- Modify: `src/pkcs11_check/testcases/test_aes_modes.py`
- Modify: `src/pkcs11_check/testcases/test_api_security.py`
- Modify: `src/pkcs11_check/testcases/test_aria.py`
- Modify: `src/pkcs11_check/testcases/test_attribute_defaults.py`
- Modify: `src/pkcs11_check/testcases/test_attribute_enforcement.py`
- Modify: `src/pkcs11_check/testcases/test_attribute_fuzz.py`
- Modify: `src/pkcs11_check/testcases/test_authenticated_wrap.py`
- Modify: `src/pkcs11_check/testcases/test_blowfish.py`
- Modify: `src/pkcs11_check/testcases/test_buffers.py`
- Modify: `src/pkcs11_check/testcases/test_camellia.py`
- Modify: `src/pkcs11_check/testcases/test_cctv_ed25519.py`
- Modify: `src/pkcs11_check/testcases/test_cctv_mldsa.py`
- Modify: `src/pkcs11_check/testcases/test_cctv_rfc6979.py`
- Modify: `src/pkcs11_check/testcases/test_cms.py`
- Modify: `src/pkcs11_check/testcases/test_concurrent_sessions.py`
- Modify: `src/pkcs11_check/testcases/test_crossverify.py`
- Modify: `src/pkcs11_check/testcases/test_crossverify_extended.py`
- Modify: `src/pkcs11_check/testcases/test_cve_regression.py`
- Modify: `src/pkcs11_check/testcases/test_data_objects.py`
- Modify: `src/pkcs11_check/testcases/test_des.py`
- Modify: `src/pkcs11_check/testcases/test_dh_key_agreement.py`
- Modify: `src/pkcs11_check/testcases/test_digest.py`
- Modify: `src/pkcs11_check/testcases/test_domain_params.py`
- Modify: `src/pkcs11_check/testcases/test_double_ratchet.py`
- Modify: `src/pkcs11_check/testcases/test_dsa_complete.py`
- Modify: `src/pkcs11_check/testcases/test_duplicate_labels.py`
- Modify: `src/pkcs11_check/testcases/test_ec_curves.py`
- Modify: `src/pkcs11_check/testcases/test_ec_import_export.py`
- Modify: `src/pkcs11_check/testcases/test_ecdh_extended.py`
- Modify: `src/pkcs11_check/testcases/test_ecdh_known_answer.py`
- Modify: `src/pkcs11_check/testcases/test_eddsa.py`
- Modify: `src/pkcs11_check/testcases/test_encrypt.py`
- Modify: `src/pkcs11_check/testcases/test_errors.py`

- [ ] **Step 1: Remove int() in all listed files**

Apply all safe removal patterns from the rules section.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/test_a*.py src/pkcs11_check/testcases/test_b*.py \
  src/pkcs11_check/testcases/test_c*.py src/pkcs11_check/testcases/test_d*.py \
  src/pkcs11_check/testcases/test_e*.py
uv run ruff format --check src/pkcs11_check/testcases/test_a*.py src/pkcs11_check/testcases/test_b*.py \
  src/pkcs11_check/testcases/test_c*.py src/pkcs11_check/testcases/test_d*.py \
  src/pkcs11_check/testcases/test_e*.py
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/test_a*.py src/pkcs11_check/testcases/test_b*.py \
  src/pkcs11_check/testcases/test_c*.py src/pkcs11_check/testcases/test_d*.py \
  src/pkcs11_check/testcases/test_e*.py
git commit -m "refactor: remove unnecessary int() in testcases A-E"
```

---

### Task 7: Remove int() in testcases/ (F-K batch)

**Files (~20 files):**
- Modify: `src/pkcs11_check/testcases/test_fuzz.py`
- Modify: `src/pkcs11_check/testcases/test_generic_secret.py`
- Modify: `src/pkcs11_check/testcases/test_gost.py`
- Modify: `src/pkcs11_check/testcases/test_handle_reuse.py`
- Modify: `src/pkcs11_check/testcases/test_hash_ml_dsa.py`
- Modify: `src/pkcs11_check/testcases/test_hash_slh_dsa.py`
- Modify: `src/pkcs11_check/testcases/test_hkdf_extended.py`
- Modify: `src/pkcs11_check/testcases/test_hw_features.py`
- Modify: `src/pkcs11_check/testcases/test_ike.py`
- Modify: `src/pkcs11_check/testcases/test_interface.py`
- Modify: `src/pkcs11_check/testcases/test_interface_negotiation.py`
- Modify: `src/pkcs11_check/testcases/test_interop.py`
- Modify: `src/pkcs11_check/testcases/test_kdf.py`
- Modify: `src/pkcs11_check/testcases/test_kem.py`
- Modify: `src/pkcs11_check/testcases/test_key_flags.py`
- Modify: `src/pkcs11_check/testcases/test_key_lifecycle.py`
- Modify: `src/pkcs11_check/testcases/test_key_sizes.py`
- Modify: `src/pkcs11_check/testcases/test_key_usage_policy.py`
- Modify: `src/pkcs11_check/testcases/test_keymgmt.py`
- Modify: `src/pkcs11_check/testcases/test_keypair_consistency.py`

- [ ] **Step 1: Remove int() in all listed files**

Apply all safe removal patterns.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/test_f*.py src/pkcs11_check/testcases/test_g*.py \
  src/pkcs11_check/testcases/test_h*.py src/pkcs11_check/testcases/test_i*.py \
  src/pkcs11_check/testcases/test_k*.py
uv run ruff format --check src/pkcs11_check/testcases/test_f*.py src/pkcs11_check/testcases/test_g*.py \
  src/pkcs11_check/testcases/test_h*.py src/pkcs11_check/testcases/test_i*.py \
  src/pkcs11_check/testcases/test_k*.py
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/test_f*.py src/pkcs11_check/testcases/test_g*.py \
  src/pkcs11_check/testcases/test_h*.py src/pkcs11_check/testcases/test_i*.py \
  src/pkcs11_check/testcases/test_k*.py
git commit -m "refactor: remove unnecessary int() in testcases F-K"
```

---

### Task 8: Remove int() in testcases/ (L-P batch)

**Files (~20 files):**
- Modify: `src/pkcs11_check/testcases/test_large_objects.py`
- Modify: `src/pkcs11_check/testcases/test_mechanism.py`
- Modify: `src/pkcs11_check/testcases/test_mechanism_fuzz.py`
- Modify: `src/pkcs11_check/testcases/test_mechanism_objects.py`
- Modify: `src/pkcs11_check/testcases/test_metamorphic.py`
- Modify: `src/pkcs11_check/testcases/test_misc_kdf.py`
- Modify: `src/pkcs11_check/testcases/test_multipart_streaming.py`
- Modify: `src/pkcs11_check/testcases/test_nonce_quality.py`
- Modify: `src/pkcs11_check/testcases/test_object.py`
- Modify: `src/pkcs11_check/testcases/test_object_search_patterns.py`
- Modify: `src/pkcs11_check/testcases/test_object_size.py`
- Modify: `src/pkcs11_check/testcases/test_object_visibility.py`
- Modify: `src/pkcs11_check/testcases/test_operation_state.py`
- Modify: `src/pkcs11_check/testcases/test_otp.py`
- Modify: `src/pkcs11_check/testcases/test_padding_oracle.py`
- Modify: `src/pkcs11_check/testcases/test_pbe.py`
- Modify: `src/pkcs11_check/testcases/test_pin.py`
- Modify: `src/pkcs11_check/testcases/test_pqc_sign.py`
- Modify: `src/pkcs11_check/testcases/test_profiles.py`
- Modify: `src/pkcs11_check/testcases/test_protocol_edge_cases.py`

- [ ] **Step 1: Remove int() in all listed files**

Apply all safe removal patterns.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/test_l*.py src/pkcs11_check/testcases/test_m*.py \
  src/pkcs11_check/testcases/test_n*.py src/pkcs11_check/testcases/test_o*.py \
  src/pkcs11_check/testcases/test_p*.py
uv run ruff format --check src/pkcs11_check/testcases/test_l*.py src/pkcs11_check/testcases/test_m*.py \
  src/pkcs11_check/testcases/test_n*.py src/pkcs11_check/testcases/test_o*.py \
  src/pkcs11_check/testcases/test_p*.py
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/test_l*.py src/pkcs11_check/testcases/test_m*.py \
  src/pkcs11_check/testcases/test_n*.py src/pkcs11_check/testcases/test_o*.py \
  src/pkcs11_check/testcases/test_p*.py
git commit -m "refactor: remove unnecessary int() in testcases L-P"
```

---

### Task 9: Remove int() in testcases/ (R-Z batch)

**Files (~30 files):**
- Modify: `src/pkcs11_check/testcases/test_reinitialize.py`
- Modify: `src/pkcs11_check/testcases/test_remaining_gaps.py`
- Modify: `src/pkcs11_check/testcases/test_resource.py`
- Modify: `src/pkcs11_check/testcases/test_ro_session.py`
- Modify: `src/pkcs11_check/testcases/test_ro_session_restrictions.py`
- Modify: `src/pkcs11_check/testcases/test_rsa_extended.py`
- Modify: `src/pkcs11_check/testcases/test_rsa_key_import.py`
- Modify: `src/pkcs11_check/testcases/test_rsa_key_wrapping.py`
- Modify: `src/pkcs11_check/testcases/test_rsa_oaep.py`
- Modify: `src/pkcs11_check/testcases/test_salsa20.py`
- Modify: `src/pkcs11_check/testcases/test_search.py`
- Modify: `src/pkcs11_check/testcases/test_seed.py`
- Modify: `src/pkcs11_check/testcases/test_sensitivity.py`
- Modify: `src/pkcs11_check/testcases/test_session_edge_cases.py`
- Modify: `src/pkcs11_check/testcases/test_session_exhaustion.py`
- Modify: `src/pkcs11_check/testcases/test_session_info.py`
- Modify: `src/pkcs11_check/testcases/test_session_state_machine.py`
- Modify: `src/pkcs11_check/testcases/test_subprocess_safety.py`
- Modify: `src/pkcs11_check/testcases/test_set_attribute.py`
- Modify: `src/pkcs11_check/testcases/test_sign.py`
- Modify: `src/pkcs11_check/testcases/test_so_pin.py`
- Modify: `src/pkcs11_check/testcases/test_sp800_108_kdf.py`
- Modify: `src/pkcs11_check/testcases/test_ssl3.py`
- Modify: `src/pkcs11_check/testcases/test_stateful.py`
- Modify: `src/pkcs11_check/testcases/test_stateful_sigs.py`
- Modify: `src/pkcs11_check/testcases/test_stress.py`
- Modify: `src/pkcs11_check/testcases/test_surface_audit.py`
- Modify: `src/pkcs11_check/testcases/test_tls12.py`
- Modify: `src/pkcs11_check/testcases/test_token_objects.py`
- Modify: `src/pkcs11_check/testcases/test_threading.py`
- Modify: `src/pkcs11_check/testcases/test_tls12.py`
- Modify: `src/pkcs11_check/testcases/test_token_flags.py`
- Modify: `src/pkcs11_check/testcases/test_token_objects.py`
- Modify: `src/pkcs11_check/testcases/test_tookan.py`
- Modify: `src/pkcs11_check/testcases/test_tool_templates.py`
- Modify: `src/pkcs11_check/testcases/test_trust_objects.py`
- Modify: `src/pkcs11_check/testcases/test_twofish.py`
- Modify: `src/pkcs11_check/testcases/test_v30_session.py`
- Modify: `src/pkcs11_check/testcases/test_validation_objects.py`
- Modify: `src/pkcs11_check/testcases/test_vendor_extensions.py`
- Modify: `src/pkcs11_check/testcases/test_wtls.py`
- Modify: `src/pkcs11_check/testcases/test_x942_dh.py`

- [ ] **Step 1: Remove int() in all listed files**

Apply all safe removal patterns.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/test_r*.py src/pkcs11_check/testcases/test_s*.py \
  src/pkcs11_check/testcases/test_t*.py src/pkcs11_check/testcases/test_v*.py \
  src/pkcs11_check/testcases/test_w*.py src/pkcs11_check/testcases/test_x*.py
uv run ruff format --check src/pkcs11_check/testcases/test_r*.py src/pkcs11_check/testcases/test_s*.py \
  src/pkcs11_check/testcases/test_t*.py src/pkcs11_check/testcases/test_v*.py \
  src/pkcs11_check/testcases/test_w*.py src/pkcs11_check/testcases/test_x*.py
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/test_r*.py src/pkcs11_check/testcases/test_s*.py \
  src/pkcs11_check/testcases/test_t*.py src/pkcs11_check/testcases/test_v*.py \
  src/pkcs11_check/testcases/test_w*.py src/pkcs11_check/testcases/test_x*.py
git commit -m "refactor: remove unnecessary int() in testcases R-Z"
```

---

### Task 10: int() removal verification

- [ ] **Step 1: Run smoke tests against SoftHSM2**

```bash
bash local-builds/test.sh softhsm2 -m smoke
```
Expected: all smoke tests pass.

- [ ] **Step 2: Run full mypy type check**

```bash
uv run mypy src/
```
Expected: no new errors.

- [ ] **Step 3: Run full lint**

```bash
uv run ruff check src/ tests/
```
Expected: clean.

- [ ] **Step 4: Verify no remaining int(CK*) in safe-to-remove positions**

Grep for remaining `int(CK` patterns and manually verify each is in the excluded
categories (subprocess strings, int(value) in attr_auto, __getnewargs__, etc.).

```bash
rg 'int\(CK[ACMRKOFGDHKNPSTUVZ]' src/pkcs11_check/ | grep -v 'int\.from_bytes' | grep -v '__getnewargs__'
```

---

### Task 11: Split pack.py mechanism packers

**Files:**
- Modify: `src/pkcs11_check/raw/pack.py`
- Create: `src/pkcs11_check/raw/pack_mechanisms.py`
- Modify: `src/pkcs11_check/raw/__init__.py`

- [ ] **Step 1: Create pack_mechanisms.py**

Move all mechanism packer functions from `pack.py` starting at `mech_gcm` (line 489)
through end of file to `pack_mechanisms.py`. This includes:
`mech_gcm`, `mech_ccm`, `mech_pss`, `mech_oaep`, `mech_ecdh`, `mech_hkdf`,
`mech_cbc_pad`, `mech_ctr`, `mech_chacha20`, `mech_chacha20_poly1305`, `mech_eddsa`,
`mech_pbkdf2`, `mech_string_data`, `mech_ssl3_master_key_derive`, `mech_ssl3_key_mat`,
`mech_tls12_master_key_derive`, `mech_tls12_key_mat`,
`mech_tls12_extended_master_key_derive`, `mech_tls_prf`, `mech_tls_kdf`,
`mech_tls_mac`, `mech_wtls_master_key_derive`, `mech_wtls_key_mat`, `mech_wtls_prf`

The new file needs these imports from pack.py:
```python
from .pack import (
    PackedMechanism,
    _mech_struct,
    _pack_bytes,
    mech_bytes,
)
```

Plus any ctypes and types_std imports used by the moved functions (CKM, CK_VOID_PTR,
structure types like CK_AES_GCM_PARAMS etc.). Note: `mech_cbc_pad` calls `mech_bytes`
so it must be imported. `LengthArg` is NOT directly used by the moved functions.

**Keep in pack.py:** `mech_simple`, `mech_bytes`, `_pack_bytes`, `_mech_struct` and
all core classes/attribute packers.

- [ ] **Step 2: Add re-exports to pack.py**

At the bottom of `pack.py`, add re-exports so existing imports work:
```python
from .pack_mechanisms import (  # noqa: E402
    mech_gcm,
    mech_ccm,
    mech_pss,
    mech_oaep,
    mech_ecdh,
    mech_hkdf,
    mech_cbc_pad,
    mech_ctr,
    mech_chacha20,
    mech_chacha20_poly1305,
    mech_eddsa,
    mech_pbkdf2,
    mech_string_data,
    mech_ssl3_master_key_derive,
    mech_ssl3_key_mat,
    mech_tls12_master_key_derive,
    mech_tls12_key_mat,
    mech_tls12_extended_master_key_derive,
    mech_tls_prf,
    mech_tls_kdf,
    mech_tls_mac,
    mech_wtls_master_key_derive,
    mech_wtls_key_mat,
    mech_wtls_prf,
)
```

- [ ] **Step 3: Update __init__.py if needed**

Verify that `src/pkcs11_check/raw/__init__.py` exports mechanism packers. If it
imports from `pack`, the re-exports in pack.py handle it. If it needs explicit
imports from `pack_mechanisms`, add them.

- [ ] **Step 4: Verify imports work**

Quick smoke test that all re-exports resolve:
```bash
uv run python -c "from pkcs11_check.raw.pack import mech_gcm, mech_pss, mech_oaep, mech_ecdh, mech_hkdf, mech_cbc_pad"
uv run python -c "from pkcs11_check.raw import mech_gcm, mech_pss"
```
Expected: no ImportError.

- [ ] **Step 5: Lint, format, tests**

```bash
uv run ruff check src/pkcs11_check/raw/
uv run ruff format --check src/pkcs11_check/raw/
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/pack.py src/pkcs11_check/raw/pack_mechanisms.py \
  src/pkcs11_check/raw/__init__.py
git commit -m "refactor: split pack.py mechanism packers into pack_mechanisms.py

Separates 24 mechanism-specific parameter packers (~650 lines) from core
packing infrastructure (~400 lines). All existing import paths preserved
via re-exports in pack.py."
```

---

### Task 12: Final verification

- [ ] **Step 1: Full SoftHSM2 test run**

```bash
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)"
```
Expected: ~2300 tests pass.

- [ ] **Step 2: Kryoptic v3.0+ smoke test**

```bash
bash local-builds/test.sh kryoptic -m smoke
```
Expected: smoke tests pass, validates v3.0+ interface paths in api.py.

- [ ] **Step 3: Full type check and lint**

```bash
uv run mypy src/
uv run ruff check src/ tests/
```
Expected: clean.
