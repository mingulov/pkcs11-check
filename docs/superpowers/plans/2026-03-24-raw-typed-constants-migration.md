# Raw Typed Constants and Phase 3+4 Migration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add typed int-subclass constant families to pkcs11_check.raw, migrate all remaining test files, replace magic numbers, and expand recipes.

**Architecture:** Typed constant classes (CKA, CKM, CKR, etc.) are int subclasses placed at the top of the generated `types_std.py`. The generator emits `CKA_TOKEN = CKA(0x01, "CKA_TOKEN")` instead of plain ints. Pack/bootstrap/recipe helpers get type annotations. 16 test files get migrated imports and named constants. New recipes handle keypair gen, import, encrypt, sign.

**Tech Stack:** Python 3.12, ctypes, generated code via `scripts/generate_raw_standard.py`

**Spec:** `docs/superpowers/specs/2026-03-24-raw-typed-constants-and-migration-design.md`

---

## File Map

**Modify:**
- `scripts/generate_raw_standard.py` - prefix-to-type mapping, emit typed constants
- `src/pkcs11_check/raw/types_std.py` - regenerated with typed constants
- `src/pkcs11_check/raw/metadata_std.py` - regenerated (no change expected)
- `src/pkcs11_check/raw/pack.py` - type annotations (CKA, CKM)
- `src/pkcs11_check/raw/bootstrap.py` - type annotations (RawPKCS11, CKF, CKU)
- `src/pkcs11_check/raw/rv.py` - type annotations (CKR)
- `src/pkcs11_check/raw/inspect.py` - use typed constant repr
- `src/pkcs11_check/raw/recipes.py` - type annotations + new recipes
- `src/pkcs11_check/raw/__init__.py` - add constant class re-exports
- `src/pkcs11_check/raw/README.md` - document typed constants
- 9 already-migrated test files (replace magic numbers)
- 7 unmigrated test files (change imports to pkcs11_check.raw)

**Create:**
- `tests/test_raw_constants.py` - typed constant tests
- `tests/test_raw_recipes.py` - recipe tests

**Update:**
- `tests/test_raw_header_parity.py` - verify constants are typed

---

### Task 1: Add typed constant classes to types_std.py

**Files:**
- Modify: `scripts/generate_raw_standard.py`
- Modify: `src/pkcs11_check/raw/types_std.py` (regenerated)
- Test: `tests/test_raw_constants.py`

- [ ] **Step 1: Write test_raw_constants.py with core typed constant tests**

Create `tests/test_raw_constants.py` with tests for:
- `CKA(1)` is `int`, is `CK_CONSTANT`, is `CKA`, not `CKM`
- Equality: `CKA(1) == 1` is True
- Hash: `hash(CKA(1)) == hash(1)`
- ctypes compat: `ctypes.c_ulong(CKA(0x0001))` works
- repr named: `CKA(1, "CKA_TOKEN")` shows `<CKA_TOKEN: 0x00000001>`
- repr unnamed: `CKM(0x80010001)` shows `<CKM(0x80010001)>`
- str named: `str(CKA(1, "CKA_TOKEN"))` is `"CKA_TOKEN"`
- str unnamed: `str(CKM(0x80010001))` contains `"0x80010001"`
- Serialization roundtrip: `CKA(1, "CKA_TOKEN")` survives serialization and retains type and name
- CKF bitwise: `CKF(0x02) | CKF(0x04)` returns `CKF`, value `0x06`
- CKF reversed: `0x100 | CKF(0x02)` returns `CKF`
- CKF invert: `~CKF(0x02)` returns `CKF`, repr has no `-`
- CKP overlap: `CKP(1, "CKP_ML_DSA_44")` and `CKP(1, "CKP_ML_KEM_512")` have distinct reprs
- Vendor: `CKM(0x80010001)` is `CKM`, no registration needed
- Generated constants: `CKA_TOKEN` is `CKA`, `CKM_AES_KEY_GEN` is `CKM`, `CKR_OK` is `CKR`, `CKF_RW_SESSION` is `CKF`
- Combined generated flags: `CKF_RW_SESSION | CKF_SERIAL_SESSION` is `CKF`

- [ ] **Step 2: Run tests - verify they fail**

Run: `uv run python -m pytest tests/test_raw_constants.py -x -q --no-header --timeout=10`
Expected: FAIL (CKA is not a class yet, or CKA_TOKEN is plain int)

- [ ] **Step 3: Add CK_CONSTANT classes and prefix mapping to generator**

In `scripts/generate_raw_standard.py`:

1. Add `CONSTANT_TYPE_MAP` list from spec (last-match-wins ordering)
2. Add `_resolve_constant_type(name)` that walks the map
3. Update `_render_types_module` to emit class definitions at top of types_std.py
4. Change constant emission from `{name} = {hex_value}` to `{name} = {type_class}({hex_value}, "{name}")`
5. Add safety net: warn for unmatched `CK*`/`CRYPTOKI*` constants, default to `CK_CONSTANT`

- [ ] **Step 4: Regenerate types_std.py**

Run: `uv run python scripts/generate_raw_standard.py`

- [ ] **Step 5: Run constant tests - verify they pass**

Run: `uv run python -m pytest tests/test_raw_constants.py -v --no-header --timeout=10`
Expected: ALL PASS

- [ ] **Step 6: Run all existing raw tests - verify no regressions**

Run: `uv run python -m pytest tests/test_raw*.py -q --no-header --timeout=30 -k "not sdist"`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add scripts/generate_raw_standard.py src/pkcs11_check/raw/types_std.py \
    src/pkcs11_check/raw/metadata_std.py tests/test_raw_constants.py
git commit -m "feat: add typed CK_CONSTANT families to generated types_std"
```

---

### Task 2: Update type annotations and exports

**Files:**
- Modify: `src/pkcs11_check/raw/pack.py`
- Modify: `src/pkcs11_check/raw/bootstrap.py`
- Modify: `src/pkcs11_check/raw/rv.py`
- Modify: `src/pkcs11_check/raw/inspect.py`
- Modify: `src/pkcs11_check/raw/recipes.py`
- Modify: `src/pkcs11_check/raw/__init__.py`

- [ ] **Step 1: Update pack.py type annotations**

Change `attr_*` signatures: `attr_type: int` -> `attr_type: CKA`
Change `mech_*` signatures: `mechanism_type: int` -> `mechanism_type: CKM`
Add import: `from .types_std import CKA, CKM`

- [ ] **Step 2: Update bootstrap.py type annotations**

Change `raw: object` -> `raw: RawPKCS11` on all functions.
Add import: `from .api import RawPKCS11`

- [ ] **Step 3: Update rv.py type annotations**

Change `expect_rv(rv: int, *allowed: int)` -> `expect_rv(rv: int, *allowed: CKR)`
Add import: `from .types_std import CKR`

- [ ] **Step 4: Update inspect.py to use typed constant repr**

Simplify name lookups where typed constant `repr()` or `str()` can replace manual table lookups.

- [ ] **Step 5: Update recipes.py type annotations**

Change `raw: Any` -> `raw: RawPKCS11` on all functions.
Add import: `from .api import RawPKCS11`

- [ ] **Step 6: Update __init__.py exports**

Add typed constant class re-exports:
```python
from .types_std import (
    CK_CONSTANT, CKA, CKM, CKK, CKO, CKR, CKF,
    CKC, CKD, CKG, CKH, CKP, CKS, CKU, CKN, CKT, CKV, CKZ,
)
```
Add to `__all__`.

- [ ] **Step 7: Run all raw tests**

Run: `uv run python -m pytest tests/test_raw*.py -q --no-header --timeout=30 -k "not sdist"`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/raw/pack.py src/pkcs11_check/raw/bootstrap.py \
    src/pkcs11_check/raw/rv.py src/pkcs11_check/raw/inspect.py \
    src/pkcs11_check/raw/recipes.py src/pkcs11_check/raw/__init__.py
git commit -m "feat: add type annotations to raw pack/bootstrap/rv/recipe helpers"
```

---

### Task 3: Replace magic numbers in already-migrated files

**Files:**
- Modify: 9 test files under `src/pkcs11_check/testcases/`

- [ ] **Step 1: Replace magic numbers in 4 CKR raw test files**

In `test_ckr_raw_args_bad.py`, `test_ckr_raw_attrs.py`, `test_ckr_raw_buffer.py`, `test_ckr_raw_state.py`:

Replace hex literals in subprocess preambles with named constants. Common replacements:
- `0x161` -> `CKA_VALUE_LEN`, `0x104` -> `CKA_ENCRYPT`, `0x105` -> `CKA_DECRYPT`
- `0x108` -> `CKA_SIGN`, `0x10a` -> `CKA_VERIFY`, `0x01` (attr) -> `CKA_TOKEN`
- `0x1080` -> `CKM_AES_KEY_GEN`, `0x1085` -> `CKM_AES_ECB`

Add corresponding imports from `pkcs11_check.raw.types_std`.

- [ ] **Step 2: Replace magic numbers in 5 larger migrated test files**

Same pattern for `test_dual_function.py`, `test_operation_state.py`, `test_remaining_gaps.py`, `test_sign_recover.py`, `test_tls12.py`.

- [ ] **Step 3: Run all raw meta-tests**

Run: `uv run python -m pytest tests/test_raw*.py -q --no-header --timeout=30 -k "not sdist"`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/
git commit -m "refactor: replace magic numbers with typed constants in migrated tests"
```

---

### Task 4: Migrate 7 remaining test files

**Files:**
- Modify: 7 test files (see spec for list)

- [ ] **Step 1: Migrate 6 CKR test files**

Change subprocess preamble imports from `pkcs11.raw` to `pkcs11_check.raw.*`. Replace magic numbers with named constants. Adjust `RawPKCS11` instantiation to `RawPKCS11.from_lib(...)` if needed.

Files: `test_ckr_raw_multipart.py`, `test_ckr_v30_raw.py`, `test_ckr_v32_raw.py`, `test_ckr_universal.py`, `test_ckr_destructive.py`, `test_ckr_null_params.py`

- [ ] **Step 2: Migrate test_v30_session.py**

Same import pattern. This file is 691 lines and tests v3.0 interface functions.

- [ ] **Step 3: Run meta-tests**

Run: `uv run python -m pytest tests/test_raw*.py -q --no-header --timeout=30 -k "not sdist"`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/
git commit -m "refactor: migrate remaining 7 test files to pkcs11_check.raw"
```

---

### Task 5: Add new recipes

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Create: `tests/test_raw_recipes.py`

- [ ] **Step 1: Write recipe tests**

Create `tests/test_raw_recipes.py` with existence/signature tests for all recipes (skip when no PKCS#11 module available for integration tests).

- [ ] **Step 2: Run tests - verify they fail**

Run: `uv run python -m pytest tests/test_raw_recipes.py -x -q --no-header --timeout=10`
Expected: FAIL (new functions don't exist yet)

- [ ] **Step 3: Implement new recipes**

Add to `src/pkcs11_check/raw/recipes.py`:
- `gen_rsa_keypair` - CKM_RSA_PKCS_KEY_PAIR_GEN, explicit templates
- `gen_ec_keypair` - CKM_EC_KEY_PAIR_GEN, curve_oid as raw DER bytes
- `import_secret_key` - C_CreateObject with CKO_SECRET_KEY
- `destroy_quietly` - C_DestroyObject, catches all exceptions
- `encrypt_single` - two-call C_EncryptInit + C_Encrypt pattern
- `sign_single` - two-call C_SignInit + C_Sign pattern

All use `expect_rv()`, all use typed constants, all take `raw: RawPKCS11`.

- [ ] **Step 4: Run tests - verify they pass**

Run: `uv run python -m pytest tests/test_raw_recipes.py -v --no-header --timeout=10`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/raw/recipes.py tests/test_raw_recipes.py
git commit -m "feat: add gen_rsa_keypair, gen_ec_keypair, import_secret_key, encrypt_single, sign_single recipes"
```

---

### Task 6: Update parity test and README

**Files:**
- Modify: `tests/test_raw_header_parity.py`
- Modify: `src/pkcs11_check/raw/README.md`

- [ ] **Step 1: Add typed constant parity check**

Add test to `tests/test_raw_header_parity.py` that verifies no plain `int` constant assignments remain in `types_std.py` (all must use typed families).

- [ ] **Step 2: Run parity tests**

Run: `uv run python -m pytest tests/test_raw_header_parity.py -v --no-header --timeout=10`
Expected: ALL PASS

- [ ] **Step 3: Update README.md**

Add sections to `src/pkcs11_check/raw/README.md`:
- Typed constant classes and import patterns
- Vendor constant examples (`CKM(0x80010001)`, `CKM(0x80010001, "CKM_IBM_KYBER")`)
- Recipe list and contract
- Example usage showing named constants vs magic numbers

- [ ] **Step 4: Commit**

```bash
git add tests/test_raw_header_parity.py src/pkcs11_check/raw/README.md
git commit -m "docs: update parity test and README for typed constants and recipes"
```

---

### Task 7: Integration verification

- [ ] **Step 1: Run full meta-test suite**

Run: `uv run python -m pytest tests/ -q --no-header --timeout=60 -k "not sdist"`
Expected: ALL PASS

- [ ] **Step 2: Run against SoftHSM2 (smoke test)**

Run: `bash local-builds/test.sh softhsm2 -m smoke`
Expected: smoke tests pass, no import errors

- [ ] **Step 3: Final commit if any cleanup needed**

```bash
git add -A && git commit -m "chore: Phase 3+4 integration cleanup" || echo "nothing to commit"
```
