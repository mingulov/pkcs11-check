# 2026-03-24 Raw Prevention and Status Report

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement strict standard-constant enforcement in `pkcs11_check.raw` and achieve full attribute parity in the X.509 limbo import suite.

**Architecture:** Extend `pkcs11_check.raw` with a validation registry for standard enums. Build task-specific "readability recipes" in a new `pkcs11_check.raw.recipes` module. Maintain the raw trust boundary (integer-first results) while providing spec-aligned, type-safe API calls.

**Tech Stack:** Python 3.11+, ctypes, pkcs11-check raw substrate, x509-limbo dataset, pytest.

---

## Status Report (2026-03-24)

- **Raw Architecture:** Tasks 1-8 of the [Raw Architecture Implementation Plan](file:///home/user/src/m/pkcs11-check/docs/superpowers/plans/2026-03-23-pkcs11-raw-implementation.md) are COMPLETE. The suite now uses a generated standard v3.2 substrate.
- **Test Coverage:** All Tiers 1-9 from `master-plan.md` are marked done. The suite contains 194 test files and ~75K tests.
- **X.509 Limbo:** The [test_limbo_import.py](file:///home/user/src/m/pkcs11-check/src/pkcs11_check/testcases/x509/test_limbo_import.py) is operational with raw DER import, sampling 183 structured cases + 50 BetterTLS variants. Strict attribute parity (SUBJECT/ISSUER/SERIAL_NUMBER) is partially implemented.
- **Local Health:** `dev` branch is 421 commits ahead of `origin`. All local meta-tests pass.
- **Pending Gaps:** Several `SecretKey` methods and `KeyType.DES` are missing from the `python-pkcs11` fork, causing ~15-20 test failures across providers (SoftHSM2/Kryoptic).

---

## Task 1: Enforce Enum Usage for Standard Constants

**Files:**
- Modify: `src/pkcs11_check/raw/types_std.py`
- Modify: `src/pkcs11_check/raw/pack.py`
- Test: `tests/test_raw_validation.py`

**Goal:** Prevent developers from using raw numeric literals (like `0x00000001` for `CKA_CLASS`) while still allowing them for vendor extensions (>= 0x80000000).

**Step 1: Write failing validation tests**

```python
def test_standard_attr_numeric_fails():
    from pkcs11_check.raw.pack import attr_ulong
    with pytest.raises(ValueError, match="is a standard constant; use enum instead"):
        attr_ulong(0x00000161, 32)  # CKA_VALUE_LEN
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_raw_validation.py -v`
Expected: FAIL (no validation yet)

**Step 3: Implement validation in `pack.py`**

Refine `PackedAttribute` and `PackedMechanism` constructors to check if the numeric ID is in the `STANDARD_SYMBOLS` set and NOT >= 0x80000000.

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_raw_validation.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/pkcs11_check/raw/pack.py tests/test_raw_validation.py
git commit -m "feat: enforce enum usage for standard PKCS#11 constants"
```

---

## Task 2: Implement Readability Recipes (Phase 4)

**Files:**
- Create: `src/pkcs11_check/raw/recipes.py`
- Modify: `src/pkcs11_check/raw/__init__.py`
- Test: `tests/test_raw_recipes.py`

**Goal:** Provide high-level wrappers for common operation sequences (e.g. `import_rsa_key_raw`, `sign_verify_roundtrip`) that look like spec text but execute on the raw substrate.

---

## Task 3: Achieve Full X.509 Limbo Parity

**Files:**
- Modify: `src/pkcs11_check/testcases/x509/test_limbo_import.py`
- Modify: `src/pkcs11_check/testcases/x509/conftest.py`

**Goal:** Ensure that EVERY certificate attribute from the Limbo dataset is verified if the module supports it. Failure to match is a regression; missing module support is a compliance note.

---

## Task 4: Final Verification and Master Plan Update

**Goal:** Update `docs/status.md` and `docs/master-plan.md` to reflect the 2026-03-24 reality.

**Step 1: Run full regression**

Run: `bash local-builds/test.sh softhsm2` and `bash local-builds/test.sh kryoptic`.

**Step 2: Update status documentation**

**Step 3: Commit**
