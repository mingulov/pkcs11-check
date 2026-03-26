# pkcs11_check.raw Module Cleanup

**Date:** 2026-03-26
**Status:** Approved
**Scope:** Remove unnecessary `int()` conversions, split pack.py, tighten exception handling

## Problem

`CK_CONSTANT` in `types_std.py` is an `int` subclass:

```python
class CK_CONSTANT(int):
    def __new__(cls, value: int, name: str | None = None):
        obj = super().__new__(cls, value)
        obj._name = name
        return obj
```

All CKA, CKM, CKR, CKO, CKK etc. constants ARE ints. `hash(CKA_CLASS) == hash(0)`,
`isinstance(CKA_CLASS, int) == True`. Dict lookups, set membership, and comparisons
all work natively without explicit `int()` conversion.

Additionally, `RawPKCS11._call()` already returns `int(func(*args))`, making all
downstream `int(rv)` wrapping redundant. ctypes `.value` accessors on simple types
(`c_ulong`, `c_ubyte`) also return plain Python `int`.

**~4,500 unnecessary `int()` calls** exist across 175+ files.

## Changes

### 1. Remove `int()` in raw/ core (~260 removals)

**Boundary point kept:** `api.py:179` `return int(func(*args))` stays as the single
ctypes-to-Python conversion point. All other `int()` calls in raw/ are removed.

#### attr_metadata.py (~170 removals)

All dict keys change from `int(CKA_*):` to `CKA_*:`. Type annotation `dict[int, str]`
stays correct (CKA is a subclass of int).

Before:
```python
ATTR_VALUE_TYPES: dict[int, str] = {
    int(CKA_CLASS): "ulong",
    int(CKA_TOKEN): "bool",
```

After:
```python
ATTR_VALUE_TYPES: dict[int, str] = {
    CKA_CLASS: "ulong",
    CKA_TOKEN: "bool",
```

#### recipes.py (~80 removals)

- `expect_rv(int(rv), CKR_OK)` -> `expect_rv(rv, CKR_OK)` (rv already int from _call)
- `int(handle.value)` -> `handle.value` (ctypes .value returns int)
- `int(count.value)` -> `count.value`
- `{int(CKA_VALUE_LEN)}` -> `{CKA_VALUE_LEN}` (CKA is int, works in sets)
- `int(CKR_SIGNATURE_INVALID)` -> `CKR_SIGNATURE_INVALID` (CKR is int)
- `attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY))` -> `attr_ulong(CKA_CLASS, CKO_SECRET_KEY)`

#### bootstrap.py (~10 removals)

- `expect_rv(int(raw.C_GetSlotList(...)), CKR_OK)` -> `expect_rv(raw.C_GetSlotList(...), CKR_OK)`
- `int(count.value)` -> `count.value`
- `int(slots[index])` -> `slots[index]` (ctypes array indexing returns int)
- `int(session.value)` -> `session.value`
- `int(raw.C_GetTokenInfo(...)) == CKR_OK` -> `raw.C_GetTokenInfo(...) == CKR_OK`

#### api.py (~5 removals)

- `int(version.major), int(version.minor)` -> `version.major, version.minor`
- `int(get_interface(...))` -> `get_interface(...)` (restype=c_ulong returns int)
- `int(function_list_ptr)` -> `function_list_ptr`
- `int(get_function_list(...))` -> `get_function_list(...)`
- **Keep:** `return int(func(*args))` in `_call()` (line 179)

#### pack.py (~1 removal, 1 kept)

- `ATTR_VALUE_TYPES.get(int(attr_type))` -> `ATTR_VALUE_TYPES.get(attr_type)`
- **Keep:** `attr_ulong(attr_type, int(value))` in `attr_auto()` -- `value` is `Any`
  (from `template_from_dict(attrs: dict[int, Any])`), not necessarily a CK_CONSTANT.
  The `int()` here coerces arbitrary values for `ctypes.c_ulong()`, which is intentional.

#### inspect.py (~2 removals)

- `int(attribute.attribute.type)` -> `attribute.attribute.type`
- `int(mechanism.ck.mechanism)` -> `mechanism.ck.mechanism`

#### types_std.py (0 changes)

`__getnewargs__` uses `int(self)` for serialization protocol -- keep as-is.

### 2. Remove `int()` in testcases/ and other source files (~4,200 removals)

Same mechanical patterns as raw/:

| Pattern | Before | After |
|---------|--------|-------|
| Dict key | `{int(CKA_CLASS): val}` | `{CKA_CLASS: val}` |
| Set member | `{int(CKA_VALUE_LEN)}` | `{CKA_VALUE_LEN}` |
| Constant as value | `attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY))` | `attr_ulong(CKA_CLASS, CKO_SECRET_KEY)` |
| Tuple member | `(int(CKR_OK), int(CKR_DEVICE_ERROR))` | `(CKR_OK, CKR_DEVICE_ERROR)` |
| rv from raw.C_*() | `expect_rv(int(rv), CKR_OK)` | `expect_rv(rv, CKR_OK)` |
| ctypes .value | `int(handle.value)` | `handle.value` |

**Excluded from mechanical replacement:**
- `int()` on non-CK values (hex strings, user data, byte conversions)
- `int.from_bytes(...)` -- unrelated
- `int()` inside subprocess script strings -- different context, needs manual review

**Includes:**
- `testcases/`: `_error_tuples.py`, all `conftest.py` files, `ckr/` subdirectory,
  `wycheproof/`, `x509/`
- `fixtures.py` (~2 occurrences: `int(CKF_*)`, `int(CKU_USER)`)
- `raw_fixtures.py` (~8 occurrences: `int(slot)`, `int(flags)`, `int(CKU_USER)`,
  `int(raw.C_GetMechanismList(...))`, `int(count.value)`, `int(mechs[i])`)
- `cli/test_cmd.py`, `cli/info_cmd.py` (~2 occurrences)

### 3. Split pack.py mechanism packers

Split `pack.py` (1,059 lines) into two files by concern:

| File | Contents | ~Lines |
|------|----------|--------|
| `pack.py` | Core infrastructure: `PointerArg`, `LengthArg`, `PackedAttribute`, `PackedMechanism`, `TemplateArg`, attribute packers (`attr_bool`, `attr_ulong`, `attr_bytes`, `attr_string`, `attr_date`, `attr_array`, `attr_template`, `attr_auto`, `template`), `mech_simple`, `mech_bytes`, `_mech_struct`, `_pack_bytes` | ~400 |
| `pack_mechanisms.py` | All specialized mechanism packers: `mech_gcm`, `mech_ccm`, `mech_pss`, `mech_oaep`, `mech_ecdh`, `mech_hkdf`, `mech_pbkdf2`, `mech_eddsa`, `mech_ssl3_*`, `mech_tls12_*`, `mech_kem_*`, etc. | ~650 |

**Why `mech_simple` and `mech_bytes` stay in pack.py:** They are trivial/generic
building blocks, not mechanism-specific parameter struct builders.

**Import structure:**
- `pack_mechanisms.py` imports from `pack.py`: `PointerArg`, `LengthArg`,
  `PackedMechanism`, `_mech_struct`, `_pack_bytes`
- `pack.py` re-exports all public names from `pack_mechanisms.py` at the bottom
  (e.g., `from .pack_mechanisms import mech_gcm, mech_pss, ...`). This is required
  because 30+ files import directly from `pkcs11_check.raw.pack`, not from
  `pkcs11_check.raw`. The re-exports in `pack.py` ensure all existing import paths
  continue to work without modification.
- `__init__.py` also re-exports from both for `from pkcs11_check.raw import mech_gcm`

### 4. Tighten close_session_quietly exception handling

`bootstrap.py` `close_session_quietly()` changes from bare `except Exception` to
specific exception types:

Before:
```python
def close_session_quietly(raw: RawPKCS11, session: int) -> None:
    try:
        raw.C_CloseSession(session)
    except Exception:
        return
```

After:
```python
def close_session_quietly(raw: RawPKCS11, session: int) -> None:
    try:
        raw.C_CloseSession(session)
    except (AttributeError, OSError, ctypes.ArgumentError):
        return
```

**Rationale:** `_call()` returns CK_RV as int -- PKCS#11 errors are not raised as
exceptions. The only possible exceptions are:
- `AttributeError` -- C_CloseSession not in loaded function list
- `OSError` -- module .so crashed or unloaded
- `ctypes.ArgumentError` -- type mismatch (programming bug)

These are suppressed because the function is used in `finally` blocks where cleanup
failures would mask the original test result.

## Verification Plan

1. **After raw/ changes:** `uv run python -m pytest tests/` (meta-tests)
2. **After testcases/ changes:** `bash local-builds/test.sh softhsm2 -m smoke` then
   `bash local-builds/test.sh softhsm2`
3. **After pack.py split:** `uv run python -m pytest tests/` then
   `bash local-builds/test.sh softhsm2 -m smoke`
4. **v3.0+ verification:** `bash local-builds/test.sh kryoptic -m smoke` --
   Kryoptic exercises v3.0+ interface paths (C_GetInterface, version negotiation)
   that SoftHSM2 does not, validating the api.py int() removals
5. **Type check:** `uv run mypy src/` after each layer
6. **Lint:** `uv run ruff check src/ tests/` after each layer

## Out of Scope

- types_std.py / metadata_std.py deduplication (deferred -- expect more changes)
- recipes.py splitting (not needed now, each function is self-contained)
- Python version upgrade (int() issue is not version-dependent)
