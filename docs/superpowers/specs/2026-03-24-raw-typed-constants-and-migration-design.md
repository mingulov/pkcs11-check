# Raw Typed Constants, Phase 3 Migration, and Recipes

**Date:** 2026-03-24
**Status:** Approved
**Scope:** Complete pkcs11_check.raw Phase 3 + Phase 4

## Summary

Add typed int-subclass constant families to pkcs11_check.raw, finish
migrating all raw-heavy test files to pkcs11_check.raw imports, replace
magic numbers with named constants, add type annotations to helpers,
and expand the recipe layer.

## Typed Constant Classes

### Base and families

```python
class CK_CONSTANT(int):
    _name: str | None
    def __new__(cls, value: int, name: str | None = None):
        obj = super().__new__(cls, value)
        obj._name = name
        return obj
    def _hex(self) -> str:
        # Mask to unsigned CK_ULONG width for repr (handles ~CKF negatives)
        import ctypes
        mask = (1 << (ctypes.sizeof(ctypes.c_ulong) * 8)) - 1
        return f"0x{self & mask:08x}"
    def __repr__(self) -> str:
        if self._name:
            return f"<{self._name}: {self._hex()}>"
        return f"<{self.__class__.__name__}({self._hex()})>"
    def __str__(self) -> str:
        if self._name:
            return self._name
        return self._hex()
    def __getnewargs__(self) -> tuple:
        return (int(self), self._name)

class CKA(CK_CONSTANT): pass
class CKM(CK_CONSTANT): pass
class CKK(CK_CONSTANT): pass
class CKO(CK_CONSTANT): pass
class CKR(CK_CONSTANT): pass
class CKF(CK_CONSTANT):
    def __or__(self, other): return CKF(int.__or__(self, other))
    def __ror__(self, other): return CKF(int.__or__(self, other))
    def __and__(self, other): return CKF(int.__and__(self, other))
    def __rand__(self, other): return CKF(int.__and__(self, other))
    def __invert__(self): return CKF(int.__invert__(self))
class CKC(CK_CONSTANT): pass
class CKD(CK_CONSTANT): pass
class CKG(CK_CONSTANT): pass
class CKH(CK_CONSTANT): pass
class CKP(CK_CONSTANT): pass
class CKS(CK_CONSTANT): pass
class CKU(CK_CONSTANT): pass
class CKN(CK_CONSTANT): pass
class CKT(CK_CONSTANT): pass
class CKV(CK_CONSTANT): pass
class CKZ(CK_CONSTANT): pass
```

### Properties

- `int` subclass: works with ctypes, arithmetic, dict keys, pickling
- Name stored at construction time (generator provides it)
- `__repr__` shows `<CKA_TOKEN: 0x00000001>` for named, `<CKM(0x80010001)>` for unnamed
- `__str__` shows `CKA_TOKEN` for named, `0x00000001` for unnamed (useful in logs)
- `__getnewargs__` ensures pickling works (pytest-xdist, multiprocessing)
- Handles value overlaps (CKP, CKF, CKG) via per-instance name
- Vendor constants: `CKM(0x80010001)` or `CKM(0x80010001, "CKM_IBM_KYBER")`
- CKF bitwise ops (`|`, `&`, `~`) return CKF, including reversed operands

### Generator output

```python
CKA_TOKEN = CKA(0x00000001, "CKA_TOKEN")
CKM_AES_KEY_GEN = CKM(0x00001080, "CKM_AES_KEY_GEN")
CKF_RW_SESSION = CKF(0x00000002, "CKF_RW_SESSION")
CKP_ML_DSA_44 = CKP(0x00000001, "CKP_ML_DSA_44")
CKP_ML_KEM_512 = CKP(0x00000001, "CKP_ML_KEM_512")
```

## Generator Prefix-to-Type Mapping

Last-match-wins ordering, derived from rust-cryptoki fix/autotype branch:

```python
CONSTANT_TYPE_MAP = [
    ("CK_", "CK_CONSTANT"),
    ("CKA_", "CKA"),
    ("CKC_", "CKC"),
    ("CKD_", "CKD"),
    ("CKF_", "CKF"),
    ("CKG_", "CKG"),
    ("CKH_", "CKH"),
    ("CKK_", "CKK"),
    ("CKM_", "CKM"),
    ("CKN_", "CKN"),
    ("CKO_", "CKO"),
    ("CKP_", "CKP"),
    ("CKR_", "CKR"),
    ("CKS_", "CKS"),
    ("CKT_", "CKT"),
    ("CKU_", "CKU"),
    ("CKV_", "CKV"),
    ("CKZ_", "CKZ"),
    ("CRYPTOKI_VERSION_", "CK_CONSTANT"),
    # PKCS#11 3.x overrides (more specific last)
    ("CKG_MGF1_", "CKG"),
    ("CKH_HEDGE_", "CKH"),
    ("CKH_DETERMINISTIC_", "CKH"),
    ("CKP_ML_DSA_", "CKP"),
    ("CKP_ML_KEM_", "CKP"),
    ("CKP_SLH_DSA_", "CKP"),
    ("CKP_PKCS5_PBKD2_", "CKP"),
    ("CKS_LAST_VALIDATION_", "CKS"),
    ("CK_CERTIFICATE_CATEGORY_", "CK_CONSTANT"),
    ("CK_SECURITY_DOMAIN_", "CK_CONSTANT"),
]
```

Safety net: any unmatched `CK*`/`CRYPTOKI*` constant gets `CK_CONSTANT`
with a generator warning.

## Type Annotations

### Pack helpers

```python
def attr_bool(attr_type: CKA, value: bool, ...) -> PackedAttribute:
def attr_ulong(attr_type: CKA, value: int, ...) -> PackedAttribute:
def attr_bytes(attr_type: CKA, value: bytes, ...) -> PackedAttribute:
def mech_simple(mechanism_type: CKM) -> PackedMechanism:
def mech_bytes(mechanism_type: CKM, value: bytes, ...) -> PackedMechanism:
```

### Bootstrap helpers

```python
def open_session(raw: RawPKCS11, slot_id: int, flags: CKF) -> int:
def login_user(raw: RawPKCS11, session: int, user_type: CKU, pin: bytes) -> None:
def get_slot_ids(raw: RawPKCS11, token_present: bool = True) -> list[int]:
```

### rv.py

```python
def expect_rv(rv: int, *accepted: CKR) -> None:
```

`rv` stays `int` because raw C_* calls return plain int. The
`accepted` values use `CKR` for clarity.

### RawPKCS11 dispatch

Stays untyped (`int` everywhere). The raw dispatch layer accepts any
integer. Type safety is in the helper/recipe layer only.

## Phase 3: Migrate Remaining Test Files

7 files to migrate from `pkcs11.raw` to `pkcs11_check.raw`:

- `test_ckr_raw_multipart.py`
- `test_ckr_v30_raw.py`
- `test_ckr_v32_raw.py`
- `test_ckr_universal.py`
- `test_ckr_destructive.py`
- `test_ckr_null_params.py`
- `test_v30_session.py`

9 already-migrated files: replace remaining magic numbers with named
constants from `types_std`.

Migration is mechanical: change import paths in subprocess preambles,
use named constants, no behavioral changes.

## Phase 4: Recipes

### Existing (keep)

- `quick_session` - open session + optional login
- `gen_aes_key` - generate AES key with explicit attrs

### New

- `gen_rsa_keypair(raw, session, bits, public_attrs, private_attrs)`
- `gen_ec_keypair(raw, session, curve_oid, public_attrs, private_attrs)`
  `curve_oid` is raw DER-encoded OID bytes (explicit, no name-to-OID
  magic); a separate utility may convert curve names if needed later
- `import_secret_key(raw, session, key_type, value, attrs)`
- `destroy_quietly(raw, session, handle)`
- `encrypt_single(raw, session, key, mechanism, plaintext)` - two-call pattern
- `sign_single(raw, session, key, mechanism, data)` - two-call pattern

### Recipe rules

- All parameters explicit, no defaults injected for crypto-relevant attrs
- `attrs` dict passed through as-is
- `RawPKCS11` as first parameter type
- Recipes call `expect_rv()` and raise on non-OK return values; tests
  that need exact CK_RV control use raw C_* calls directly
- `gen_aes_key` derives CKA_VALUE_LEN from `bits` parameter (explicit
  1:1 mapping, not a hidden default)
- Additional template/attribute helpers may be added later as patterns
  emerge from real test usage

## ABI Note

CK_ULONG is `ctypes.c_ulong` (platform-native: 4 bytes on 32-bit,
8 bytes on 64-bit). Typed constants inherit from Python `int` (arbitrary
precision). Width conversion happens at the ctypes boundary. No ABI
issue from the typed constant change.

## Package Exports

`__init__.py` re-exports typed constant classes for convenience:

```python
from .types_std import (
    CK_CONSTANT, CKA, CKM, CKK, CKO, CKR, CKF,
    CKC, CKD, CKG, CKH, CKP, CKS, CKU, CKN, CKT, CKV, CKZ,
)
```

Individual constants (CKA_TOKEN, CKM_AES_KEY_GEN, etc.) remain in
`types_std` and are not re-exported from `__init__.py` to avoid
namespace pollution. Tests import them explicitly:

```python
from pkcs11_check.raw import CKA, CKM, RawPKCS11
from pkcs11_check.raw.types_std import CKA_TOKEN, CKM_AES_KEY_GEN
```

## Testing

### New test files

- `tests/test_raw_constants.py` - typed constant properties, ctypes
  compat, repr, str, pickling, CKF bitwise (including reversed
  operands), vendor constants, hash consistency
- `tests/test_raw_recipes.py` - recipe helpers (skip when no module)

### Updated tests

- `tests/test_raw_header_parity.py` - verify all constants are typed
  (no plain int assignments remain)
- All 16 migrated test files: run against SoftHSM2

## Inspect Module Improvement

With typed constants, `inspect.py` can simplify its rendering. Instead
of manually looking up names in metadata tables, it can use `repr()`
and `str()` on typed constant values directly. This is not blocking
but should be done as part of step 5 to keep the modules consistent.

## Cleanup

### Remove stale files

- `rv.py`: verify no stale patterns remain after type annotation update
- `__init__.py`: verify no wildcard imports or stale re-exports remain

### README.md update

Update `src/pkcs11_check/raw/README.md` to document:
- Typed constant classes and their usage
- Import patterns for constants vs classes
- Recipe contract and available recipes
- Vendor constant usage examples

## Implementation Order

1. Add typed constant classes to types_std.py (hand-written, above generated section)
2. Update generator with prefix-to-type mapping and safety net warning
3. Regenerate types_std.py and metadata_std.py
4. Add constant tests (ctypes compat, repr, str, pickling, CKF bitwise
   with reversed operands, negative mask, vendor constants, hash)
5. Update pack/bootstrap/rv/recipe/inspect type annotations
6. Update `__init__.py` exports (add constant class re-exports)
7. Replace magic numbers in 9 already-migrated files with named constants
8. Migrate 7 remaining files from fork imports to pkcs11_check.raw
9. Add new recipes (gen_rsa_keypair, gen_ec_keypair, import_secret_key,
   destroy_quietly, encrypt_single, sign_single)
10. Update parity test to verify all constants are typed
11. Update README.md with typed constant documentation
12. Run full test suite against SoftHSM2
