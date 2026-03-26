# pkcs11_check.raw Module Polish (Phase 2)

**Date:** 2026-03-26
**Status:** Approved
**Scope:** Bug fix, dead code removal, API hygiene, DRY improvements, style cleanup, structural improvements

**Depends on:** Phase 1 cleanup (int() removal, pack.py split) -- already complete.

## Changes

### A. Bug fix: test_v30_session.py CK_NOTIFY

`test_v30_session.py:579` subprocess script passes `None` as the CK_NOTIFY callback
argument to `C_OpenSession`. ctypes CFUNCTYPE is strict -- needs `CK_NOTIFY()` (null
function pointer instance), not bare `None`.

**Fix:** Add `CK_NOTIFY` to the subprocess script imports at line ~543 and change
line 580 from `None, None, byref(session_handle)` to `None, CK_NOTIFY(), byref(session_handle)`.

### B. Dead code removal

#### B1. Remove dead aliases in pack.py

`pack.py:154-155`:
```python
MechanismArg = PackedMechanism
CKTemplate = TemplateArg
```
Zero usages anywhere. Remove both lines.

#### B2. Remove dead functions in rv.py

`rv.py:22-29`:
```python
def ckr_is_ok(rv: int) -> bool:
    return rv == 0

def ckr_in(rv: int, *acceptable: int) -> bool:
    return rv in acceptable
```
Zero imports anywhere. Remove both functions.

#### B3. Collapse ckr_name / rv_name

`rv.py:12-19`:
```python
def rv_name(rv: int) -> str:
    return lookup_symbol_name("rvs", rv) or _RV_NAMES.get(rv, f"0x{rv:08x}")

def ckr_name(rv: int) -> str:
    return rv_name(rv)
```

`ckr_name` has 157 usages across 34 files. `rv_name` is only used internally by
`expect_rv` (same file). Rename `rv_name` to `ckr_name` as the single implementation,
remove the alias. Update `expect_rv` to call `ckr_name` directly.

Also add `rv_name = ckr_name` as a deprecated alias for any external code that
might use it (the `__init__.py` re-exports `rv_name`). Update `__init__.py` accordingly.

#### B4. Remove dead _lookup_unique in extensions.py

`extensions.py:247-253` -- defined, never called. Remove.

#### B5. Narrow destroy_quietly exception handling

`recipes.py:259`:
```python
except Exception:
    pass
```
Same pattern as `close_session_quietly` which was already fixed. Narrow to:
```python
except (AttributeError, OSError, ctypes.ArgumentError):
    pass
```
Add `import ctypes` at top of recipes.py if not already present.

### C. API hygiene

#### C1. Make _gen_keypair public

`recipes.py:138` `_gen_keypair` -- imported by 6 test files. Rename to `gen_keypair`.
Add to `__init__.py` re-exports. All 6 test file imports stay valid (Python import
resolution handles both `_gen_keypair` and `gen_keypair` but the underscore was
the naming violation).

#### C2. Make _pack_attrs public

`recipes.py:98` `_pack_attrs` -- imported by 9 test files (one with `noqa: PLC2701`).
Rename to `pack_attrs`. Add to `__init__.py` re-exports. Remove the noqa suppression
in `test_rsa_extended.py`.

### D. DRY improvements

#### D1. Extract _to_ubyte_buf helper

23 occurrences of `(ctypes.c_ubyte * len(data))(*data)` in recipes.py.

Add to recipes.py (near top, after imports):
```python
def _to_ubyte_buf(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    """Convert bytes to a ctypes c_ubyte array."""
    return (ctypes.c_ubyte * len(data))(*data)
```

Replace all 23 occurrences with `_to_ubyte_buf(data)`.

#### D2. Merge _fill_ssl3_random and _fill_wtls_random

`pack_mechanisms.py:262-276` and `pack_mechanisms.py:515-528` are identical logic
on structs with the same field names (`pClientRandom`, `ulClientRandomLen`,
`pServerRandom`, `ulServerRandomLen`).

Replace both with a single:
```python
def _fill_random_data(
    random_info: Any,
    client_random: bytes,
    server_random: bytes,
    keepalive: list[Any],
) -> None:
    """Fill pClientRandom/pServerRandom fields on SSL3/WTLS random structs."""
    cr_ptr, cr_len = _pack_bytes(client_random, keepalive)
    sr_ptr, sr_len = _pack_bytes(server_random, keepalive)
    random_info.pClientRandom = cr_ptr
    random_info.ulClientRandomLen = cr_len
    random_info.pServerRandom = sr_ptr
    random_info.ulServerRandomLen = sr_len
```

Update all 7 call sites.

#### D3. Parameterize lookup_packer / lookup_inspector

`extensions.py:323-368` -- 44 lines of near-identical code. Extract:
```python
def _lookup_helper(
    category: str, value: int | str, *, namespace: str | None = None
) -> Any | None:
```
Reduce `lookup_packer` and `lookup_inspector` to 3-line wrappers.

#### D4. Add TemplateArg helper for optional unpacking

7 repetitions of `tmpl.ptr if tmpl else None, tmpl.count if tmpl else 0` in recipes.py.

Add to pack.py:
```python
def template_ptr_count(tmpl: TemplateArg | None) -> tuple[Any, int]:
    """Return (ptr, count) for an optional template, (None, 0) if None."""
    if tmpl is None:
        return None, 0
    return tmpl.ptr, tmpl.count
```

Replace all 7 sites in recipes.py.

#### D5. Redesign _two_call_output to accept callable

Current `_two_call_output(raw, session, call_fn, *args)` uses string-based function
lookup and hardcodes session as first arg. This prevents use with `C_WrapKey`,
`C_EncapsulateKey`, `C_WrapKeyAuthenticated` which have extra args between session
and the output buffer.

Change signature to:
```python
def _two_call_output(
    raw: RawPKCS11,
    call_fn: str,
    *args: Any,
) -> bytes:
```
Where `*args` are ALL arguments before the output buffer pair (including session).
The function appends `(None, byref(out_len))` for the size probe and
`(out_buf, byref(out_len))` for the actual call. This makes it work for any
PKCS#11 function that follows the two-call pattern.

Update `encrypt_single`, `decrypt_single`, `sign_single`, `digest_single` to use
the new signature, and refactor `wrap_key` and `encapsulate_key` to use it too.

#### D6. Subprocess session preamble helper

10 test files construct subprocess scripts with identical boilerplate (load module,
initialize, open session, login). 9 of them use `RawPKCS11.from_lib()`.

Create `src/pkcs11_check/testcases/_subprocess_preamble.py`:
```python
def subprocess_session_preamble(
    module_path: str,
    slot_id: int | None = None,
    pin: str | None = None,
    extra_imports: str = "",
) -> str:
    """Return Python code string that sets up a PKCS#11 session.

    After executing the returned code, these variables are available:
    - raw: RawPKCS11 instance (initialized)
    - sh: int session handle (opened, logged in if pin provided)
    - slot_id: int slot used

    The code also defines cleanup() which calls C_CloseSession + C_Finalize.
    """
```

This generates a script string with:
- Standard imports (RawPKCS11, open_session, login_user, get_slot_ids, etc.)
- `raw = RawPKCS11.from_lib(module_path)`
- `raw.C_Initialize(None)` with CKR_OK / ALREADY_INITIALIZED check
- Slot discovery via `get_slot_ids()`
- `sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)`
- Optional `login_user(raw, sh, CKU_USER, pin.encode())` if pin given
- `cleanup()` function for `C_CloseSession` + `C_Finalize`

**Special case:** `test_v30_session.py` does manual v3.0 interface negotiation and
cannot use this helper. It only needs the CK_NOTIFY fix (Group A).

Update the 9 applicable test files to use the preamble helper.

### E. Style / cleanup

#### E1. Move deferred import in pack.py

`import datetime` at line 337 inside `attr_auto()` body. Move to module-level imports.

#### E2. Move deferred import in bootstrap.py

`from .types_std import CK_TOKEN_INFO` at line 36 inside `get_slot_ids()`.
Move to module-level imports.

#### E3. Replace magic number in pack_mechanisms.py

Line 239: `params.saltSource = 1  # CKZ_SALT_SPECIFIED`
Change to: `params.saltSource = CKZ_SALT_SPECIFIED`
Add `CKZ_SALT_SPECIFIED` to the imports from `types_std`.

#### E4. Add docstring to pack_mechanisms.py

Add module-level note that callers should import mechanism packers from
`pkcs11_check.raw.pack` (which re-exports), not directly from `pack_mechanisms`.

### F. Structural

#### F1. Clean up __init__.py constant re-exports

Only 1 test file imports constants from `pkcs11_check.raw` directly. Remove
individual CKR_*, CKA_*, CKF_*, etc. constant re-exports from `__init__.py`.
Keep module re-exports (`types_std`, `metadata_std`, `recipes`, `pack`, etc.)
and class/function re-exports (`RawPKCS11`, `get_slot_ids`, etc.).

Update the 1 test file (`test_tls12.py`) to import from `types_std` instead.

#### F2. DER sequence decoding deduplication

`der.py:79-93` (`ecdsa_sig_from_der`) and `der.py:160-177` (`decode_rsa_public_key_der`)
share the same SEQUENCE decode pattern. Extract:
```python
def _decode_der_sequence_integers(data: bytes, count: int) -> tuple[int, ...]:
```
Both functions become thin wrappers.

#### F3. Eliminate explicit_length wrapper in faults.py

`faults.py:66-68`:
```python
def explicit_length(size: int) -> LengthArg:
    return pack_explicit_length(size)
```
This is a one-line re-export via alias. Change the import to use the real name directly
and remove the wrapper. Update callers if any.

## Verification Plan

1. `uv run ruff check src/ tests/ --fix && uv run ruff format src/ tests/`
2. `uv run python -m pytest tests/ -x -q` (meta-tests)
3. `bash local-builds/test.sh softhsm2 -m smoke`
4. `bash local-builds/test.sh kryoptic -m smoke` (v3.0+ paths)

## Execution Order

1. A (bug fix) -- standalone
2. B (dead code) -- standalone
3. C (API hygiene) -- standalone
4. E (style) -- standalone
5. D1-D4 (small DRY) -- standalone
6. D5 (_two_call_output redesign) -- needs careful testing
7. D6 (subprocess preamble) -- touches 9 test files
8. F (structural) -- standalone
9. Final verification
