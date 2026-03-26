# pkcs11_check.raw Quality Improvement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve pkcs11_check.raw quality: add missing convenience recipes, add `__all__` exports, fix DRY violations, mark dead code, and add meta-tests.

**Architecture:** Add 8 missing recipe functions to `bootstrap.py` and `recipes.py` following existing patterns. Add `__all__` to 10 submodules for clean public API. Extract duplicated Final two-call from `_multipart_output`. Mark unused `faults.py` functions. Add meta-tests in `tests/test_raw_recipes.py` and `tests/test_raw_bootstrap.py`.

**Tech Stack:** Python 3.11+, ctypes, pytest, ruff, mypy

**Verification:** `uv run ruff check src/pkcs11_check/raw/` + `uv run ruff format --check src/pkcs11_check/raw/` + `uv run python -m pytest tests/ -q` after each task.

---

## Task 1: Add `__all__` to `rv.py`

**Files:**
- Modify: `src/pkcs11_check/raw/rv.py`

- [ ] **Step 1: Read current file and add `__all__`**

Current exports are `ckr_name` and `expect_rv`. Add at the end of the file (before any existing code — rv.py is 22 lines, put `__all__` after the imports but before the functions, or at the very end):

```python
__all__ = [
    "ckr_name",
    "expect_rv",
]
```

Place it after line 19 (after `expect_rv` definition, before the helper used internally).

- [ ] **Step 2: Verify**

Run: `uv run ruff check src/pkcs11_check/raw/rv.py && uv run python -c "from pkcs11_check.raw.rv import *; print('OK')"`
Expected: OK, no warnings

- [ ] **Step 3: Commit**

```
refactor(raw): add __all__ to rv.py
```

---

## Task 2: Add `__all__` to `pack.py`

**Files:**
- Modify: `src/pkcs11_check/raw/pack.py`

- [ ] **Step 1: Identify all public names in pack.py**

Run: `grep -n "^def \|^class \|^Packed\|^Template\|^Length\|^Pointer" src/pkcs11_check/raw/pack.py`

Public API (based on usage across the codebase):
- `LengthArg`, `PointerArg`, `PackedAttribute`, `PackedMechanism`, `TemplateArg`
- `attr_bool`, `attr_ulong`, `attr_bytes`, `attr_string`, `attr_date`, `attr_array`, `attr_template`, `attr_auto`
- `template`, `template_from_dict`, `template_ptr_count`
- `mech_simple`, `mech_bytes`

- [ ] **Step 2: Add `__all__` at end of pack.py**

```python
__all__ = [
    "LengthArg",
    "PointerArg",
    "PackedAttribute",
    "PackedMechanism",
    "TemplateArg",
    "attr_array",
    "attr_auto",
    "attr_bool",
    "attr_bytes",
    "attr_date",
    "attr_string",
    "attr_template",
    "attr_ulong",
    "mech_bytes",
    "mech_simple",
    "template",
    "template_from_dict",
    "template_ptr_count",
]
```

- [ ] **Step 3: Verify**

Run: `uv run ruff check src/pkcs11_check/raw/pack.py && uv run ruff format --check src/pkcs11_check/raw/pack.py && uv run python -c "from pkcs11_check.raw.pack import *; print('OK')"`
Expected: OK

- [ ] **Step 4: Commit**

```
refactor(raw): add __all__ to pack.py
```

---

## Task 3: Add `__all__` to `pack_mechanisms.py`

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`

- [ ] **Step 1: Identify all public mech_* functions**

Run: `grep "^def mech_" src/pkcs11_check/raw/pack_mechanisms.py`

Expected 24 functions: `mech_gcm`, `mech_ccm`, `mech_ctr`, `mech_cbc`, `mech_ecb`, `mech_cfb`, `mech_ofb`, `mech_pss`, `mech_oaep`, `mech_ecdh`, `mech_hkdf`, `mech_tls12_master_key_derive`, `mech_ssl3_master_key_derive`, `mech_tls12_key_mat`, `mech_tls_kdf`, `mech_tls_mac`, `mech_tls_prf`, `mech_tls12_extended_master_key_derive`, `mech_eddsa`, `mech_pkcs5_pbkd2`, `mech_chacha20_poly1305`, `mech_salsa20_chacha20_poly1305`, `mech_wtls_master_key_derive`, `mech_wtls_key_mat`

- [ ] **Step 2: Generate `__all__` from the grep output and add to end of file**

```python
__all__ = [
    "mech_ccm",
    "mech_cbc",
    "mech_cfb",
    "mech_chacha20_poly1305",
    "mech_ctr",
    "mech_ecb",
    "mech_ecdh",
    "mech_eddsa",
    "mech_gcm",
    "mech_hkdf",
    "mech_oaep",
    "mech_ofb",
    "mech_pkcs5_pbkd2",
    "mech_pss",
    "mech_salsa20_chacha20_poly1305",
    "mech_ssl3_master_key_derive",
    "mech_tls12_extended_master_key_derive",
    "mech_tls12_key_mat",
    "mech_tls12_master_key_derive",
    "mech_tls_kdf",
    "mech_tls_mac",
    "mech_tls_prf",
    "mech_wtls_key_mat",
    "mech_wtls_master_key_derive",
]
```

- [ ] **Step 3: Verify and commit**

Run: `uv run ruff check src/pkcs11_check/raw/pack_mechanisms.py`

```
refactor(raw): add __all__ to pack_mechanisms.py
```

---

## Task 4: Add `__all__` to remaining submodules

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Modify: `src/pkcs11_check/raw/faults.py`
- Modify: `src/pkcs11_check/raw/inspect.py`
- Modify: `src/pkcs11_check/raw/der.py`
- Modify: `src/pkcs11_check/raw/ec.py`
- Modify: `src/pkcs11_check/raw/extensions.py`
- Modify: `src/pkcs11_check/raw/attr_metadata.py`

For each file, add `__all__` listing only the public symbols (no `_` prefixed). The existing public exports are already known from the gap analysis. Key ones:

**recipes.py** — all `def` names not starting with `_` (46 public functions), plus any dataclass names.

**faults.py** — `SizedFaultArg`, `CountFaultArg`, `null_pointer`, `zero_length`, `nonnull_zero_length_bytes`, `nonnull_zero_length_scalar`, `nonnull_zero_length_struct`, `nonnull_zero_length_array`, `incorrect_explicit_length_bytes`, `incorrect_explicit_length_struct`, `truncated_struct`, `mismatched_template_count`, `wrong_buffer_shape_ulong_array_as_bytes`

**inspect.py** — `render_length`, `render_pointer`, `render_attribute`, `render_template`, `render_count_fault`, `render_sized_fault`, `render_mechanism`

**der.py** — all public `def` names: `ecdsa_sig_to_der`, `ecdsa_sig_from_der`, `ecdsa_sig_p1363_to_der`, `ecdsa_sig_der_to_p1363`, `encode_ec_point`, `decode_ec_point`, `encode_rsa_public_key_der`, `decode_rsa_public_key_der`

**ec.py** — `encode_named_curve_parameters`

**extensions.py** — `register_vendor_namespace`, `clear_extensions`, `lookup_symbol_name`, `lookup_struct`, `lookup_packer`, `lookup_inspector`

**attr_metadata.py** — `ATTR_VALUE_TYPES`

- [ ] **Step 1: Add `__all__` to each file (batch edit)**

- [ ] **Step 2: Verify all**

Run: `uv run ruff check src/pkcs11_check/raw/`

- [ ] **Step 3: Commit**

```
refactor(raw): add __all__ to remaining raw submodules
```

---

## Task 5: Export `der` and `ec` from `__init__.py`

**Files:**
- Modify: `src/pkcs11_check/raw/__init__.py`

- [ ] **Step 1: Add imports**

Add after the existing `from . import der, extensions, ...` line:

```python
from .der import (
    decode_ec_point,
    decode_rsa_public_key_der,
    ecdsa_sig_der_to_p1363,
    ecdsa_sig_from_der,
    ecdsa_sig_p1363_to_der,
    ecdsa_sig_to_der,
    encode_ec_point,
    encode_rsa_public_key_der,
)
from .ec import encode_named_curve_parameters
```

And add to `__all__`:

```python
"decode_ec_point",
"decode_rsa_public_key_der",
"ecdsa_sig_der_to_p1363",
"ecdsa_sig_from_der",
"ecdsa_sig_p1363_to_der",
"ecdsa_sig_to_der",
"encode_ec_point",
"encode_named_curve_parameters",
"encode_rsa_public_key_der",
```

- [ ] **Step 2: Verify**

Run: `uv run ruff check src/pkcs11_check/raw/__init__.py && uv run python -c "from pkcs11_check.raw import encode_named_curve_parameters, decode_ec_point; print('OK')"`

- [ ] **Step 3: Commit**

```
refactor(raw): export der and ec from __init__.py
```

---

## Task 6: Add `logout()` and `logout_quietly()` to `bootstrap.py`

**Files:**
- Modify: `src/pkcs11_check/raw/bootstrap.py`
- Test: `tests/test_raw_bootstrap.py`

- [ ] **Step 1: Add `logout` function**

Add after `login_user` (after line 80):

```python
def logout(raw: RawPKCS11, session: int) -> None:
    """C_Logout — log out from a token session."""
    expect_rv(raw.C_Logout(session), CKR_OK, CKR_USER_NOT_LOGGED_IN)
```

- [ ] **Step 2: Add `logout_quietly` function**

```python
def logout_quietly(raw: RawPKCS11, session: int) -> None:
    """C_Logout — log out, ignoring errors (for use in finally blocks)."""
    try:
        raw.C_Logout(session)
    except (AttributeError, OSError, ctypes.ArgumentError):
        return
```

- [ ] **Step 3: Update `__all__`**

```python
__all__ = [
    "close_session_quietly",
    "get_slot_ids",
    "login_user",
    "logout",
    "logout_quietly",
    "open_session",
]
```

- [ ] **Step 4: Add meta-test in tests/test_raw_bootstrap.py**

Add to end of file:

```python
def test_logout_delegates_to_raw_with_allowed_rvs() -> None:
    from pkcs11_check.raw.bootstrap import logout
    from pkcs11_check.raw.types_std import CKR_OK, CKR_USER_NOT_LOGGED_IN

    class FakeRaw:
        def C_Logout(self, session: int) -> int:
            return CKR_OK

    logout(FakeRaw(), 42)


def test_logout_quietly_catches_exceptions() -> None:
    from pkcs11_check.raw.bootstrap import logout_quietly

    class FakeRaw:
        def C_Logout(self, session: int) -> int:
            raise OSError("boom")

    logout_quietly(FakeRaw(), 42)  # no exception
```

- [ ] **Step 5: Verify**

Run: `uv run ruff check src/pkcs11_check/raw/bootstrap.py && uv run python -m pytest tests/test_raw_bootstrap.py -q`

- [ ] **Step 6: Commit**

```
feat(raw): add logout and logout_quietly to bootstrap
```

---

## Task 7: Add `login_user_with_name()` to `bootstrap.py`

**Files:**
- Modify: `src/pkcs11_check/raw/bootstrap.py`
- Test: `tests/test_raw_bootstrap.py`

- [ ] **Step 1: Add function**

Add after `login_user`:

```python
def login_user_with_name(
    raw: RawPKCS11,
    session: int,
    user_type: int,
    pin: bytes | bytearray | memoryview,
    username: bytes = b"",
) -> None:
    """C_LoginUser (v3.0+) — login with an explicit username.

    If username is empty (default), behaves like C_Login.
    """
    if isinstance(pin, str):
        raise TypeError("pin must be bytes-like")
    try:
        pin_bytes = bytes(memoryview(pin))
    except TypeError as exc:
        raise TypeError("pin must be bytes-like") from exc
    pin_buffer = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    user_buffer = (CK_UTF8CHAR * len(username))(*username) if username else None
    user_len = len(username) if username else 0
    fn = getattr(raw, "C_LoginUser", None)
    if fn is None:
        raise AttributeError("C_LoginUser not available in this module")
    expect_rv(
        fn(session, user_type, pin_buffer, len(pin_bytes), user_buffer, user_len),
        CKR_OK,
        CKR_USER_ALREADY_LOGGED_IN,
    )
```

- [ ] **Step 2: Update `__all__`**

Add `"login_user_with_name"`.

- [ ] **Step 3: Add meta-test**

```python
def test_login_user_with_name_passes_username_to_raw() -> None:
    from pkcs11_check.raw.bootstrap import login_user_with_name
    from pkcs11_check.raw.types_std import CKR_OK

    captured: list[tuple[bytes, int]] = []

    class FakeRaw:
        def C_LoginUser(
            self, session: int, user_type: int, pin, pin_len: int, username, username_len: int
        ) -> int:
            captured.append((bytes(username), username_len))
            return CKR_OK

    login_user_with_name(FakeRaw(), 1, b"pin", username=b"alice")
    assert captured == [(b"alice", 5)]


def test_login_user_with_name_raises_when_function_missing() -> None:
    from pkcs11_check.raw.bootstrap import login_user_with_name

    class FakeRaw:
        pass  # no C_LoginUser

    try:
        login_user_with_name(FakeRaw(), 1, b"pin")
        assert False, "Should have raised"
    except AttributeError:
        pass
```

- [ ] **Step 4: Verify and commit**

```
feat(raw): add login_user_with_name to bootstrap
```

---

## Task 8: Add `get_session_info()`, `get_mechanism_info()`, `get_slot_info()` to `recipes.py`

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Test: `tests/test_raw_recipes.py`

- [ ] **Step 1: Add imports to recipes.py**

Add `CK_SESSION_INFO`, `CK_MECHANISM_INFO`, `CK_SLOT_INFO` to the existing `from .types_std import` block. Also add `CK_STATE` if used.

- [ ] **Step 2: Add three functions after `get_mechanism_list` (after line 827)**

```python
def get_session_info(raw: RawPKCS11, session: int) -> dict[str, int]:
    """C_GetSessionInfo — returns session info as dict."""
    info = CK_SESSION_INFO()
    expect_rv(raw.C_GetSessionInfo(session, byref(info)), CKR_OK)
    return {
        "slot_id": info.slotID,
        "state": info.state,
        "flags": info.flags,
        "device_error": info.ulDeviceError,
    }


def get_mechanism_info(raw: RawPKCS11, slot_id: int, mechanism: CKM) -> dict[str, int]:
    """C_GetMechanismInfo — returns mechanism info as dict."""
    info = CK_MECHANISM_INFO()
    expect_rv(raw.C_GetMechanismInfo(slot_id, mechanism, byref(info)), CKR_OK)
    return {
        "min_key_size": info.ulMinKeySize,
        "max_key_size": info.ulMaxKeySize,
        "flags": info.flags,
    }


def get_slot_info(raw: RawPKCS11, slot_id: int) -> dict[str, Any]:
    """C_GetSlotInfo — returns slot info as dict."""
    info = CK_SLOT_INFO()
    expect_rv(raw.C_GetSlotInfo(slot_id, byref(info)), CKR_OK)
    return {
        "description": bytes(info.slotDescription).decode("utf-8", errors="replace").rstrip("\x00"),
        "manufacturer": bytes(info.manufacturerID).decode("utf-8", errors="replace").rstrip("\x00"),
        "flags": info.flags,
        "hardware_version": (info.hardwareVersion.major, info.hardwareVersion.minor),
        "firmware_version": (info.firmwareVersion.major, info.firmwareVersion.minor),
    }
```

- [ ] **Step 3: Add meta-tests in tests/test_raw_recipes.py**

```python
def test_get_session_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_session_info
    from pkcs11_check.raw.types_std import CK_SESSION_INFO, CKR_OK

    class FakeRaw:
        def C_GetSessionInfo(self, session: int, info) -> int:
            info.contents.slotID = 42
            info.contents.state = 1
            info.contents.flags = 0x04
            info.contents.ulDeviceError = 0
            return CKR_OK

    result = get_session_info(FakeRaw(), 1)
    assert result == {"slot_id": 42, "state": 1, "flags": 0x04, "device_error": 0}


def test_get_mechanism_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_mechanism_info
    from pkcs11_check.raw.types_std import CK_MECHANISM_INFO, CKR_OK

    class FakeRaw:
        def C_GetMechanismInfo(self, slot_id: int, mech: int, info) -> int:
            info.contents.ulMinKeySize = 128
            info.contents.ulMaxKeySize = 256
            info.contents.flags = 0x01
            return CKR_OK

    result = get_mechanism_info(FakeRaw(), 0, 0x01)
    assert result == {"min_key_size": 128, "max_key_size": 256, "flags": 0x01}


def test_get_slot_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_slot_info
    from pkcs11_check.raw.types_std import CK_SLOT_INFO, CK_VERSION, CKR_OK

    class FakeRaw:
        def C_GetSlotInfo(self, slot_id: int, info) -> int:
            info.contents.flags = 0x03
            info.contents.hardwareVersion = CK_VERSION(2, 1)
            info.contents.firmwareVersion = CK_VERSION(1, 0)
            return CKR_OK

    result = get_slot_info(FakeRaw(), 0)
    assert result["flags"] == 0x03
    assert result["hardware_version"] == (2, 1)
    assert result["firmware_version"] == (1, 0)
```

- [ ] **Step 4: Verify and commit**

```
feat(raw): add get_session_info, get_mechanism_info, get_slot_info recipes
```

---

## Task 9: Add `sign_recover_single()` and `verify_recover_single()` to `recipes.py`

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Test: `tests/test_raw_recipes.py`

- [ ] **Step 1: Add functions after `verify_single`**

```python
def sign_recover_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign and recover data in a single operation (C_SignRecoverInit + C_SignRecover)."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_SignRecoverInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = _to_ubyte_buf(data)
    return _two_call_output(raw, "C_SignRecover", session, in_buf, len(data))


def verify_recover_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    signature: bytes,
) -> tuple[bool, bytes]:
    """Verify and recover data (C_VerifyRecoverInit + C_VerifyRecover).

    Returns (True, recovered_data) on valid signature,
    (False, b"") on CKR_SIGNATURE_INVALID or CKR_SIGNATURE_LEN_RANGE.
    Raises on unexpected CKR values.
    """
    mech = _resolve_mech(mechanism)
    rv = raw.C_VerifyRecoverInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    sig_buf = _to_ubyte_buf(signature)
    rec_len = CK_ULONG(0)
    rv = raw.C_VerifyRecover(session, sig_buf, len(signature), None, byref(rec_len))
    if rv in _VERIFY_FAIL_RVS:
        return False, b""
    expect_rv(rv, CKR_OK)
    rec_buf = (ctypes.c_ubyte * rec_len.value)()
    rv = raw.C_VerifyRecover(session, sig_buf, len(signature), rec_buf, byref(rec_len))
    if rv in _VERIFY_FAIL_RVS:
        return False, b""
    expect_rv(rv, CKR_OK)
    return True, bytes(rec_buf[: rec_len.value])
```

**IMPORTANT:** Per PKCS#11 spec, `CKR_SIGNATURE_INVALID` has higher priority than `CKR_BUFFER_TOO_SMALL` for `C_VerifyRecover`. The NULL probe call (first call) may return `CKR_SIGNATURE_INVALID` instead of `CKR_OK` + size. The implementation above handles this correctly by checking for `_VERIFY_FAIL_RVS` before `expect_rv`.

- [ ] **Step 2: Add to `__all__` in recipes.py** (if using __all__)

- [ ] **Step 3: Add meta-tests**

```python
def test_sign_recover_single_uses_two_call_pattern() -> None:
    from pkcs11_check.raw.recipes import sign_recover_single
    from pkcs11_check.raw.types_std import CKR_OK, CK_ULONG, CKM

    class FakeRaw:
        def C_SignRecoverInit(self, session, mech, key) -> int:
            return CKR_OK

        def C_SignRecover(self, session, data, data_len, out, out_len):
            out_len[0] = 8
            return CKR_OK

    # sign_recover_single uses _two_call_output which needs actual buffer
    # — test via integration, not unit fake, since _two_call_output uses ctypes buffers


def test_verify_recover_single_returns_false_on_invalid_sig() -> None:
    from pkcs11_check.raw.recipes import verify_recover_single, _VERIFY_FAIL_RVS
    from pkcs11_check.raw.types_std import CKM, CKR_OK, CKR_SIGNATURE_INVALID

    class FakeRaw:
        def C_VerifyRecoverInit(self, session, mech, key) -> int:
            return CKR_OK

        def C_VerifyRecover(self, session, sig, sig_len, out, out_len):
            return CKR_SIGNATURE_INVALID

    valid, data = verify_recover_single(FakeRaw(), 1, 1, CKM, b"x" * 8)
    assert valid is False
    assert data == b""
```

- [ ] **Step 4: Verify and commit**

```
feat(raw): add sign_recover_single and verify_recover_single recipes
```

---

## Task 10: Add `digest_single_with_key()` to `recipes.py`

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Test: `tests/test_raw_recipes.py`

- [ ] **Step 1: Add function after `digest_single`**

```python
def digest_single_with_key(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM,
    key: int,
) -> bytes:
    """Digest a secret key value (C_DigestInit + C_DigestKey + C_DigestFinal).

    The key material is digested directly without exposing it outside the token.
    Raises CKR_FUNCTION_NOT_SUPPORTED if C_DigestKey is not implemented.
    """
    mech = _resolve_mech(mechanism)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(rv, CKR_OK)
    rv = raw.C_DigestKey(session, key)
    expect_rv(rv, CKR_OK, CKR_FUNCTION_NOT_SUPPORTED)
    return _two_call_output(raw, "C_DigestFinal", session)
```

- [ ] **Step 2: Add meta-test**

```python
def test_digest_single_with_key_calls_init_key_final() -> None:
    from pkcs11_check.raw.recipes import digest_single_with_key
    from pkcs11_check.raw.types_std import CKR_OK, CK_ULONG, CKM

    calls: list[str] = []

    class FakeRaw:
        def C_DigestInit(self, session, mech) -> int:
            calls.append("init")
            return CKR_OK

        def C_DigestKey(self, session, key) -> int:
            calls.append("key")
            return CKR_OK

        def C_DigestFinal(self, session, out, out_len):
            calls.append("final")
            if out is None:
                out_len[0] = 4
                return CKR_OK
            out[0] = 0x01
            out[1] = 0x02
            out[2] = 0x03
            out[3] = 0x04
            return CKR_OK

    result = digest_single_with_key(FakeRaw(), 1, CKM, 99)
    assert calls == ["init", "key", "final", "final"]
    assert result == b"\x01\x02\x03\x04"
```

- [ ] **Step 3: Verify and commit**

```
feat(raw): add digest_single_with_key recipe
```

---

## Task 11: Extract Final two-call from `_multipart_output`

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`

- [ ] **Step 1: Simplify the Final section**

Current code (lines 634-642):
```python
    # Final
    out_len = CK_ULONG(0)
    rv = getattr(raw, final_fn)(session, None, byref(out_len))
    expect_rv(rv, CKR_OK)
    if out_len.value > 0:
        out_buf = (ctypes.c_ubyte * out_len.value)()
        rv = getattr(raw, final_fn)(session, out_buf, byref(out_len))
        expect_rv(rv, CKR_OK)
        parts.append(bytes(out_buf[: out_len.value]))
```

Replace with:
```python
    parts.append(_two_call_output(raw, final_fn, session))
```

**NOTE:** This is correct because `_two_call_output` already handles the case where the first NULL call returns a zero-length output — it will allocate a zero-length buffer and the second call will return zero bytes, resulting in `b""`. The `if out_len.value > 0` guard in the Update loop (lines 623-633) remains because Update produces output per-chunk and skipping zero-length chunks is an optimization (avoids unnecessary ctypes allocations in tight loops).

- [ ] **Step 2: Verify no test breakage**

Run: `uv run python -m pytest tests/test_raw_recipes.py -q`

- [ ] **Step 3: Commit**

```
refactor(raw): simplify _multipart_output Final with _two_call_output
```

---

## Task 12: Mark unused `faults.py` functions

**Files:**
- Modify: `src/pkcs11_check/raw/faults.py`

- [ ] **Step 1: Add deprecation note docstrings**

For `nonnull_zero_length_scalar`, `nonnull_zero_length_struct`, `incorrect_explicit_length_struct`, change the docstring first line to add "(unused — retained for future tests)" after the existing description:

```python
def nonnull_zero_length_scalar(value: int) -> SizedFaultArg:
    """Model a live non-NULL scalar pointer passed with length zero.

    (unused — retained for future tests)
    """
```

Do the same for the other two functions.

- [ ] **Step 2: Verify and commit**

```
chore(raw): mark unused fault helpers as retained for future tests
```

---

## Task 13: Add `context` parameter to `expect_rv`

**Files:**
- Modify: `src/pkcs11_check/raw/rv.py`

- [ ] **Step 1: Add context parameter**

Change:
```python
def expect_rv(rv: int, *allowed: CKR) -> int:
    if rv in allowed:
        return rv
    raise AssertionError(
        f"Unexpected CK_RV {ckr_name(rv)}; expected one of: {_ckr_names(allowed)}"
    )
```

To:
```python
def expect_rv(rv: int, *allowed: CKR, context: str | None = None) -> int:
    """Return rv if allowed, otherwise raise an AssertionError."""
    if rv in allowed:
        return rv
    msg = f"Unexpected CK_RV {ckr_name(rv)}"
    if context:
        msg = f"{context}: {msg}"
    raise AssertionError(f"{msg}; expected one of: {_ckr_names(allowed)}")
```

- [ ] **Step 2: Verify no breakage**

Run: `uv run ruff check src/pkcs11_check/raw/rv.py && uv run python -m pytest tests/ -q`

- [ ] **Step 3: Commit**

```
feat(raw): add context parameter to expect_rv for debugging
```

---

## Tier 2: Medium-Impact (Conditional)

## Task 14: Document `_two_call_output` limitations

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`

- [ ] **Step 1: Expand docstring of `_two_call_output`**

Replace current docstring with:

```python
def _two_call_output(
    raw: RawPKCS11,
    call_fn: str,
    *args: Any,
) -> bytes:
    """Execute a PKCS#11 function using the standard two-call size pattern.

    ``args`` are ALL arguments before the output (buffer_ptr, buffer_len_ptr) pair,
    including session. The function appends the buffer pair automatically.

    Works for: C_Encrypt, C_Sign, C_Decrypt, C_Digest, C_WrapKey, C_GetOperationState,
    C_SignFinal, C_DigestFinal.

    NOT suitable for:
    - C_EncryptUpdate / C_DecryptUpdate (conditional zero-length output, use _multipart_output)
    - C_EncryptMessage / C_DecryptMessage (extra aad args, use _message_crypto)
    - C_EncapsulateKey (output buffer not the last arg, extra handle output after it)
    - C_WrapKeyAuthenticated (two output pairs: wrapped + tag)
    - C_GetMechanismList / C_GetSlotList / C_GetAttributeValue (non-byte array types)
    """
```

- [ ] **Step 2: Verify and commit**

```
docs(raw): document _two_call_output applicability
```

---

## Tier 3: Future Tests (Design Only)

These are product tests (in `src/pkcs11_check/testcases/`) that would exercise the new recipes. They require a PKCS#11 module to run. Design them for future implementation.

## Task 15: Design — Session Info Test

**Test file:** `src/pkcs11_check/testcases/test_session_info.py`

Purpose: Exercise `get_session_info()` recipe against real modules.

Test cases:
1. `test_session_info_returns_valid_struct` — call `get_session_info()`, verify dict has all 4 keys, types are int
2. `test_session_info_state_after_login` — verify `state` changes from `CKS_RW_PUBLIC_SESSION` to `CKS_RW_USER_FUNCTIONS` after login
3. `test_session_info_rw_vs_ro_flags` — open RW and RO sessions, verify `CKF_RW_SESSION` flag

Dependencies: Task 8

## Task 16: Design — Mechanism Info Audit Test

**Test file:** `src/pkcs11_check/testcases/test_mechanism_info.py`

Purpose: Exercise `get_mechanism_info()` recipe.

Test cases:
1. `test_aes_mechanism_info_returns_expected_key_sizes` — verify AES-128/192/256 key sizes
2. `test_mechanism_info_flags_consistency` — for each mechanism in `get_mechanism_list()`, verify flags are non-zero
3. `test_mechanism_info_min_lte_max` — verify `min_key_size <= max_key_size` for all mechanisms

Dependencies: Task 8

## Task 17: Design — Slot Info Test

**Test file:** `src/pkcs11_check/testcases/test_slot_info.py`

Purpose: Exercise `get_slot_info()` recipe.

Test cases:
1. `test_slot_info_returns_valid_struct` — verify dict has all keys, types correct
2. `test_slot_info_description_not_empty` — verify `description` is a non-empty string
3. `test_all_slots_have_valid_info` — iterate all slots from `get_slot_ids(token_present=False)`

Dependencies: Task 8

## Task 18: Design — DigestKey Test

**Test file:** `src/pkcs11_check/testcases/test_digest.py` (extend existing `TestDigestKey`)

Purpose: Exercise `digest_single_with_key()` recipe.

Test cases:
1. `test_digest_single_with_key_matches_digest_update` — digest a key via `digest_single_with_key()` and compare with `digest_single(key_bytes)` — both must produce the same digest
2. `test_digest_single_with_key_unsupported` — verify `CKR_FUNCTION_NOT_SUPPORTED` is handled gracefully (skip or xfail)

Dependencies: Task 10

## Task 19: Design — SignRecover / VerifyRecover Test

**Test file:** `src/pkcs11_check/testcases/test_sign_recover.py` (extend existing)

Purpose: Exercise `sign_recover_single()` and `verify_recover_single()` recipes.

Test cases:
1. `test_sign_recover_single_roundtrip` — sign with `sign_recover_single()`, verify with `verify_recover_single()`, assert recovered data equals original
2. `test_verify_recover_single_invalid_signature` — verify with wrong signature, assert returns `(False, b"")`

Dependencies: Task 9

## Task 20: Design — LoginUser Test

**Test file:** `src/pkcs11_check/testcases/test_v30_session.py` (extend existing `TestCLoginUser`)

Purpose: Exercise `login_user_with_name()` recipe.

Test cases:
1. `test_login_user_with_name_recipe_roundtrip` — login with `login_user_with_name()`, verify session works, logout
2. `test_login_user_with_name_empty_username` — verify empty username works same as `login_user()`
3. `test_login_user_with_name_nonempty_username` — verify username is passed through (may xfail depending on module)

Dependencies: Task 7

---

## Task Summary

| Tier | Task | Type | Est. Time |
|------|------|------|-----------|
| 1 | Add `__all__` to rv.py | Refactor | 5 min |
| 2 | Add `__all__` to pack.py | Refactor | 10 min |
| 3 | Add `__all__` to pack_mechanisms.py | Refactor | 5 min |
| 4 | Add `__all__` to remaining 7 submodules | Refactor | 20 min |
| 5 | Export der/ec from `__init__.py` | Refactor | 10 min |
| 6 | Add `logout()` / `logout_quietly()` | Feature + test | 20 min |
| 7 | Add `login_user_with_name()` | Feature + test | 20 min |
| 8 | Add `get_session_info/mech_info/slot_info` | Feature + test | 30 min |
| 9 | Add `sign_recover_single()` / `verify_recover_single()` | Feature + test | 30 min |
| 10 | Add `digest_single_with_key()` | Feature + test | 15 min |
| 11 | Extract Final two-call from `_multipart_output` | Refactor | 15 min |
| 12 | Mark unused `faults.py` functions | Chore | 10 min |
| 13 | Add `context` to `expect_rv` | Feature | 10 min |
| 2 | Document `_two_call_output` limitations | Docs | 10 min |
| **Total Tier 1+2** | **14 tasks** | | **~3.5 hours** |
| 3 | Design session info test | Design | — |
| 4 | Design mechanism info test | Design | — |
| 5 | Design slot info test | Design | — |
| 6 | Design digest key test | Design | — |
| 7 | Design sign/verify recover test | Design | — |
| 8 | Design LoginUser test | Design | — |
| **Total Tier 3** | **6 designs** | | **deferred** |
