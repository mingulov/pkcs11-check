# Test Migration Batch 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate 10 test files from the python-pkcs11 fork API to `pkcs11_check.raw`, eliminating fork dependency for these files while preserving identical test behavior.

**Architecture:** Bridge-based migration — a new `p11_raw_session` fixture wraps the existing `p11_module` loader with `raw_from_module()`, providing a `RawSession` dataclass with `raw`, `sh`, `slot_id`, and a cached `has_mechanism()` method to migrated tests. Each file replaces fork method calls (e.g., `key.encrypt()`) with raw recipes (e.g., `encrypt_single()`), and replaces `except PKCS11Error` with raw CKR value checks. The fork remains loaded — only test-level API usage changes.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw (RawPKCS11, recipes, pack, bootstrap, ec, types_std)

**References:**
- Master plan: `docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md` (Sub-project 3)
- Raw package: `src/pkcs11_check/raw/README.md`
- Raw architecture: `docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md`
- OASIS spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`

**Critical rules (from CLAUDE.md):**
- Do NOT change test logic or skip/fail behavior
- Do NOT introduce new xfails
- NEVER skip/disable/suppress real failures or crashes
- NEVER use generic `except PKCS11Error: pass` — list specific CKR codes
- Commit after each file

**Scope clarification:** Files using `p11_module` and `p11_interface_version` fixtures for non-crypto operations (slot enumeration, interface queries) retain that indirect fork dependency through the fixture layer. "Fully migrated" here means: zero `from pkcs11` / `import pkcs11` statements in the test file, zero fork method calls on key/session objects. The fixture-layer dependency is eliminated in Sub-project 5 (Fork Removal).

---

## Migration Pattern Reference

These patterns apply to every file. Tasks reference them by number.

| # | Fork pattern | Raw replacement |
|---|---|---|
| P1 | `p11_session.generate_key(KeyType.AES, N)` | `gen_aes_key(raw, sh, N)` → returns `int` handle |
| P2 | `p11_session.generate_keypair(KeyType.RSA, N)` | `gen_rsa_keypair(raw, sh, N)` → returns `(pub_h, priv_h)` |
| P3 | `key.encrypt(pt, mechanism=Mechanism.X)` | `encrypt_single(raw, sh, key_h, CKM_X, pt)` |
| P4 | `key.decrypt(ct, mechanism=Mechanism.X)` | `decrypt_single(raw, sh, key_h, CKM_X, ct)` |
| P5 | `priv.sign(data, mechanism=Mechanism.X)` | `sign_single(raw, sh, priv_h, CKM_X, data)` |
| P6 | `pub.verify(data, sig, mechanism=Mechanism.X)` | `verify_single(raw, sh, pub_h, CKM_X, data, sig)` — **note:** returns `False` only for `CKR_SIGNATURE_INVALID`/`CKR_SIGNATURE_LEN_RANGE`; other errors raise `AssertionError` (stricter than fork, intentional: surfaces module bugs) |
| P7 | `p11_session.digest(data, mechanism=Mechanism.X)` | `digest_single(raw, sh, CKM_X, data)` |
| P8 | `p11_session.generate_random(N_bits)` | `generate_random(raw, sh, N_bits // 8)` — fork uses **bits**, raw uses **bytes** |
| P9 | `p11_session.create_object({Attribute.X: v, ...})` | `create_object(raw, sh, {int(CKA_X): v, ...})` — **string values (LABEL, APPLICATION) must be `.encode("utf-8")` to bytes**; use `attr_bytes` for labels, NOT `attr_string` (which is for CK_CHAR padding) |
| P10 | `key[Attribute.VALUE]` or `key.key_type` | `read_attributes(raw, sh, h, [int(CKA_VALUE)])[int(CKA_VALUE)]` — ULONG attrs return `int`, compare with `int(CKK_AES)` |
| P11 | `key.destroy()` | `destroy_quietly(raw, sh, h)` |
| P12 | `p11_session.get_objects({...})` | `find_objects(raw, sh, template(...))` |
| P13 | `encode_named_curve_parameters("secp256r1")` | `from pkcs11_check.raw.ec import encode_named_curve_parameters` (same function name) |
| P14 | `except pkcs11.exceptions.PKCS11Error:` | Use raw `C_*` call, check `rv` against **specific** acceptable CKR codes |
| P15 | `key.encrypt(pt, mechanism_param=iv)` (default) | `encrypt_single(raw, sh, h, CKM_AES_CBC_PAD, pt, mech_param=mech_bytes(CKM_AES_CBC_PAD, iv))` — **fork default is `CKM_AES_CBC_PAD`, NOT `CKM_AES_CBC`** |
| P16 | `Mechanism.SHA256_RSA_PKCS_PSS` + `(hash, mgf, salt)` | `mech_pss(CKM_SHA256_RSA_PKCS_PSS, hash_mech=int(CKM_SHA256), mgf=int(CKG_MGF1_SHA256), salt_len=32)` |
| P17 | `has_mechanism(p11_module, "NAME")` | `rs.has_mechanism("NAME")` (cached on `RawSession` dataclass) |
| P18 | `wrap_key.wrap_key(target, mechanism=M)` | `wrap_key(raw, sh, wrap_h, target_h, CKM_X)` |
| P19 | `wrap_key.unwrap_key(ObjClass, KeyType, data, mechanism=M, template={...})` | `unwrap_key(raw, sh, wrap_h, data, CKM_X, attrs={...})` |
| P20 | `generate_key(KeyType.GENERIC_SECRET, N, ...)` | `gen_aes_key(raw, sh, N, mechanism=CKM_GENERIC_SECRET_KEY_GEN, attrs={int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET), ...})` — **must include `CKA_KEY_TYPE` in attrs** |
| P21 | `generate_key(KeyType.AES, N, label="foo")` | `gen_aes_key(raw, sh, N, attrs={int(CKA_LABEL): b"foo"})` — labels must be bytes |

### Bits-to-bytes conversion audit (P8)

Every `generate_random` call must convert bits→bytes. Known call sites:

| File | Fork call | Raw call |
|---|---|---|
| test_slot.py:21 | `generate_random(256)` | `generate_random(raw, sh, 32)` |
| test_encrypt.py:26,41,77 | `generate_random(128)` | `generate_random(raw, sh, 16)` |
| test_errors.py:66 | `generate_random(2048)` | `generate_random(raw, sh, 256)` |
| test_errors.py:143 | `generate_random(8192)` | `generate_random(raw, sh, 1024)` |
| test_errors.py:148 | `generate_random(8)` | `generate_random(raw, sh, 1)` |

---

## File Structure

### New files
- `tests/test_raw_fixtures.py` — meta-tests for the new fixture and helpers

### Modified files
- `src/pkcs11_check/raw/recipes.py` — add `create_object()`, `get_mechanism_list()`, add `str` handling to `_pack_attrs()`
- `src/pkcs11_check/fixtures.py` — add `RawSession` dataclass, `p11_raw_session` fixture
- `src/pkcs11_check/testcases/conftest.py` — no `has_mechanism_raw` needed (caching lives on `RawSession`)
- `src/pkcs11_check/testcases/test_slot.py` — migrate (52 lines)
- `src/pkcs11_check/testcases/test_interface.py` — migrate (100 lines)
- `src/pkcs11_check/testcases/test_digest.py` — migrate (167 lines)
- `src/pkcs11_check/testcases/test_encrypt.py` — migrate (140 lines)
- `src/pkcs11_check/testcases/test_generic_secret.py` — migrate (99 lines)
- `src/pkcs11_check/testcases/test_errors.py` — migrate (171 lines)
- `src/pkcs11_check/testcases/test_sign.py` — migrate (192 lines)
- `src/pkcs11_check/testcases/test_session_info.py` — migrate (91 lines)
- `src/pkcs11_check/testcases/test_data_objects.py` — migrate (267 lines)
- `src/pkcs11_check/testcases/test_key_lifecycle.py` — migrate (224 lines)

---

## Task 0: Capture Pre-migration Baseline

- [ ] **Step 1: Run baseline and save results**

```bash
bash local-builds/test.sh softhsm2 -k "test_slot or test_interface or test_digest or test_encrypt or test_generic_secret or test_errors or test_sign or test_session_info or test_data_objects or test_key_lifecycle" -v 2>&1 | tee /tmp/batch1-baseline.txt | tail -5
```

Record the pass/skip/xfail/fail counts. After migration, these must be identical.

---

## Task 1: Infrastructure — Raw Session Fixture and Helpers

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py` (add `create_object`, `get_mechanism_list`, str support in `_pack_attrs`)
- Modify: `src/pkcs11_check/fixtures.py` (add `RawSession` dataclass, `p11_raw_session`)
- Modify: `src/pkcs11_check/plugin.py` (add `p11_raw_session` to fixture imports)
- Create: `tests/test_raw_fixtures.py`

### 1a: Add str support to `_pack_attrs` and `create_object` recipe

- [ ] **Step 1: Write failing test for create_object**

In `tests/test_raw_fixtures.py`:

```python
"""Meta-tests for raw migration infrastructure."""
from __future__ import annotations

from pkcs11_check.raw.recipes import create_object


def test_create_object_importable() -> None:
    """create_object recipe exists and is importable."""
    assert callable(create_object)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_raw_fixtures.py::test_create_object_importable -v`
Expected: FAIL with `ImportError: cannot import name 'create_object'`

- [ ] **Step 3: Add str handling to `_pack_attrs` and implement `create_object`**

In `src/pkcs11_check/raw/recipes.py`, add `str` case to `_pack_attrs`:

```python
def _pack_attrs(
    attrs: dict[int, Any] | None,
    *,
    skip: set[int] | None = None,
) -> list[Any]:
    """Convert a {attr_type: value} dict to a list of PackedAttributes.

    Supports bool, int, bytes/bytearray, and str values.
    str values are auto-encoded to UTF-8 bytes (for CKA_LABEL, CKA_APPLICATION etc).
    """
    if not attrs:
        return []
    result = []
    for attr_type, value in attrs.items():
        if skip and int(attr_type) in skip:
            continue
        if isinstance(value, bool):
            result.append(attr_bool(attr_type, value))
        elif isinstance(value, int):
            result.append(attr_ulong(attr_type, value))
        elif isinstance(value, str):
            result.append(attr_bytes(attr_type, value.encode("utf-8")))
        elif isinstance(value, (bytes, bytearray)):
            result.append(attr_bytes(attr_type, value))
        else:
            raise TypeError(
                f"Unsupported attr type {type(value)} for {attr_type}"
            )
    return result
```

Add `create_object` after `import_secret_key`:

```python
def create_object(
    raw: RawPKCS11,
    session: int,
    attrs: dict[int, Any],
) -> int:
    """Create a PKCS#11 object with arbitrary attributes. Returns handle.

    attrs maps CKA_* int constants to values (bool, int, bytes, or str).
    str values auto-encode to UTF-8. For secret key import, prefer
    import_secret_key() which handles CKA_CLASS/CKA_KEY_TYPE/CKA_VALUE.
    """
    packed = _pack_attrs(attrs)
    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(int(rv), CKR_OK)
    return int(handle.value)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_raw_fixtures.py::test_create_object_importable -v`
Expected: PASS

### 1b: Add `get_mechanism_list` recipe

- [ ] **Step 5: Implement get_mechanism_list in recipes.py**

```python
def get_mechanism_list(raw: RawPKCS11, slot_id: int) -> list[int]:
    """Get mechanisms supported by a slot. Returns list of CKM_* ints."""
    count = CK_ULONG(0)
    rv = raw.C_GetMechanismList(slot_id, None, byref(count))
    expect_rv(int(rv), CKR_OK)
    if count.value == 0:
        return []
    from .types_std import CK_MECHANISM_TYPE
    mechs = (CK_MECHANISM_TYPE * int(count.value))()
    rv = raw.C_GetMechanismList(slot_id, mechs, byref(count))
    expect_rv(int(rv), CKR_OK)
    return [int(mechs[i]) for i in range(int(count.value))]
```

### 1c: Add `RawSession` dataclass and `p11_raw_session` fixture

- [ ] **Step 6: Add RawSession dataclass and fixture to fixtures.py**

`RawSession` is a **dataclass** (not NamedTuple) to support the lazy `mechanisms` property and `has_mechanism()` method. Tests access fields via `rs.raw`, `rs.sh`, `rs.slot_id`.

```python
from dataclasses import dataclass, field

from pkcs11_check.raw.api import RawPKCS11


@dataclass
class RawSession:
    """Raw PKCS#11 session for migrated tests.

    Mechanism list is cached lazily on first access — raw package stays
    stateless, caching is fixture-owned and dies with the session.
    """
    raw: RawPKCS11
    sh: int
    slot_id: int
    _mechanisms: frozenset[str] | None = field(default=None, repr=False)

    @property
    def mechanisms(self) -> frozenset[str]:
        """Cached mechanism name set (both 'CKM_AES_ECB' and 'AES_ECB' forms)."""
        if self._mechanisms is None:
            from pkcs11_check.raw.recipes import get_mechanism_list
            from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
            mechs = get_mechanism_list(self.raw, self.slot_id)
            names: set[str] = set()
            for m in mechs:
                mname = MECHANISM_NAMES.get(m, "")
                if mname:
                    names.add(mname)
                    if mname.startswith("CKM_"):
                        names.add(mname[4:])
            self._mechanisms = frozenset(names)
        return self._mechanisms

    def has_mechanism(self, name: str) -> bool:
        """Check if a mechanism is supported by name (prefix-optional)."""
        return name in self.mechanisms


@pytest.fixture
def p11_raw_session(
    p11_module: P11Module, p11_config: P11TestConfig,
) -> Generator[RawSession, None, None]:
    """Open a raw PKCS#11 session bridged from the loaded module.

    Yields RawSession with raw, session_handle, slot_id, and cached
    mechanism discovery. Handles login/logout.

    Note: this opens a separate session from p11_session. Both can coexist
    because PKCS#11 login is per-token, and login_user() accepts
    CKR_USER_ALREADY_LOGGED_IN.
    """
    from pkcs11_check.raw.bridge import raw_from_module
    from pkcs11_check.raw.bootstrap import (
        close_session_quietly,
        get_slot_ids,
        login_user,
        open_session as raw_open_session,
    )
    from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER

    raw = raw_from_module(p11_module)
    slots = get_slot_ids(raw)
    slot_idx = p11_config.slot if p11_config.slot is not None else 0
    slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]

    flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
    sh = raw_open_session(raw, slot_id, flags)

    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    if pin is not None:
        login_user(raw, sh, int(CKU_USER), pin.encode("utf-8"))

    try:
        yield RawSession(raw, sh, slot_id)
    finally:
        if pin is not None:
            raw.C_Logout(sh)  # returns CKR int, never raises
        close_session_quietly(raw, sh)
```

- [ ] **Step 7: Register fixture in plugin.py**

Add `p11_raw_session` and `RawSession` to the imports in `src/pkcs11_check/plugin.py`:

```python
from pkcs11_check.fixtures import (
    RawSession,
    p11_config,
    p11_interface_version,
    p11_module,
    p11_raw_session,
    p11_session,
)
```

Without this, pytest will not discover the fixture.

- [ ] **Step 8: Run existing meta-tests to verify no regressions**

Run: `uv run python -m pytest tests/ -v --timeout=30`
Expected: All existing tests PASS

- [ ] **Step 9: Commit infrastructure**

```bash
git add src/pkcs11_check/raw/recipes.py src/pkcs11_check/fixtures.py \
        src/pkcs11_check/plugin.py tests/test_raw_fixtures.py
git commit -m "feat: add raw migration infrastructure (RawSession, create_object, get_mechanism_list)"
```

---

## Task 2: Migrate test_slot.py (52 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_slot.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_slot -v`

**Current imports:** `from pkcs11_check.testcases.conftest import mech_name` — no direct fork imports.
**Fork API used:** `p11_session.generate_random()`, `p11_module.get_slots()`, `slot.get_mechanisms()`
**Fixtures:** `p11_session`, `p11_module`

- [ ] **Step 1: Rewrite test_slot.py**

Replace entire file. Key changes:
- `p11_session` → `p11_raw_session` (access as `rs.raw`, `rs.sh`, `rs.slot_id`)
- `p11_module.get_slots()` → `get_mechanism_list(rs.raw, rs.slot_id)`
- `p11_session.generate_random(256)` → `generate_random(rs.raw, rs.sh, 32)` (P8: 256 bits = 32 bytes)
- `mech_name(m)` → `MECHANISM_NAMES.get(m, "")`

```python
"""Tests for PKCS#11 slot, token, and session management."""
from __future__ import annotations
from typing import Any
import pytest
from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.recipes import generate_random, get_mechanism_list

pytestmark = pytest.mark.smoke


class TestSessionManagement:
    def test_session_is_open(self, p11_raw_session: Any) -> None:
        """Session is usable after fixture setup."""
        rs = p11_raw_session
        assert rs.sh != 0

    def test_generate_random(self, p11_raw_session: Any) -> None:
        """Generate random bytes via the session."""
        rs = p11_raw_session
        random_bytes = generate_random(rs.raw, rs.sh, 32)
        assert len(random_bytes) == 32
        assert random_bytes != bytes(32)

    def test_generate_random_different_each_time(self, p11_raw_session: Any) -> None:
        """Two random generations should differ."""
        rs = p11_raw_session
        r1 = generate_random(rs.raw, rs.sh, 32)
        r2 = generate_random(rs.raw, rs.sh, 32)
        assert r1 != r2


class TestMechanismDiscovery:
    def test_slot_has_mechanisms(self, p11_raw_session: Any) -> None:
        """Slot reports available mechanisms."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        assert len(mechanisms) > 0

    def test_aes_mechanism_available(self, p11_raw_session: Any) -> None:
        """AES should be available on any reasonable PKCS#11 module."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        aes_mechs = [m for m in mechanisms if "AES" in MECHANISM_NAMES.get(m, "")]
        assert len(aes_mechs) > 0, "No AES mechanisms found"

    def test_rsa_mechanism_available(self, p11_raw_session: Any) -> None:
        """RSA should be available on any reasonable PKCS#11 module."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        rsa_mechs = [m for m in mechanisms if "RSA" in MECHANISM_NAMES.get(m, "")]
        assert len(rsa_mechs) > 0, "No RSA mechanisms found"
```

- [ ] **Step 2: Run tests against SoftHSM2**

Run: `bash local-builds/test.sh softhsm2 -k test_slot -v`
Expected: All 6 tests PASS

- [ ] **Step 3: Verify no fork imports remain**

Run: `grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_slot.py`
Expected: No matches

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/test_slot.py
git commit -m "migrate: test_slot.py to raw API"
```

---

## Task 3: Migrate test_interface.py (100 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_interface.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_interface -v`

**Fork usage:** Only lines 67-84 (TestInterfaceV30.test_v30_encrypt_decrypt_aes) use fork crypto API. Other tests use `p11_module`/`p11_interface_version` which are infrastructure fixtures (remain until fork removal).

- [ ] **Step 1: Migrate the v3.0 AES test**

Replace lines 66-84. Add raw imports at top. The fork default mechanism is `CKM_AES_CBC_PAD` (P15).

```python
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT, CKA_ENCRYPT, CKA_SENSITIVE, CKA_TOKEN, CKM_AES_CBC_PAD,
)

# In TestInterfaceV30:
def test_v30_encrypt_decrypt_aes(self, p11_raw_session: Any) -> None:
    """v3.0 AES encrypt/decrypt round-trip via v3.0 function list."""
    rs = p11_raw_session
    from pkcs11_check.raw.recipes import decrypt_single, encrypt_single, gen_aes_key, destroy_quietly
    from pkcs11_check.raw.pack import mech_bytes

    key = gen_aes_key(rs.raw, rs.sh, 256, attrs={
        int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True,
        int(CKA_TOKEN): False, int(CKA_SENSITIVE): False,
    })
    try:
        iv = b"\x00" * 16
        plaintext = b"v3.0 interface AES test data 123"
        ciphertext = encrypt_single(
            rs.raw, rs.sh, key, CKM_AES_CBC_PAD, plaintext,
            mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
        )
        recovered = decrypt_single(
            rs.raw, rs.sh, key, CKM_AES_CBC_PAD, ciphertext,
            mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
        )
        assert recovered == plaintext
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
```

- [ ] **Step 2: Run tests**

Run: `bash local-builds/test.sh softhsm2 -k test_interface -v`
Expected: All tests PASS

- [ ] **Step 3: Verify and commit**

```bash
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_interface.py
git add src/pkcs11_check/testcases/test_interface.py
git commit -m "migrate: test_interface.py to raw API"
```

---

## Task 4: Migrate test_digest.py (167 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_digest.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_digest -v`

**Key complexity:** TestDigestKey tests call `C_DigestKey` — no recipe exists, use inline raw calls. Check `CKR_FUNCTION_NOT_SUPPORTED` specifically (not generic catch).

- [ ] **Step 1: Rewrite test_digest.py**

Key changes:
- `Mechanism.SHA_1` → `CKM_SHA_1`, `Mechanism.SHA256` → `CKM_SHA256`, etc.
- `p11_session.digest(data, mechanism=M)` → `digest_single(rs.raw, rs.sh, CKM_X, data)`
- `FunctionNotSupported` catch → check `rv == int(CKR_FUNCTION_NOT_SUPPORTED)`
- DigestKey: inline `C_DigestInit` + `C_DigestKey` + `C_DigestFinal`
- `key[Attribute.VALUE]` → `read_attributes(rs.raw, rs.sh, key, [int(CKA_VALUE)])[int(CKA_VALUE)]`

DigestKey pattern:
```python
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

mech = mech_simple(CKM_SHA256)
rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
expect_rv(int(rv), CKR_OK)
rv = int(rs.raw.C_DigestKey(rs.sh, key_handle))
if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
    pytest.skip("C_DigestKey not supported by this module")
expect_rv(rv, CKR_OK)
# C_DigestFinal (two-call)
out_len = CK_ULONG(0)
rv = rs.raw.C_DigestFinal(rs.sh, None, byref(out_len))
expect_rv(int(rv), CKR_OK)
out_buf = (ctypes.c_ubyte * out_len.value)()
rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
expect_rv(int(rv), CKR_OK)
digest = bytes(out_buf[:out_len.value])
```

For `test_digest_key_with_data` (mixed data + key digest), insert a `C_DigestUpdate` call between `C_DigestInit` and `C_DigestKey`:
```python
# After C_DigestInit, before C_DigestKey:
in_buf = (ctypes.c_ubyte * len(data_prefix))(*data_prefix)
rv = rs.raw.C_DigestUpdate(rs.sh, in_buf, len(data_prefix))
expect_rv(int(rv), CKR_OK)
# Then C_DigestKey, then C_DigestFinal as above
```

For `test_digest_key_matches_hashlib` and `test_digest_key_256bit`, skip `C_DigestUpdate` — go straight from `C_DigestInit` to `C_DigestKey`.

- [ ] **Step 2: Run tests**

Run: `bash local-builds/test.sh softhsm2 -k test_digest -v`

- [ ] **Step 3: Verify and commit**

```bash
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_digest.py
git add src/pkcs11_check/testcases/test_digest.py
git commit -m "migrate: test_digest.py to raw API (including C_DigestKey)"
```

---

## Task 5: Migrate test_encrypt.py (140 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_encrypt.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_encrypt -v`

**Critical:** Fork default encrypt mechanism is `CKM_AES_CBC_PAD` (NOT `CKM_AES_CBC`). All calls like `key.encrypt(pt, mechanism_param=iv)` without explicit `mechanism=` use CBC-PAD.

- [ ] **Step 1: Rewrite test_encrypt.py**

**TestAESEncryption:**
- Default mechanism calls (lines 30, 34, 44-45, 79-80) → `CKM_AES_CBC_PAD` with `mech_bytes(CKM_AES_CBC_PAD, iv)` (P15)
- `key.encrypt(pt, mechanism=Mechanism.AES_ECB)` → `encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)`
- `generate_random(128)` → `generate_random(rs.raw, rs.sh, 16)` (P8: 128 bits = 16 bytes)
- `key.key_type` → `read_attributes(rs.raw, rs.sh, key, [int(CKA_KEY_TYPE)])[int(CKA_KEY_TYPE)]` compared against `int(CKK_AES)` (P10)
- All keys destroyed in `finally` blocks (P11)

**TestRSAEncryption:**
- `generate_keypair(...)` → `gen_rsa_keypair(rs.raw, rs.sh, 2048, ...)` (P2)
- `Mechanism.RSA_PKCS` → `CKM_RSA_PKCS` with `mech_simple`
- `Mechanism.RSA_PKCS_OAEP` → `mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=int(CKM_SHA_1), mgf=int(CKG_MGF1_SHA1))` — OAEP defaults in PKCS#11 spec are SHA-1/MGF1-SHA1
- Destroy both pub and priv in `finally` (P11)

- [ ] **Step 2: Run tests**

Run: `bash local-builds/test.sh softhsm2 -k test_encrypt -v`
Expected: All tests PASS

- [ ] **Step 3: Verify and commit**

```bash
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_encrypt.py
git add src/pkcs11_check/testcases/test_encrypt.py
git commit -m "migrate: test_encrypt.py to raw API (AES-CBC-PAD/ECB, RSA-PKCS/OAEP)"
```

---

## Task 6: Migrate test_generic_secret.py (99 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_generic_secret.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_generic_secret -v`

**Critical:** `gen_aes_key` doesn't set `CKA_KEY_TYPE`. For generic secret keys, **must pass `CKA_KEY_TYPE: int(CKK_GENERIC_SECRET)` in attrs** (P20).

- [ ] **Step 1: Rewrite test_generic_secret.py**

**TestGenericSecretKeyGen:**
- `has_mechanism(p11_module, "GENERIC_SECRET_KEY_GEN")` → `rs.has_mechanism("GENERIC_SECRET_KEY_GEN")` (P17)
- `generate_key(KeyType.GENERIC_SECRET, bits, ...)` →
  ```python
  gen_aes_key(rs.raw, rs.sh, bits,
      mechanism=CKM_GENERIC_SECRET_KEY_GEN,
      attrs={int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET),
             int(CKA_SENSITIVE): False, int(CKA_EXTRACTABLE): True})
  ```

**TestGenericSecretHMAC:**
- `create_object({...})` → `create_object(rs.raw, rs.sh, {...})` with all attrs as `int(CKA_*)` keys (P9)
- `key.sign(data, mechanism=Mechanism.SHA256_HMAC)` → `sign_single(rs.raw, rs.sh, key_h, CKM_SHA256_HMAC, data)` (P5)

- [ ] **Step 2: Run tests and commit**

```bash
bash local-builds/test.sh softhsm2 -k test_generic_secret -v
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_generic_secret.py
git add src/pkcs11_check/testcases/test_generic_secret.py
git commit -m "migrate: test_generic_secret.py to raw API"
```

---

## Task 7: Migrate test_errors.py (171 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_errors.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_errors -v`

**Critical:** Generic `except PKCS11Error: pass` patterns. Migration uses raw C_* calls with **specific acceptable CKR codes** per test (satisfies CLAUDE.md). Default encrypt mechanism is `CKM_AES_CBC_PAD` (P15).

### Acceptable CKR codes per error test

| Test method | Acceptable non-OK CKR codes |
|---|---|
| `test_invalid_mechanism_param` | `CKR_MECHANISM_PARAM_INVALID`, `CKR_MECHANISM_INVALID`, `CKR_ARGUMENTS_BAD`, `CKR_DATA_LEN_RANGE` |
| `test_generate_key_invalid_size` | `CKR_KEY_SIZE_RANGE`, `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_MECHANISM_INVALID`, `CKR_ARGUMENTS_BAD`, `CKR_TEMPLATE_INCOMPLETE` |
| `test_verify_with_wrong_mechanism` | `CKR_SIGNATURE_INVALID`, `CKR_SIGNATURE_LEN_RANGE`, `CKR_GENERAL_ERROR` |
| `test_encrypt_with_sign_key` | `CKR_KEY_FUNCTION_NOT_PERMITTED`, `CKR_KEY_TYPE_INCONSISTENT`, `CKR_MECHANISM_INVALID`, `CKR_ARGUMENTS_BAD` |
| `test_decrypt_garbage` | `CKR_ENCRYPTED_DATA_INVALID`, `CKR_DATA_LEN_RANGE`, `CKR_GENERAL_ERROR`, `CKR_ENCRYPTED_DATA_LEN_RANGE` |
| `test_encrypt_empty_data` | `CKR_DATA_LEN_RANGE`, `CKR_ARGUMENTS_BAD`, `CKR_MECHANISM_PARAM_INVALID` |
| `test_sign_empty_data` | `CKR_DATA_LEN_RANGE`, `CKR_ARGUMENTS_BAD` |
| `test_use_destroyed_key` | any non-OK (assert `rv != CKR_OK`) |

Pattern:
```python
# Define acceptable failure CKRs at module level
_INVALID_PARAM_RVS = {int(c) for c in (
    CKR_MECHANISM_PARAM_INVALID, CKR_MECHANISM_INVALID,
    CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE,
)}

# In test:
rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key))
if rv != int(CKR_OK):
    assert rv in _INVALID_PARAM_RVS, f"Unexpected CKR: {ckr_name(rv)}"
    return
# ... continue if init succeeded
```

Also fix:
- `generate_random(2048)` → `generate_random(rs.raw, rs.sh, 256)` (P8: 2048 bits = 256 bytes)
- `generate_random(8192)` → `generate_random(rs.raw, rs.sh, 1024)` (P8: 8192 bits = 1024 bytes)
- `generate_random(8)` → `generate_random(rs.raw, rs.sh, 1)` (P8: 8 bits = 1 byte)
- `generate_key(KeyType.AES, 256, label=f"bulk-{i}")` → `gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): f"bulk-{i}".encode()})` (P21)

- [ ] **Step 1: Rewrite test_errors.py with specific CKR codes**

- [ ] **Step 2: Run tests**

Run: `bash local-builds/test.sh softhsm2 -k test_errors -v`
Expected: Same pass/fail/skip counts as baseline

- [ ] **Step 3: Verify and commit**

```bash
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_errors.py
git add src/pkcs11_check/testcases/test_errors.py
git commit -m "migrate: test_errors.py to raw API (specific CKR codes per error test)"
```

---

## Task 8: Migrate test_sign.py (192 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_sign.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_sign -v`

**Key complexity:** PSS params, ECDSA, DSA (complex), HMAC generic secret keys.

- [ ] **Step 1: Rewrite test_sign.py**

**TestRSASignature:**
- `generate_keypair(KeyType.RSA, 2048)` → `gen_rsa_keypair(rs.raw, rs.sh, 2048)` (P2)
- Sign/verify → `sign_single`/`verify_single` (P5/P6)
- PSS: `(Mechanism.SHA256, MGF.SHA256, 32)` → `mech_pss(CKM_SHA256_RSA_PKCS_PSS, hash_mech=int(CKM_SHA256), mgf=int(CKG_MGF1_SHA256), salt_len=32)` (P16)
- Tamper detection: `verify_single` returns `False` for invalid signatures (P6 note — stricter than fork)
- Destroy keys in `finally` (P11)

**TestECDSASignature:**
- `_generate_ec_keypair()` → `gen_ec_keypair(rs.raw, rs.sh, encode_named_curve_parameters(curve))` (P13)
- ECDSA sign → `sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)` (P5)

**TestHMACSign:**
- Generic secret key: `gen_aes_key(rs.raw, rs.sh, 256, mechanism=CKM_GENERIC_SECRET_KEY_GEN, attrs={int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET), int(CKA_SIGN): True, int(CKA_VERIFY): True, int(CKA_TOKEN): False})` (P20)

**TestDSASignature — full raw implementation:**

DSA requires 3-step domain parameter generation. Full code:
```python
def test_dsa_generate_and_sign(self, p11_raw_session: Any) -> None:
    """Generate DSA params + keypair, sign and verify."""
    rs = p11_raw_session
    if not rs.has_mechanism("DSA_SHA256"):
        pytest.skip("DSA_SHA256 not supported")

    # Step 1: Generate DSA domain parameters
    dsa_param_tmpl = template(attr_ulong(CKA_PRIME_BITS, 2048))
    mech = mech_simple(CKM_DSA_PARAMETER_GEN)
    param_obj = CK_OBJECT_HANDLE(0)
    rv = int(rs.raw.C_GenerateKey(
        rs.sh, mech.byref(), dsa_param_tmpl.ptr, dsa_param_tmpl.count,
        byref(param_obj),
    ))
    if rv != int(CKR_OK):
        pytest.skip(f"DSA parameter generation not supported: {ckr_name(rv)}")

    try:
        # Step 2: Extract P, Q, G
        params = read_attributes(rs.raw, rs.sh, int(param_obj.value),
            [int(CKA_PRIME), int(CKA_SUBPRIME), int(CKA_BASE)])
        prime = params[int(CKA_PRIME)]
        subprime = params[int(CKA_SUBPRIME)]
        base = params[int(CKA_BASE)]

        # Step 3: Generate DSA keypair
        pub_tmpl = template(
            attr_bytes(CKA_PRIME, prime),
            attr_bytes(CKA_SUBPRIME, subprime),
            attr_bytes(CKA_BASE, base),
        )
        priv_tmpl = template()  # empty
        kp_mech = mech_simple(CKM_DSA_KEY_PAIR_GEN)
        pub_h = CK_OBJECT_HANDLE(0)
        priv_h = CK_OBJECT_HANDLE(0)
        rv = int(rs.raw.C_GenerateKeyPair(
            rs.sh, kp_mech.byref(),
            pub_tmpl.ptr, pub_tmpl.count,
            priv_tmpl.ptr, priv_tmpl.count,
            byref(pub_h), byref(priv_h),
        ))
        if rv != int(CKR_OK):
            pytest.skip(f"DSA key generation not supported: {ckr_name(rv)}")

        # Sign and verify
        data = b"DSA test data for signing"
        sig = sign_single(rs.raw, rs.sh, int(priv_h.value), CKM_DSA_SHA256, data)
        assert verify_single(rs.raw, rs.sh, int(pub_h.value), CKM_DSA_SHA256, data, sig)
    finally:
        destroy_quietly(rs.raw, rs.sh, int(param_obj.value))
        destroy_quietly(rs.raw, rs.sh, int(pub_h.value))
        destroy_quietly(rs.raw, rs.sh, int(priv_h.value))
```

Note: `CKA_PRIME_BITS`, `CKA_PRIME`, `CKA_SUBPRIME`, `CKA_BASE`, `CKM_DSA_PARAMETER_GEN`, `CKM_DSA_KEY_PAIR_GEN` must be imported from `types_std`.

- [ ] **Step 2: Run tests**

Run: `bash local-builds/test.sh softhsm2 -k test_sign -v`
Expected: Same pass/skip counts (DSA usually skipped on SoftHSM2)

- [ ] **Step 3: Verify and commit**

```bash
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_sign.py
git add src/pkcs11_check/testcases/test_sign.py
git commit -m "migrate: test_sign.py to raw API (RSA-PKCS/PSS, ECDSA, HMAC, DSA)"
```

---

## Task 9: Migrate test_session_info.py (91 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_session_info.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_session_info -v`

**Key complexity:** Opens its own sessions. Use raw `C_OpenSession`, `C_GetSessionInfo`, `C_Login`.

- [ ] **Step 1: Rewrite test_session_info.py**

- `p11_module.get_token()` → use `rs.slot_id` from `p11_raw_session`
- `token.open(rw=True, user_pin=pin_str)` → `open_session(rs.raw, rs.slot_id, flags)` + `login_user()`
- `session.rw` → `C_GetSessionInfo()` + check `info.flags & CKF_RW_SESSION`
- `session.close()` → `close_session_quietly(rs.raw, test_sh)`
- RO session: use `CKF_SERIAL_SESSION` only (no `CKF_RW_SESSION`)
- RO session TOKEN=True test: raw `C_GenerateKey` call, check specific CKR codes:

```python
# Generate key with TOKEN=True on RO session — must fail
tmpl = template(
    attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)),
    attr_ulong(CKA_KEY_TYPE, int(CKK_AES)),
    attr_ulong(CKA_VALUE_LEN, 16),
    attr_bool(CKA_TOKEN, True),
)
mech = mech_simple(CKM_AES_KEY_GEN)
key_h = CK_OBJECT_HANDLE(0)
rv = int(rs.raw.C_GenerateKey(
    ro_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h),
))
assert rv in (int(CKR_SESSION_READ_ONLY), int(CKR_USER_NOT_LOGGED_IN),
              int(CKR_SESSION_READ_ONLY_EXISTS)), \
    f"Expected CKR_SESSION_READ_ONLY, got {ckr_name(rv)}"
```

```python
from pkcs11_check.raw.types_std import (
    CK_SESSION_INFO, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKU_USER,
)

info = CK_SESSION_INFO()
rv = rs.raw.C_GetSessionInfo(test_sh, byref(info))
expect_rv(int(rv), CKR_OK)
is_rw = bool(info.flags & int(CKF_RW_SESSION))
```

PIN extraction stays the same — get from `p11_config.pin`.

- [ ] **Step 2: Run tests and commit**

```bash
bash local-builds/test.sh softhsm2 -k test_session_info -v
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_session_info.py
git add src/pkcs11_check/testcases/test_session_info.py
git commit -m "migrate: test_session_info.py to raw API (C_GetSessionInfo, RW/RO)"
```

---

## Task 10: Migrate test_data_objects.py (267 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_data_objects.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_data_objects -v`

**Key complexity:** Heavy `create_object`/`find_objects`/`read_attributes` use. Token persistence test opens its own sessions. String attributes must be bytes (P9).

- [ ] **Step 1: Rewrite test_data_objects.py**

**create_object calls:** String attrs (LABEL, APPLICATION) are auto-encoded by `_pack_attrs` str support. But raw `read_attributes` returns bytes — decode when comparing. **This applies to ALL label/application comparisons in the file** (6+ places). Add a file-local helper:

```python
def _read_str(attrs: dict[int, Any], key: int) -> str:
    """Decode a bytes attribute to str."""
    v = attrs[key]
    return v.decode("utf-8") if isinstance(v, bytes) else v

# Usage:
attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_LABEL)])
label_val = _read_str(attrs, int(CKA_LABEL))
```

**find_objects calls:**
```python
tmpl = template(
    attr_ulong(CKA_CLASS, int(CKO_DATA)),
    attr_bytes(CKA_LABEL, label.encode("utf-8")),
)
handles = find_objects(rs.raw, rs.sh, tmpl)
```

**Token persistence test:** Opens its own sessions using raw bootstrap (like test_session_info.py):
```python
from pkcs11_check.raw.bootstrap import open_session as raw_open_session, login_user, close_session_quietly

# Session 1: create
sh1 = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
login_user(rs.raw, sh1, int(CKU_USER), pin_bytes)
try:
    create_object(rs.raw, sh1, {...})
finally:
    close_session_quietly(rs.raw, sh1)

# Session 2: find and verify
sh2 = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
login_user(rs.raw, sh2, int(CKU_USER), pin_bytes)
try:
    handles = find_objects(rs.raw, sh2, tmpl)
    ...
finally:
    # Cleanup: destroy in session 2
    for h in handles:
        rs.raw.C_DestroyObject(sh2, h)  # ignore rv
    close_session_quietly(rs.raw, sh2)
```

- [ ] **Step 2: Run tests and commit**

```bash
bash local-builds/test.sh softhsm2 -k test_data_objects -v
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_data_objects.py
git add src/pkcs11_check/testcases/test_data_objects.py
git commit -m "migrate: test_data_objects.py to raw API (CKO_DATA CRUD, multi-session)"
```

---

## Task 11: Migrate test_key_lifecycle.py (224 lines)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_key_lifecycle.py`
- Test: `bash local-builds/test.sh softhsm2 -k test_key_lifecycle -v`

**Key complexity:** Export/import RSA/EC keys, AES key wrapping, attribute access. EC lifecycle skip must check specific CKR codes (not generic AssertionError).

- [ ] **Step 1: Rewrite test_key_lifecycle.py**

**TestRSAKeyLifecycle:** Export modulus/exponent, import, verify (P10, P9, P6)

**TestAESKeyWrapLifecycle:** Use `wrap_key`/`unwrap_key` recipes (P18/P19). Import recipe as `wrap_key as wrap_key_recipe` to avoid name clash.

**TestECKeyLifecycle:** Use `gen_ec_keypair` (P2/P13). For the skip on unsupported curves, use raw `C_GenerateKeyPair` and check specific CKR codes:
```python
pub_h, priv_h = CK_OBJECT_HANDLE(0), CK_OBJECT_HANDLE(0)
rv = int(rs.raw.C_GenerateKeyPair(
    rs.sh, kp_mech.byref(),
    pub_tmpl.ptr, pub_tmpl.count,
    priv_tmpl.ptr, priv_tmpl.count,
    byref(pub_h), byref(priv_h),
))
# Module responses to unsupported curves vary widely
_CURVE_UNSUPPORTED_RVS = {int(c) for c in (
    CKR_CURVE_NOT_SUPPORTED, CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE, CKR_DEVICE_ERROR, CKR_GENERAL_ERROR,
)}
if rv in _CURVE_UNSUPPORTED_RVS:
    pytest.skip(f"secp256r1 not supported: {ckr_name(rv)}")
expect_rv(rv, CKR_OK)
```

**TestKeyDestroyVerification:** Labels as bytes in attrs (P21), find_objects with `attr_bytes(CKA_LABEL, b"destroy-verify")`.

- [ ] **Step 2: Run tests and commit**

```bash
bash local-builds/test.sh softhsm2 -k test_key_lifecycle -v
grep -n "from pkcs11\|import pkcs11" src/pkcs11_check/testcases/test_key_lifecycle.py
git add src/pkcs11_check/testcases/test_key_lifecycle.py
git commit -m "migrate: test_key_lifecycle.py to raw API (export/import/wrap/unwrap)"
```

---

## Task 12: Final Verification

- [ ] **Step 1: Run all 10 migrated files together**

```bash
bash local-builds/test.sh softhsm2 -k "test_slot or test_interface or test_digest or test_encrypt or test_generic_secret or test_errors or test_sign or test_session_info or test_data_objects or test_key_lifecycle" -v 2>&1 | tee /tmp/batch1-post.txt | tail -5
```

Compare against `/tmp/batch1-baseline.txt`. Pass/skip/xfail counts must match.

- [ ] **Step 2: Verify zero fork imports**

```bash
grep -rn "from pkcs11 \|import pkcs11" src/pkcs11_check/testcases/test_slot.py src/pkcs11_check/testcases/test_interface.py src/pkcs11_check/testcases/test_digest.py src/pkcs11_check/testcases/test_encrypt.py src/pkcs11_check/testcases/test_generic_secret.py src/pkcs11_check/testcases/test_errors.py src/pkcs11_check/testcases/test_sign.py src/pkcs11_check/testcases/test_session_info.py src/pkcs11_check/testcases/test_data_objects.py src/pkcs11_check/testcases/test_key_lifecycle.py
```
Expected: No matches

- [ ] **Step 3: Run full test suite**

```bash
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)"
```

- [ ] **Step 4: Run mypy and ruff**

```bash
uv run mypy src/pkcs11_check/testcases/test_slot.py src/pkcs11_check/testcases/test_encrypt.py src/pkcs11_check/testcases/test_digest.py src/pkcs11_check/testcases/test_sign.py
uv run ruff check src/pkcs11_check/testcases/test_slot.py src/pkcs11_check/testcases/test_interface.py src/pkcs11_check/testcases/test_digest.py src/pkcs11_check/testcases/test_encrypt.py src/pkcs11_check/testcases/test_generic_secret.py src/pkcs11_check/testcases/test_errors.py src/pkcs11_check/testcases/test_sign.py src/pkcs11_check/testcases/test_session_info.py src/pkcs11_check/testcases/test_data_objects.py src/pkcs11_check/testcases/test_key_lifecycle.py
```

- [ ] **Step 5: Update master plan progress**

Edit `docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md`:
Change `- [ ] Sub-project 2: Test Migration Batch 1` to `- [x] Sub-project 2: Test Migration Batch 1`
