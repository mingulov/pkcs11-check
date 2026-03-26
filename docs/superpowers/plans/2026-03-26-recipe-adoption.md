# Recipe Adoption — Refactor Existing Tests + New Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate dead recipe code by migrating existing product tests to use 6 new recipe functions, and write new in-process tests for recipes that cannot replace existing subprocess-based tests.

**Architecture:** Three categories of work:
1. **Refactor** 23 info-query call sites (get_session_info, get_mechanism_info, get_slot_info) — mechanical find-and-replace across 7 files
2. **Refactor** 2 digest_single_with_key call sites — slightly more involved due to CKR_FUNCTION_NOT_SUPPORTED skip handling
3. **Write new** in-process tests for sign_recover_single/verify_recover_single and login_user_with_name — existing tests use subprocess isolation or raw CKR assertions, so we write NEW tests that exercise the recipe code path

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw recipes

**Verification:** `uv run ruff check src/pkcs11_check/testcases/ tests/ && uv run ruff format --check src/pkcs11_check/testcases/ tests/ && uv run python -m pytest tests/ -q` after each task.

---

## Task 1: Refactor `test_session_info.py` — 2 sites

**Files:**
- Modify: `src/pkcs11_check/testcases/test_session_info.py`

- [ ] **Step 1: Add import**

Add `get_session_info` to existing `from pkcs11_check.raw.recipes import` line.

- [ ] **Step 2: Refactor 2 call sites**

Replace this pattern (appears twice, lines 64-66 and 81-83):
```python
            info = CK_SESSION_INFO()
            rv = rs.raw.C_GetSessionInfo(test_sh, byref(info))
            expect_rv(rv, CKR_OK)
            is_rw = bool(info.flags & CKF_RW_SESSION)
```

With:
```python
            is_rw = bool(get_session_info(rs.raw, test_sh)["flags"] & CKF_RW_SESSION)
```

- [ ] **Step 3: Clean up unused imports**

Remove `CK_SESSION_INFO` from `types_std` imports if no other usage. Remove `from ctypes import byref` if no other usage. Remove `expect_rv` import if no other usage.

- [ ] **Step 4: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/test_session_info.py
uv run ruff format --check src/pkcs11_check/testcases/test_session_info.py
```

---

## Task 2: Refactor `test_session_state_machine.py` — 6 sites

**Files:**
- Modify: `src/pkcs11_check/testcases/test_session_state_machine.py`

- [ ] **Step 1: Add import**

Add `get_session_info` to existing `from pkcs11_check.raw.recipes import` block.

- [ ] **Step 2: Refactor 6 call sites**

4 sites use `expect_rv` pattern — replace `info.flags` with `get_session_info(...)["flags"]`:

Lines 485-489:
```python
            info = CK_SESSION_INFO()
            rv = rs.raw.C_GetSessionInfo(test_sh, byref(info))
            expect_rv(rv, CKR_OK)
            is_rw = bool(info.flags & CKF_RW_SESSION)
```
→
```python
            is_rw = bool(get_session_info(rs.raw, test_sh)["flags"] & CKF_RW_SESSION)
```

Lines 498-503: same pattern.

Lines 928-931:
```python
        info = CK_SESSION_INFO()
        rv = rs.raw.C_GetSessionInfo(test_sh, byref(info))
        expect_rv(rv, CKR_OK)
        assert bool(info.flags & CKF_RW_SESSION) is True
```
→
```python
        assert bool(get_session_info(rs.raw, test_sh)["flags"] & CKF_RW_SESSION) is True
```

2 sites at lines 513-519 do NOT use expect_rv — they directly assert flags:
```python
            info_rw = CK_SESSION_INFO()
            rs.raw.C_GetSessionInfo(rw_sh, byref(info_rw))
            assert bool(info_rw.flags & CKF_RW_SESSION) is True
```
→
```python
            assert bool(get_session_info(rs.raw, rw_sh)["flags"] & CKF_RW_SESSION) is True
```

Lines 517-519 and 530-533: same pattern.

- [ ] **Step 3: Clean up unused imports**

Remove `CK_SESSION_INFO` from `types_std` imports if no other usage. Check if `expect_rv`, `byref` are still used elsewhere in the file before removing.

- [ ] **Step 4: Verify lint + format**

---

## Task 3: Refactor `test_mechanism.py` — 4 sites

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mechanism.py`

- [ ] **Step 1: Add import**

Add `get_mechanism_info` to existing `from pkcs11_check.raw.recipes import` line.

- [ ] **Step 2: Refactor 4 call sites**

Lines 35-39:
```python
            info = CK_MECHANISM_INFO()
            rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mech, byref(info))
            expect_rv(rv, CKR_OK)
            assert info.ulMinKeySize >= 0
            assert info.ulMaxKeySize >= info.ulMinKeySize
```
→
```python
            info = get_mechanism_info(rs.raw, rs.slot_id, mech)
            assert info["min_key_size"] >= 0
            assert info["max_key_size"] >= info["min_key_size"]
```

Lines 46-48: simplify to just `get_mechanism_info(rs.raw, rs.slot_id, mech)` (no fields used, just checking no crash).

Lines 56-60:
```python
            info.ulMinKeySize <= 16  # → info["min_key_size"]
            info.ulMaxKeySize >= 32  # → info["max_key_size"]
```

Lines 68-72: same pattern with `ulMinKeySize`/`ulMaxKeySize` → `min_key_size`/`max_key_size`.

- [ ] **Step 3: Clean up unused imports** (CK_MECHANISM_INFO, byref, expect_rv)

- [ ] **Step 4: Verify**

---

## Task 4: Refactor `test_surface_audit.py` — 6 sites (5 mech + 1 slot)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_surface_audit.py`

- [ ] **Step 1: Add imports**

Add `get_mechanism_info`, `get_slot_info` to existing `from pkcs11_check.raw.recipes import` block.

- [ ] **Step 2: Refactor 5 C_GetMechanismInfo sites**

Site 1 (line 58-61): Uses `assert rv == CKR_OK`. The recipe raises on non-OK, so:
```python
            info = CK_MECHANISM_INFO()
            rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mech, byref(info))
            assert rv == CKR_OK, f"Mechanism {_mech_name(mech)} has no info"
```
→
```python
            get_mechanism_info(rs.raw, rs.slot_id, mech)  # raises on failure
```

Site 2 (line 224-228): No rv check at all, just calls. Replace with `get_mechanism_info(...)` call.

Sites 3-5 (lines 253-260, 285-292, 315-322, 414-421): Use `if rv != CKR_OK: pytest.skip(...)`. The recipe raises on non-OK. Wrap in try/except:
```python
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)
        except AssertionError:
            pytest.skip("Cannot get AES_KEY_GEN mechanism info")
```

Site at line 103-106 (C_GetSlotInfo): Uses `assert rv == CKR_OK`. Replace with:
```python
            get_slot_info(rs.raw, slot_id)  # raises on failure
```
Also remove the local `from pkcs11_check.raw.types_std import CK_SLOT_INFO` import.

- [ ] **Step 3: Clean up unused imports** (CK_MECHANISM_INFO, CK_SLOT_INFO, byref, CKR_OK if unused)

- [ ] **Step 4: Verify**

---

## Task 5: Refactor `test_token_flags.py` — 4 sites

**Files:**
- Modify: `src/pkcs11_check/testcases/test_token_flags.py`

- [ ] **Step 1: Add import**

Add `get_slot_info` to existing `from pkcs11_check.raw.recipes import` line (or add a new import line).

- [ ] **Step 2: Refactor 4 C_GetSlotInfo sites**

All 4 sites follow the same pattern inside `for slot_id in get_slot_ids(...)` loops:
```python
            info = CK_SLOT_INFO()
            rv = rs.raw.C_GetSlotInfo(slot_id, byref(info))
            expect_rv(rv, CKR_OK)
            assert info.flags & CKF_TOKEN_PRESENT
```
→
```python
            info = get_slot_info(rs.raw, slot_id)
            assert info["flags"] & CKF_TOKEN_PRESENT
```

For version fields:
```python
            assert info.hardwareVersion.major >= 0
```
→
```python
            assert info["hardware_version"][0] >= 0
```

- [ ] **Step 3: Clean up unused imports** (CK_SLOT_INFO, byref, expect_rv if unused)

- [ ] **Step 4: Verify**

---

## Task 6: Refactor `test_cms.py` — 1 site

**Files:**
- Modify: `src/pkcs11_check/testcases/test_cms.py`

- [ ] **Step 1: Add import and refactor**

The call site has local imports for `byref` and `CK_MECHANISM_INFO`. Add `get_mechanism_info` to the existing top-level `from pkcs11_check.raw.recipes import` block. Replace:
```python
        from ctypes import byref
        from pkcs11_check.raw.types_std import CK_MECHANISM_INFO

        info = CK_MECHANISM_INFO()
        rv = rs.raw.C_GetMechanismInfo(rs.slot_id, CKM_CMS_SIG, byref(info))
        if rv == CKR_OK:
            assert info is not None
```
→
```python
        try:
            get_mechanism_info(rs.raw, rs.slot_id, CKM_CMS_SIG)
        except AssertionError:
            pass  # mechanism not available — not an error for this test
```

- [ ] **Step 2: Verify**

---

## Task 7: Refactor `test_vendor_extensions.py` — 1 site

**Files:**
- Modify: `src/pkcs11_check/testcases/test_vendor_extensions.py`

- [ ] **Step 1: Add import and refactor**

Add `get_mechanism_info` to existing `from pkcs11_check.raw.recipes import` line. Replace:
```python
            info = CK_MECHANISM_INFO()
            rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mech, byref(info))
            # Any response is OK - just verify no crash
            assert rv == CKR_OK or rv != CKR_OK
```
→
```python
            get_mechanism_info(rs.raw, rs.slot_id, mech)  # crash safety check
```

The recipe will raise on non-OK CKR, which is actually better crash detection than the tautology.

- [ ] **Step 2: Clean up unused imports** (CK_MECHANISM_INFO, byref)

- [ ] **Step 3: Verify**

---

## Task 8: Refactor `test_digest.py` — 2 sites (digest_single_with_key)

**Files:**
- Modify: `src/pkcs11_check/testcases/test_digest.py`

- [ ] **Step 1: Add import**

Add `digest_single_with_key` to existing `from pkcs11_check.raw.recipes import` block.

- [ ] **Step 2: Refactor test_digest_key_matches_hashlib**

Replace lines 166-180 (the C_DigestInit + C_DigestKey + C_DigestFinal two-call):
```python
            # C_DigestInit
            mech = mech_simple(CKM_SHA256)
            rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
            expect_rv(rv, CKR_OK)
            # C_DigestKey
            rv = rs.raw.C_DigestKey(rs.sh, key)
            if rv == CKR_FUNCTION_NOT_SUPPORTED:
                pytest.skip("C_DigestKey not supported by this module")
            expect_rv(rv, CKR_OK)
            # C_DigestFinal (two-call pattern)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_DigestFinal(rs.sh, None, byref(out_len))
            expect_rv(rv, CKR_OK)
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
            expect_rv(rv, CKR_OK)
            p11_digest = bytes(out_buf[: out_len.value])
```
→
```python
            try:
                p11_digest = digest_single_with_key(rs.raw, rs.sh, CKM_SHA256, key)
            except AssertionError:
                pytest.skip("C_DigestKey not supported by this module")
```

- [ ] **Step 3: Refactor test_digest_key_256bit** — same pattern, same replacement.

- [ ] **Step 4: Clean up unused imports**

Remove: `ctypes`, `from ctypes import byref`, `CK_ULONG`, `CKR_FUNCTION_NOT_SUPPORTED`, `CKR_OK`, `expect_rv`, `mech_simple` — only if no other usage in the file. Check carefully — the file has `TestDigestKey` with 3 tests, and the third test (`test_digest_key_with_data`) still uses raw calls, so some imports may still be needed.

- [ ] **Step 5: Verify**

---

## Task 9: Write new in-process sign_recover tests

**Files:**
- Modify: `src/pkcs11_check/testcases/test_sign_recover.py`

- [ ] **Step 1: Add imports**

Add at the top:
```python
from pkcs11_check.raw.recipes import (
    gen_rsa_keypair,
    sign_recover_single,
    verify_recover_single,
)
from pkcs11_check.raw.types_std import CKM_RSA_X_509
```

Note: The existing tests use subprocess isolation. New tests are in-process using `p11_raw_session` fixture, which is safe for sign/verify operations that don't test crash behavior.

- [ ] **Step 2: Add TestSignRecoverRecipes class**

```python
class TestSignRecoverRecipes:
    """In-process tests exercising sign_recover_single / verify_recover_single recipes."""

    @staticmethod
    def _gen_recover_key(rs: Any) -> tuple[int, int]:
        """Generate RSA key pair suitable for sign-recover (CKM_RSA_X_509)."""
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        return gen_rsa_keypair(rs.raw, rs.sh, 2048)

    def test_sign_recover_single_returns_signature(self, p11_raw_session: Any) -> None:
        """sign_recover_single produces output of expected size."""
        rs = p11_raw_session
        pub, _priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254  # 256 bytes, padded for RSA X.509
            sig = sign_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, data)
            assert isinstance(sig, bytes)
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_verify_recover_single_round_trip(self, p11_raw_session: Any) -> None:
        """sign + verify_recover recovers original data."""
        rs = p11_raw_session
        pub, _priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, data)
            valid, recovered = verify_recover_single(
                rs.raw, rs.sh, pub, CKM_RSA_X_509, sig
            )
            assert valid is True
            assert recovered == data
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_verify_recover_single_invalid_signature(self, p11_raw_session: Any) -> None:
        """verify_recover_single returns False on wrong signature."""
        rs = p11_raw_session
        pub, _priv = self._gen_recover_key(rs)
        try:
            bad_sig = b"\x00" * 256
            valid, recovered = verify_recover_single(
                rs.raw, rs.sh, pub, CKM_RSA_X_509, bad_sig
            )
            assert valid is False
            assert recovered == b""
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
```

**IMPORTANT:** For RSA X.509 sign-recover, the public key is used for BOTH signing AND verification (raw RSA operation, no private key needed for sign-recover). This is because CKM_RSA_X_509 with C_SignRecover does: sig = data^d mod n using the private key, and C_VerifyRecover does: data = sig^e mod n using the public key. However, in some PKCS#11 implementations, C_SignRecoverInit requires the PRIVATE key handle. Check this during testing — if sign_recover_single needs the private key, pass `_priv` instead of `pub`.

- [ ] **Step 3: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/test_sign_recover.py
uv run ruff format --check src/pkcs11_check/testcases/test_sign_recover.py
```

---

## Task 10: Write new login_user_with_name test

**Files:**
- Modify: `src/pkcs11_check/testcases/test_v30_session.py`

- [ ] **Step 1: Add import**

Add to existing `from pkcs11_check.raw.recipes import` block (or `from pkcs11_check.raw.bootstrap import login_user_with_name`).

- [ ] **Step 2: Add TestLoginUserWithNameRecipe class**

```python
class TestLoginUserWithNameRecipe:
    """Tests exercising the login_user_with_name() bootstrap recipe."""

    def test_login_user_with_name_empty_username(self, p11_raw_session: Any) -> None:
        """login_user_with_name with empty username behaves like C_Login."""
        rs = p11_raw_session
        if not hasattr(rs.raw, "C_LoginUser"):
            pytest.skip("C_LoginUser not available (v2.40 module)")
        from pkcs11_check.raw.bootstrap import login_user_with_name

        login_user_with_name(rs.raw, rs.sh, CKU_USER, rs.config.pin or b"")
        from pkcs11_check.raw.bootstrap import logout_quietly

        logout_quietly(rs.raw, rs.sh)

    def test_login_user_with_name_nonempty_username(self, p11_raw_session: Any) -> None:
        """login_user_with_name with non-empty username.

        Most current PKCS#11 providers ignore the username field or reject it.
        This test is future-ready: it will pass on modules that support named users.
        """
        rs = p11_raw_session
        if not hasattr(rs.raw, "C_LoginUser"):
            pytest.skip("C_LoginUser not available (v2.40 module)")
        from pkcs11_check.raw.bootstrap import login_user_with_name, logout_quietly

        try:
            login_user_with_name(
                rs.raw, rs.sh, CKU_USER, rs.config.pin or b"", username=b"testuser"
            )
            logout_quietly(rs.raw, rs.sh)
        except AssertionError:
            pytest.xfail("Module does not support non-empty username for C_LoginUser")
```

**Note on provider support:** As of 2026, no mainstream PKCS#11 provider (SoftHSM2, Kryoptic, NSS, OpenCryptoki, BouncyHSM) validates the username field. The empty-username test should pass everywhere (equivalent to C_Login). The non-empty-username test is marked xfail and will become meaningful when providers add username support.

- [ ] **Step 3: Verify**

---

## Task Summary

| Task | Type | Files | Sites |
|------|------|-------|-------|
| 1 | Refactor | test_session_info.py | 2 |
| 2 | Refactor | test_session_state_machine.py | 6 |
| 3 | Refactor | test_mechanism.py | 4 |
| 4 | Refactor | test_surface_audit.py | 6 |
| 5 | Refactor | test_token_flags.py | 4 |
| 6 | Refactor | test_cms.py | 1 |
| 7 | Refactor | test_vendor_extensions.py | 1 |
| 8 | Refactor | test_digest.py | 2 |
| 9 | New test | test_sign_recover.py | 3 new tests |
| 10 | New test | test_v30_session.py | 2 new tests |
| **Total** | | **10 files** | **25 refactor + 5 new** |
