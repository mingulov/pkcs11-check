"""CKR compliance tests for C_WrapKey and C_UnwrapKey.

Source: PKCS#11 v3.1 Sec.5.14.3 (C_WrapKey), Sec.5.14.4 (C_UnwrapKey).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, import_secret_key
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases._module_quirks import quirk_extras
from pkcs11_check.testcases.ckr._ckr_spec import CKR_WRAP, assert_ckr
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail

pytestmark = pytest.mark.access


class TestWrapKeyErrors:
    """Error conditions for C_WrapKey (Sec.5.14.3)."""

    def test_key_not_extractable(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Wrapping non-extractable key -> CKR_KEY_UNEXTRACTABLE.

        PKCS#11 v3.1 Sec.5.14.3: C_WrapKey on a key with CKA_EXTRACTABLE=False MUST
        return CKR_KEY_UNEXTRACTABLE.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
        )
        try:
            # Verify the module actually honoured CKA_EXTRACTABLE=False
            check = (CK_ATTRIBUTE * 1)()
            check[0].type = CKA_EXTRACTABLE
            val = CK_BBOOL(0xFF)  # sentinel
            check[0].pValue = ctypes.cast(ctypes.pointer(val), ctypes.c_void_p)
            check[0].ulValueLen = ctypes.sizeof(val)
            rv = rs.raw.C_GetAttributeValue(rs.sh, target, check, 1)
            if rv != CKR_OK or val.value != 0:
                pytest.skip(
                    "Module did not honour CKA_EXTRACTABLE=False on generated key "
                    f"(CKR=0x{rv:08x}, value={val.value})"
                )

            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK on CKA_EXTRACTABLE=False key "
                    "(expected CKR_KEY_UNEXTRACTABLE). Non-extractable keys can be exported.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.5.14.3",
                )
                pytest.fail(
                    "SECURITY: module returns CKR_OK for C_WrapKey on "
                    "CKA_EXTRACTABLE=False key (expected CKR_KEY_UNEXTRACTABLE) — "
                    "non-extractable keys can be exported, defeating the "
                    "extractability access control"
                )
            # CKR_KEY_UNEXTRACTABLE or CKR_KEY_NOT_WRAPPABLE - both acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for wrap -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_WRAP: True},
            purpose="CKR wrap mechanism-invalid setup",
        )
        target = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            purpose="CKR wrap mechanism-invalid target setup",
        )
        try:
            mech = mech_simple(CKM_SHA256)  # Wrong: hash mechanism
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                pytest.fail("Should have rejected SHA256 as wrap mechanism")
            assert_ckr(CKR_WRAP["wrap_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_wrapping_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Stale wrap-key handle -> CKR_WRAPPING_KEY_HANDLE_INVALID.

        PKCS#11 v3.1 Sec.5.14.3: "the key handle specified to be used to
        wrap another key is not valid."

        Use a destroyed handle to guarantee invalidity (handle 0 may be
        rejected earlier with CKR_OBJECT_HANDLE_INVALID).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_WRAP: True})
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        # Destroy the wrap key so its handle is now stale.
        rv = rs.raw.C_DestroyObject(rs.sh, wrap_key)
        if rv != CKR_OK:
            destroy_quietly(rs.raw, rs.sh, target)
            pytest.skip(f"Could not destroy wrap key for stale-handle test (CKR=0x{rv:08x})")
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,  # stale
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK on a destroyed wrap-key handle "
                    "(expected CKR_WRAPPING_KEY_HANDLE_INVALID).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.5.14.3",
                )
                pytest.fail(
                    "Module accepted a stale wrap-key handle "
                    "(expected CKR_WRAPPING_KEY_HANDLE_INVALID)"
                )
            accepted = (
                CKR_WRAPPING_KEY_HANDLE_INVALID,
                CKR_KEY_HANDLE_INVALID,
                CKR_OBJECT_HANDLE_INVALID,
            )
            assert rv in accepted, (
                f"Unexpected CK_RV 0x{rv:08x} on stale wrap-key handle; "
                f"expected one of {[hex(c) for c in accepted]}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, target)

    def test_wrapping_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Wrap key of wrong type for mechanism -> CKR_WRAPPING_KEY_TYPE_INCONSISTENT.

        PKCS#11 v3.1 Sec.5.14.3: "the type of the key specified to wrap
        another key is not consistent with the mechanism specified for
        wrapping."

        Use a CKK_GENERIC_SECRET key (HMAC-style) as the wrap key with
        CKM_AES_KEY_WRAP (which requires an AES key).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        # Import a 32-byte generic-secret as the (wrong-type) wrap key.
        try:
            wrap_key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_GENERIC_SECRET,
                value=b"\x00" * 32,
                attrs={CKA_WRAP: True, CKA_EXTRACTABLE: True},
            )
        except AssertionError as exc:
            pytest.skip(f"Module rejected generic-secret key import for wrap test: {exc}")

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK with a generic-secret wrap key "
                    "for CKM_AES_KEY_WRAP (expected CKR_WRAPPING_KEY_TYPE_INCONSISTENT).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.5.14.3",
                )
                pytest.fail(
                    "Module accepted a generic-secret key for AES wrap "
                    "(expected CKR_WRAPPING_KEY_TYPE_INCONSISTENT)"
                )
            accepted = (
                CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
                CKR_KEY_TYPE_INCONSISTENT,
                CKR_KEY_FUNCTION_NOT_PERMITTED,
            )
            assert rv in accepted, (
                f"Unexpected CK_RV 0x{rv:08x} on type-inconsistent wrap key; "
                f"expected one of {[hex(c) for c in accepted]}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_wrapping_key_size_range(
        self, p11_raw_session: Any, p11_config: Any, ckr_strict: bool
    ) -> None:
        """Wrap key of out-of-range size -> CKR_WRAPPING_KEY_SIZE_RANGE.

        PKCS#11 v3.1 Sec.5.14.3: "the supplied wrapping key's size is
        outside the range of key sizes that it can handle."

        Try to import an undersized AES key (8 bytes / 64 bits) — below
        the AES-128 minimum — and use it for CKM_AES_KEY_WRAP. Most
        modules either reject the import outright (acceptable: we then
        skip) or reject the wrap with a size-related CKR.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        try:
            undersized_wrap = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                value=b"\x00" * 8,  # 64-bit, below AES-128 minimum
                attrs={CKA_WRAP: True, CKA_EXTRACTABLE: True},
            )
        except AssertionError:
            pytest.skip(
                "Module rejected import of undersized AES wrap key "
                "(itself a valid size-range enforcement)"
            )

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                undersized_wrap,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK with a 64-bit AES wrap key "
                    "(expected CKR_WRAPPING_KEY_SIZE_RANGE — AES requires "
                    "128/192/256 bits).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.5.14.3",
                )
                pytest.fail(
                    "Module accepted a 64-bit AES wrap key for CKM_AES_KEY_WRAP "
                    "(expected CKR_WRAPPING_KEY_SIZE_RANGE)"
                )
            accepted = (
                CKR_WRAPPING_KEY_SIZE_RANGE,
                CKR_KEY_SIZE_RANGE,
                # Some modules treat undersized AES as type-inconsistent
                CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
                CKR_KEY_TYPE_INCONSISTENT,
                *(() if ckr_strict else quirk_extras(p11_config, "size_range_on_wrap")),
            )
            assert rv in accepted, (
                f"Unexpected CK_RV 0x{rv:08x} on undersized wrap key; "
                f"expected one of {[hex(c) for c in accepted]}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, undersized_wrap)
            destroy_quietly(rs.raw, rs.sh, target)


class TestUnwrapKeyErrors:
    """Error conditions for C_UnwrapKey (Sec.5.14.4)."""

    def test_wrapped_key_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Unwrapping garbage data -> CKR_WRAPPED_KEY_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        unwrap_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_UNWRAP: True, CKA_WRAP: True},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            # Garbage wrapped data (24 bytes for AES-KW)
            garbage = (ctypes.c_ubyte * 24)(*([0xFF] * 24))
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
            )
            new_key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_UnwrapKey(
                rs.sh,
                mech.byref(),
                unwrap_key,
                garbage,
                24,
                tmpl.ptr,
                tmpl.count,
                byref(new_key),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, new_key.value)
                pytest.fail("Should have rejected garbage wrapped key data")
            # CKR_WRAPPED_KEY_INVALID or CKR_WRAPPED_KEY_LEN_RANGE
        finally:
            destroy_quietly(rs.raw, rs.sh, unwrap_key)
