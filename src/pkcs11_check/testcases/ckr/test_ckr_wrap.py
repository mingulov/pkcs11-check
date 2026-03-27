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
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.types_std import (
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
    CKM_AES_KEY_WRAP,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_OK,
)

pytestmark = pytest.mark.access


class TestWrapKeyErrors:
    """Error conditions for C_WrapKey (Sec.5.14.3)."""

    def test_key_not_extractable(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Wrapping non-extractable key -> CKR_KEY_UNEXTRACTABLE.

        PKCS#11 v3.1 Sec.5.14.3: C_WrapKey on a key with CKA_EXTRACTABLE=False MUST
        return CKR_KEY_UNEXTRACTABLE. NSS returns CKR_OK, meaning non-extractable keys
        can be exported in wrapped form — a security violation.
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
                    "NSS returns CKR_OK for C_WrapKey on CKA_EXTRACTABLE=False key "
                    "(expected CKR_KEY_UNEXTRACTABLE). Non-extractable keys can be exported.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.5.14.3",
                )
                pytest.xfail(
                    "SECURITY: NSS returns CKR_OK for C_WrapKey on non-extractable key "
                    "(expected CKR_KEY_UNEXTRACTABLE)"
                )
            # CKR_KEY_UNEXTRACTABLE or CKR_KEY_NOT_WRAPPABLE - both acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for wrap -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
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
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
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
            # CKR_MECHANISM_INVALID or related
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
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
