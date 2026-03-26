"""CKR compliance tests for C_DeriveKey.

Source: PKCS#11 v3.1 Sec.5.14.5.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_bytes,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, gen_rsa_keypair
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DERIVE,
    CKA_VALUE_LEN,
    CKM_ECDH1_DERIVE,
    CKM_SHA256,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_DERIVE, assert_ckr

pytestmark = pytest.mark.access


class TestDeriveKeyErrors:
    """Error conditions for C_DeriveKey (Sec.5.14.5)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for derive -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_DERIVE: True},
        )
        try:
            mech = mech_simple(CKM_SHA256)
            tmpl = template(attr_ulong(CKA_VALUE_LEN, 16))
            derived = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                key,
                tmpl.ptr,
                tmpl.count,
                byref(derived),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, derived.value)
                pytest.fail("Should have rejected SHA256 as derive mechanism")
            assert_ckr(CKR_DERIVE["mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA key with ECDH derive mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("ECDH1_DERIVE not supported")
        _pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            private_attrs={CKA_DERIVE: True},
        )
        try:
            # ECDH1_DERIVE with garbage param
            mech = mech_bytes(CKM_ECDH1_DERIVE, b"\x00" * 65)
            tmpl = template(attr_ulong(CKA_VALUE_LEN, 16))
            derived = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                priv,
                tmpl.ptr,
                tmpl.count,
                byref(derived),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, derived.value)
                pytest.fail("Should have rejected RSA key with ECDH derive")
            assert_ckr(CKR_DERIVE["key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)
