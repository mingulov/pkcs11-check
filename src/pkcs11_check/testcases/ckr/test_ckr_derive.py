"""CKR compliance tests for C_DeriveKey.

Source: PKCS#11 v3.1 Sec.5.14.5.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_ulong,
    mech_bytes,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKM_SHA256,
    CKM_SHA256_KEY_DERIVATION,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_DERIVE, assert_ckr
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail

pytestmark = pytest.mark.access


class TestDeriveKeyErrors:
    """Error conditions for C_DeriveKey (Sec.5.14.5)."""

    def test_null_base_key_handle(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """C_DeriveKey with hBaseKey=0 -> CKR_KEY_HANDLE_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_KEY_DERIVATION"):
            pytest.skip("SHA256_KEY_DERIVATION not supported")

        mech = mech_simple(CKM_SHA256_KEY_DERIVATION)
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_TOKEN, False),
        )
        derived = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_DeriveKey(
            rs.sh,
            mech.byref(),
            0,
            tmpl.ptr,
            tmpl.count,
            byref(derived),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, derived.value)
            classify(
                "accepted_invalid",
                kind="policy",
                label="C_DeriveKey:null-base-key",
                operation="C_DeriveKey",
                actual=rv,
                summary="C_DeriveKey accepted hBaseKey=0",
            )
        assert_ckr(CKR_DERIVE["key_handle_invalid"], rv, ckr_strict)

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for derive -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
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
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DeriveKey:digest-mechanism",
                    operation="C_DeriveKey",
                    actual=rv,
                    summary="Should have rejected SHA256 as derive mechanism",
                )
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
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DeriveKey:key-type-inconsistent",
                    operation="C_DeriveKey",
                    mechanism="CKM_ECDH1_DERIVE",
                    actual=rv,
                    summary="Should have rejected RSA key with ECDH derive",
                )
            assert_ckr(CKR_DERIVE["key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)
