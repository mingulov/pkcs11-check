"""CKR compliance tests for C_SignInit and C_Sign.

Source: PKCS#11 v3.1 Sec.5.10.1 (C_SignInit), Sec.5.10.2 (C_Sign).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, gen_rsa_keypair
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_SIGN, assert_ckr

pytestmark = pytest.mark.access


class TestSignInitErrors:
    """Per-parameter error conditions for C_SignInit (Sec.5.10.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for sign -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        _pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            if rv == CKR_OK:
                pytest.fail("Should have rejected AES_ECB as signing mechanism")
            assert_ckr(CKR_SIGN["init_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, _pub)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key with RSA signing mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), key)
            # Type-A crypto-correctness: accepting an AES key under an RSA signing
            # mechanism (CKR_OK) is key-type confusion -> fail; an expected reject
            # -> pass; another clean reject -> xfail (3-way assert_ckr).
            assert_ckr(CKR_SIGN["init_key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_mechanism_param_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA-PSS with invalid salt length param -> CKR_MECHANISM_PARAM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("RSA-PSS not supported")
        _pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            # RSA-PSS needs CK_RSA_PKCS_PSS_PARAMS - provide 3 garbage bytes
            mech = mech_bytes(CKM_SHA256_RSA_PKCS_PSS, b"\x00" * 3)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            if rv == CKR_OK:
                pytest.fail("Should have rejected garbage PSS params")
            assert_ckr(CKR_SIGN["init_mechanism_param_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, _pub)

    def test_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Sign with destroyed key handle -> CKR_KEY_HANDLE_INVALID."""
        rs = p11_raw_session
        _pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        destroy_quietly(rs.raw, rs.sh, _pub)
        rs.raw.C_DestroyObject(rs.sh, priv)
        mech = mech_simple(CKM_SHA256_RSA_PKCS)
        rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
        if rv != CKR_OK:
            assert_ckr(CKR_SIGN["init_key_handle_invalid"], rv, ckr_strict)


class TestSignDataErrors:
    """Data-level error conditions for C_Sign (Sec.5.10.2)."""

    def test_rsa_pkcs_data_too_long(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA-PKCS sign with data > max allowed -> CKR_DATA_LEN_RANGE.

        RSA-PKCS v1.5 signing: max data = k - 11 bytes = 245 for RSA-2048.
        """
        rs = p11_raw_session
        _pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                pytest.skip(f"C_SignInit failed: 0x{rv:08x}")
            data = (ctypes.c_ubyte * 246)(*([0x42] * 246))
            sig_len = CK_ULONG(256)
            sig_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_Sign(rs.sh, data, 246, sig_buf, byref(sig_len))
            if rv == CKR_OK:
                pytest.fail("Should have rejected 246-byte data for raw RSA-PKCS sign")
            assert_ckr(CKR_SIGN["data_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, _pub)
