"""CKR compliance tests for C_EncryptInit and C_Encrypt.

Each test triggers a specific error condition and validates the CKR code
against the OASIS PKCS#11 spec. In compat mode (default), acceptable
alternatives are logged as compliance notes. In strict mode (--ckr-strict),
only the spec-mandated CKR is accepted.

Source: PKCS#11 v3.2 (C_EncryptInit, C_Encrypt).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_SHA256,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_ENCRYPT, assert_ckr
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail, gen_rsa_keypair_or_xfail

pytestmark = pytest.mark.access


class TestEncryptInitErrors:
    """Per-parameter error conditions for C_EncryptInit (Sec.5.8.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using digest mechanism for encrypt -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR encrypt-init setup")
        try:
            mech = mech_simple(CKM_SHA256)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncryptInit:digest-mechanism",
                    operation="C_EncryptInit",
                    actual=rv,
                    summary="Should have rejected SHA256 as encryption mechanism",
                )
            assert_ckr(CKR_ENCRYPT["init_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_function_not_permitted(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Key with CKA_ENCRYPT=False -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_ENCRYPT: False, CKA_SIGN: True},
            purpose="CKR encrypt key-usage setup",
        )
        try:
            exp = CKR_ENCRYPT["init_key_function_not_permitted"]
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                if not exp.allow_success:
                    classify(
                        "accepted_invalid",
                        kind="policy",
                        label="C_EncryptInit:CKA_ENCRYPT-false",
                        operation="C_EncryptInit",
                        actual=rv,
                        summary="Should have rejected key without CKA_ENCRYPT",
                    )
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA public key with AES mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), pub)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncryptInit:key-type-inconsistent",
                    operation="C_EncryptInit",
                    actual=rv,
                    summary="Should have rejected RSA key with AES mechanism",
                )
            assert_ckr(CKR_ENCRYPT["init_key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_mechanism_param_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES-CBC with wrong-length IV -> CKR_MECHANISM_PARAM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-CBC parameter setup")
        try:
            # AES-CBC needs 16-byte IV, provide 8 bytes
            mech = mech_bytes(CKM_AES_CBC, b"\x00" * 8)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncryptInit:AES-CBC-IV-length",
                    operation="C_EncryptInit",
                    mechanism="CKM_AES_CBC",
                    actual=rv,
                    summary="Should have rejected 8-byte IV for AES-CBC",
                )
            assert_ckr(CKR_ENCRYPT["init_mechanism_param_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestEncryptDataErrors:
    """Data-level error conditions for C_Encrypt (Sec.5.8.2)."""

    @pytest.mark.parametrize("size", [1, 7, 15, 17, 31, 33])
    def test_ecb_non_aligned(self, p11_raw_session: Any, ckr_strict: bool, size: int) -> None:
        """AES-ECB with non-block-aligned data -> CKR_DATA_LEN_RANGE."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-ECB data-length setup")
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_EncryptInit failed: {ckr_name(rv)}")
            data = (ctypes.c_ubyte * size)(*([0xAA] * size))
            out_len = CK_ULONG(size + 16)
            out_buf = (ctypes.c_ubyte * (size + 16))()
            rv = rs.raw.C_Encrypt(rs.sh, data, size, out_buf, byref(out_len))
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_Encrypt:AES-ECB-unaligned-data",
                    operation="C_Encrypt",
                    mechanism="CKM_AES_ECB",
                    actual=rv,
                    summary=f"Should have rejected {size}-byte ECB data",
                )
            assert_ckr(CKR_ENCRYPT["data_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_empty_data(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES-ECB with empty data - reject or return empty ciphertext."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-ECB empty-data setup")
        try:
            exp = CKR_ENCRYPT["data_empty"]
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_EncryptInit failed: {ckr_name(rv)}")
            out_len = CK_ULONG(16)
            out_buf = (ctypes.c_ubyte * 16)()
            rv = rs.raw.C_Encrypt(rs.sh, None, 0, out_buf, byref(out_len))
            if rv == CKR_OK:
                # Some modules accept empty -> empty (spec doesn't forbid it)
                assert out_len.value == 0
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_pkcs_too_long(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA-PKCS data > k-11 bytes -> CKR_DATA_LEN_RANGE."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_EncryptInit failed: {ckr_name(rv)}")
            # Max data for RSA-2048 PKCS#1 v1.5 = 245 bytes (256 - 11)
            data = (ctypes.c_ubyte * 246)(*([0x42] * 246))
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_Encrypt(rs.sh, data, 246, out_buf, byref(out_len))
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_Encrypt:RSA-PKCS-data-too-long",
                    operation="C_Encrypt",
                    mechanism="CKM_RSA_PKCS",
                    actual=rv,
                    summary="Should have rejected 246 bytes for RSA-2048 PKCS",
                )
            assert_ckr(CKR_ENCRYPT["data_too_long_rsa"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_cbc_pad_non_aligned(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES-CBC-PAD with 15 bytes - should succeed (padding handles it)."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("AES_CBC_PAD not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-CBC-PAD setup")
        try:
            exp = CKR_ENCRYPT["data_invalid_cbc_padding"]
            mech = mech_bytes(CKM_AES_CBC_PAD, b"\x00" * 16)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_EncryptInit failed: {ckr_name(rv)}")
            data = (ctypes.c_ubyte * 15)(*([0xAA] * 15))
            out_len = CK_ULONG(32)
            out_buf = (ctypes.c_ubyte * 32)()
            rv = rs.raw.C_Encrypt(rs.sh, data, 15, out_buf, byref(out_len))
            if rv == CKR_OK:
                assert out_len.value == 16  # Padded to one block
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_size_range(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Wrong-type key with AES mechanism -> CKR_KEY_SIZE_RANGE or KEY_TYPE_INCONSISTENT.

        Generate a DES3 key (wrong type for AES) and try AES encrypt.
        Modules may reject via key type or key size - both are spec-compliant.
        """
        from pkcs11_check.raw.types_std import (
            CKM_DES3_KEY_GEN,
            CKR_KEY_SIZE_RANGE,
            CKR_KEY_TYPE_INCONSISTENT,
        )

        rs = p11_raw_session
        if not rs.has_mechanism("DES3_ECB"):
            pytest.skip("DES3 not supported - can't create wrong-type key")
        # Generate DES3 key
        from pkcs11_check.raw.pack import template as tmpl_fn
        from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

        mech = mech_simple(CKM_DES3_KEY_GEN)
        t = tmpl_fn()  # empty template, module uses defaults
        des_key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), t.ptr, t.count, byref(des_key))
        if rv != CKR_OK:
            pytest.skip(f"DES3 keygen failed: {ckr_name(rv)}")
        try:
            mech_ecb = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech_ecb.byref(), des_key.value)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncryptInit:DES3-key-AES-mechanism",
                    operation="C_EncryptInit",
                    mechanism="CKM_AES_ECB",
                    actual=rv,
                    summary="Should have rejected DES3 key with AES mechanism",
                )
            if rv in (CKR_KEY_TYPE_INCONSISTENT, CKR_KEY_SIZE_RANGE):
                pass  # Both are correct per spec
            else:
                assert_ckr(CKR_ENCRYPT["init_key_size_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, des_key.value)
