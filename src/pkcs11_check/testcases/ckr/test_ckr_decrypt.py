"""CKR compliance tests for C_DecryptInit and C_Decrypt.

Each test triggers a specific error condition and validates the CKR code
against the OASIS PKCS#11 spec.

Source: PKCS#11 v3.2 (C_DecryptInit, C_Decrypt).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.pack import mech_bytes, mech_oaep, mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKG_MGF1_SHA1,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_DECRYPT, assert_ckr
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
)

pytestmark = pytest.mark.access

_RSA_OAEP_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


class TestDecryptInitErrors:
    """Per-parameter error conditions for C_DecryptInit (Sec.5.9.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using digest mechanism for decrypt -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR decrypt-init setup")
        try:
            mech = mech_simple(CKM_SHA256)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DecryptInit:digest-mechanism",
                    operation="C_DecryptInit",
                    actual=rv,
                    summary="Should have rejected SHA256 as decryption mechanism",
                )
            assert_ckr(CKR_DECRYPT["init_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key with RSA mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR decrypt key-type setup")
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DecryptInit:key-type-inconsistent",
                    operation="C_DecryptInit",
                    actual=rv,
                    summary="Should have rejected AES key with RSA mechanism",
                )
            assert_ckr(CKR_DECRYPT["init_key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_mechanism_param_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES-CBC with wrong-length IV -> CKR_MECHANISM_PARAM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-CBC decrypt-param setup")
        try:
            # AES-CBC needs 16-byte IV, provide 8 bytes
            mech = mech_bytes(CKM_AES_CBC, b"\x00" * 8)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DecryptInit:AES-CBC-IV-length",
                    operation="C_DecryptInit",
                    mechanism="CKM_AES_CBC",
                    actual=rv,
                    summary="Should have rejected 8-byte IV for AES-CBC",
                )
            assert_ckr(CKR_DECRYPT["init_mechanism_param_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDecryptDataErrors:
    """Data-level error conditions for C_Decrypt (Sec.5.9.2)."""

    @pytest.mark.parametrize("size", [1, 7, 15, 17, 31])
    def test_ecb_ciphertext_not_aligned(
        self, p11_raw_session: Any, ckr_strict: bool, size: int
    ) -> None:
        """AES-ECB with non-block-aligned ciphertext -> CKR_ENCRYPTED_DATA_LEN_RANGE."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-ECB decrypt-length setup")
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_DecryptInit failed: {ckr_name(rv)}")
            data = (ctypes.c_ubyte * size)(*([0xBB] * size))
            out_len = CK_ULONG(size + 16)
            out_buf = (ctypes.c_ubyte * (size + 16))()
            rv = rs.raw.C_Decrypt(rs.sh, data, size, out_buf, byref(out_len))
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_Decrypt:AES-ECB-unaligned-ciphertext",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_ECB",
                    actual=rv,
                    summary=f"Should have rejected {size}-byte ECB ciphertext",
                )
            assert_ckr(CKR_DECRYPT["encrypted_data_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ecb_garbage_ciphertext(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES-ECB decrypt of garbage (block-aligned) - may return data or error."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-ECB garbage setup")
        try:
            exp = CKR_DECRYPT["encrypted_data_invalid"]
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_DecryptInit failed: {ckr_name(rv)}")
            data = (ctypes.c_ubyte * 16)(*([0xCC] * 16))
            out_len = CK_ULONG(16)
            out_buf = (ctypes.c_ubyte * 16)()
            rv = rs.raw.C_Decrypt(rs.sh, data, 16, out_buf, byref(out_len))
            if rv == CKR_OK:
                # ECB decrypts anything block-aligned - not an error
                assert out_len.value == 16
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_ciphertext_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA-PKCS decrypt with wrong ciphertext length -> CKR_ENCRYPTED_DATA_LEN_RANGE."""
        rs = p11_raw_session
        _pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            exp = CKR_DECRYPT["rsa_ciphertext_wrong_length"]
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                pytest.skip(f"C_DecryptInit failed: {ckr_name(rv)}")
            # RSA-2048 expects 256-byte ciphertext, provide 128
            data = (ctypes.c_ubyte * 128)(*([0] * 128))
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_Decrypt(rs.sh, data, 128, out_buf, byref(out_len))
            # Type-A crypto-correctness: accepting a wrong-length RSA ciphertext
            # (CKR_OK) is a break for any provider -> fail; an expected reject ->
            # pass; another clean reject code -> xfail (3-way assert_ckr).
            assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_cbc_pad_bad_padding(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES-CBC-PAD decrypt garbage -> CKR_ENCRYPTED_DATA_INVALID (bad padding)."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("AES_CBC_PAD not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR AES-CBC-PAD decrypt setup")
        try:
            mech = mech_bytes(CKM_AES_CBC_PAD, b"\x00" * 16)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_DecryptInit failed: {ckr_name(rv)}")
            # Garbage 16 bytes - will have invalid PKCS#7 padding
            data = (ctypes.c_ubyte * 16)(*([0xDD] * 16))
            out_len = CK_ULONG(16)
            out_buf = (ctypes.c_ubyte * 16)()
            rv = rs.raw.C_Decrypt(rs.sh, data, 16, out_buf, byref(out_len))
            if rv != CKR_OK:
                assert_ckr(CKR_DECRYPT["encrypted_data_cbc_wrong_padding"], rv, ckr_strict)
            # Some modules may "decrypt" garbage without checking padding
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_oaep_garbage(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA-OAEP decrypt garbage -> CKR_ENCRYPTED_DATA_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("RSA_PKCS_OAEP not supported")
        _pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA_1, mgf=CKG_MGF1_SHA1)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                # RSA_PKCS_OAEP is advertised but C_DecryptInit cleanly errored:
                # advertised positive op not operational -> xfail (whether or not
                # the code is in the known runtime-reject set).
                operational = rv in _RSA_OAEP_RUNTIME_REJECT_RVS
                detail = (
                    "SHA-1 OAEP params are not operational"
                    if operational
                    else "C_DecryptInit(RSA_OAEP) failed unexpectedly"
                )
                xfail_as(
                    "not_operational",
                    label="RSA_PKCS_OAEP:decrypt-init",
                    operation="C_DecryptInit",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=f"RSA_PKCS_OAEP advertised but {detail}: {ckr_name(rv)}",
                )
            data = (ctypes.c_ubyte * 256)(*([0xEE] * 256))
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_Decrypt(rs.sh, data, 256, out_buf, byref(out_len))
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_Decrypt:RSA-OAEP-garbage",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary="Should have rejected garbage OAEP ciphertext",
                )
            assert_ckr(CKR_DECRYPT["rsa_oaep_garbage"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Decrypt with destroyed key handle -> CKR_KEY_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="CKR destroyed-key setup")
        encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
        destroy_rv = rs.raw.C_DestroyObject(rs.sh, key)
        mech = mech_simple(CKM_AES_ECB)
        rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
        if rv == CKR_OK:
            # Type-C use-after-destroy: the destroy claimed success yet
            # C_DecryptInit on the same handle still succeeded -> contradiction.
            classify_lifecycle_effect(
                claimed_success=destroy_rv == CKR_OK,
                effect_observed=True,
                label="C_DecryptInit on a destroyed key handle (use-after-destroy)",
            )
        else:
            assert_ckr(CKR_DECRYPT["init_key_handle_invalid"], rv, ckr_strict)

    def test_key_function_not_permitted(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Key with CKA_DECRYPT=False -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_DECRYPT: False, CKA_ENCRYPT: True},
            purpose="CKR decrypt key-usage setup",
        )
        try:
            exp = CKR_DECRYPT["init_key_function_not_permitted"]
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                if not exp.allow_success:
                    classify(
                        "accepted_invalid",
                        kind="policy",
                        label="C_DecryptInit:CKA_DECRYPT-false",
                        operation="C_DecryptInit",
                        actual=rv,
                        summary="Should have rejected key without CKA_DECRYPT",
                    )
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
