"""CKR compliance tests for C_VerifyInit and C_Verify.

Source: PKCS#11 v3.1 Sec.5.11.1 (C_VerifyInit), Sec.5.11.2 (C_Verify).
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    sign_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_SHA256_RSA_PKCS,
    CKR_DEVICE_ERROR,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_VERIFY, assert_ckr

pytestmark = pytest.mark.access


class TestVerifyInitErrors:
    """Per-parameter error conditions for C_VerifyInit (Sec.5.11.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for verify -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = int(rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub))
            if rv == int(CKR_OK):
                pytest.fail("Should have rejected AES_ECB as verify mechanism")
            assert_ckr(CKR_VERIFY["init_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key with RSA verify mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            exp = CKR_VERIFY["init_key_type_inconsistent"]
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = int(rs.raw.C_VerifyInit(rs.sh, mech.byref(), key))
            if rv == int(CKR_OK):
                if not exp.allow_success:
                    pytest.fail("Should have rejected AES key with RSA verify mechanism")
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_VerifyInit accepted AES key with RSA mechanism",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference=exp.spec_ref,
                )
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Verify with destroyed key handle -> CKR_KEY_HANDLE_INVALID."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        destroy_quietly(rs.raw, rs.sh, _priv)
        rs.raw.C_DestroyObject(rs.sh, pub)
        mech = mech_simple(CKM_SHA256_RSA_PKCS)
        rv = int(rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub))
        if rv != int(CKR_OK):
            assert_ckr(CKR_VERIFY["init_key_handle_invalid"], rv, ckr_strict)


class TestVerifyErrors:
    """Error conditions for C_Verify (Sec.5.11.2)."""

    def test_signature_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Tampered RSA signature -> CKR_SIGNATURE_INVALID."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"CKR compliance test data"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Tamper last byte
            tampered = bytearray(sig)
            tampered[-1] ^= 0xFF

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = int(rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub))
            if rv != int(CKR_OK):
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * len(tampered))(*tampered)
            rv = int(
                rs.raw.C_Verify(
                    rs.sh,
                    data_buf,
                    len(data),
                    sig_buf,
                    len(tampered),
                )
            )
            if rv == int(CKR_DEVICE_ERROR):
                pytest.xfail("Kryoptic bug: returns CKR_DEVICE_ERROR for verify failure")
            if rv == int(CKR_OK):
                pytest.fail("Tampered signature verified as valid!")
            assert_ckr(CKR_VERIFY["signature_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_signature_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA signature with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            exp = CKR_VERIFY["signature_len_range"]
            data = b"CKR compliance test data"

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = int(rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub))
            if rv != int(CKR_OK):
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            # RSA-2048 signature should be 256 bytes, provide 128
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * 128)(*([0] * 128))
            rv = int(rs.raw.C_Verify(rs.sh, data_buf, len(data), sig_buf, 128))
            if rv == int(CKR_DEVICE_ERROR):
                pytest.xfail("Kryoptic bug: returns CKR_DEVICE_ERROR for verify failure")
            if rv == int(CKR_OK):
                if not exp.allow_success:
                    pytest.fail("Should have rejected 128-byte signature for RSA-2048")
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_Verify accepted wrong-length RSA signature without length check",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference=exp.spec_ref,
                )
            elif rv in (int(CKR_SIGNATURE_INVALID), int(CKR_SIGNATURE_LEN_RANGE)):
                assert_ckr(exp, rv, ckr_strict)
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)
