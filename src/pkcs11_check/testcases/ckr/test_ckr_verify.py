"""CKR compliance tests for C_VerifyInit and C_Verify.

Source: PKCS#11 v3.2 (C_VerifyInit, C_Verify).
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKF_VERIFY,
    CKM_AES_ECB,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_VERIFY, assert_ckr
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    gen_aes_key_or_xfail,
    skip_unless_mechanism_flag,
)

pytestmark = pytest.mark.access


class TestVerifyInitErrors:
    """Per-parameter error conditions for C_VerifyInit (Sec.5.11.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for verify -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_VerifyInit:AES-mechanism",
                    operation="C_VerifyInit",
                    actual=rv,
                    summary="Should have rejected AES_ECB as verify mechanism",
                )
            assert_ckr(CKR_VERIFY["init_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key with RSA verify mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            exp = CKR_VERIFY["init_key_type_inconsistent"]
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), key)
            # crypto-correctness: accepting an AES key under an RSA verify
            # mechanism (CKR_OK) is key-type confusion -> fail; an expected
            # reject -> pass; another clean reject -> xfail (3-way assert_ckr).
            assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Verify with destroyed key handle -> CKR_KEY_HANDLE_INVALID."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        destroy_quietly(rs.raw, rs.sh, _priv)
        destroy_rv = rs.raw.C_DestroyObject(rs.sh, pub)
        mech = mech_simple(CKM_SHA256_RSA_PKCS)
        rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
        if rv == CKR_OK:
            # lifecycle use-after-destroy: destroy claimed CKR_OK yet C_VerifyInit
            # on the same handle still succeeded -> contradiction.
            classify_lifecycle_effect(
                claimed_success=destroy_rv == CKR_OK,
                effect_observed=True,
                label="C_VerifyInit on a destroyed key handle (use-after-destroy)",
            )
        else:
            assert_ckr(CKR_VERIFY["init_key_handle_invalid"], rv, ckr_strict)


class TestVerifyErrors:
    """Error conditions for C_Verify (Sec.5.11.2)."""

    def test_signature_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Tampered RSA signature -> CKR_SIGNATURE_INVALID."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_SHA256_RSA_PKCS, int(CKF_VERIFY))
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"CKR compliance test data"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Tamper last byte
            tampered = bytearray(sig)
            tampered[-1] ^= 0xFF

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * len(tampered))(*tampered)
            rv = rs.raw.C_Verify(
                rs.sh,
                data_buf,
                len(data),
                sig_buf,
                len(tampered),
            )
            # CKR_DEVICE_ERROR is a clean non-spec reject -> classified as a noted
            # deviation (xfail) by assert_ckr via _TOKEN_UNIVERSAL; no provider-
            # specific pre-guard (it would leak provider identity into the report).
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_Verify:tampered-signature",
                    operation="C_Verify",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    actual=rv,
                    summary="Tampered signature verified as valid!",
                )
            assert_ckr(CKR_VERIFY["signature_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_signature_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA signature with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_SHA256_RSA_PKCS, int(CKF_VERIFY))
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            exp = CKR_VERIFY["signature_len_range"]
            data = b"CKR compliance test data"

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            # RSA-2048 signature should be 256 bytes, provide 128
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * 128)(*([0] * 128))
            rv = rs.raw.C_Verify(rs.sh, data_buf, len(data), sig_buf, 128)
            # CKR_DEVICE_ERROR is a clean non-spec reject -> classified as a noted
            # deviation (xfail) by assert_ckr via _TOKEN_UNIVERSAL; no provider-
            # specific pre-guard (it would leak provider identity into the report).
            # crypto-correctness: a wrong-length RSA signature that
            # verifies (CKR_OK) is a break -> fail; an expected reject -> pass;
            # another clean reject -> xfail (3-way assert_ckr).
            assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)
