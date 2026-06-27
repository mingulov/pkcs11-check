"""CKR compliance tests for C_EncapsulateKey and C_DecapsulateKey.

v3.2 only - requires ML-KEM mechanism support.
Few modules currently implement KEM operations.

Source: PKCS#11 v3.2 Sec.5.14.7 (C_EncapsulateKey), Sec.5.14.8 (C_DecapsulateKey).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_DECAPSULATE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKM_AES_ECB,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKP_ML_KEM_768,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEM, assert_ckr

pytestmark = [pytest.mark.access, pytest.mark.pqc]


def _generate_ml_kem_keypair(raw: Any, sh: int) -> tuple[int, int]:
    """Generate ML-KEM-768 keypair for tests. Returns (pub_handle, priv_handle)."""
    mech = mech_simple(CKM_ML_KEM_KEY_PAIR_GEN)
    pub_tmpl = template(
        attr_bool(CKA_ENCAPSULATE, True),
        attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_DECAPSULATE, True),
        attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, False),
    )
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    from pkcs11_check.raw.rv import expect_rv

    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub),
        byref(priv),
    )
    expect_rv(rv, CKR_OK)
    return pub.value, priv.value


@pytest.mark.needs_function("C_EncapsulateKey")
class TestEncapsulateKeyErrors:
    """Error conditions for C_EncapsulateKey (Sec.5.14.7)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using AES mechanism for encapsulate -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, _priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        try:
            mech = mech_simple(CKM_AES_ECB)  # Wrong: not a KEM mechanism
            # C_EncapsulateKey(session, mech, key, pTemplate, ulCount, pCiphertext,
            #                  pulCiphertextLen, phSecret)
            ct_len = CK_ULONG(0)
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                secret_tmpl.ptr,
                secret_tmpl.count,
                None,
                byref(ct_len),
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncapsulateKey:AES-mechanism",
                    operation="C_EncapsulateKey",
                    actual=rv,
                    summary="Should have rejected AES_ECB as encapsulate mechanism",
                )
            assert_ckr(CKR_KEM["encap_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA key with ML-KEM mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        from pkcs11_check.raw.recipes import gen_rsa_keypair

        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_ML_KEM)
            ct_len = CK_ULONG(0)
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                secret_tmpl.ptr,
                secret_tmpl.count,
                None,
                byref(ct_len),
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncapsulateKey:key-type-inconsistent",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    actual=rv,
                    summary="Should have rejected RSA key with ML-KEM mechanism",
                )
            assert_ckr(CKR_KEM["encap_key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)


@pytest.mark.needs_function("C_DecapsulateKey")
class TestDecapsulateKeyErrors:
    """Error conditions for C_DecapsulateKey (Sec.5.14.8)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using AES mechanism for decapsulate -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        _pub, priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        try:
            mech = mech_simple(CKM_AES_ECB)  # Wrong: not a KEM mechanism
            ct_buf = (ctypes.c_ubyte * 1088)(*([0] * 1088))  # ML-KEM-768 ct size
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                secret_tmpl.ptr,
                secret_tmpl.count,
                ct_buf,
                1088,
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DecapsulateKey:AES-mechanism",
                    operation="C_DecapsulateKey",
                    actual=rv,
                    summary="Should have rejected AES_ECB as decapsulate mechanism",
                )
            assert_ckr(CKR_KEM["decap_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_garbage_ciphertext(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Decapsulate garbage ciphertext - reject or implicit rejection."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        _pub, priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        try:
            exp = CKR_KEM["decap_ciphertext_invalid"]
            mech = mech_simple(CKM_ML_KEM)
            # ML-KEM-768 ciphertext = 1088 bytes. Provide garbage.
            ct_buf = (ctypes.c_ubyte * 1088)(*([0xFF] * 1088))
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                secret_tmpl.ptr,
                secret_tmpl.count,
                ct_buf,
                1088,
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                # ML-KEM implicit rejection: may produce a key (spec allows this)
                if not exp.allow_success:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label="C_DecapsulateKey:garbage-ciphertext",
                        operation="C_DecapsulateKey",
                        mechanism="CKM_ML_KEM",
                        actual=rv,
                        summary="Should have rejected garbage ciphertext",
                    )
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)
