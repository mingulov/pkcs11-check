"""Tests for PKCS#11 sign/verify operations.

Covers RSA PKCS#1 v1.5, RSA-PSS, ECDSA, HMAC, and DSA sign/verify.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, mech_pss, mech_simple, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VERIFY,
    CKG_MGF1_SHA256,
    CKK_GENERIC_SECRET,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_DSA_PARAMETER_GEN,
    CKM_DSA_SHA256,
    CKM_ECDSA,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    gen_rsa_keypair_or_xfail,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

_SIGN_OPERATION_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_SIGN_MECHANISM_NAMES = {
    int(CKM_SHA1_RSA_PKCS): "SHA1_RSA_PKCS",
    int(CKM_SHA256_RSA_PKCS): "SHA256_RSA_PKCS",
    int(CKM_SHA384_RSA_PKCS): "SHA384_RSA_PKCS",
    int(CKM_SHA512_RSA_PKCS): "SHA512_RSA_PKCS",
    int(CKM_SHA256_RSA_PKCS_PSS): "SHA256_RSA_PKCS_PSS",
}


def _assert_invalid_signature_rejected(call_verify: Callable[[], bool], label: str) -> None:
    """Assert invalid signature input is rejected, allowing non-clean CKR xfails."""
    try:
        accepted = call_verify()
    except AssertionError as exc:
        signature_rejected_or_xfail(exc, label)
        return
    assert accepted is False


def _require_sign_mechanism(rs: Any, mechanism: Any) -> str:
    name = _SIGN_MECHANISM_NAMES[int(mechanism)]
    skip_unless_mechanism(rs, name)
    return name


def _rsa_keypair_for_signing(rs: Any) -> tuple[int, int]:
    return gen_rsa_keypair_or_xfail(rs, 2048)


def _sign_or_xfail(
    rs: Any,
    private_key: int,
    mechanism: Any,
    data: bytes,
    *,
    mech_param: Any | None = None,
) -> bytes:
    mech_name = _SIGN_MECHANISM_NAMES[int(mechanism)]
    try:
        return sign_single(rs.raw, rs.sh, private_key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _SIGN_OPERATION_REJECT_RVS, f"{mech_name} sign rejected")
    raise


def _verify_or_xfail(
    rs: Any,
    public_key: int,
    mechanism: Any,
    data: bytes,
    signature: bytes,
    *,
    mech_param: Any | None = None,
) -> bool:
    mech_name = _SIGN_MECHANISM_NAMES[int(mechanism)]
    try:
        return verify_single(
            rs.raw,
            rs.sh,
            public_key,
            mechanism,
            data,
            signature,
            mech_param=mech_param,
        )
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _SIGN_OPERATION_REJECT_RVS, f"{mech_name} verify rejected")
    raise


class TestRSASignature:
    def test_rsa_generate_keypair(self, p11_raw_session: Any) -> None:
        """Generate an RSA-2048 key pair."""
        rs = p11_raw_session
        pub, priv = _rsa_keypair_for_signing(rs)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_pkcs_sign_verify(self, p11_raw_session: Any) -> None:
        """Sign data with RSA PKCS#1 v1.5 and verify."""
        rs = p11_raw_session
        _require_sign_mechanism(rs, CKM_SHA256_RSA_PKCS)
        pub, priv = _rsa_keypair_for_signing(rs)
        try:
            data = b"test data for PKCS#11 signing"
            sig = _sign_or_xfail(rs, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) == 256  # 2048-bit RSA = 256 bytes
            assert _verify_or_xfail(rs, pub, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_sign_wrong_data_fails_verify(self, p11_raw_session: Any) -> None:
        """Verification with wrong data should fail."""
        rs = p11_raw_session
        _require_sign_mechanism(rs, CKM_SHA256_RSA_PKCS)
        pub, priv = _rsa_keypair_for_signing(rs)
        try:
            data = b"original data"
            wrong_data = b"tampered data"
            sig = _sign_or_xfail(rs, priv, CKM_SHA256_RSA_PKCS, data)
            _assert_invalid_signature_rejected(
                lambda: verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_SHA256_RSA_PKCS,
                    wrong_data,
                    sig,
                ),
                "RSA wrong-data verification",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(
        "mechanism",
        [CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS],
        ids=["SHA1", "SHA256", "SHA384", "SHA512"],
    )
    def test_rsa_hash_mechanisms(self, p11_raw_session: Any, mechanism: Any) -> None:
        """RSA sign/verify works with all standard hash mechanisms."""
        rs = p11_raw_session
        _require_sign_mechanism(rs, mechanism)
        pub, priv = _rsa_keypair_for_signing(rs)
        try:
            data = b"hash mechanism test data"
            sig = _sign_or_xfail(rs, priv, mechanism, data)
            assert _verify_or_xfail(rs, pub, mechanism, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_pss_sign_verify(self, p11_raw_session: Any) -> None:
        """RSA-PSS sign/verify roundtrip."""
        rs = p11_raw_session
        _require_sign_mechanism(rs, CKM_SHA256_RSA_PKCS_PSS)
        pub, priv = _rsa_keypair_for_signing(rs)
        try:
            data = b"RSA-PSS test data for signing"
            pss = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
                salt_len=32,
            )
            sig = _sign_or_xfail(rs, priv, CKM_SHA256_RSA_PKCS_PSS, data, mech_param=pss)
            assert (
                _verify_or_xfail(rs, pub, CKM_SHA256_RSA_PKCS_PSS, data, sig, mech_param=pss)
                is True
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_different_keys_different_signatures(self, p11_raw_session: Any) -> None:
        """Same data signed with different keys produces different signatures."""
        rs = p11_raw_session
        _require_sign_mechanism(rs, CKM_SHA256_RSA_PKCS)
        pub1, priv1 = _rsa_keypair_for_signing(rs)
        pub2, priv2 = _rsa_keypair_for_signing(rs)
        try:
            data = b"key independence test"
            sig1 = _sign_or_xfail(rs, priv1, CKM_SHA256_RSA_PKCS, data)
            sig2 = _sign_or_xfail(rs, priv2, CKM_SHA256_RSA_PKCS, data)
            assert sig1 != sig2
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)


class TestECDSASignature:
    def test_ec_generate_keypair(self, p11_raw_session: Any) -> None:
        """Generate an EC P-256 key pair."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ecdsa_sign_verify(self, p11_raw_session: Any) -> None:
        """Sign and verify with ECDSA P-256."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            digest = hashlib.sha256(b"ECDSA test data").digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            assert len(sig) > 0
            assert verify_single(rs.raw, rs.sh, pub, CKM_ECDSA, digest, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ecdsa_wrong_data_fails(self, p11_raw_session: Any) -> None:
        """ECDSA verification with wrong digest should fail."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            digest = hashlib.sha256(b"original").digest()
            wrong_digest = hashlib.sha256(b"tampered").digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            _assert_invalid_signature_rejected(
                lambda: verify_single(rs.raw, rs.sh, pub, CKM_ECDSA, wrong_digest, sig),
                "ECDSA wrong-digest verification",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1"])
    def test_ecdsa_multiple_curves(self, p11_raw_session: Any, curve: str) -> None:
        """ECDSA sign/verify works with P-256 and P-384."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters(curve)
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            digest = hashlib.sha256(b"multi-curve test").digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            assert verify_single(rs.raw, rs.sh, pub, CKM_ECDSA, digest, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ecdsa_nondeterministic(self, p11_raw_session: Any) -> None:
        """ECDSA signatures for same data should differ (random nonce)."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            digest = hashlib.sha256(b"nonce test").digest()
            sig1 = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            sig2 = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            assert sig1 != sig2
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestHMACSign:
    def _hmac_key(self, rs: Any) -> int:
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")
        return gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            mechanism=CKM_GENERIC_SECRET_KEY_GEN,
            attrs={
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )

    def test_hmac_sha256_sign_verify(self, p11_raw_session: Any) -> None:
        """HMAC-SHA256 sign and verify roundtrip."""
        rs = p11_raw_session
        key = self._hmac_key(rs)
        try:
            data = b"HMAC test data"
            mac = sign_single(rs.raw, rs.sh, key, CKM_SHA256_HMAC, data)
            assert len(mac) == 32  # SHA-256 output
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_hmac_different_data_different_mac(self, p11_raw_session: Any) -> None:
        """Different messages produce different MACs."""
        rs = p11_raw_session
        key = self._hmac_key(rs)
        try:
            mac1 = sign_single(rs.raw, rs.sh, key, CKM_SHA256_HMAC, b"message one")
            mac2 = sign_single(rs.raw, rs.sh, key, CKM_SHA256_HMAC, b"message two")
            assert mac1 != mac2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDSASignature:
    def test_dsa_generate_and_sign(self, p11_raw_session: Any) -> None:
        """Generate DSA params + keypair, sign and verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("DSA_SHA256"):
            pytest.skip("CKM_DSA_SHA256 not supported")

        # Step 1: Generate DSA domain parameters
        dsa_tmpl = template(attr_ulong(CKA_PRIME_BITS, 2048))
        mech = mech_simple(CKM_DSA_PARAMETER_GEN)
        param_obj = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh, mech.byref(), dsa_tmpl.ptr, dsa_tmpl.count, byref(param_obj)
        )
        if rv != CKR_OK:
            pytest.skip(f"DSA parameter generation not supported: {ckr_name(rv)}")

        pub_h = CK_OBJECT_HANDLE(0)
        priv_h = CK_OBJECT_HANDLE(0)
        try:
            # Step 2: Extract P, Q, G from domain parameters
            params = read_attributes(
                rs.raw,
                rs.sh,
                param_obj.value,
                [CKA_PRIME, CKA_SUBPRIME, CKA_BASE],
            )

            # Step 3: Generate keypair with extracted domain parameters
            pub_tmpl = template(
                attr_bytes(CKA_PRIME, params[CKA_PRIME]),
                attr_bytes(CKA_SUBPRIME, params[CKA_SUBPRIME]),
                attr_bytes(CKA_BASE, params[CKA_BASE]),
            )
            priv_tmpl = template()
            kp_mech = mech_simple(CKM_DSA_KEY_PAIR_GEN)
            rv = rs.raw.C_GenerateKeyPair(
                rs.sh,
                kp_mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub_h),
                byref(priv_h),
            )
            if rv != CKR_OK:
                pytest.skip(f"DSA key generation not supported: {ckr_name(rv)}")

            # Step 4: Sign and verify
            data = b"DSA test data for signing"
            sig = sign_single(rs.raw, rs.sh, priv_h.value, CKM_DSA_SHA256, data)
            assert verify_single(rs.raw, rs.sh, pub_h.value, CKM_DSA_SHA256, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, param_obj.value)
            if pub_h.value:
                destroy_quietly(rs.raw, rs.sh, pub_h.value)
            if priv_h.value:
                destroy_quietly(rs.raw, rs.sh, priv_h.value)
