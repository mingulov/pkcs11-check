"""Tests for ECDSA prehash sign/verify variants.

Covers CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, and CKM_ECDSA_SHA3_* mechanisms.
Basic CKM_ECDSA (raw) is tested in test_sign.py.
Uses the raw PKCS#11 API via pkcs11_check.raw.

OASIS spec: elliptic_curves.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA3_224,
    CKM_ECDSA_SHA3_256,
    CKM_ECDSA_SHA3_384,
    CKM_ECDSA_SHA3_512,
    CKM_ECDSA_SHA224,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail

pytestmark = pytest.mark.sign

_ECDSA_HASH_MECHS = [
    pytest.param("ECDSA_SHA1", CKM_ECDSA_SHA1, id="SHA1"),
    pytest.param("ECDSA_SHA224", CKM_ECDSA_SHA224, id="SHA224"),
    pytest.param("ECDSA_SHA3_224", CKM_ECDSA_SHA3_224, id="SHA3-224"),
    pytest.param("ECDSA_SHA3_256", CKM_ECDSA_SHA3_256, id="SHA3-256"),
    pytest.param("ECDSA_SHA3_384", CKM_ECDSA_SHA3_384, id="SHA3-384"),
    pytest.param("ECDSA_SHA3_512", CKM_ECDSA_SHA3_512, id="SHA3-512"),
]


class TestECDSAPrehash:
    """ECDSA prehash sign/verify - mechanism handles hashing internally."""

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_sign_verify_roundtrip(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech: Any,
    ) -> None:
        """Sign raw message data and verify succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            data = b"ECDSA prehash roundtrip test data"
            signature = sign_single(rs.raw, rs.sh, priv, mech, data)
            assert len(signature) > 0

            result = verify_single(rs.raw, rs.sh, pub, mech, data, signature)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_tampered_data_fails(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech: Any,
    ) -> None:
        """Verify with wrong data must fail."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            original = b"original message for ECDSA"
            tampered = b"tampered message for ECDSA"

            sig = sign_single(rs.raw, rs.sh, priv, mech, original)
            try:
                result = verify_single(rs.raw, rs.sh, pub, mech, tampered, sig)
            except AssertionError as exc:
                if signature_rejected_or_xfail(exc, f"CKM_{mech_name}") is False:
                    return
                raise
            assert result is False, f"CKM_{mech_name}: verify with tampered data should fail"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_nondeterministic(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech: Any,
    ) -> None:
        """Two signatures of the same data must differ (random nonce)."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            data = b"nonce uniqueness test for ECDSA prehash"
            sig1 = sign_single(rs.raw, rs.sh, priv, mech, data)
            sig2 = sign_single(rs.raw, rs.sh, priv, mech, data)
            assert sig1 != sig2, f"CKM_{mech_name}: two ECDSA signatures should differ (random k)"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
