"""Tests for EC key generation and ECDSA across multiple curves.

Parametrized tests for P-224, P-256, P-384, P-521.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pkcs11 import Attribute, KeyType, Mechanism

from pkcs11_check.testcases.conftest import extract_ec_point

pytestmark = pytest.mark.crossverify

_EC_CURVES = [
    ("secp224r1", 28, ec.SECP224R1(), hashes.SHA224()),
    ("secp256r1", 32, ec.SECP256R1(), hashes.SHA256()),
    ("secp384r1", 48, ec.SECP384R1(), hashes.SHA384()),
    ("secp521r1", 66, ec.SECP521R1(), hashes.SHA512()),
]


class TestECKeygen:
    @pytest.mark.parametrize(
        "curve_name,_,__,___",
        _EC_CURVES,
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ec_keygen(self, p11_session: Any, curve_name: str, _: int, __: Any, ___: Any) -> None:
        """Generate EC key pair on the given curve."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve_name)},
            local=True,
        )
        try:
            pub, priv = ecparams.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip(f"Curve {curve_name} not supported by module")
        assert pub is not None
        assert priv is not None

    @pytest.mark.parametrize(
        "curve_name,_,__,___",
        _EC_CURVES,
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ec_key_type(
        self, p11_session: Any, curve_name: str, _: int, __: Any, ___: Any
    ) -> None:
        """EC key pair should have EC key type."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve_name)},
            local=True,
        )
        try:
            pub, priv = ecparams.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip(f"Curve {curve_name} not supported")
        assert pub.key_type == KeyType.EC
        assert priv.key_type == KeyType.EC


class TestECDSACrossVerify:
    @pytest.mark.parametrize(
        "curve_name,coord_size,crypto_curve,hash_algo",
        _EC_CURVES,
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ecdsa_sign_p11_verify_crypto(
        self,
        p11_session: Any,
        curve_name: str,
        coord_size: int,
        crypto_curve: ec.EllipticCurve,
        hash_algo: hashes.HashAlgorithm,
    ) -> None:
        """ECDSA sign with PKCS#11, verify with cryptography."""
        hash_fns = {28: hashlib.sha224, 32: hashlib.sha256, 48: hashlib.sha384, 66: hashlib.sha512}

        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve_name)},
            local=True,
        )
        try:
            pub_p11, priv_p11 = ecparams.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip(f"Curve {curve_name} not supported")

        data = f"ECDSA {curve_name} cross-verify".encode()
        digest = hash_fns[coord_size](data).digest()

        sig = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        point_bytes = extract_ec_point(pub_p11[Attribute.EC_POINT])
        pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, point_bytes)

        half = len(sig) // 2
        r = int.from_bytes(sig[:half], "big")
        s = int.from_bytes(sig[half:], "big")
        der_sig = encode_dss_signature(r, s)

        pub_crypto.verify(der_sig, data, ec.ECDSA(hash_algo))
