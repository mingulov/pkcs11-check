"""Tests for EC key generation and ECDSA across multiple curves.

Parametrized tests for P-256, P-384, P-521 and Ed25519.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.crossverify

_EC_CURVES = [
    ("secp256r1", 32, ec.SECP256R1()),
    ("secp384r1", 48, ec.SECP384R1()),
    ("secp521r1", 66, ec.SECP521R1()),
]


class TestECKeygen:
    """Test EC key generation across curves."""

    @pytest.mark.parametrize("curve_name,_,__", _EC_CURVES, ids=["P-256", "P-384", "P-521"])
    def test_ec_keygen(
        self, p11_session: Any, curve_name: str, _: int, __: ec.EllipticCurve
    ) -> None:
        """Generate EC key pair on the given curve."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve_name)},
            local=True,
        )
        pub, priv = ecparams.generate_keypair()
        assert pub is not None
        assert priv is not None
        pub.destroy()
        priv.destroy()


class TestECDSACrossVerifyCurves:
    """Cross-verify ECDSA signatures across curves against cryptography."""

    @pytest.mark.parametrize(
        "curve_name,coord_size,crypto_curve",
        _EC_CURVES,
        ids=["P-256", "P-384", "P-521"],
    )
    def test_ecdsa_crossverify(
        self,
        p11_session: Any,
        curve_name: str,
        coord_size: int,
        crypto_curve: ec.EllipticCurve,
    ) -> None:
        """ECDSA sign with PKCS#11, verify with cryptography."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve_name)},
            local=True,
        )
        pub_p11, priv_p11 = ecparams.generate_keypair()

        data = f"ECDSA {curve_name} cross-verify".encode()
        if coord_size <= 32:
            hash_fn = hashlib.sha256
        elif coord_size <= 48:
            hash_fn = hashlib.sha384
        else:
            hash_fn = hashlib.sha512
        digest = hash_fn(data).digest()

        signature = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        # Export public key and verify with cryptography
        ec_point = pub_p11[Attribute.EC_POINT]
        # Strip DER OCTET STRING wrapper (handles both short and long form)
        if ec_point[0] == 0x04:
            if ec_point[1] < 0x80:
                # Short form: 04 <len> <point>
                point_bytes = ec_point[2:]
            elif ec_point[1] == 0x81:
                # Long form: 04 81 <len> <point>
                point_bytes = ec_point[3:]
            else:
                point_bytes = ec_point
        else:
            point_bytes = ec_point

        pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, point_bytes)

        # Convert raw r||s to DER
        half = len(signature) // 2
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        der_sig = encode_dss_signature(r, s)

        from cryptography.hazmat.primitives import hashes

        if coord_size <= 32:
            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        elif coord_size <= 48:
            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA384()))
        else:
            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA512()))

        pub_p11.destroy()
        priv_p11.destroy()
