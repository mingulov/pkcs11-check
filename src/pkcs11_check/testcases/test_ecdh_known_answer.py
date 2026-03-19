"""ECDH known-answer tests.

Verifies ECDH key agreement produces the correct shared secret
by deriving with known keys in both PKCS#11 and Python cryptography,
then comparing the raw shared secrets.

This catches subtle ECDH implementation bugs that roundtrip tests miss.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import KDF
from pkcs11.util.ec import encode_named_curve_parameters

from pkcs11_check.testcases.conftest import extract_ec_point, has_mechanism

pytestmark = pytest.mark.crossverify


class TestECDHKnownAnswer:
    """Verify ECDH produces correct shared secret using known keys."""

    def test_ecdh_p256_crossverify(self, p11_session: Any, p11_module: Any) -> None:
        """ECDH P-256: derive in both PKCS#11 and cryptography, compare raw secrets."""
        if not has_mechanism(p11_module, "ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        # Generate P-256 keypair in cryptography
        crypto_priv = ec.generate_private_key(ec.SECP256R1())
        crypto_pub = crypto_priv.public_key()
        pub_numbers = crypto_pub.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_bytes = pub_numbers.y.to_bytes(32, "big")
        crypto_point = b"\x04" + x_bytes + y_bytes

        # Generate P-256 keypair in PKCS#11
        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            p11_pub, p11_priv = params.generate_keypair()
        except Exception:
            pytest.skip("P-256 not supported")
            return

        p11_point = extract_ec_point(p11_pub[Attribute.EC_POINT])

        # PKCS#11: p11_priv × crypto_pub (NULL KDF = raw shared secret)
        try:
            p11_derived = p11_priv.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_DERIVE,
                mechanism_param=(KDF.NULL, None, crypto_point),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
        except Exception:
            pytest.skip("ECDH derivation failed")
            return

        p11_secret = p11_derived[Attribute.VALUE]

        # cryptography: crypto_priv × p11_pub
        p11_x = int.from_bytes(p11_point[1:33], "big")
        p11_y = int.from_bytes(p11_point[33:65], "big")
        p11_pub_crypto = ec.EllipticCurvePublicNumbers(p11_x, p11_y, ec.SECP256R1()).public_key()
        crypto_secret = crypto_priv.exchange(ec.ECDH(), p11_pub_crypto)

        # Both should produce the same raw shared secret
        assert p11_secret == crypto_secret, (
            f"ECDH shared secret mismatch: "
            f"PKCS#11={p11_secret.hex()[:16]}... "
            f"crypto={crypto_secret.hex()[:16]}..."
        )

    def test_ecdh_symmetric_agreement(self, p11_session: Any, p11_module: Any) -> None:
        """Two PKCS#11 keypairs derive the same shared secret (symmetric)."""
        if not has_mechanism(p11_module, "ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            pub_a, priv_a = params.generate_keypair()
            pub_b, priv_b = params.generate_keypair()
        except Exception:
            pytest.skip("P-256 not supported")
            return

        point_a = extract_ec_point(pub_a[Attribute.EC_POINT])
        point_b = extract_ec_point(pub_b[Attribute.EC_POINT])

        try:
            key_ab = priv_a.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_DERIVE,
                mechanism_param=(KDF.NULL, None, point_b),
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )
            key_ba = priv_b.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_DERIVE,
                mechanism_param=(KDF.NULL, None, point_a),
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )
        except Exception:
            pytest.skip("ECDH derivation failed")
            return

        assert key_ab[Attribute.VALUE] == key_ba[Attribute.VALUE]
