"""Tests for EdDSA (Ed25519/Ed448) key generation, signing, and properties.

EdDSA is available on SoftHSM2 2.7.0+, Kryoptic, and NSS.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.crossverify

ED25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])


@pytest.fixture()
def ed25519_keypair(p11_session: Any, p11_module: Any) -> tuple[Any, Any]:
    """Generate Ed25519 keypair, skip if unsupported."""
    if not has_mechanism(p11_module, "EDDSA"):
        pytest.skip("EDDSA mechanism not supported")

    try:
        pub, priv = p11_session.generate_keypair(
            KeyType.EC_EDWARDS,
            mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
            public_template={
                Attribute.EC_PARAMS: ED25519_OID,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
            private_template={
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
            },
        )
        return pub, priv
    except (p11.exceptions.PKCS11Error, AttributeError):
        pytest.skip("Ed25519 keygen not available")
        raise  # unreachable, satisfies mypy


class TestEdDSAKeyGeneration:
    def test_ed25519_keygen(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Generate Ed25519 key pair."""
        pub, priv = ed25519_keypair
        assert pub is not None
        assert priv is not None

    def test_ed25519_key_type(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Ed25519 key should have EC_EDWARDS key type."""
        pub, priv = ed25519_keypair
        assert pub.key_type == KeyType.EC_EDWARDS
        assert priv.key_type == KeyType.EC_EDWARDS

    def test_ed25519_ec_params(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Ed25519 key should have correct EC params (OID)."""
        pub, _ = ed25519_keypair
        params = pub[Attribute.EC_PARAMS]
        assert params == ED25519_OID


class TestEdDSASignVerify:
    def test_sign_verify_roundtrip(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Sign and verify with Ed25519."""
        pub, priv = ed25519_keypair
        data = b"EdDSA sign-verify test data"

        signature = priv.sign(data, mechanism=Mechanism.EDDSA)
        assert len(signature) == 64  # Ed25519 = 64 bytes

        result = pub.verify(data, signature, mechanism=Mechanism.EDDSA)
        assert result is True

    def test_wrong_data_fails(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Verification with wrong data must fail."""
        pub, priv = ed25519_keypair
        sig = priv.sign(b"original data", mechanism=Mechanism.EDDSA)

        try:
            result = pub.verify(b"tampered data", sig, mechanism=Mechanism.EDDSA)
            assert result is False
        except p11.exceptions.PKCS11Error:
            pass  # Expected

    def test_signature_length(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Ed25519 signatures are always exactly 64 bytes."""
        _, priv = ed25519_keypair
        for data in [b"", b"x", b"a" * 1000]:
            sig = priv.sign(data, mechanism=Mechanism.EDDSA)
            assert len(sig) == 64

    def test_different_data_different_signatures(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Different messages produce different signatures."""
        _, priv = ed25519_keypair
        sig1 = priv.sign(b"message one", mechanism=Mechanism.EDDSA)
        sig2 = priv.sign(b"message two", mechanism=Mechanism.EDDSA)
        assert sig1 != sig2

    def test_deterministic_signatures(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Ed25519 signatures are deterministic (same key+data → same sig)."""
        _, priv = ed25519_keypair
        data = b"determinism test"
        sig1 = priv.sign(data, mechanism=Mechanism.EDDSA)
        sig2 = priv.sign(data, mechanism=Mechanism.EDDSA)
        assert sig1 == sig2

    def test_different_keys_different_signatures(self, p11_session: Any, p11_module: Any) -> None:
        """Same data signed with different Ed25519 keys gives different sigs."""
        if not has_mechanism(p11_module, "EDDSA"):
            pytest.skip("EDDSA not supported")
        try:
            _, priv1 = p11_session.generate_keypair(
                KeyType.EC_EDWARDS,
                mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                public_template={Attribute.EC_PARAMS: ED25519_OID, Attribute.TOKEN: False},
                private_template={Attribute.SIGN: True, Attribute.TOKEN: False},
            )
            _, priv2 = p11_session.generate_keypair(
                KeyType.EC_EDWARDS,
                mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                public_template={Attribute.EC_PARAMS: ED25519_OID, Attribute.TOKEN: False},
                private_template={Attribute.SIGN: True, Attribute.TOKEN: False},
            )
        except (p11.exceptions.PKCS11Error, AttributeError):
            pytest.skip("Ed25519 keygen not available")

        data = b"key independence test"
        sig1 = priv1.sign(data, mechanism=Mechanism.EDDSA)
        sig2 = priv2.sign(data, mechanism=Mechanism.EDDSA)
        assert sig1 != sig2


class TestEdDSACrossVerify:
    """Cross-verify Ed25519 signatures with Python cryptography."""

    def test_sign_p11_verify_crypto(self, ed25519_keypair: tuple[Any, Any]) -> None:
        """Sign in PKCS#11, verify with cryptography Ed25519."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub, priv = ed25519_keypair
        data = b"Ed25519 cross-verify test"
        sig = priv.sign(data, mechanism=Mechanism.EDDSA)

        # Export the public key point
        ec_point = pub[Attribute.EC_POINT]
        # DER OCTET STRING: 04 <len> <32-byte point>
        if ec_point[0] == 0x04:
            raw_key = ec_point[2:] if ec_point[1] < 128 else ec_point[3:]
        else:
            raw_key = ec_point

        pub_crypto = Ed25519PublicKey.from_public_bytes(raw_key)
        pub_crypto.verify(sig, data)  # raises on failure
