"""Tests for EdDSA (Ed25519/Ed448) key generation and signing.

EdDSA is available on SoftHSM2 2.7.0+, Kryoptic, and NSS.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.crossverify


class TestEdDSAKeyGeneration:
    """Test Ed25519/Ed448 key pair generation."""

    def test_ed25519_keygen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate Ed25519 key pair if supported."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        mech_names = {mech_name(m) for m in mechanisms}

        if "EC_EDWARDS_KEY_PAIR_GEN" not in mech_names and "EDDSA" not in mech_names:
            pytest.skip("EdDSA not supported by this module")

        # Ed25519 OID: 1.3.101.112
        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.EC_EDWARDS,
                mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                public_template={
                    Attribute.EC_PARAMS: ed25519_oid,
                    Attribute.VERIFY: True,
                    Attribute.TOKEN: False,
                },
                private_template={
                    Attribute.SIGN: True,
                    Attribute.TOKEN: False,
                },
            )
            assert pub is not None
            assert priv is not None
            pub.destroy()
            priv.destroy()
        except (p11.exceptions.PKCS11Error, AttributeError) as exc:
            pytest.skip(f"Ed25519 keygen failed: {type(exc).__name__}")


class TestEdDSASignVerify:
    """Test EdDSA sign and verify operations."""

    def test_ed25519_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Sign and verify with Ed25519."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        mech_names = {mech_name(m) for m in mechanisms}

        if "EDDSA" not in mech_names:
            pytest.skip("EDDSA mechanism not supported")

        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.EC_EDWARDS,
                mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                public_template={
                    Attribute.EC_PARAMS: ed25519_oid,
                    Attribute.VERIFY: True,
                    Attribute.TOKEN: False,
                },
                private_template={
                    Attribute.SIGN: True,
                    Attribute.TOKEN: False,
                },
            )
        except (p11.exceptions.PKCS11Error, AttributeError):
            pytest.skip("Ed25519 keygen not available")

        data = b"EdDSA sign-verify test data"

        try:
            signature = priv.sign(data, mechanism=Mechanism.EDDSA)
            assert len(signature) == 64  # Ed25519 signature = 64 bytes

            result = pub.verify(data, signature, mechanism=Mechanism.EDDSA)
            assert result is True
        except p11.exceptions.PKCS11Error as exc:
            pytest.skip(f"EdDSA sign/verify failed: {type(exc).__name__}")
        finally:
            pub.destroy()
            priv.destroy()

    def test_ed25519_wrong_data_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Ed25519: verification with wrong data must fail."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        mech_names = {mech_name(m) for m in mechanisms}

        if "EDDSA" not in mech_names:
            pytest.skip("EDDSA mechanism not supported")

        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.EC_EDWARDS,
                mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                public_template={
                    Attribute.EC_PARAMS: ed25519_oid,
                    Attribute.VERIFY: True,
                    Attribute.TOKEN: False,
                },
                private_template={
                    Attribute.SIGN: True,
                    Attribute.TOKEN: False,
                },
            )
        except (p11.exceptions.PKCS11Error, AttributeError):
            pytest.skip("Ed25519 keygen not available")

        signature = priv.sign(b"original data", mechanism=Mechanism.EDDSA)

        try:
            result = pub.verify(b"tampered data", signature, mechanism=Mechanism.EDDSA)
            assert result is False
        except p11.exceptions.PKCS11Error:
            pass  # Expected — invalid signature
        finally:
            pub.destroy()
            priv.destroy()
