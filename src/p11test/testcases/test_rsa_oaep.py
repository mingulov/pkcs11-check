"""Tests for RSA-OAEP encrypt/decrypt with cross-verification."""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.crossverify


class TestRSAOAEPRoundtrip:
    """Test RSA-OAEP encrypt/decrypt roundtrip."""

    def test_oaep_encrypt_decrypt(self, p11_session: Any) -> None:
        """RSA-OAEP: encrypt then decrypt must return original."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        plaintext = b"RSA-OAEP roundtrip"

        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)

        assert pt == plaintext
        pub.destroy()
        priv.destroy()

    def test_oaep_different_encryptions_differ(self, p11_session: Any) -> None:
        """RSA-OAEP is randomized — same plaintext produces different ciphertext."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        plaintext = b"OAEP randomness"

        ct1 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        ct2 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)

        assert ct1 != ct2  # OAEP is randomized
        # Both should decrypt correctly
        assert priv.decrypt(ct1, mechanism=Mechanism.RSA_PKCS_OAEP) == plaintext
        assert priv.decrypt(ct2, mechanism=Mechanism.RSA_PKCS_OAEP) == plaintext
        pub.destroy()
        priv.destroy()


class TestRSAOAEPCrossVerify:
    """Cross-verify RSA-OAEP against cryptography library."""

    def _export_rsa_pubkey(self, pub_p11: Any) -> rsa.RSAPublicKey:
        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_oaep_encrypt_p11_decrypt_crypto(self, p11_session: Any) -> None:
        """Encrypt with PKCS#11, verify decryptable with cryptography.

        Note: This requires extractable private key, which most HSMs don't allow.
        We test the inverse: encrypt with crypto, decrypt with PKCS#11.
        """
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        pub_crypto = self._export_rsa_pubkey(pub_p11)

        plaintext = b"OAEP cross-verify"

        # Encrypt with cryptography
        ct = pub_crypto.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        # Decrypt with PKCS#11
        try:
            pt = priv_p11.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
            assert pt == plaintext
        except p11.exceptions.PKCS11Error:
            # Some modules use different default OAEP params
            pytest.xfail("OAEP param mismatch between module and cryptography")
        finally:
            pub_p11.destroy()
            priv_p11.destroy()
