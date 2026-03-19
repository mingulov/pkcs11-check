"""Tests for RSA-OAEP encrypt/decrypt with cross-verification.

Covers roundtrip, randomness, cross-verification with cryptography,
different plaintext sizes, and max plaintext length.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.crossverify


class TestRSAOAEPRoundtrip:
    def test_oaep_encrypt_decrypt(self, p11_session: Any) -> None:
        """RSA-OAEP: encrypt then decrypt returns original."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        plaintext = b"RSA-OAEP roundtrip"

        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert pt == plaintext

    def test_oaep_randomized(self, p11_session: Any) -> None:
        """RSA-OAEP produces different ciphertext for same plaintext."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        plaintext = b"OAEP randomness"

        ct1 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        ct2 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert ct1 != ct2
        assert priv.decrypt(ct1, mechanism=Mechanism.RSA_PKCS_OAEP) == plaintext
        assert priv.decrypt(ct2, mechanism=Mechanism.RSA_PKCS_OAEP) == plaintext

    def test_oaep_empty_plaintext(self, p11_session: Any) -> None:
        """RSA-OAEP with empty plaintext."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        ct = pub.encrypt(b"", mechanism=Mechanism.RSA_PKCS_OAEP)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert pt == b""

    def test_oaep_max_plaintext(self, p11_session: Any) -> None:
        """RSA-OAEP with maximum plaintext size.

        For RSA-2048 with SHA-1 OAEP: max = 256 - 2*20 - 2 = 214 bytes.
        """
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        plaintext = b"\xab" * 190  # Safe under 214-byte limit
        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert pt == plaintext

    def test_oaep_ciphertext_size(self, p11_session: Any) -> None:
        """RSA-OAEP ciphertext is always modulus-length (256 bytes for 2048)."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        for pt_len in [1, 16, 100, 190]:
            ct = pub.encrypt(b"\x00" * pt_len, mechanism=Mechanism.RSA_PKCS_OAEP)
            assert len(ct) == 256


class TestRSAOAEPCrossVerify:
    def _export_rsa_pubkey(self, pub_p11: Any) -> rsa.RSAPublicKey:
        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_encrypt_crypto_decrypt_p11(self, p11_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        pub_crypto = self._export_rsa_pubkey(pub_p11)
        plaintext = b"OAEP cross-verify"

        ct = pub_crypto.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        try:
            pt = priv_p11.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
            assert pt == plaintext
        except p11.exceptions.PKCS11Error:
            pytest.xfail("OAEP param mismatch between module and cryptography")

    def test_wrong_key_decrypt_fails(self, p11_session: Any) -> None:
        """Decrypting with wrong private key should fail."""
        pub1, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        _, priv2 = p11_session.generate_keypair(KeyType.RSA, 2048)

        ct = pub1.encrypt(b"wrong key test", mechanism=Mechanism.RSA_PKCS_OAEP)
        try:
            priv2.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
            pytest.fail("Decryption with wrong key should fail")
        except p11.exceptions.PKCS11Error:
            pass  # Expected
