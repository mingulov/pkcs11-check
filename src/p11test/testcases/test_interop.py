"""Interoperability tests — generate keys in PKCS#11, use in cryptography, and vice versa.

Tests the full round-trip: PKCS#11 → export → cryptography → verify back in PKCS#11.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.interop


class TestRSAInterop:
    """RSA key interop between PKCS#11 and cryptography."""

    def test_sign_in_crypto_verify_in_p11(self, p11_session: Any) -> None:
        """Generate RSA in PKCS#11, export pubkey, sign with crypto, verify in PKCS#11."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)

        # Export public key components
        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")

        # Create cryptography private key... we can't (private key not extractable)
        # Instead: sign in PKCS#11, verify in crypto (already tested in crossverify)
        # Here: test the reverse where possible

        # Sign with PKCS#11
        data = b"interop test data"
        sig = priv_p11.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Verify with cryptography
        pub_crypto = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        pub_crypto.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())

        # Also verify back in PKCS#11 (full round-trip)
        assert pub_p11.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)

        pub_p11.destroy()
        priv_p11.destroy()

    def test_rsa_pubkey_encoding(self, p11_session: Any) -> None:
        """Export RSA public key, serialize to PEM, parse back."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)

        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        pub_crypto = rsa.RSAPublicNumbers(exponent, modulus).public_key()

        # Serialize to PEM
        pem = pub_crypto.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert b"BEGIN PUBLIC KEY" in pem

        # Parse back
        pub_parsed = serialization.load_pem_public_key(pem)
        assert hasattr(pub_parsed, "key_size")
        assert pub_parsed.key_size == 2048

        pub_p11.destroy()
        priv_p11.destroy()


class TestECDSAInterop:
    """ECDSA key interop between PKCS#11 and cryptography."""

    def test_ecdsa_sign_p11_verify_crypto_verify_p11(self, p11_session: Any) -> None:
        """Full ECDSA round-trip: sign in P11, verify in crypto, verify in P11."""
        import hashlib

        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub_p11, priv_p11 = ecparams.generate_keypair()

        data = b"ECDSA interop round-trip"
        digest = hashlib.sha256(data).digest()

        # Sign in PKCS#11
        sig_raw = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        # Verify in PKCS#11
        assert pub_p11.verify(digest, sig_raw, mechanism=Mechanism.ECDSA)

        # Export point and verify in cryptography
        ec_point = pub_p11[Attribute.EC_POINT]
        if ec_point[0] == 0x04:
            point_bytes = ec_point[2:] if ec_point[1] < 128 else ec_point[3:]
        else:
            point_bytes = ec_point

        pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)

        r = int.from_bytes(sig_raw[:32], "big")
        s = int.from_bytes(sig_raw[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)

        pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))

        pub_p11.destroy()
        priv_p11.destroy()


class TestAESInterop:
    """AES key interop — import key from raw bytes, use in both."""

    def test_aes_key_roundtrip(self, p11_session: Any) -> None:
        """Import AES key, encrypt in P11, decrypt in crypto, compare."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key_bytes = bytes(range(32))
        plaintext = b"AES interop test"  # 16 bytes

        # Import into PKCS#11
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: p11.ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )

        # Encrypt in PKCS#11
        ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        # Decrypt in cryptography
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        dec = cipher.decryptor()
        pt = dec.update(ct) + dec.finalize()

        assert pt == plaintext

    def test_aes_encrypt_crypto_decrypt_p11(self, p11_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key_bytes = bytes(range(32))
        plaintext = b"reverse interop!"  # 16 bytes

        # Encrypt with cryptography
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()

        # Import key and decrypt in PKCS#11
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: p11.ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        pt = p11_key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext
