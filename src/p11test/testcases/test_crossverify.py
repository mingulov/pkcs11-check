"""Cross-verification: perform ops via PKCS#11, verify with cryptography library."""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.crossverify


class TestAESCrossVerify:
    """Verify AES encrypt via PKCS#11 matches cryptography library.

    Uses AES-ECB for exact comparison (no padding ambiguity).
    """

    def _import_aes_key(self, session: Any, key_bytes: bytes) -> Any:
        return session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            }
        )

    def test_aes_256_ecb_encrypt(self, p11_session: Any) -> None:
        """AES-256-ECB: PKCS#11 encrypt must match cryptography."""
        key_bytes = bytes(range(32))
        plaintext = b"cross-verify AES"  # exactly 16 bytes

        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        crypto_ct = enc.update(plaintext) + enc.finalize()

        assert p11_ct == crypto_ct

    def test_aes_128_ecb_encrypt(self, p11_session: Any) -> None:
        """AES-128-ECB cross-verification."""
        key_bytes = bytes(16)
        plaintext = b"128-bit AES key!"

        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        crypto_ct = enc.update(plaintext) + enc.finalize()

        assert p11_ct == crypto_ct

    def test_aes_ecb_decrypt(self, p11_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        key_bytes = bytes(range(32))
        plaintext = b"decrypt-xverify!"

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()

        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_pt = p11_key.decrypt(ciphertext, mechanism=Mechanism.AES_ECB)

        assert p11_pt == plaintext

    def test_aes_ecb_multiblock(self, p11_session: Any) -> None:
        """AES-ECB with multiple blocks cross-verification."""
        key_bytes = bytes(range(32))
        plaintext = b"A" * 64  # 4 blocks

        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        crypto_ct = enc.update(plaintext) + enc.finalize()

        assert p11_ct == crypto_ct


class TestRSACrossVerify:
    """Verify RSA signatures via PKCS#11 are valid per cryptography.

    Exports modulus + exponent (v2.40 compatible) instead of PUBLIC_KEY_INFO.
    """

    def _export_rsa_pubkey(self, pub_p11: Any) -> rsa.RSAPublicKey:
        """Export RSA public key from PKCS#11 and load into cryptography."""
        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_rsa_pkcs_sign(self, p11_session: Any) -> None:
        """RSA PKCS#1 v1.5: sign with PKCS#11, verify with cryptography."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA PKCS cross-verify test data"

        signature = priv_p11.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        pub_crypto = self._export_rsa_pubkey(pub_p11)
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())

    def test_rsa_4096_sign(self, p11_session: Any) -> None:
        """RSA-4096 PKCS#1 v1.5 cross-verification."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 4096)
        data = b"RSA-4096 cross-verify"

        signature = priv_p11.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(signature) == 512

        pub_crypto = self._export_rsa_pubkey(pub_p11)
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())

    def test_rsa_sha512_sign(self, p11_session: Any) -> None:
        """RSA with SHA-512 cross-verification."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA SHA-512 cross-verify"

        signature = priv_p11.sign(data, mechanism=Mechanism.SHA512_RSA_PKCS)

        pub_crypto = self._export_rsa_pubkey(pub_p11)
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())


class TestECDSACrossVerify:
    """Verify ECDSA signatures via PKCS#11 are valid per cryptography.

    Exports EC point (v2.40 compatible) and constructs public key.
    """

    def _export_ec_pubkey(self, pub_p11: Any, curve: ec.EllipticCurve) -> ec.EllipticCurvePublicKey:
        """Export EC public key from PKCS#11 point encoding."""
        ec_point = pub_p11[Attribute.EC_POINT]
        # python-pkcs11 wraps the point in DER OCTET STRING — strip it
        # The raw point is typically 04 || x || y (uncompressed)
        if ec_point[0] == 0x04 and len(ec_point) > 65:
            # DER OCTET STRING wrapper: tag(04) + length + point
            point_bytes = ec_point[2:] if ec_point[1] < 128 else ec_point[3:]
        else:
            point_bytes = ec_point
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point_bytes)

    def test_ecdsa_p256(self, p11_session: Any) -> None:
        """ECDSA P-256: sign with PKCS#11, verify with cryptography."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub_p11, priv_p11 = ecparams.generate_keypair()
        data = b"ECDSA P-256 cross-verify"
        digest = hashlib.sha256(data).digest()

        signature = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        pub_crypto = self._export_ec_pubkey(pub_p11, ec.SECP256R1())

        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_sig = encode_dss_signature(r, s)

        pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))

    def test_ecdsa_p384(self, p11_session: Any) -> None:
        """ECDSA P-384: sign with PKCS#11, verify with cryptography."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp384r1")},
            local=True,
        )
        pub_p11, priv_p11 = ecparams.generate_keypair()
        data = b"ECDSA P-384 cross-verify"
        digest = hashlib.sha384(data).digest()

        signature = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        pub_crypto = self._export_ec_pubkey(pub_p11, ec.SECP384R1())

        half = len(signature) // 2
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        der_sig = encode_dss_signature(r, s)

        pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA384()))


class TestDigestCrossVerify:
    """Verify PKCS#11 digests match Python hashlib."""

    def test_sha256(self, p11_session: Any) -> None:
        data = b"digest cross-verification data"
        assert p11_session.digest(data, mechanism=Mechanism.SHA256) == hashlib.sha256(data).digest()

    def test_sha512(self, p11_session: Any) -> None:
        data = b"sha512 cross-verify"
        assert p11_session.digest(data, mechanism=Mechanism.SHA512) == hashlib.sha512(data).digest()

    def test_sha384(self, p11_session: Any) -> None:
        data = b"sha384 cross-verify"
        assert p11_session.digest(data, mechanism=Mechanism.SHA384) == hashlib.sha384(data).digest()

    def test_sha1(self, p11_session: Any) -> None:
        data = b"sha1 cross-verify"
        assert p11_session.digest(data, mechanism=Mechanism.SHA_1) == hashlib.sha1(data).digest()

    def test_sha256_empty(self, p11_session: Any) -> None:
        assert p11_session.digest(b"", mechanism=Mechanism.SHA256) == hashlib.sha256(b"").digest()

    def test_sha256_large(self, p11_session: Any) -> None:
        data = b"X" * 100_000
        assert p11_session.digest(data, mechanism=Mechanism.SHA256) == hashlib.sha256(data).digest()

    def test_sha224(self, p11_session: Any) -> None:
        data = b"sha224 cross-verify"
        assert p11_session.digest(data, mechanism=Mechanism.SHA224) == hashlib.sha224(data).digest()


class TestHMACCrossVerify:
    """Verify PKCS#11 HMAC matches Python hmac module."""

    def test_hmac_sha256(self, p11_session: Any) -> None:
        """HMAC-SHA256: PKCS#11 vs Python hmac."""
        import hmac as hmac_mod

        key_bytes = bytes(range(32))
        data = b"HMAC cross-verification data"

        # Import key for HMAC
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA256_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )

        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        py_mac = hmac_mod.new(key_bytes, data, "sha256").digest()

        assert p11_mac == py_mac

    def test_hmac_sha1(self, p11_session: Any) -> None:
        """HMAC-SHA1: PKCS#11 vs Python hmac."""
        import hmac as hmac_mod

        key_bytes = bytes(range(20))

        try:
            p11_key = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.SHA_1_HMAC,
                    Attribute.VALUE: key_bytes,
                    Attribute.SIGN: True,
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                }
            )
        except (p11.exceptions.PKCS11Error, AttributeError):
            pytest.skip("SHA-1 HMAC key type not supported")

        data = b"HMAC-SHA1 cross-verify"
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA_1_HMAC)
        py_mac = hmac_mod.new(key_bytes, data, "sha1").digest()

        assert p11_mac == py_mac


class TestRSAKeySizeCrossVerify:
    """Cross-verify RSA across different key sizes and hash algorithms."""

    def _export_rsa_pubkey(self, pub_p11: Any) -> Any:
        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_rsa_3072_sha384(self, p11_session: Any) -> None:
        """RSA-3072 with SHA-384."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 3072)
        data = b"RSA-3072 SHA-384 cross-verify"
        signature = priv_p11.sign(data, mechanism=Mechanism.SHA384_RSA_PKCS)
        pub_crypto = self._export_rsa_pubkey(pub_p11)
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA384())

    def test_rsa_2048_sha1(self, p11_session: Any) -> None:
        """RSA-2048 with SHA-1 (legacy, still common)."""
        from p11test.compliance import ComplianceLevel, note

        note(
            "RSA with SHA-1 signatures",
            ComplianceLevel.DEPRECATED,
            reference="NIST SP 800-131A Rev. 2",
        )
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA SHA-1 cross-verify"
        signature = priv_p11.sign(data, mechanism=Mechanism.SHA1_RSA_PKCS)
        pub_crypto = self._export_rsa_pubkey(pub_p11)
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())

    def test_rsa_2048_sha224(self, p11_session: Any) -> None:
        """RSA-2048 with SHA-224."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA SHA-224 cross-verify"
        signature = priv_p11.sign(data, mechanism=Mechanism.SHA224_RSA_PKCS)
        pub_crypto = self._export_rsa_pubkey(pub_p11)
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA224())
