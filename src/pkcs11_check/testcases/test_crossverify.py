"""Cross-verification: perform ops via PKCS#11, verify with cryptography library."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_ec_keypair,
    gen_rsa_keypair,
    import_secret_key,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKK_SHA_1_HMAC,
    CKM_AES_ECB,
    CKM_ECDSA,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA224,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA_1,
    CKM_SHA_1_HMAC,
)

pytestmark = pytest.mark.crossverify


def _import_aes_key_raw(rs: Any, key_bytes: bytes) -> int:
    """Import raw AES key bytes via raw API."""
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        key_bytes,
        attrs={
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


class TestAESCrossVerify:
    """Verify AES encrypt via PKCS#11 matches cryptography library.

    Uses AES-ECB for exact comparison (no padding ambiguity).
    """

    def test_aes_256_ecb_encrypt(self, p11_raw_session: Any) -> None:
        """AES-256-ECB: PKCS#11 encrypt must match cryptography."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        plaintext = b"cross-verify AES"  # exactly 16 bytes

        p11_key = _import_aes_key_raw(rs, key_bytes)
        try:
            p11_ct = encrypt_single(rs.raw, rs.sh, p11_key, CKM_AES_ECB, plaintext)

            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            enc = cipher.encryptor()
            crypto_ct = enc.update(plaintext) + enc.finalize()

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_aes_128_ecb_encrypt(self, p11_raw_session: Any) -> None:
        """AES-128-ECB cross-verification."""
        rs = p11_raw_session
        key_bytes = bytes(16)
        plaintext = b"128-bit AES key!"

        p11_key = _import_aes_key_raw(rs, key_bytes)
        try:
            p11_ct = encrypt_single(rs.raw, rs.sh, p11_key, CKM_AES_ECB, plaintext)

            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            enc = cipher.encryptor()
            crypto_ct = enc.update(plaintext) + enc.finalize()

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_aes_ecb_decrypt(self, p11_raw_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        plaintext = b"decrypt-xverify!"

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()

        p11_key = _import_aes_key_raw(rs, key_bytes)
        try:
            p11_pt = decrypt_single(rs.raw, rs.sh, p11_key, CKM_AES_ECB, ciphertext)
            assert p11_pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_aes_ecb_multiblock(self, p11_raw_session: Any) -> None:
        """AES-ECB with multiple blocks cross-verification."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        plaintext = b"A" * 64  # 4 blocks

        p11_key = _import_aes_key_raw(rs, key_bytes)
        try:
            p11_ct = encrypt_single(rs.raw, rs.sh, p11_key, CKM_AES_ECB, plaintext)

            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            enc = cipher.encryptor()
            crypto_ct = enc.update(plaintext) + enc.finalize()

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)


class TestRSACrossVerify:
    """Verify RSA signatures via PKCS#11 are valid per cryptography.

    Exports modulus + exponent (v2.40 compatible) instead of PUBLIC_KEY_INFO.
    """

    def _export_rsa_pubkey(self, rs: Any, pub_h: int) -> rsa.RSAPublicKey:
        """Export RSA public key from PKCS#11 and load into cryptography."""
        attrs = read_attributes(
            rs.raw,
            rs.sh,
            pub_h,
            [CKA_MODULUS, CKA_PUBLIC_EXPONENT],
        )
        modulus = int.from_bytes(attrs[CKA_MODULUS], "big")
        exponent = int.from_bytes(attrs[CKA_PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_rsa_pkcs_sign(self, p11_raw_session: Any) -> None:
        """RSA PKCS#1 v1.5: sign with PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"RSA PKCS cross-verify test data"
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            pub_crypto = self._export_rsa_pubkey(rs, pub)
            pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_4096_sign(self, p11_raw_session: Any) -> None:
        """RSA-4096 PKCS#1 v1.5 cross-verification."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 4096)
        try:
            data = b"RSA-4096 cross-verify"
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(signature) == 512

            pub_crypto = self._export_rsa_pubkey(rs, pub)
            pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_sha512_sign(self, p11_raw_session: Any) -> None:
        """RSA with SHA-512 cross-verification."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"RSA SHA-512 cross-verify"
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA512_RSA_PKCS, data)

            pub_crypto = self._export_rsa_pubkey(rs, pub)
            pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSACrossVerify:
    """Verify ECDSA signatures via PKCS#11 are valid per cryptography.

    Exports EC point (v2.40 compatible) and constructs public key.
    """

    def _export_ec_pubkey(
        self,
        rs: Any,
        pub_h: int,
        curve: ec.EllipticCurve,
    ) -> ec.EllipticCurvePublicKey:
        """Export EC public key from PKCS#11 point encoding."""
        attrs = read_attributes(
            rs.raw,
            rs.sh,
            pub_h,
            [CKA_EC_POINT],
        )
        ec_point = attrs[CKA_EC_POINT]
        assert isinstance(ec_point, bytes)
        # Unwrap DER OCTET STRING to raw point (0x04||x||y)
        point_bytes = decode_ec_point(ec_point)
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point_bytes)

    def test_ecdsa_p256(self, p11_raw_session: Any) -> None:
        """ECDSA P-256: sign with PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            data = b"ECDSA P-256 cross-verify"
            digest = hashlib.sha256(data).digest()
            signature = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)

            pub_crypto = self._export_ec_pubkey(rs, pub, ec.SECP256R1())

            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der_sig = encode_dss_signature(r, s)

            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ecdsa_p384(self, p11_raw_session: Any) -> None:
        """ECDSA P-384: sign with PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        curve_oid = encode_named_curve_parameters("secp384r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            data = b"ECDSA P-384 cross-verify"
            digest = hashlib.sha384(data).digest()
            signature = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)

            pub_crypto = self._export_ec_pubkey(rs, pub, ec.SECP384R1())

            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            der_sig = encode_dss_signature(r, s)

            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA384()))
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestDigestCrossVerify:
    """Verify PKCS#11 digests match Python hashlib."""

    def test_sha256(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        data = b"digest cross-verification data"
        assert digest_single(rs.raw, rs.sh, CKM_SHA256, data) == hashlib.sha256(data).digest()

    def test_sha512(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        data = b"sha512 cross-verify"
        assert digest_single(rs.raw, rs.sh, CKM_SHA512, data) == hashlib.sha512(data).digest()

    def test_sha384(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        data = b"sha384 cross-verify"
        assert digest_single(rs.raw, rs.sh, CKM_SHA384, data) == hashlib.sha384(data).digest()

    def test_sha1(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        data = b"sha1 cross-verify"
        assert digest_single(rs.raw, rs.sh, CKM_SHA_1, data) == hashlib.sha1(data).digest()

    def test_sha256_empty(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert digest_single(rs.raw, rs.sh, CKM_SHA256, b"") == hashlib.sha256(b"").digest()

    def test_sha256_large(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        data = b"X" * 100_000
        assert digest_single(rs.raw, rs.sh, CKM_SHA256, data) == hashlib.sha256(data).digest()

    def test_sha224(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        data = b"sha224 cross-verify"
        assert digest_single(rs.raw, rs.sh, CKM_SHA224, data) == hashlib.sha224(data).digest()


class TestHMACCrossVerify:
    """Verify PKCS#11 HMAC matches Python hmac module."""

    def test_hmac_sha256(self, p11_raw_session: Any) -> None:
        """HMAC-SHA256: PKCS#11 vs Python hmac."""
        import hmac as hmac_mod

        rs = p11_raw_session
        key_bytes = bytes(range(32))
        data = b"HMAC cross-verification data"

        # Try SHA256_HMAC key type first, fall back to GENERIC_SECRET
        p11_key = 0
        for key_type in (CKK_SHA256_HMAC, CKK_GENERIC_SECRET):
            try:
                p11_key = import_secret_key(
                    rs.raw,
                    rs.sh,
                    key_type,
                    key_bytes,
                    attrs={
                        CKA_SIGN: True,
                        CKA_VERIFY: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
                break
            except AssertionError as exc:
                if any(
                    name in str(exc)
                    for name in (
                        "CKR_MECHANISM_INVALID",
                        "CKR_KEY_SIZE_RANGE",
                        "CKR_TEMPLATE_INCONSISTENT",
                    )
                ):
                    continue
                raise
        if p11_key == 0:
            pytest.skip("Cannot create HMAC key")

        try:
            p11_mac = sign_single(rs.raw, rs.sh, p11_key, CKM_SHA256_HMAC, data)
            py_mac = hmac_mod.new(key_bytes, data, "sha256").digest()
            assert p11_mac == py_mac
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_hmac_sha1(self, p11_raw_session: Any) -> None:
        """HMAC-SHA1: PKCS#11 vs Python hmac."""
        import hmac as hmac_mod

        rs = p11_raw_session
        key_bytes = bytes(range(20))

        try:
            p11_key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_SHA_1_HMAC,
                key_bytes,
                attrs={
                    CKA_SIGN: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
            )
        except (AssertionError, AttributeError):
            pytest.skip("SHA-1 HMAC key type not supported")
            return

        try:
            data = b"HMAC-SHA1 cross-verify"
            p11_mac = sign_single(rs.raw, rs.sh, p11_key, CKM_SHA_1_HMAC, data)
            py_mac = hmac_mod.new(key_bytes, data, "sha1").digest()
            assert p11_mac == py_mac
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)


class TestRSAKeySizeCrossVerify:
    """Cross-verify RSA across different key sizes and hash algorithms."""

    def _export_rsa_pubkey(self, rs: Any, pub_h: int) -> Any:
        attrs = read_attributes(
            rs.raw,
            rs.sh,
            pub_h,
            [CKA_MODULUS, CKA_PUBLIC_EXPONENT],
        )
        modulus = int.from_bytes(attrs[CKA_MODULUS], "big")
        exponent = int.from_bytes(attrs[CKA_PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_rsa_3072_sha384(self, p11_raw_session: Any) -> None:
        """RSA-3072 with SHA-384."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 3072)
        try:
            data = b"RSA-3072 SHA-384 cross-verify"
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA384_RSA_PKCS, data)
            pub_crypto = self._export_rsa_pubkey(rs, pub)
            pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA384())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_2048_sha1(self, p11_raw_session: Any) -> None:
        """RSA-2048 with SHA-1 (legacy, still common)."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        note(
            "RSA with SHA-1 signatures",
            ComplianceLevel.DEPRECATED,
            reference="NIST SP 800-131A Rev. 2",
        )
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"RSA SHA-1 cross-verify"
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA1_RSA_PKCS, data)
            pub_crypto = self._export_rsa_pubkey(rs, pub)
            pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_2048_sha224(self, p11_raw_session: Any) -> None:
        """RSA-2048 with SHA-224."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"RSA SHA-224 cross-verify"
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA224_RSA_PKCS, data)
            pub_crypto = self._export_rsa_pubkey(rs, pub)
            pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA224())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
