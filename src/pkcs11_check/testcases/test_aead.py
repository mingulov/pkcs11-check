"""Tests for AEAD (Authenticated Encryption) - AES-GCM cross-verification.

Verifies AES-GCM encrypt/decrypt via PKCS#11 against Python cryptography.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pkcs11_check.raw.pack import mech_gcm
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    generate_random,
    import_secret_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_GCM,
)

pytestmark = pytest.mark.crossverify


def _import_aes(rs: Any, key_bytes: bytes) -> int:
    """Import an AES key with encrypt/decrypt for the raw session."""
    return import_secret_key(
        rs.raw, rs.sh, CKK_AES, key_bytes,
        attrs={
            int(CKA_ENCRYPT): True,
            int(CKA_DECRYPT): True,
            int(CKA_TOKEN): False,
        },
    )


class TestAESGCMCrossVerify:
    """Cross-verify AES-GCM against Python cryptography."""

    def test_gcm_256_encrypt_crossverify(self, p11_raw_session: Any) -> None:
        """AES-256-GCM: encrypt via PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        nonce = bytes(12)  # 96-bit recommended IV
        plaintext = b"GCM cross-verify test data!!"
        aad = b"additional authenticated data"

        p11_key = _import_aes(rs, key_bytes)
        try:
            p11_ct = encrypt_single(
                rs.raw, rs.sh, p11_key, CKM_AES_GCM, plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
            )

            # p11 returns ciphertext + tag concatenated
            # cryptography returns the same format
            aesgcm = AESGCM(key_bytes)
            crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_128_encrypt_crossverify(self, p11_raw_session: Any) -> None:
        """AES-128-GCM cross-verify."""
        rs = p11_raw_session
        key_bytes = bytes(16)
        nonce = bytes(range(12))
        plaintext = b"GCM-128 test!!"

        p11_key = _import_aes(rs, key_bytes)
        try:
            p11_ct = encrypt_single(
                rs.raw, rs.sh, p11_key, CKM_AES_GCM, plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, tag_bits=128),
            )

            aesgcm = AESGCM(key_bytes)
            crypto_ct = aesgcm.encrypt(nonce, plaintext, None)

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_decrypt_crossverify(self, p11_raw_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"decrypt cross-verify"
        aad = b"aad data"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        p11_key = _import_aes(rs, key_bytes)
        try:
            p11_pt = decrypt_single(
                rs.raw, rs.sh, p11_key, CKM_AES_GCM, crypto_ct,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
            )

            assert p11_pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_tampered_tag_rejected(self, p11_raw_session: Any) -> None:
        """Tampered GCM ciphertext must be rejected by PKCS#11."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"tamper detection"
        aad = b"auth data"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        # Tamper with the tag (last 16 bytes)
        tampered = bytearray(crypto_ct)
        tampered[-1] ^= 0xFF

        p11_key = _import_aes(rs, key_bytes)
        try:
            with pytest.raises(AssertionError):
                decrypt_single(
                    rs.raw, rs.sh, p11_key, CKM_AES_GCM, bytes(tampered),
                    mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_wrong_aad_rejected(self, p11_raw_session: Any) -> None:
        """Wrong AAD must cause decryption failure."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"aad integrity"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, b"correct aad")

        p11_key = _import_aes(rs, key_bytes)
        try:
            with pytest.raises(AssertionError):
                decrypt_single(
                    rs.raw, rs.sh, p11_key, CKM_AES_GCM, crypto_ct,
                    mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=b"wrong aad", tag_bits=128),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)


class TestAESGCMProperties:
    """Test AES-GCM AEAD properties."""

    def test_gcm_different_nonces_different_ct(self, p11_raw_session: Any) -> None:
        """Same key+plaintext with different nonces must produce different ciphertext."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        plaintext = b"nonce uniqueness"

        nonce1 = generate_random(rs.raw, rs.sh, 12)
        nonce2 = generate_random(rs.raw, rs.sh, 12)

        try:
            ct1 = encrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM, plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce1, tag_bits=128),
            )
            ct2 = encrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM, plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce2, tag_bits=128),
            )

            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_gcm_roundtrip(self, p11_raw_session: Any) -> None:
        """GCM encrypt then decrypt must return original plaintext."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        nonce = generate_random(rs.raw, rs.sh, 12)
        plaintext = b"GCM roundtrip test data"
        aad = b"authenticated but not encrypted"

        try:
            ct = encrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM, plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
            )

            pt = decrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM, ct,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
            )

            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
