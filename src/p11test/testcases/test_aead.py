"""Tests for AEAD (Authenticated Encryption) — AES-GCM cross-verification.

Verifies AES-GCM encrypt/decrypt via PKCS#11 against Python cryptography.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pkcs11 import KeyType, Mechanism
from pkcs11.mechanisms import GCMParams

from p11test.testcases.conftest import import_aes_key

pytestmark = pytest.mark.crossverify


class TestAESGCMCrossVerify:
    """Cross-verify AES-GCM against Python cryptography."""

    def test_gcm_256_encrypt_crossverify(self, p11_session: Any) -> None:
        """AES-256-GCM: encrypt via PKCS#11, verify with cryptography."""
        key_bytes = bytes(range(32))
        nonce = bytes(12)  # 96-bit recommended IV
        plaintext = b"GCM cross-verify test data!!"
        aad = b"additional authenticated data"

        p11_key = import_aes_key(p11_session, key_bytes)
        gcm_params = GCMParams(nonce=nonce, aad=aad, tag_bits=128)
        p11_ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=gcm_params)

        # p11 returns ciphertext + tag concatenated
        # cryptography returns the same format
        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        assert p11_ct == crypto_ct

    def test_gcm_128_encrypt_crossverify(self, p11_session: Any) -> None:
        """AES-128-GCM cross-verify."""
        key_bytes = bytes(16)
        nonce = bytes(range(12))
        plaintext = b"GCM-128 test!!"

        p11_key = import_aes_key(p11_session, key_bytes)
        gcm_params = GCMParams(nonce=nonce, tag_bits=128)
        p11_ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=gcm_params)

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, None)

        assert p11_ct == crypto_ct

    def test_gcm_decrypt_crossverify(self, p11_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"decrypt cross-verify"
        aad = b"aad data"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        p11_key = import_aes_key(p11_session, key_bytes)
        gcm_params = GCMParams(nonce=nonce, aad=aad, tag_bits=128)
        p11_pt = p11_key.decrypt(crypto_ct, mechanism=Mechanism.AES_GCM, mechanism_param=gcm_params)

        assert p11_pt == plaintext

    def test_gcm_tampered_tag_rejected(self, p11_session: Any) -> None:
        """Tampered GCM ciphertext must be rejected by PKCS#11."""
        import pkcs11 as p11

        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"tamper detection"
        aad = b"auth data"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        # Tamper with the tag (last 16 bytes)
        tampered = bytearray(crypto_ct)
        tampered[-1] ^= 0xFF

        p11_key = import_aes_key(p11_session, key_bytes)
        gcm_params = GCMParams(nonce=nonce, aad=aad, tag_bits=128)

        with pytest.raises(p11.exceptions.PKCS11Error):
            p11_key.decrypt(
                bytes(tampered),
                mechanism=Mechanism.AES_GCM,
                mechanism_param=gcm_params,
            )

    def test_gcm_wrong_aad_rejected(self, p11_session: Any) -> None:
        """Wrong AAD must cause decryption failure."""
        import pkcs11 as p11

        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"aad integrity"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, b"correct aad")

        p11_key = import_aes_key(p11_session, key_bytes)
        gcm_params = GCMParams(nonce=nonce, aad=b"wrong aad", tag_bits=128)

        with pytest.raises(p11.exceptions.PKCS11Error):
            p11_key.decrypt(crypto_ct, mechanism=Mechanism.AES_GCM, mechanism_param=gcm_params)


class TestAESGCMProperties:
    """Test AES-GCM AEAD properties."""

    def test_gcm_different_nonces_different_ct(self, p11_session: Any) -> None:
        """Same key+plaintext with different nonces must produce different ciphertext."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"nonce uniqueness"

        nonce1 = p11_session.generate_random(96)
        nonce2 = p11_session.generate_random(96)

        gcm1 = GCMParams(nonce=nonce1, tag_bits=128)
        gcm2 = GCMParams(nonce=nonce2, tag_bits=128)

        ct1 = key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=gcm1)
        ct2 = key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=gcm2)

        assert ct1 != ct2

    def test_gcm_roundtrip(self, p11_session: Any) -> None:
        """GCM encrypt then decrypt must return original plaintext."""
        key = p11_session.generate_key(KeyType.AES, 256)
        nonce = p11_session.generate_random(96)
        plaintext = b"GCM roundtrip test data"
        aad = b"authenticated but not encrypted"

        gcm_enc = GCMParams(nonce=nonce, aad=aad, tag_bits=128)
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=gcm_enc)

        gcm_dec = GCMParams(nonce=nonce, aad=aad, tag_bits=128)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_GCM, mechanism_param=gcm_dec)

        assert pt == plaintext
