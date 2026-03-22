"""Standalone stream cipher tests -- Salsa20, ChaCha20, Poly1305.

Covers:
  - CKM_SALSA20_KEY_GEN + CKM_SALSA20: Salsa20 stream cipher encrypt/decrypt
  - CKM_POLY1305_KEY_GEN + CKM_POLY1305: standalone Poly1305 MAC sign/verify
  - CKM_CHACHA20_KEY_GEN + CKM_CHACHA20: ChaCha20 stream cipher encrypt/decrypt

Note: CKM_CHACHA20_POLY1305 (AEAD combined) is tested in wycheproof/test_wycheproof_chacha.py.

OASIS spec: stream_ciphers.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import FunctionFailed, MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# ChaCha20 nonce: 12 bytes (96 bits) is the standard IETF nonce size.
# Block counter: 4 bytes (32 bits) as per IETF ChaCha20 (RFC 7539).
_CHACHA20_NONCE = b"\x00" * 12
_CHACHA20_BLOCK_COUNTER = b"\x00\x00\x00\x00"

# Salsa20 nonce: 8 bytes (64 bits).
# Block counter: 8 bytes (64 bits).
_SALSA20_NONCE = b"\x00" * 8
_SALSA20_BLOCK_COUNTER = b"\x00\x00\x00\x00\x00\x00\x00\x00"

class TestSalsa20:
    """Tests for CKM_SALSA20_KEY_GEN and CKM_SALSA20 stream cipher."""

    def test_salsa20_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a Salsa20 256-bit session key."""
        if not has_mechanism(p11_module, "SALSA20_KEY_GEN"):
            pytest.skip("CKM_SALSA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.SALSA20,
            256,
            mechanism=Mechanism.SALSA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            assert key is not None
            assert key.key_type == KeyType.SALSA20
        finally:
            key.destroy()

    def test_salsa20_encrypt_decrypt(self, p11_session: Any, p11_module: Any) -> None:
        """Salsa20 encrypt/decrypt roundtrip produces original plaintext."""
        if not has_mechanism(p11_module, "SALSA20"):
            pytest.skip("CKM_SALSA20 not supported")
        if not has_mechanism(p11_module, "SALSA20_KEY_GEN"):
            pytest.skip("CKM_SALSA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.SALSA20,
            256,
            mechanism=Mechanism.SALSA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            plaintext = b"Salsa20 test plaintext data!!!!!"
            params = (_SALSA20_BLOCK_COUNTER, _SALSA20_NONCE)
            ciphertext = key.encrypt(
                plaintext,
                mechanism=Mechanism.SALSA20,
                mechanism_param=params,
            )
            assert ciphertext != plaintext
            assert len(ciphertext) == len(plaintext)  # stream cipher: no padding
            recovered = key.decrypt(
                ciphertext,
                mechanism=Mechanism.SALSA20,
                mechanism_param=params,
            )
            assert recovered == plaintext
        finally:
            key.destroy()

    def test_salsa20_different_nonces_differ(self, p11_session: Any, p11_module: Any) -> None:
        """Salsa20 with different nonces produces different ciphertext."""
        if not has_mechanism(p11_module, "SALSA20"):
            pytest.skip("CKM_SALSA20 not supported")
        if not has_mechanism(p11_module, "SALSA20_KEY_GEN"):
            pytest.skip("CKM_SALSA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.SALSA20,
            256,
            mechanism=Mechanism.SALSA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            plaintext = b"nonce differentiation test data!"
            nonce1 = b"\x00" * 8
            nonce2 = b"\x01" * 8
            ct1 = key.encrypt(
                plaintext,
                mechanism=Mechanism.SALSA20,
                mechanism_param=(_SALSA20_BLOCK_COUNTER, nonce1),
            )
            ct2 = key.encrypt(
                plaintext,
                mechanism=Mechanism.SALSA20,
                mechanism_param=(_SALSA20_BLOCK_COUNTER, nonce2),
            )
            assert ct1 != ct2
        finally:
            key.destroy()


class TestPoly1305:
    """Tests for CKM_POLY1305_KEY_GEN and CKM_POLY1305 standalone MAC."""

    def test_poly1305_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a Poly1305 256-bit session key."""
        if not has_mechanism(p11_module, "POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.POLY1305,
            256,
            mechanism=Mechanism.POLY1305_KEY_GEN,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            assert key is not None
            assert key.key_type == KeyType.POLY1305
        finally:
            key.destroy()

    def test_poly1305_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Poly1305 sign and verify roundtrip succeeds."""
        if not has_mechanism(p11_module, "POLY1305"):
            pytest.skip("CKM_POLY1305 not supported")
        if not has_mechanism(p11_module, "POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.POLY1305,
            256,
            mechanism=Mechanism.POLY1305_KEY_GEN,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            data = b"Poly1305 MAC test message"
            tag = key.sign(data, mechanism=Mechanism.POLY1305)
            assert len(tag) == 16  # Poly1305 always produces a 16-byte (128-bit) tag
            result = key.verify(data, tag, mechanism=Mechanism.POLY1305)
            assert result is True
        finally:
            key.destroy()

    def test_poly1305_tamper_detection(self, p11_session: Any, p11_module: Any) -> None:
        """Poly1305 verification fails when data is tampered."""
        if not has_mechanism(p11_module, "POLY1305"):
            pytest.skip("CKM_POLY1305 not supported")
        if not has_mechanism(p11_module, "POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.POLY1305,
            256,
            mechanism=Mechanism.POLY1305_KEY_GEN,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            data = b"original message"
            tampered = b"tampered message"
            tag = key.sign(data, mechanism=Mechanism.POLY1305)
            try:
                result = key.verify(tampered, tag, mechanism=Mechanism.POLY1305)
                assert result is False
            except (FunctionFailed, MechanismInvalid):
                pass  # module rejected invalid MAC -- acceptable
        finally:
            key.destroy()

    def test_poly1305_different_keys_differ(self, p11_session: Any, p11_module: Any) -> None:
        """Poly1305 MACs from different keys differ for the same message."""
        if not has_mechanism(p11_module, "POLY1305"):
            pytest.skip("CKM_POLY1305 not supported")
        if not has_mechanism(p11_module, "POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key1 = p11_session.generate_key(
            KeyType.POLY1305,
            256,
            mechanism=Mechanism.POLY1305_KEY_GEN,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
        )
        key2 = p11_session.generate_key(
            KeyType.POLY1305,
            256,
            mechanism=Mechanism.POLY1305_KEY_GEN,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            data = b"same message for both keys"
            tag1 = key1.sign(data, mechanism=Mechanism.POLY1305)
            tag2 = key2.sign(data, mechanism=Mechanism.POLY1305)
            assert tag1 != tag2
        finally:
            key1.destroy()
            key2.destroy()


class TestChaCha20Standalone:
    """Tests for CKM_CHACHA20_KEY_GEN and CKM_CHACHA20 standalone stream cipher.

    Note: CKM_CHACHA20_POLY1305 (AEAD) is tested separately in
    wycheproof/test_wycheproof_chacha.py.
    """

    def test_chacha20_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a ChaCha20 256-bit session key."""
        if not has_mechanism(p11_module, "CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.CHACHA20,
            256,
            mechanism=Mechanism.CHACHA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            assert key is not None
            assert key.key_type == KeyType.CHACHA20
        finally:
            key.destroy()

    def test_chacha20_encrypt_decrypt(self, p11_session: Any, p11_module: Any) -> None:
        """ChaCha20 encrypt/decrypt roundtrip produces original plaintext."""
        if not has_mechanism(p11_module, "CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not has_mechanism(p11_module, "CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.CHACHA20,
            256,
            mechanism=Mechanism.CHACHA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            plaintext = b"ChaCha20 standalone test message"
            params = (_CHACHA20_BLOCK_COUNTER, _CHACHA20_NONCE)
            ciphertext = key.encrypt(
                plaintext,
                mechanism=Mechanism.CHACHA20,
                mechanism_param=params,
            )
            assert ciphertext != plaintext
            assert len(ciphertext) == len(plaintext)  # stream cipher: no padding
            recovered = key.decrypt(
                ciphertext,
                mechanism=Mechanism.CHACHA20,
                mechanism_param=params,
            )
            assert recovered == plaintext
        finally:
            key.destroy()

    def test_chacha20_different_nonces_differ(self, p11_session: Any, p11_module: Any) -> None:
        """ChaCha20 with different nonces produces different ciphertext."""
        if not has_mechanism(p11_module, "CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not has_mechanism(p11_module, "CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.CHACHA20,
            256,
            mechanism=Mechanism.CHACHA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            plaintext = b"nonce differentiation test data!"
            nonce1 = b"\x00" * 12
            nonce2 = b"\x01" * 12
            ct1 = key.encrypt(
                plaintext,
                mechanism=Mechanism.CHACHA20,
                mechanism_param=(_CHACHA20_BLOCK_COUNTER, nonce1),
            )
            ct2 = key.encrypt(
                plaintext,
                mechanism=Mechanism.CHACHA20,
                mechanism_param=(_CHACHA20_BLOCK_COUNTER, nonce2),
            )
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_chacha20_different_block_counters_differ(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """ChaCha20 with different block counters produces different ciphertext."""
        if not has_mechanism(p11_module, "CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not has_mechanism(p11_module, "CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType.CHACHA20,
            256,
            mechanism=Mechanism.CHACHA20_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            plaintext = b"block counter differentiation!  "
            counter0 = b"\x00\x00\x00\x00"
            counter1 = b"\x01\x00\x00\x00"
            ct0 = key.encrypt(
                plaintext,
                mechanism=Mechanism.CHACHA20,
                mechanism_param=(counter0, _CHACHA20_NONCE),
            )
            ct1 = key.encrypt(
                plaintext,
                mechanism=Mechanism.CHACHA20,
                mechanism_param=(counter1, _CHACHA20_NONCE),
            )
            assert ct0 != ct1
        finally:
            key.destroy()
