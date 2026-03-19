"""Parametrized tests across key sizes for AES and RSA.

Verifies that all standard key sizes work correctly for generation,
encrypt/decrypt, and sign/verify operations.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.keymgmt


class TestAESKeySizes:
    """Test AES operations across all standard key sizes."""

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_generate(self, p11_session: Any, key_bits: int) -> None:
        """Generate AES key at each standard size."""
        key = p11_session.generate_key(KeyType.AES, key_bits)
        assert key is not None
        assert key.key_type == KeyType.AES
        key.destroy()

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_ecb_roundtrip(self, p11_session: Any, key_bits: int) -> None:
        """AES-ECB encrypt/decrypt roundtrip at each key size."""
        key = p11_session.generate_key(KeyType.AES, key_bits)
        plaintext = b"key size test!!!"  # 16 bytes
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext
        key.destroy()

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_import_export(self, p11_session: Any, key_bits: int) -> None:
        """Import and export AES key at each size."""
        key_bytes = bytes(key_bits // 8)
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        exported = key[Attribute.VALUE]
        assert exported == key_bytes
        key.destroy()


class TestRSAKeySizes:
    """Test RSA operations across key sizes."""

    @pytest.mark.parametrize("key_bits", [2048, 3072, 4096])
    def test_rsa_generate(self, p11_session: Any, key_bits: int) -> None:
        """Generate RSA key pair at each size."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, key_bits)
        modulus = pub[Attribute.MODULUS]
        assert len(modulus) == key_bits // 8
        pub.destroy()
        priv.destroy()

    @pytest.mark.parametrize("key_bits", [2048, 3072, 4096])
    def test_rsa_sign_verify(self, p11_session: Any, key_bits: int) -> None:
        """RSA sign/verify at each key size."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, key_bits)
        data = f"RSA-{key_bits} sign test".encode()
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == key_bits // 8
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)
        pub.destroy()
        priv.destroy()

    @pytest.mark.parametrize("key_bits", [2048, 4096])
    def test_rsa_oaep_roundtrip(self, p11_session: Any, key_bits: int) -> None:
        """RSA-OAEP encrypt/decrypt at each key size."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, key_bits)
        plaintext = f"OAEP-{key_bits}".encode()
        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert pt == plaintext
        pub.destroy()
        priv.destroy()
