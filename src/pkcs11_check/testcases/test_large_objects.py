"""Large object stress tests.

Verifies that PKCS#11 modules handle large data correctly:
- 1MB CKO_DATA objects
- Large random generation
- Large plaintext encryption
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.security


def _unique_label(prefix: str = "large") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class TestLargeDataObjects:
    """Test large CKO_DATA object storage."""

    def test_1mb_data_object(self, p11_session: Any) -> None:
        """Create and read back a 1MB CKO_DATA object."""
        label = _unique_label()
        big_data = b"\xab" * (1024 * 1024)  # 1MB

        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: big_data,
                Attribute.TOKEN: False,
            }
        )
        stored = obj[Attribute.VALUE]
        assert stored == big_data
        assert len(stored) == 1024 * 1024

    def test_100kb_data_object(self, p11_session: Any) -> None:
        """Create and read back a 100KB CKO_DATA object."""
        label = _unique_label()
        data = bytes(range(256)) * 400  # 102,400 bytes

        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: data,
                Attribute.TOKEN: False,
            }
        )
        assert obj[Attribute.VALUE] == data


class TestLargeRandomGeneration:
    """Test large random number generation."""

    def test_generate_100kb_random(self, p11_session: Any) -> None:
        """Generate 100KB of random data via C_GenerateRandom."""
        rand = p11_session.generate_random(100 * 1024 * 8)  # bits
        assert len(rand) == 100 * 1024

    def test_generate_1kb_random_is_unique(self, p11_session: Any) -> None:
        """Two 1KB random blocks should be different."""
        r1 = p11_session.generate_random(1024 * 8)
        r2 = p11_session.generate_random(1024 * 8)
        assert r1 != r2


class TestLargeEncryption:
    """Test encryption of large plaintexts."""

    def test_encrypt_64kb_aes_ecb(self, p11_session: Any) -> None:
        """AES-ECB encrypt/decrypt 64KB data."""
        key = p11_session.generate_key(KeyType.AES, 256)
        data = b"\x42" * 65536  # 64KB, block-aligned

        ct = key.encrypt(data, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == data

    def test_encrypt_1mb_aes_cbc(self, p11_session: Any) -> None:
        """AES-CBC encrypt/decrypt 1MB data."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)  # 16 bytes
        data = b"\x99" * (1024 * 1024)  # 1MB

        ct = key.encrypt(data, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert pt == data
