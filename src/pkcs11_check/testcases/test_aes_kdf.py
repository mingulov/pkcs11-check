"""Tests for AES key derivation by data encryption.

Covers CKM_AES_ECB_ENCRYPT_DATA and CKM_AES_CBC_ENCRYPT_DATA - mechanisms
that derive new keys by encrypting supplied data with a base key.

OASIS spec: key_derivation_by_data_encryption_aes-des.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# 32-byte AES key for base key creation
_BASE_KEY_BYTES = bytes(range(32))

# Data inputs must be multiples of 16 bytes (AES block size)
_DATA_16 = b"derive__test__01"  # 16 bytes
_DATA_32 = b"derive__test__01derive__test__02"  # 32 bytes
_ALT_DATA_16 = b"alt_derive_data!"  # 16 bytes, different content

# 16-byte IV for CBC mode
_IV = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

_DERIVE_TEMPLATE: dict[Attribute, Any] = {
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.TOKEN: False,
}


def _create_base_key(session: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> Any:
    """Create an AES base key suitable for derivation."""
    return session.create_object(
        {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.DERIVE: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
        }
    )


class TestAESECBEncryptData:
    """CKM_AES_ECB_ENCRYPT_DATA - derive keys by AES-ECB encrypting data."""

    def test_derive_basic(self, p11_session: Any, p11_module: Any) -> None:
        """Derive an AES key via ECB encryption and verify it is non-empty."""
        if not has_mechanism(p11_module, "AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=_DATA_16,
                template=_DERIVE_TEMPLATE,
            )
            try:
                okm = derived[Attribute.VALUE]
                assert len(okm) == 16, f"Expected 16-byte derived key, got {len(okm)}"
                assert okm != b"\x00" * 16, "Derived key is all zeros"
            finally:
                derived.destroy()
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same base key + same data produces the same derived key."""
        if not has_mechanism(p11_module, "AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=_DATA_16,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=_DATA_16,
                template=_DERIVE_TEMPLATE,
            )
            try:
                assert derived1[Attribute.VALUE] == derived2[Attribute.VALUE]
            finally:
                derived2.destroy()
                derived1.destroy()
        finally:
            base_key.destroy()

    def test_derive_different_data(self, p11_session: Any, p11_module: Any) -> None:
        """Different input data produces different derived keys."""
        if not has_mechanism(p11_module, "AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=_DATA_16,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=_ALT_DATA_16,
                template=_DERIVE_TEMPLATE,
            )
            try:
                assert derived1[Attribute.VALUE] != derived2[Attribute.VALUE]
            finally:
                derived2.destroy()
                derived1.destroy()
        finally:
            base_key.destroy()

    def test_derive_32_byte_data(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 256-bit key from 32 bytes of input data."""
        if not has_mechanism(p11_module, "AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=_DATA_32,
                template=_DERIVE_TEMPLATE,
            )
            try:
                okm = derived[Attribute.VALUE]
                assert len(okm) == 32, f"Expected 32-byte derived key, got {len(okm)}"
            finally:
                derived.destroy()
        finally:
            base_key.destroy()


class TestAESCBCEncryptData:
    """CKM_AES_CBC_ENCRYPT_DATA - derive keys by AES-CBC encrypting data."""

    def test_derive_basic(self, p11_session: Any, p11_module: Any) -> None:
        """Derive an AES key via CBC encryption and verify it is non-empty."""
        if not has_mechanism(p11_module, "AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            try:
                okm = derived[Attribute.VALUE]
                assert len(okm) == 16, f"Expected 16-byte derived key, got {len(okm)}"
                assert okm != b"\x00" * 16, "Derived key is all zeros"
            finally:
                derived.destroy()
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same base key + same IV + same data produces the same derived key."""
        if not has_mechanism(p11_module, "AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            try:
                assert derived1[Attribute.VALUE] == derived2[Attribute.VALUE]
            finally:
                derived2.destroy()
                derived1.destroy()
        finally:
            base_key.destroy()

    def test_derive_different_data(self, p11_session: Any, p11_module: Any) -> None:
        """Different input data produces different derived keys."""
        if not has_mechanism(p11_module, "AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _ALT_DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            try:
                assert derived1[Attribute.VALUE] != derived2[Attribute.VALUE]
            finally:
                derived2.destroy()
                derived1.destroy()
        finally:
            base_key.destroy()

    def test_derive_different_iv(self, p11_session: Any, p11_module: Any) -> None:
        """Different IVs with same data produce different derived keys."""
        if not has_mechanism(p11_module, "AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        alt_iv = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

        base_key = _create_base_key(p11_session)
        try:
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(alt_iv, _DATA_16),
                template=_DERIVE_TEMPLATE,
            )
            try:
                assert derived1[Attribute.VALUE] != derived2[Attribute.VALUE]
            finally:
                derived2.destroy()
                derived1.destroy()
        finally:
            base_key.destroy()

    def test_derive_32_byte_data(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 256-bit key from 32 bytes of input data."""
        if not has_mechanism(p11_module, "AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(_IV, _DATA_32),
                template=_DERIVE_TEMPLATE,
            )
            try:
                okm = derived[Attribute.VALUE]
                assert len(okm) == 32, f"Expected 32-byte derived key, got {len(okm)}"
            finally:
                derived.destroy()
        finally:
            base_key.destroy()
