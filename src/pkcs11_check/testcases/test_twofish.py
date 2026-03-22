"""Tests for Twofish PKCS#11 mechanisms.

Twofish: 128/192/256-bit keys, 16-byte block.
Only CBC and CBC_PAD are defined in the OASIS PKCS#11 spec -- there is no
CKM_TWOFISH_ECB mechanism. IV for CBC modes is 16 bytes.

Most modules do NOT support Twofish -- all tests will skip cleanly on those
platforms.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# Twofish block is 16 bytes -- CBC data must be 16-byte aligned
_TWO_BLOCKS = b"sixteen bytes!!\x01" * 2  # exactly 32 bytes


def _tf_iv(session: Any) -> Any:
    """Generate a 16-byte IV (128 bits) for Twofish CBC modes."""
    return session.generate_random(128)


def _tf_key(session: Any, bits: int, template: dict[str, Any]) -> Any:
    """Generate a Twofish session key of the given bit length."""
    return session.generate_key(
        KeyType.TWOFISH,
        bits,
        mechanism=Mechanism.TWOFISH_KEY_GEN,
        template=template,
    )


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestTwofishKeyGen:
    """CKM_TWOFISH_KEY_GEN -- key generation for 128/192/256-bit Twofish keys."""

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_twofish_key_gen(self, p11_session: Any, p11_module: Any, key_bits: int) -> None:
        """Generate a Twofish session key of the specified bit length."""
        if not has_mechanism(p11_module, "TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        key = _tf_key(p11_session, key_bits, {Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.TWOFISH
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestTwofishEncryption:
    """Twofish encryption/decryption: CBC and CBC_PAD.

    Note: CKM_TWOFISH_ECB is not defined in the OASIS PKCS#11 spec.
    Only CBC and CBC_PAD mechanisms exist for Twofish.
    """

    def test_twofish_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Twofish-CBC encrypt/decrypt roundtrip with 16-byte IV and block-aligned data."""
        if not has_mechanism(p11_module, "TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "TWOFISH_CBC"):
            pytest.skip("CKM_TWOFISH_CBC not supported")
        key = _tf_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _tf_iv(p11_session)
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.TWOFISH_CBC, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_TWOFISH_CBC advertised but rejected at use")
            assert ct != _TWO_BLOCKS
            pt = key.decrypt(ct, mechanism=Mechanism.TWOFISH_CBC, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_twofish_cbc_different_ivs(self, p11_session: Any, p11_module: Any) -> None:
        """Twofish-CBC with different IVs produces different ciphertexts."""
        if not has_mechanism(p11_module, "TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "TWOFISH_CBC"):
            pytest.skip("CKM_TWOFISH_CBC not supported")
        key = _tf_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv1 = _tf_iv(p11_session)
        iv2 = _tf_iv(p11_session)
        try:
            try:
                ct1 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.TWOFISH_CBC, mechanism_param=iv1)
            except MechanismInvalid:
                pytest.skip("CKM_TWOFISH_CBC advertised but rejected at use")
            ct2 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.TWOFISH_CBC, mechanism_param=iv2)
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_twofish_cbc_pad_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Twofish-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        if not has_mechanism(p11_module, "TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "TWOFISH_CBC_PAD"):
            pytest.skip("CKM_TWOFISH_CBC_PAD not supported")
        key = _tf_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _tf_iv(p11_session)
        # Non-block-aligned data -- PKCS#7 padding handles it
        plaintext = b"Twofish CBC PAD test!"  # 21 bytes, not a multiple of 16
        try:
            try:
                ct = key.encrypt(plaintext, mechanism=Mechanism.TWOFISH_CBC_PAD, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_TWOFISH_CBC_PAD advertised but rejected at use")
            assert ct != plaintext
            # Ciphertext is padded to 16-byte block boundary
            assert len(ct) % 16 == 0
            pt = key.decrypt(ct, mechanism=Mechanism.TWOFISH_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_twofish_cbc_pad_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Twofish-CBC-PAD: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "TWOFISH_CBC_PAD"):
            pytest.skip("CKM_TWOFISH_CBC_PAD not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = _tf_key(p11_session, 128, tmpl)
        key2 = _tf_key(p11_session, 128, tmpl)
        iv = _tf_iv(p11_session)
        plaintext = b"Twofish CBC PAD key independence!!"  # 34 bytes
        try:
            try:
                ct1 = key1.encrypt(
                    plaintext, mechanism=Mechanism.TWOFISH_CBC_PAD, mechanism_param=iv
                )
            except MechanismInvalid:
                pytest.skip("CKM_TWOFISH_CBC_PAD advertised but rejected at use")
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.TWOFISH_CBC_PAD, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()
