"""Tests for Blowfish PKCS#11 mechanisms.

Blowfish: variable key size (32-448 bits), 8-byte block.
Only CBC and CBC_PAD are defined in the OASIS PKCS#11 spec - there is no
CKM_BLOWFISH_ECB mechanism. IV for CBC modes is 8 bytes.

Most modules do NOT support Blowfish - all tests will skip cleanly on those
platforms.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# Blowfish block is 8 bytes - CBC data must be 8-byte aligned
_TWO_BLOCKS = b"12345678abcdefgh"  # exactly 16 bytes (2 x 8-byte blocks)


def _bf_iv(session: Any) -> Any:
    """Generate an 8-byte IV (64 bits) for Blowfish CBC modes."""
    return session.generate_random(64)


def _bf_key(session: Any, bits: int, template: dict[str, Any]) -> Any:
    """Generate a Blowfish session key of the given bit length."""
    return session.generate_key(
        KeyType.BLOWFISH,
        bits,
        mechanism=Mechanism.BLOWFISH_KEY_GEN,
        template=template,
    )


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestBlowfishKeyGen:
    """CKM_BLOWFISH_KEY_GEN - key generation for variable-length Blowfish keys."""

    @pytest.mark.parametrize("key_bits", [128, 256])
    def test_blowfish_key_gen(self, p11_session: Any, p11_module: Any, key_bits: int) -> None:
        """Generate a Blowfish session key of the specified bit length."""
        if not has_mechanism(p11_module, "BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        key = _bf_key(p11_session, key_bits, {Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.BLOWFISH
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestBlowfishEncryption:
    """Blowfish encryption/decryption: CBC and CBC_PAD.

    Note: CKM_BLOWFISH_ECB is not defined in the OASIS PKCS#11 spec.
    Only CBC and CBC_PAD mechanisms exist for Blowfish.
    """

    def test_blowfish_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Blowfish-CBC encrypt/decrypt roundtrip with 8-byte IV and block-aligned data."""
        if not has_mechanism(p11_module, "BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "BLOWFISH_CBC"):
            pytest.skip("CKM_BLOWFISH_CBC not supported")
        key = _bf_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _bf_iv(p11_session)
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.BLOWFISH_CBC, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_BLOWFISH_CBC advertised but rejected at use")
            assert ct != _TWO_BLOCKS
            pt = key.decrypt(ct, mechanism=Mechanism.BLOWFISH_CBC, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_blowfish_cbc_different_ivs(self, p11_session: Any, p11_module: Any) -> None:
        """Blowfish-CBC with different IVs produces different ciphertexts."""
        if not has_mechanism(p11_module, "BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "BLOWFISH_CBC"):
            pytest.skip("CKM_BLOWFISH_CBC not supported")
        key = _bf_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv1 = _bf_iv(p11_session)
        iv2 = _bf_iv(p11_session)
        try:
            try:
                ct1 = key.encrypt(
                    _TWO_BLOCKS, mechanism=Mechanism.BLOWFISH_CBC, mechanism_param=iv1
                )
            except MechanismInvalid:
                pytest.skip("CKM_BLOWFISH_CBC advertised but rejected at use")
            ct2 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.BLOWFISH_CBC, mechanism_param=iv2)
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_blowfish_cbc_pad_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Blowfish-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        if not has_mechanism(p11_module, "BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "BLOWFISH_CBC_PAD"):
            pytest.skip("CKM_BLOWFISH_CBC_PAD not supported")
        key = _bf_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _bf_iv(p11_session)
        # Non-block-aligned data - PKCS#7 padding handles it
        plaintext = b"Blowfish CBC PAD test!"  # 22 bytes, not a multiple of 8
        try:
            try:
                ct = key.encrypt(
                    plaintext, mechanism=Mechanism.BLOWFISH_CBC_PAD, mechanism_param=iv
                )
            except MechanismInvalid:
                pytest.skip("CKM_BLOWFISH_CBC_PAD advertised but rejected at use")
            assert ct != plaintext
            # Ciphertext is padded to 8-byte block boundary
            assert len(ct) % 8 == 0
            pt = key.decrypt(ct, mechanism=Mechanism.BLOWFISH_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_blowfish_cbc_pad_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Blowfish-CBC-PAD: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not has_mechanism(p11_module, "BLOWFISH_CBC_PAD"):
            pytest.skip("CKM_BLOWFISH_CBC_PAD not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = _bf_key(p11_session, 128, tmpl)
        key2 = _bf_key(p11_session, 128, tmpl)
        iv = _bf_iv(p11_session)
        plaintext = b"Blowfish CBC PAD key independence!!"  # 35 bytes
        try:
            try:
                ct1 = key1.encrypt(
                    plaintext, mechanism=Mechanism.BLOWFISH_CBC_PAD, mechanism_param=iv
                )
            except MechanismInvalid:
                pytest.skip("CKM_BLOWFISH_CBC_PAD advertised but rejected at use")
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.BLOWFISH_CBC_PAD, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()
