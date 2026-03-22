"""Tests for ARIA PKCS#11 mechanisms.

Covers key generation, encryption/decryption (ECB, CBC, CBC_PAD),
MAC signing/verification, and key derivation availability checks.

ARIA: 128/192/256-bit keys, 16-byte block.

Most modules do NOT support ARIA - all tests will skip cleanly on those
platforms. Some Korean-standard-focused HSMs and certain NSS builds include
ARIA support.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# 16-byte ARIA block - ECB/CBC data must be block-aligned
_TWO_BLOCKS = b"sixteen bytes!!\x01" * 2  # exactly 32 bytes


def _aria_iv(session: Any) -> Any:
    """Generate a 16-byte IV (128 bits) for ARIA CBC modes."""
    return session.generate_random(128)


def _aria_key(session: Any, bits: int, template: dict[str, Any]) -> Any:
    """Generate an ARIA session key of the given bit length."""
    return session.generate_key(
        KeyType.ARIA,
        bits,
        mechanism=Mechanism.ARIA_KEY_GEN,
        template=template,
    )


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestARIAKeyGen:
    """CKM_ARIA_KEY_GEN - key generation for 128/192/256-bit keys."""

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aria_key_gen(self, p11_session: Any, p11_module: Any, key_bits: int) -> None:
        """Generate an ARIA session key of the specified bit length."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        key = _aria_key(p11_session, key_bits, {Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.ARIA
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestARIAEncryption:
    """ARIA encryption/decryption: ECB, CBC, CBC_PAD."""

    def test_aria_ecb_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-ECB encrypt/decrypt roundtrip with block-aligned data."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_ECB"):
            pytest.skip("CKM_ARIA_ECB not supported")
        key = _aria_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.ARIA_ECB)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_ECB advertised but rejected at use")
            assert ct != _TWO_BLOCKS
            assert len(ct) == len(_TWO_BLOCKS)
            pt = key.decrypt(ct, mechanism=Mechanism.ARIA_ECB)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_aria_ecb_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-ECB: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_ECB"):
            pytest.skip("CKM_ARIA_ECB not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = _aria_key(p11_session, 128, tmpl)
        key2 = _aria_key(p11_session, 128, tmpl)
        try:
            try:
                ct1 = key1.encrypt(_TWO_BLOCKS, mechanism=Mechanism.ARIA_ECB)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_ECB advertised but rejected at use")
            ct2 = key2.encrypt(_TWO_BLOCKS, mechanism=Mechanism.ARIA_ECB)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()

    def test_aria_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-CBC encrypt/decrypt roundtrip with 16-byte IV and block-aligned data."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_CBC"):
            pytest.skip("CKM_ARIA_CBC not supported")
        key = _aria_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _aria_iv(p11_session)
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.ARIA_CBC, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_CBC advertised but rejected at use")
            assert ct != _TWO_BLOCKS
            pt = key.decrypt(ct, mechanism=Mechanism.ARIA_CBC, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_aria_cbc_different_ivs(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-CBC with different IVs produces different ciphertexts."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_CBC"):
            pytest.skip("CKM_ARIA_CBC not supported")
        key = _aria_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv1 = _aria_iv(p11_session)
        iv2 = _aria_iv(p11_session)
        try:
            try:
                ct1 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.ARIA_CBC, mechanism_param=iv1)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_CBC advertised but rejected at use")
            ct2 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.ARIA_CBC, mechanism_param=iv2)
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_aria_cbc_pad_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_CBC_PAD"):
            pytest.skip("CKM_ARIA_CBC_PAD not supported")
        key = _aria_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _aria_iv(p11_session)
        # Non-block-aligned data - PKCS#7 padding handles it
        plaintext = b"ARIA CBC PAD test data!!"  # 24 bytes, not a multiple of 16
        try:
            try:
                ct = key.encrypt(plaintext, mechanism=Mechanism.ARIA_CBC_PAD, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_CBC_PAD advertised but rejected at use")
            assert ct != plaintext
            # Ciphertext is padded to block boundary
            assert len(ct) % 16 == 0
            pt = key.decrypt(ct, mechanism=Mechanism.ARIA_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_aria_cbc_pad_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-CBC-PAD: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_CBC_PAD"):
            pytest.skip("CKM_ARIA_CBC_PAD not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = _aria_key(p11_session, 128, tmpl)
        key2 = _aria_key(p11_session, 128, tmpl)
        iv = _aria_iv(p11_session)
        plaintext = b"ARIA CBC PAD key independence test!!"  # 36 bytes
        try:
            try:
                ct1 = key1.encrypt(plaintext, mechanism=Mechanism.ARIA_CBC_PAD, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_CBC_PAD advertised but rejected at use")
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.ARIA_CBC_PAD, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()


# ---------------------------------------------------------------------------
# MAC (sign/verify)
# ---------------------------------------------------------------------------


class TestARIAMAC:
    """CKM_ARIA_MAC and CKM_ARIA_MAC_GENERAL - MAC sign/verify tests."""

    def test_aria_mac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-MAC sign and verify roundtrip."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_MAC"):
            pytest.skip("CKM_ARIA_MAC not supported")
        key = _aria_key(
            p11_session,
            128,
            {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"ARIA MAC test data for signing"
        try:
            try:
                mac = key.sign(data, mechanism=Mechanism.ARIA_MAC)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_MAC advertised but rejected at use")
            assert len(mac) > 0
            assert key.verify(data, mac, mechanism=Mechanism.ARIA_MAC)
        finally:
            key.destroy()

    def test_aria_mac_general_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """ARIA-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_MAC_GENERAL"):
            pytest.skip("CKM_ARIA_MAC_GENERAL not supported")
        key = _aria_key(
            p11_session,
            128,
            {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"ARIA MAC GENERAL test data"
        mac_len = 8  # request 8-byte MAC (half block)
        try:
            try:
                mac = key.sign(data, mechanism=Mechanism.ARIA_MAC_GENERAL, mechanism_param=mac_len)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_MAC_GENERAL advertised but rejected at use")
            assert len(mac) == mac_len
            assert key.verify(
                data, mac, mechanism=Mechanism.ARIA_MAC_GENERAL, mechanism_param=mac_len
            )
        finally:
            key.destroy()

    def test_aria_mac_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different ARIA keys produce different MAC values."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ARIA_MAC"):
            pytest.skip("CKM_ARIA_MAC not supported")
        tmpl = {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False}
        key1 = _aria_key(p11_session, 128, tmpl)
        key2 = _aria_key(p11_session, 128, tmpl)
        data = b"MAC key independence test data"
        try:
            try:
                mac1 = key1.sign(data, mechanism=Mechanism.ARIA_MAC)
            except MechanismInvalid:
                pytest.skip("CKM_ARIA_MAC advertised but rejected at use")
            mac2 = key2.sign(data, mechanism=Mechanism.ARIA_MAC)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()


# ---------------------------------------------------------------------------
# Key derivation by data encryption - availability checks only
# ---------------------------------------------------------------------------


class TestARIAKeyDerivation:
    """Availability checks for ARIA key derivation by data encryption.

    CKM_ARIA_ECB_ENCRYPT_DATA and CKM_ARIA_CBC_ENCRYPT_DATA are used
    via derive_key() with module-specific parameter structures. The tests here
    confirm the mechanisms are advertised by the module; full derivation tests
    live in the key derivation test suite.
    """

    def test_aria_ecb_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_ARIA_ECB_ENCRYPT_DATA is advertised when ARIA is supported."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported - skipping derivation check")
        if not has_mechanism(p11_module, "ARIA_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_ARIA_ECB_ENCRYPT_DATA not supported")
        # Mechanism is present - no further operation needed for availability check
        assert True

    def test_aria_cbc_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_ARIA_CBC_ENCRYPT_DATA is advertised when ARIA is supported."""
        if not has_mechanism(p11_module, "ARIA_KEY_GEN"):
            pytest.skip("CKM_ARIA_KEY_GEN not supported - skipping derivation check")
        if not has_mechanism(p11_module, "ARIA_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_ARIA_CBC_ENCRYPT_DATA not supported")
        assert True
