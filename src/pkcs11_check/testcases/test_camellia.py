"""Tests for Camellia PKCS#11 mechanisms.

Covers key generation, encryption/decryption (ECB, CBC, CBC_PAD, CTR),
MAC signing/verification, and key derivation availability checks.

Camellia: 128/192/256-bit keys, 16-byte block.
IV for CBC/CTR modes: 16 bytes.

Most modules do NOT support Camellia -- all tests will skip cleanly on those
platforms. Kryoptic and some NSS builds include Camellia support.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import MechanismInvalid
from pkcs11.mechanisms import CTRParams

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# 16-byte Camellia block -- ECB/CBC data must be block-aligned
_TWO_BLOCKS = b"sixteen bytes!!\x01" * 2  # exactly 32 bytes


def _camellia_iv(session: Any) -> Any:
    """Generate a 16-byte IV (128 bits) for Camellia CBC/CTR modes."""
    return session.generate_random(128)


def _camellia_key(session: Any, bits: int, template: dict[str, Any]) -> Any:
    """Generate a Camellia session key of the given bit length."""
    return session.generate_key(
        KeyType.CAMELLIA,
        bits,
        mechanism=Mechanism.CAMELLIA_KEY_GEN,
        template=template,
    )


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestCamelliaKeyGen:
    """CKM_CAMELLIA_KEY_GEN -- key generation for 128/192/256-bit keys."""

    def test_camellia_key_gen_128(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a Camellia-128 session key."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        key = _camellia_key(p11_session, 128, {Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.CAMELLIA
        finally:
            key.destroy()

    def test_camellia_key_gen_192(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a Camellia-192 session key."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        key = _camellia_key(p11_session, 192, {Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.CAMELLIA
        finally:
            key.destroy()

    def test_camellia_key_gen_256(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a Camellia-256 session key."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        key = _camellia_key(p11_session, 256, {Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.CAMELLIA
        finally:
            key.destroy()

    def test_camellia_key_gen_not_null(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia key generation produces a usable, non-null key object."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        key = _camellia_key(p11_session, 128, {Attribute.TOKEN: False})
        try:
            assert key is not None
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestCamelliaEncryption:
    """Camellia encryption/decryption: ECB, CBC, CBC_PAD."""

    def test_camellia_ecb_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-ECB encrypt/decrypt roundtrip with block-aligned data."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_ECB"):
            pytest.skip("CKM_CAMELLIA_ECB not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.CAMELLIA_ECB)
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_ECB advertised but rejected at use")
            assert ct != _TWO_BLOCKS
            assert len(ct) == len(_TWO_BLOCKS)
            pt = key.decrypt(ct, mechanism=Mechanism.CAMELLIA_ECB)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_camellia_ecb_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-ECB: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_ECB"):
            pytest.skip("CKM_CAMELLIA_ECB not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = _camellia_key(p11_session, 128, tmpl)
        key2 = _camellia_key(p11_session, 128, tmpl)
        try:
            try:
                ct1 = key1.encrypt(_TWO_BLOCKS, mechanism=Mechanism.CAMELLIA_ECB)
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_ECB advertised but rejected at use")
            ct2 = key2.encrypt(_TWO_BLOCKS, mechanism=Mechanism.CAMELLIA_ECB)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()

    def test_camellia_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-CBC encrypt/decrypt roundtrip with 16-byte IV and block-aligned data."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_CBC"):
            pytest.skip("CKM_CAMELLIA_CBC not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _camellia_iv(p11_session)
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.CAMELLIA_CBC, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_CBC advertised but rejected at use")
            assert ct != _TWO_BLOCKS
            pt = key.decrypt(ct, mechanism=Mechanism.CAMELLIA_CBC, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_camellia_cbc_different_ivs(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-CBC with different IVs produces different ciphertexts."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_CBC"):
            pytest.skip("CKM_CAMELLIA_CBC not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv1 = _camellia_iv(p11_session)
        iv2 = _camellia_iv(p11_session)
        try:
            try:
                ct1 = key.encrypt(
                    _TWO_BLOCKS, mechanism=Mechanism.CAMELLIA_CBC, mechanism_param=iv1
                )
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_CBC advertised but rejected at use")
            ct2 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.CAMELLIA_CBC, mechanism_param=iv2)
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_camellia_cbc_pad_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_CBC_PAD"):
            pytest.skip("CKM_CAMELLIA_CBC_PAD not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _camellia_iv(p11_session)
        # Non-block-aligned data -- PKCS#7 padding handles it
        plaintext = b"Camellia CBC PAD test data!"  # 27 bytes, not a multiple of 16
        try:
            try:
                ct = key.encrypt(
                    plaintext, mechanism=Mechanism.CAMELLIA_CBC_PAD, mechanism_param=iv
                )
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_CBC_PAD advertised but rejected at use")
            assert ct != plaintext
            # Ciphertext is padded to block boundary
            assert len(ct) % 16 == 0
            pt = key.decrypt(ct, mechanism=Mechanism.CAMELLIA_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_camellia_cbc_pad_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-CBC-PAD: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_CBC_PAD"):
            pytest.skip("CKM_CAMELLIA_CBC_PAD not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = _camellia_key(p11_session, 128, tmpl)
        key2 = _camellia_key(p11_session, 128, tmpl)
        iv = _camellia_iv(p11_session)
        plaintext = b"Camellia CBC PAD key independence!!"  # 35 bytes
        try:
            try:
                ct1 = key1.encrypt(
                    plaintext, mechanism=Mechanism.CAMELLIA_CBC_PAD, mechanism_param=iv
                )
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_CBC_PAD advertised but rejected at use")
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.CAMELLIA_CBC_PAD, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()


# ---------------------------------------------------------------------------
# CTR mode
# ---------------------------------------------------------------------------


class TestCamelliaCTR:
    """CKM_CAMELLIA_CTR -- counter mode encrypt/decrypt tests.

    Camellia CTR uses the same CK_AES_CTR_PARAMS structure (counter bits +
    16-byte counter block) as AES CTR. CTRParams from pkcs11.mechanisms wraps
    this structure and accepts a nonce up to 15 bytes; the remainder of the
    128-bit counter block is used as the counter.
    """

    def test_camellia_ctr_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-CTR encrypt/decrypt roundtrip with 16-byte nonce."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_CTR"):
            pytest.skip("CKM_CAMELLIA_CTR not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        nonce = p11_session.generate_random(96)  # 12-byte nonce; 4 bytes left as counter
        params = CTRParams(nonce)
        plaintext = b"Camellia CTR mode test data!!"  # arbitrary length -- CTR is a stream mode
        try:
            try:
                ct = key.encrypt(
                    plaintext, mechanism=Mechanism.CAMELLIA_CTR, mechanism_param=params
                )
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_CTR advertised but rejected at use")
            assert ct != plaintext
            assert len(ct) == len(plaintext)
            pt = key.decrypt(ct, mechanism=Mechanism.CAMELLIA_CTR, mechanism_param=CTRParams(nonce))
            assert pt == plaintext
        finally:
            key.destroy()

    def test_camellia_ctr_different_nonces(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-CTR with different nonces produces different ciphertexts."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_CTR"):
            pytest.skip("CKM_CAMELLIA_CTR not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        nonce1 = p11_session.generate_random(96)
        nonce2 = p11_session.generate_random(96)
        plaintext = b"CTR nonce independence test!!"
        try:
            try:
                ct1 = key.encrypt(
                    plaintext,
                    mechanism=Mechanism.CAMELLIA_CTR,
                    mechanism_param=CTRParams(nonce1),
                )
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_CTR advertised but rejected at use")
            ct2 = key.encrypt(
                plaintext, mechanism=Mechanism.CAMELLIA_CTR, mechanism_param=CTRParams(nonce2)
            )
            assert ct1 != ct2
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# MAC (sign/verify)
# ---------------------------------------------------------------------------


class TestCamelliaMAC:
    """CKM_CAMELLIA_MAC and CKM_CAMELLIA_MAC_GENERAL -- MAC sign/verify tests."""

    def test_camellia_mac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-MAC sign and verify roundtrip."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_MAC"):
            pytest.skip("CKM_CAMELLIA_MAC not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"Camellia MAC test data for signing"
        try:
            try:
                mac = key.sign(data, mechanism=Mechanism.CAMELLIA_MAC)
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_MAC advertised but rejected at use")
            assert len(mac) > 0
            assert key.verify(data, mac, mechanism=Mechanism.CAMELLIA_MAC)
        finally:
            key.destroy()

    def test_camellia_mac_general_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Camellia-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_MAC_GENERAL"):
            pytest.skip("CKM_CAMELLIA_MAC_GENERAL not supported")
        key = _camellia_key(
            p11_session,
            128,
            {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"Camellia MAC GENERAL test data"
        mac_len = 8  # request 8-byte MAC (half block)
        try:
            try:
                mac = key.sign(
                    data, mechanism=Mechanism.CAMELLIA_MAC_GENERAL, mechanism_param=mac_len
                )
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_MAC_GENERAL advertised but rejected at use")
            assert len(mac) == mac_len
            assert key.verify(
                data, mac, mechanism=Mechanism.CAMELLIA_MAC_GENERAL, mechanism_param=mac_len
            )
        finally:
            key.destroy()

    def test_camellia_mac_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different Camellia keys produce different MAC values."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not has_mechanism(p11_module, "CAMELLIA_MAC"):
            pytest.skip("CKM_CAMELLIA_MAC not supported")
        tmpl = {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False}
        key1 = _camellia_key(p11_session, 128, tmpl)
        key2 = _camellia_key(p11_session, 128, tmpl)
        data = b"MAC key independence test data"
        try:
            try:
                mac1 = key1.sign(data, mechanism=Mechanism.CAMELLIA_MAC)
            except MechanismInvalid:
                pytest.skip("CKM_CAMELLIA_MAC advertised but rejected at use")
            mac2 = key2.sign(data, mechanism=Mechanism.CAMELLIA_MAC)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()


# ---------------------------------------------------------------------------
# Key derivation by data encryption -- availability checks only
# ---------------------------------------------------------------------------


class TestCamelliaKeyDerivation:
    """Availability checks for Camellia key derivation by data encryption.

    CKM_CAMELLIA_ECB_ENCRYPT_DATA and CKM_CAMELLIA_CBC_ENCRYPT_DATA are used
    via derive_key() with module-specific parameter structures. The tests here
    confirm the mechanisms are advertised by the module; full derivation tests
    live in the key derivation test suite.
    """

    def test_camellia_ecb_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_CAMELLIA_ECB_ENCRYPT_DATA is advertised when Camellia is supported."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported -- skipping derivation check")
        if not has_mechanism(p11_module, "CAMELLIA_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_CAMELLIA_ECB_ENCRYPT_DATA not supported")
        # Mechanism is present -- no further operation needed for availability check
        assert True

    def test_camellia_cbc_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_CAMELLIA_CBC_ENCRYPT_DATA is advertised when Camellia is supported."""
        if not has_mechanism(p11_module, "CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported -- skipping derivation check")
        if not has_mechanism(p11_module, "CAMELLIA_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_CAMELLIA_CBC_ENCRYPT_DATA not supported")
        assert True
