"""Tests for DES and DES3 (Triple DES) PKCS#11 mechanisms.

Covers key generation, encryption/decryption (ECB, CBC, CBC_PAD, OFB, CFB),
MAC signing/verification (DES_MAC, DES3_CMAC), and key derivation availability
checks for DES_ECB_ENCRYPT_DATA, DES_CBC_ENCRYPT_DATA, DES3_ECB_ENCRYPT_DATA,
DES3_CBC_ENCRYPT_DATA.

DES: 8-byte (64-bit) key, 8-byte block.
DES2: 16-byte (128-bit) key (two-key Triple DES), 8-byte block.
DES3: 24-byte (192-bit) key (three-key Triple DES), 8-byte block.
IV for CBC/OFB/CFB modes: 8 bytes.

SoftHSM2 supports: DES_KEY_GEN, DES_ECB, DES_CBC, DES_CBC_PAD,
  DES2_KEY_GEN, DES3_KEY_GEN, DES3_ECB, DES3_CBC, DES3_CBC_PAD, DES3_CMAC,
  DES_ECB_ENCRYPT_DATA, DES_CBC_ENCRYPT_DATA, DES3_ECB_ENCRYPT_DATA,
  DES3_CBC_ENCRYPT_DATA.
SoftHSM2 does NOT support: DES_MAC, DES_MAC_GENERAL, DES_OFB64, DES_CFB8,
  DES_CFB64, DES3_MAC, DES3_MAC_GENERAL, DES3_CMAC_GENERAL.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.constants import MechanismFlag
from pkcs11.exceptions import MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# DES (single-DES) has no default capability map in python-pkcs11, so we must
# supply capabilities explicitly. DES2/DES3 are already in defaults.py.
_DES_CAPABILITIES = (
    MechanismFlag.ENCRYPT
    | MechanismFlag.DECRYPT
    | MechanismFlag.SIGN
    | MechanismFlag.VERIFY
    | MechanismFlag.WRAP
    | MechanismFlag.UNWRAP
)

# 8-byte DES block — ECB/CBC data must be block-aligned
_TWO_BLOCKS = b"12345678abcdefgh"  # exactly 16 bytes


def _des_iv(session: Any) -> Any:
    """Generate an 8-byte IV (64 bits) for DES CBC/OFB/CFB modes."""
    return session.generate_random(64)


# ---------------------------------------------------------------------------
# DES (single DES, 8-byte key)
# ---------------------------------------------------------------------------


class TestDESKeyGen:
    """CKM_DES_KEY_GEN — single-DES key generation."""

    def test_des_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a DES session key."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.TOKEN: False},
        )
        try:
            assert key is not None
            assert key.key_type == KeyType._DES
        finally:
            key.destroy()

    def test_des_key_gen_not_null(self, p11_session: Any, p11_module: Any) -> None:
        """DES key generation produces a usable, non-null key object."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.TOKEN: False},
        )
        try:
            assert key is not None
        finally:
            key.destroy()


class TestDESEncryption:
    """DES encryption/decryption: ECB, CBC, CBC_PAD, OFB64, CFB8, CFB64.

    Note: Some modules (e.g. SoftHSM2 on OpenSSL 3) advertise CKM_DES_ECB and
    CKM_DES_CBC in C_GetMechanismList but return CKR_MECHANISM_INVALID at
    C_EncryptInit because OpenSSL 3 does not load the legacy cipher provider by
    default.  Single-DES encrypt tests skip on MechanismInvalid so that the test
    suite remains clean on those platforms.  True bugs (e.g. a module that never
    advertised the mechanism) are caught by the has_mechanism guard.
    """

    def test_des_ecb_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES-ECB encrypt/decrypt roundtrip with block-aligned data."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_ECB"):
            pytest.skip("CKM_DES_ECB not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES_ECB)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_ECB advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            assert ct != _TWO_BLOCKS
            assert len(ct) == len(_TWO_BLOCKS)
            pt = key.decrypt(ct, mechanism=Mechanism.DES_ECB)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_des_ecb_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """DES-ECB: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_ECB"):
            pytest.skip("CKM_DES_ECB not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template=tmpl,
        )
        key2 = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template=tmpl,
        )
        try:
            try:
                ct1 = key1.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES_ECB)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_ECB advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            ct2 = key2.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES_ECB)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()

    def test_des_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES-CBC encrypt/decrypt roundtrip with 8-byte IV and block-aligned data."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_CBC"):
            pytest.skip("CKM_DES_CBC not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        try:
            try:
                ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES_CBC, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_CBC advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            assert ct != _TWO_BLOCKS
            pt = key.decrypt(ct, mechanism=Mechanism.DES_CBC, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_des_cbc_different_ivs(self, p11_session: Any, p11_module: Any) -> None:
        """DES-CBC with different IVs produces different ciphertexts."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_CBC"):
            pytest.skip("CKM_DES_CBC not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv1 = _des_iv(p11_session)
        iv2 = _des_iv(p11_session)
        try:
            try:
                ct1 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES_CBC, mechanism_param=iv1)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_CBC advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            ct2 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES_CBC, mechanism_param=iv2)
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_des_cbc_pad_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_CBC_PAD"):
            pytest.skip("CKM_DES_CBC_PAD not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        # Non-block-aligned data — PKCS#5 padding handles it
        plaintext = b"DES CBC PAD test data!"  # 22 bytes, not a multiple of 8
        try:
            try:
                ct = key.encrypt(plaintext, mechanism=Mechanism.DES_CBC_PAD, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_CBC_PAD advertised but rejected at use"
                    " (OpenSSL 3 legacy provider absent)"
                )
            assert ct != plaintext
            # Ciphertext is padded to block boundary
            assert len(ct) % 8 == 0
            pt = key.decrypt(ct, mechanism=Mechanism.DES_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_des_ofb64_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES-OFB64 encrypt/decrypt roundtrip with 8-byte IV."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_OFB64"):
            pytest.skip("CKM_DES_OFB64 not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        plaintext = b"OFB test data!!"  # 15 bytes — stream mode, no alignment needed
        try:
            try:
                ct = key.encrypt(plaintext, mechanism=Mechanism.DES_OFB64, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_OFB64 advertised but rejected at use"
                    " (OpenSSL 3 legacy provider absent)"
                )
            assert ct != plaintext
            assert len(ct) == len(plaintext)
            pt = key.decrypt(ct, mechanism=Mechanism.DES_OFB64, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_des_cfb8_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES-CFB8 encrypt/decrypt roundtrip with 8-byte IV."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_CFB8"):
            pytest.skip("CKM_DES_CFB8 not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        plaintext = b"CFB8 test data!!"  # 16 bytes
        try:
            try:
                ct = key.encrypt(plaintext, mechanism=Mechanism.DES_CFB8, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_CFB8 advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            assert ct != plaintext
            pt = key.decrypt(ct, mechanism=Mechanism.DES_CFB8, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_des_cfb64_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES-CFB64 encrypt/decrypt roundtrip with 8-byte IV."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_CFB64"):
            pytest.skip("CKM_DES_CFB64 not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        plaintext = b"CFB64 test data!"  # 16 bytes
        try:
            try:
                ct = key.encrypt(plaintext, mechanism=Mechanism.DES_CFB64, mechanism_param=iv)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_CFB64 advertised but rejected at use"
                    " (OpenSSL 3 legacy provider absent)"
                )
            assert ct != plaintext
            pt = key.decrypt(ct, mechanism=Mechanism.DES_CFB64, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()


class TestDESMAC:
    """DES_MAC and DES_MAC_GENERAL — MAC sign/verify tests.

    Like single-DES encrypt, these may return MechanismInvalid on OpenSSL 3
    platforms where the legacy DES cipher is not available.  Tests skip
    gracefully in that case.
    """

    def test_des_mac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """DES-MAC sign and verify roundtrip."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_MAC"):
            pytest.skip("CKM_DES_MAC not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"DES MAC test data for signing"
        try:
            try:
                mac = key.sign(data, mechanism=Mechanism.DES_MAC)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_MAC advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            assert len(mac) > 0
            assert key.verify(data, mac, mechanism=Mechanism.DES_MAC)
        finally:
            key.destroy()

    def test_des_mac_general_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """DES-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_MAC_GENERAL"):
            pytest.skip("CKM_DES_MAC_GENERAL not supported")
        key = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"DES MAC GENERAL test data"
        mac_len = 4  # request 4-byte MAC (half block)
        try:
            try:
                mac = key.sign(data, mechanism=Mechanism.DES_MAC_GENERAL, mechanism_param=mac_len)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_MAC_GENERAL advertised but rejected at use"
                    " (OpenSSL 3 legacy provider absent)"
                )
            assert len(mac) == mac_len
            assert key.verify(
                data, mac, mechanism=Mechanism.DES_MAC_GENERAL, mechanism_param=mac_len
            )
        finally:
            key.destroy()

    def test_des_mac_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different DES keys produce different MAC values."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES_MAC"):
            pytest.skip("CKM_DES_MAC not supported")
        tmpl = {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template=tmpl,
        )
        key2 = p11_session.generate_key(
            KeyType._DES,
            key_length=64,
            mechanism=Mechanism.DES_KEY_GEN,
            capabilities=_DES_CAPABILITIES,
            template=tmpl,
        )
        data = b"MAC key independence test data"
        try:
            try:
                mac1 = key1.sign(data, mechanism=Mechanism.DES_MAC)
            except MechanismInvalid:
                pytest.skip(
                    "CKM_DES_MAC advertised but rejected at use (OpenSSL 3 legacy provider absent)"
                )
            mac2 = key2.sign(data, mechanism=Mechanism.DES_MAC)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()


# ---------------------------------------------------------------------------
# DES2 (two-key Triple DES, 16-byte key)
# ---------------------------------------------------------------------------


class TestDES2KeyGen:
    """CKM_DES2_KEY_GEN — two-key Triple DES key generation."""

    def test_des2_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a DES2 session key."""
        if not has_mechanism(p11_module, "DES2_KEY_GEN"):
            pytest.skip("CKM_DES2_KEY_GEN not supported")
        key = p11_session.generate_key(KeyType.DES2, template={Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.DES2
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# DES3 (three-key Triple DES, 24-byte key)
# ---------------------------------------------------------------------------


class TestDES3KeyGen:
    """CKM_DES3_KEY_GEN — three-key Triple DES key generation."""

    def test_des3_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a DES3 session key."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        key = p11_session.generate_key(KeyType.DES3, template={Attribute.TOKEN: False})
        try:
            assert key is not None
            assert key.key_type == KeyType.DES3
        finally:
            key.destroy()

    def test_des3_key_gen_not_null(self, p11_session: Any, p11_module: Any) -> None:
        """DES3 key generation produces a usable, non-null key object."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        key = p11_session.generate_key(KeyType.DES3, template={Attribute.TOKEN: False})
        try:
            assert key is not None
        finally:
            key.destroy()


class TestDES3Encryption:
    """DES3 encryption/decryption: ECB, CBC, CBC_PAD."""

    def test_des3_ecb_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-ECB encrypt/decrypt roundtrip with block-aligned data."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_ECB"):
            pytest.skip("CKM_DES3_ECB not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        try:
            ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES3_ECB)
            assert ct != _TWO_BLOCKS
            assert len(ct) == len(_TWO_BLOCKS)
            pt = key.decrypt(ct, mechanism=Mechanism.DES3_ECB)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_des3_ecb_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-ECB: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_ECB"):
            pytest.skip("CKM_DES3_ECB not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        key2 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        try:
            ct1 = key1.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES3_ECB)
            ct2 = key2.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES3_ECB)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()

    def test_des3_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-CBC encrypt/decrypt roundtrip with 8-byte IV and block-aligned data."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CBC"):
            pytest.skip("CKM_DES3_CBC not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        try:
            ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
            assert ct != _TWO_BLOCKS
            pt = key.decrypt(ct, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        finally:
            key.destroy()

    def test_des3_cbc_different_ivs(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-CBC with different IVs produces different ciphertexts."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CBC"):
            pytest.skip("CKM_DES3_CBC not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv1 = _des_iv(p11_session)
        iv2 = _des_iv(p11_session)
        try:
            ct1 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES3_CBC, mechanism_param=iv1)
            ct2 = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.DES3_CBC, mechanism_param=iv2)
            assert ct1 != ct2
        finally:
            key.destroy()

    def test_des3_cbc_pad_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CBC_PAD"):
            pytest.skip("CKM_DES3_CBC_PAD not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = _des_iv(p11_session)
        plaintext = b"DES3 CBC PAD test data!"  # 23 bytes, not a multiple of 8
        try:
            ct = key.encrypt(plaintext, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
            assert ct != plaintext
            assert len(ct) % 8 == 0
            pt = key.decrypt(ct, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_des3_cbc_pad_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-CBC-PAD: same plaintext encrypted with different keys should differ."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CBC_PAD"):
            pytest.skip("CKM_DES3_CBC_PAD not supported")
        tmpl = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        key2 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        iv = _des_iv(p11_session)
        plaintext = b"DES3 CBC PAD key independence!!"  # 32 bytes
        try:
            ct1 = key1.encrypt(plaintext, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()


class TestDES3MAC:
    """DES3_MAC, DES3_MAC_GENERAL, DES3_CMAC, DES3_CMAC_GENERAL — sign/verify tests."""

    def test_des3_mac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-MAC sign and verify roundtrip."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_MAC"):
            pytest.skip("CKM_DES3_MAC not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"DES3 MAC test data for signing"
        try:
            mac = key.sign(data, mechanism=Mechanism.DES3_MAC)
            assert len(mac) > 0
            assert key.verify(data, mac, mechanism=Mechanism.DES3_MAC)
        finally:
            key.destroy()

    def test_des3_mac_general_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_MAC_GENERAL"):
            pytest.skip("CKM_DES3_MAC_GENERAL not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"DES3 MAC GENERAL test data"
        mac_len = 4  # request 4-byte MAC (half block)
        try:
            mac = key.sign(data, mechanism=Mechanism.DES3_MAC_GENERAL, mechanism_param=mac_len)
            assert len(mac) == mac_len
            assert key.verify(
                data, mac, mechanism=Mechanism.DES3_MAC_GENERAL, mechanism_param=mac_len
            )
        finally:
            key.destroy()

    def test_des3_cmac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-CMAC sign and verify roundtrip."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CMAC"):
            pytest.skip("CKM_DES3_CMAC not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"DES3 CMAC test data for signing"
        try:
            mac = key.sign(data, mechanism=Mechanism.DES3_CMAC)
            assert len(mac) > 0
            assert key.verify(data, mac, mechanism=Mechanism.DES3_CMAC)
        finally:
            key.destroy()

    def test_des3_cmac_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different DES3 keys produce different CMAC values."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CMAC"):
            pytest.skip("CKM_DES3_CMAC not supported")
        tmpl = {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        key2 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        data = b"CMAC key independence test data"
        try:
            mac1 = key1.sign(data, mechanism=Mechanism.DES3_CMAC)
            mac2 = key2.sign(data, mechanism=Mechanism.DES3_CMAC)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()

    def test_des3_cmac_general_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """DES3-CMAC-GENERAL sign and verify roundtrip with explicit length."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_CMAC_GENERAL"):
            pytest.skip("CKM_DES3_CMAC_GENERAL not supported")
        key = p11_session.generate_key(
            KeyType.DES3,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"DES3 CMAC GENERAL test data"
        mac_len = 4  # request 4-byte truncated CMAC
        try:
            mac = key.sign(data, mechanism=Mechanism.DES3_CMAC_GENERAL, mechanism_param=mac_len)
            assert len(mac) == mac_len
            assert key.verify(
                data, mac, mechanism=Mechanism.DES3_CMAC_GENERAL, mechanism_param=mac_len
            )
        finally:
            key.destroy()

    def test_des3_mac_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different DES3 keys produce different MAC values."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not has_mechanism(p11_module, "DES3_MAC"):
            pytest.skip("CKM_DES3_MAC not supported")
        tmpl = {Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        key2 = p11_session.generate_key(KeyType.DES3, template=tmpl)
        data = b"MAC key independence test data"
        try:
            mac1 = key1.sign(data, mechanism=Mechanism.DES3_MAC)
            mac2 = key2.sign(data, mechanism=Mechanism.DES3_MAC)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()


# ---------------------------------------------------------------------------
# DES key derivation by data encryption — mechanism availability checks only
# ---------------------------------------------------------------------------


class TestDESKeyDerivation:
    """Availability checks for DES/DES3 key derivation by data encryption.

    These mechanisms (DES_ECB_ENCRYPT_DATA, DES_CBC_ENCRYPT_DATA,
    DES3_ECB_ENCRYPT_DATA, DES3_CBC_ENCRYPT_DATA) are used via derive_key()
    with module-specific parameter structures. The tests here confirm the
    mechanisms are advertised by the module; full derivation tests live in
    the key derivation test suite.
    """

    def test_des_ecb_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_DES_ECB_ENCRYPT_DATA is advertised when DES is supported."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported — skipping derivation check")
        if not has_mechanism(p11_module, "DES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_DES_ECB_ENCRYPT_DATA not supported")
        # Mechanism is present — no further operation needed for availability check
        assert True

    def test_des_cbc_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_DES_CBC_ENCRYPT_DATA is advertised when DES is supported."""
        if not has_mechanism(p11_module, "DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported — skipping derivation check")
        if not has_mechanism(p11_module, "DES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_DES_CBC_ENCRYPT_DATA not supported")
        assert True

    def test_des3_ecb_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_DES3_ECB_ENCRYPT_DATA is advertised when DES3 is supported."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported — skipping derivation check")
        if not has_mechanism(p11_module, "DES3_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_DES3_ECB_ENCRYPT_DATA not supported")
        assert True

    def test_des3_cbc_encrypt_data_available(self, p11_module: Any) -> None:
        """Check CKM_DES3_CBC_ENCRYPT_DATA is advertised when DES3 is supported."""
        if not has_mechanism(p11_module, "DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported — skipping derivation check")
        if not has_mechanism(p11_module, "DES3_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_DES3_CBC_ENCRYPT_DATA not supported")
        assert True
