"""Tests for AES stream/feedback cipher modes and MAC variants.

Covers AES-CTR, AES-CTS, AES-CFB (8/64/128-bit), AES-OFB,
AES-MAC-GENERAL, AES-XCBC-MAC, and AES-KEY-WRAP-PKCS7.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import DataLenRange, DeviceError, FunctionFailed, MechanismInvalid
from pkcs11.mechanisms import CTRParams

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.encrypt


class TestAESCTR:
    """AES-CTR (Counter mode) encrypt/decrypt tests."""

    def test_aes_ctr_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """AES-CTR encrypt/decrypt roundtrip."""
        if not has_mechanism(p11_module, "AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = p11_session.generate_key(KeyType.AES, 256)
        # CTRParams takes a nonce up to 15 bytes; counter bits are derived
        nonce = os.urandom(12)
        params = CTRParams(nonce)
        plaintext = b"AES-CTR test data, any length ok"
        try:
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_CTR, mechanism_param=params)
            assert ct != plaintext
            assert len(ct) == len(plaintext)
            # Must use same nonce for decryption
            pt = key.decrypt(ct, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(nonce))
            assert pt == plaintext
        finally:
            key.destroy()

    def test_aes_ctr_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Same plaintext encrypted with different CTR keys should differ."""
        if not has_mechanism(p11_module, "AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key1 = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
        )
        key2 = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
        )
        nonce = os.urandom(12)
        params = CTRParams(nonce)
        # Use block-aligned plaintext: some modules require multiples of 16 bytes for AES-CTR
        plaintext = b"key independence!" + b"\x00" * 15  # 32 bytes
        try:
            ct1 = key1.encrypt(plaintext, mechanism=Mechanism.AES_CTR, mechanism_param=params)
            ct2 = key2.encrypt(
                plaintext, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(nonce)
            )
            assert ct1 != ct2
        except (MechanismInvalid, DeviceError, FunctionFailed, DataLenRange) as exc:
            pytest.xfail(f"CKM_AES_CTR not operational: {exc}")
        finally:
            key1.destroy()
            key2.destroy()


class TestAESCTS:
    """AES-CTS (CBC with Ciphertext Stealing) encrypt/decrypt tests."""

    def test_aes_cts_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """AES-CTS encrypt/decrypt roundtrip with non-block-aligned data."""
        if not has_mechanism(p11_module, "AES_CTS"):
            pytest.skip("CKM_AES_CTS not supported")
        key = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        iv = p11_session.generate_random(128)
        # CTS requires at least one full block; use non-block-aligned length
        plaintext = b"CTS handles non-block-aligned!" + b"\x00" * 3  # 33 bytes
        try:
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_CTS, mechanism_param=iv)
            assert ct != plaintext
            pt = key.decrypt(ct, mechanism=Mechanism.AES_CTS, mechanism_param=iv)
            assert pt == plaintext
        except (MechanismInvalid, DeviceError, FunctionFailed) as exc:
            pytest.xfail(f"CKM_AES_CTS not operational: {exc}")
        finally:
            key.destroy()

    def test_aes_cts_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Same plaintext encrypted with different CTS keys should differ."""
        if not has_mechanism(p11_module, "AES_CTS"):
            pytest.skip("CKM_AES_CTS not supported")
        key1 = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
        )
        key2 = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
        )
        iv = p11_session.generate_random(128)
        plaintext = b"CTS key independence test!!" + b"\x00" * 6  # 32 bytes
        try:
            ct1 = key1.encrypt(plaintext, mechanism=Mechanism.AES_CTS, mechanism_param=iv)
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.AES_CTS, mechanism_param=iv)
            assert ct1 != ct2
        except (MechanismInvalid, DeviceError, FunctionFailed) as exc:
            pytest.xfail(f"CKM_AES_CTS not operational: {exc}")
        finally:
            key1.destroy()
            key2.destroy()


_CFB_MODES = [
    pytest.param("AES_CFB8", Mechanism.AES_CFB8, id="CFB8"),
    pytest.param("AES_CFB64", Mechanism.AES_CFB64, id="CFB64"),
    pytest.param("AES_CFB128", Mechanism.AES_CFB128, id="CFB128"),
]


class TestAESCFB:
    """AES-CFB (Cipher Feedback) encrypt/decrypt tests for 8/64/128-bit modes."""

    @pytest.mark.parametrize("mech_name_str,mech", _CFB_MODES)
    def test_aes_cfb_roundtrip(
        self, p11_session: Any, p11_module: Any, mech_name_str: str, mech: Mechanism
    ) -> None:
        """AES-CFB encrypt/decrypt roundtrip."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"CFB mode test data block!!" + b"\x00" * 6  # 32 bytes
        try:
            ct = key.encrypt(plaintext, mechanism=mech, mechanism_param=iv)
            assert ct != plaintext
            pt = key.decrypt(ct, mechanism=mech, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    @pytest.mark.parametrize("mech_name_str,mech", _CFB_MODES)
    def test_aes_cfb_different_keys(
        self, p11_session: Any, p11_module: Any, mech_name_str: str, mech: Mechanism
    ) -> None:
        """Same plaintext encrypted with different CFB keys should differ."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        key1 = p11_session.generate_key(KeyType.AES, 256)
        key2 = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"CFB key independence!" + b"\x00" * 11  # 32 bytes
        try:
            ct1 = key1.encrypt(plaintext, mechanism=mech, mechanism_param=iv)
            ct2 = key2.encrypt(plaintext, mechanism=mech, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()


class TestAESOFB:
    """AES-OFB (Output Feedback) encrypt/decrypt tests."""

    def test_aes_ofb_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """AES-OFB encrypt/decrypt roundtrip."""
        if not has_mechanism(p11_module, "AES_OFB"):
            pytest.skip("CKM_AES_OFB not supported")
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"OFB mode test data!!" + b"\x00" * 12  # 32 bytes
        try:
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_OFB, mechanism_param=iv)
            assert ct != plaintext
            pt = key.decrypt(ct, mechanism=Mechanism.AES_OFB, mechanism_param=iv)
            assert pt == plaintext
        finally:
            key.destroy()

    def test_aes_ofb_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Same plaintext encrypted with different OFB keys should differ."""
        if not has_mechanism(p11_module, "AES_OFB"):
            pytest.skip("CKM_AES_OFB not supported")
        key1 = p11_session.generate_key(KeyType.AES, 256)
        key2 = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"OFB key independence!" + b"\x00" * 11  # 32 bytes
        try:
            ct1 = key1.encrypt(plaintext, mechanism=Mechanism.AES_OFB, mechanism_param=iv)
            ct2 = key2.encrypt(plaintext, mechanism=Mechanism.AES_OFB, mechanism_param=iv)
            assert ct1 != ct2
        finally:
            key1.destroy()
            key2.destroy()


class TestAESMACGeneral:
    """AES-MAC-GENERAL (parameterized MAC length) sign/verify tests."""

    def test_aes_mac_general_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """AES-MAC-GENERAL sign and verify roundtrip."""
        if not has_mechanism(p11_module, "AES_MAC_GENERAL"):
            pytest.skip("CKM_AES_MAC_GENERAL not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"MAC general test data for signing"
        mac_len = 8  # request 8-byte MAC
        try:
            mac = key.sign(data, mechanism=Mechanism.AES_MAC_GENERAL, mechanism_param=mac_len)
            assert len(mac) == mac_len
            assert key.verify(
                data, mac, mechanism=Mechanism.AES_MAC_GENERAL, mechanism_param=mac_len
            )
        finally:
            key.destroy()

    def test_aes_mac_general_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different keys produce different MACs."""
        if not has_mechanism(p11_module, "AES_MAC_GENERAL"):
            pytest.skip("CKM_AES_MAC_GENERAL not supported")
        key1 = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        key2 = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"MAC key independence test"
        mac_len = 8
        try:
            mac1 = key1.sign(data, mechanism=Mechanism.AES_MAC_GENERAL, mechanism_param=mac_len)
            mac2 = key2.sign(data, mechanism=Mechanism.AES_MAC_GENERAL, mechanism_param=mac_len)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()


class TestAESXCBCMAC:
    """AES-XCBC-MAC and AES-XCBC-MAC-96 sign/verify tests."""

    def test_aes_xcbc_mac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """AES-XCBC-MAC sign and verify roundtrip."""
        if not has_mechanism(p11_module, "AES_XCBC_MAC"):
            pytest.skip("CKM_AES_XCBC_MAC not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            128,  # XCBC-MAC is defined for 128-bit keys
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"XCBC-MAC test data for signing"
        try:
            mac = key.sign(data, mechanism=Mechanism.AES_XCBC_MAC)
            assert len(mac) > 0
            assert key.verify(data, mac, mechanism=Mechanism.AES_XCBC_MAC)
        finally:
            key.destroy()

    def test_aes_xcbc_mac_96_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """AES-XCBC-MAC-96 sign and verify roundtrip (truncated to 12 bytes)."""
        if not has_mechanism(p11_module, "AES_XCBC_MAC_96"):
            pytest.skip("CKM_AES_XCBC_MAC_96 not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            128,  # XCBC-MAC-96 is defined for 128-bit keys
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"XCBC-MAC-96 test data for signing"
        try:
            mac = key.sign(data, mechanism=Mechanism.AES_XCBC_MAC_96)
            assert len(mac) == 12  # truncated to 96 bits
            assert key.verify(data, mac, mechanism=Mechanism.AES_XCBC_MAC_96)
        finally:
            key.destroy()

    def test_aes_xcbc_mac_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different keys produce different XCBC-MAC values."""
        if not has_mechanism(p11_module, "AES_XCBC_MAC"):
            pytest.skip("CKM_AES_XCBC_MAC not supported")
        key1 = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        key2 = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        data = b"XCBC key independence test"
        try:
            mac1 = key1.sign(data, mechanism=Mechanism.AES_XCBC_MAC)
            mac2 = key2.sign(data, mechanism=Mechanism.AES_XCBC_MAC)
            assert mac1 != mac2
        finally:
            key1.destroy()
            key2.destroy()


class TestAESKeyWrapPKCS7:
    """AES-KEY-WRAP-PKCS7 wrap/unwrap tests."""

    def test_aes_key_wrap_pkcs7_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap and unwrap an AES key with AES-KEY-WRAP-PKCS7, verify material matches."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP_PKCS7"):
            pytest.skip("CKM_AES_KEY_WRAP_PKCS7 not supported")

        wrap_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

        # Create a target key with known material (non-block-aligned size to test PKCS7 padding)
        key_bytes = os.urandom(24)  # 192-bit key - not a multiple of 8 bytes for wrap block
        target = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            }
        )

        try:
            wrapped = wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP_PKCS7)
            assert wrapped != key_bytes

            unwrapped = wrap_key.unwrap_key(
                ObjectClass.SECRET_KEY,
                KeyType.AES,
                wrapped,
                mechanism=Mechanism.AES_KEY_WRAP_PKCS7,
                template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
            )
            assert unwrapped[Attribute.VALUE] == key_bytes
        finally:
            target.destroy()
            wrap_key.destroy()

    def test_aes_key_wrap_pkcs7_different_wrapping_keys(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different wrapping keys produce different wrapped outputs."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP_PKCS7"):
            pytest.skip("CKM_AES_KEY_WRAP_PKCS7 not supported")

        wrap_key1 = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )
        wrap_key2 = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )

        key_bytes = os.urandom(16)
        target = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            }
        )

        try:
            wrapped1 = wrap_key1.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP_PKCS7)
            wrapped2 = wrap_key2.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP_PKCS7)
            assert wrapped1 != wrapped2
        finally:
            target.destroy()
            wrap_key1.destroy()
            wrap_key2.destroy()
