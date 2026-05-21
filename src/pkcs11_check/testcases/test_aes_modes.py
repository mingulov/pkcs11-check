"""Tests for AES stream/feedback cipher modes and MAC variants.

Covers AES-CTR, AES-CTS, AES-CFB (8/64/128-bit), AES-OFB,
AES-MAC-GENERAL, AES-XCBC-MAC, and AES-KEY-WRAP-PKCS7.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_ctr
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    generate_random,
    import_secret_key,
    read_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_CFB8,
    CKM_AES_CFB64,
    CKM_AES_CFB128,
    CKM_AES_CTR,
    CKM_AES_CTS,
    CKM_AES_KEY_WRAP_PKCS7,
    CKM_AES_MAC,
    CKM_AES_MAC_GENERAL,
    CKM_AES_OFB,
    CKM_AES_XCBC_MAC,
    CKM_AES_XCBC_MAC_96,
    CKO_SECRET_KEY,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.encrypt


class TestAESCTR:
    """AES-CTR (Counter mode) encrypt/decrypt tests."""

    def test_aes_ctr_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-CTR encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        plaintext = b"AES-CTR test data, any length ok"
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_AES_CTR),
            )
            assert ct != plaintext
            assert len(ct) == len(plaintext)
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTR,
                ct,
                mech_param=mech_ctr(CKM_AES_CTR),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_ctr_different_keys(self, p11_raw_session: Any) -> None:
        """Same plaintext encrypted with different CTR keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key1 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
        key2 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
        plaintext = b"key independence test data here!!"  # 32 bytes
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_AES_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_AES_CTR),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_AES_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_AES_CTR),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_aes_ctr_non_block_aligned(self, p11_raw_session: Any) -> None:
        """AES-CTR MUST handle non-block-aligned plaintext (stream cipher).

        Per OASIS spec (NIST SP 800-38A): CTR mode encrypts individual bytes
        using the encrypted counter block. Non-block-aligned data is valid.
        Modules that reject it have a bug.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        # 17 bytes - deliberately NOT block-aligned
        plaintext = b"seventeen chars!!"[:17]
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_AES_CTR),
            )
            assert len(ct) == 17, f"CTR output must match input length, got {len(ct)}"
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTR,
                ct,
                mech_param=mech_ctr(CKM_AES_CTR),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_ctr_counter_bits_zero_rejected(self, p11_raw_session: Any) -> None:
        """ulCounterBits=0 must be rejected per OASIS spec (valid range: 1-128)."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_ctr(CKM_AES_CTR, bits=0)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                f"C_EncryptInit accepted ulCounterBits=0 (rv=0x{rv:08x}), spec requires rejection"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_ctr_counter_bits_129_rejected(self, p11_raw_session: Any) -> None:
        """ulCounterBits=129 must be rejected per OASIS spec (valid range: 1-128)."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_ctr(CKM_AES_CTR, bits=129)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                f"C_EncryptInit accepted ulCounterBits=129 (rv=0x{rv:08x}), spec requires rejection"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestAESCTS:
    """AES-CTS (CBC with Ciphertext Stealing) encrypt/decrypt tests."""

    def test_aes_cts_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-CTS encrypt/decrypt roundtrip with non-block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTS"):
            pytest.skip("CKM_AES_CTS not supported")
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        # CTS requires at least one full block; use non-block-aligned length
        plaintext = b"CTS handles non-block-aligned!" + b"\x00" * 3  # 33 bytes
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CTS, iv),
            )
            assert ct != plaintext
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                ct,
                mech_param=mech_bytes(CKM_AES_CTS, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_cts_different_keys(self, p11_raw_session: Any) -> None:
        """Same plaintext encrypted with different CTS keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTS"):
            pytest.skip("CKM_AES_CTS not supported")
        key1 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
        key2 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"CTS key independence test!!" + b"\x00" * 6  # 32 bytes
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_AES_CTS,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CTS, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_AES_CTS,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CTS, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


_CFB_MODES = [
    pytest.param("AES_CFB8", CKM_AES_CFB8, id="CFB8"),
    pytest.param("AES_CFB64", CKM_AES_CFB64, id="CFB64"),
    pytest.param("AES_CFB128", CKM_AES_CFB128, id="CFB128"),
]


class TestAESCFB:
    """AES-CFB (Cipher Feedback) encrypt/decrypt tests for 8/64/128-bit modes."""

    @pytest.mark.parametrize("mech_name_str,mech", _CFB_MODES)
    def test_aes_cfb_roundtrip(self, p11_raw_session: Any, mech_name_str: str, mech: Any) -> None:
        """AES-CFB encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"CFB mode test data block!!" + b"\x00" * 6  # 32 bytes
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                mech,
                plaintext,
                mech_param=mech_bytes(mech, iv),
            )
            assert ct != plaintext
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                mech,
                ct,
                mech_param=mech_bytes(mech, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize("mech_name_str,mech", _CFB_MODES)
    def test_aes_cfb_different_keys(
        self, p11_raw_session: Any, mech_name_str: str, mech: Any
    ) -> None:
        """Same plaintext encrypted with different CFB keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        key1 = gen_aes_key(rs.raw, rs.sh, 256)
        key2 = gen_aes_key(rs.raw, rs.sh, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"CFB key independence!" + b"\x00" * 11  # 32 bytes
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key1,
                mech,
                plaintext,
                mech_param=mech_bytes(mech, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                mech,
                plaintext,
                mech_param=mech_bytes(mech, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


class TestAESOFB:
    """AES-OFB (Output Feedback) encrypt/decrypt tests."""

    def test_aes_ofb_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-OFB encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_OFB"):
            pytest.skip("CKM_AES_OFB not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"OFB mode test data!!" + b"\x00" * 12  # 32 bytes
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_OFB,
                plaintext,
                mech_param=mech_bytes(CKM_AES_OFB, iv),
            )
            assert ct != plaintext
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_OFB,
                ct,
                mech_param=mech_bytes(CKM_AES_OFB, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_ofb_different_keys(self, p11_raw_session: Any) -> None:
        """Same plaintext encrypted with different OFB keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_OFB"):
            pytest.skip("CKM_AES_OFB not supported")
        key1 = gen_aes_key(rs.raw, rs.sh, 256)
        key2 = gen_aes_key(rs.raw, rs.sh, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"OFB key independence!" + b"\x00" * 11  # 32 bytes
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_AES_OFB,
                plaintext,
                mech_param=mech_bytes(CKM_AES_OFB, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_AES_OFB,
                plaintext,
                mech_param=mech_bytes(CKM_AES_OFB, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


class TestAESMACGeneral:
    """AES-MAC-GENERAL (parameterized MAC length) sign/verify tests."""

    def test_aes_mac_general_sign_verify(self, p11_raw_session: Any) -> None:
        """AES-MAC-GENERAL sign and verify roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC_GENERAL"):
            pytest.skip("CKM_AES_MAC_GENERAL not supported")
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        data = b"MAC general test data for signing"
        mac_len = 8  # request 8-byte MAC
        try:
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_MAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_AES_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            assert len(mac) == mac_len
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_MAC_GENERAL,
                data,
                mac,
                mech_param=mech_bytes(CKM_AES_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_mac_general_different_keys(self, p11_raw_session: Any) -> None:
        """Different keys produce different MACs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC_GENERAL"):
            pytest.skip("CKM_AES_MAC_GENERAL not supported")
        key1 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        key2 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        data = b"MAC key independence test"
        mac_len = 8
        try:
            mac1 = sign_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_AES_MAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_AES_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            mac2 = sign_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_AES_MAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_AES_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            assert mac1 != mac2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    @pytest.mark.parametrize("mac_len", [1, 4, 8, 12, 16])
    def test_aes_mac_general_variable_lengths(self, p11_raw_session: Any, mac_len: int) -> None:
        """AES-MAC-GENERAL with variable output lengths (1 to 16 bytes)."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC_GENERAL"):
            pytest.skip("CKM_AES_MAC_GENERAL not supported")
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            data = b"Variable MAC length test data!"
            import ctypes

            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_MAC_GENERAL,
                data,
                mech_param=mech_bytes(
                    CKM_AES_MAC_GENERAL,
                    mac_len.to_bytes(ctypes.sizeof(ctypes.c_ulong), "little"),
                ),
            )
            assert len(mac) == mac_len, f"Requested {mac_len}-byte MAC, got {len(mac)} bytes"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


_XCBC_VERIFY_XFAIL_MSG = (
    "Module returns CKR_KEY_TYPE_INCONSISTENT for CKM_AES_XCBC_MAC C_VerifyInit; "
    "NSS softoken rejects CKK_AES keys for XCBC-MAC verify even when CKA_VERIFY=True "
    "(NSS softoken bug -- sign works but verify is broken)"
)


class TestAESMAC:
    """CKM_AES_MAC -- fixed 8-byte (half-block) CBC-MAC."""

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """Sign and verify with CKM_AES_MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC"):
            pytest.skip("AES_MAC not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SIGN: True, CKA_VERIFY: True})
        try:
            data = b"AES-MAC test data for roundtrip verification"
            sig = sign_single(rs.raw, rs.sh, key, CKM_AES_MAC, data)
            assert len(sig) == 8, f"AES-MAC output must be 8 bytes, got {len(sig)}"
            ok = verify_single(rs.raw, rs.sh, key, CKM_AES_MAC, data, sig)
            assert ok is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_tamper_detection(self, p11_raw_session: Any) -> None:
        """Modified data must fail verification."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC"):
            pytest.skip("AES_MAC not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SIGN: True, CKA_VERIFY: True})
        try:
            sig = sign_single(rs.raw, rs.sh, key, CKM_AES_MAC, b"original")
            ok = verify_single(rs.raw, rs.sh, key, CKM_AES_MAC, b"tampered", sig)
            assert ok is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_different_keys(self, p11_raw_session: Any) -> None:
        """Different keys produce different MACs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC"):
            pytest.skip("AES_MAC not supported")
        k1 = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SIGN: True, CKA_VERIFY: True})
        k2 = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SIGN: True, CKA_VERIFY: True})
        try:
            data = b"same data different keys"
            sig1 = sign_single(rs.raw, rs.sh, k1, CKM_AES_MAC, data)
            sig2 = sign_single(rs.raw, rs.sh, k2, CKM_AES_MAC, data)
            assert sig1 != sig2
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)


class TestAESXCBCMAC:
    """AES-XCBC-MAC and AES-XCBC-MAC-96 sign/verify tests."""

    def test_aes_xcbc_mac_sign_verify(self, p11_raw_session: Any) -> None:
        """AES-XCBC-MAC sign and verify roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_XCBC_MAC"):
            pytest.skip("CKM_AES_XCBC_MAC not supported")
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,  # XCBC-MAC is defined for 128-bit keys
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        data = b"XCBC-MAC test data for signing"
        try:
            mac = sign_single(rs.raw, rs.sh, key, CKM_AES_XCBC_MAC, data)
            assert len(mac) > 0
            try:
                assert verify_single(rs.raw, rs.sh, key, CKM_AES_XCBC_MAC, data, mac)
            except AssertionError as exc:
                if is_known_error(exc, {int(CKR_KEY_TYPE_INCONSISTENT)}):
                    pytest.xfail(_XCBC_VERIFY_XFAIL_MSG)
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_xcbc_mac_96_sign_verify(self, p11_raw_session: Any) -> None:
        """AES-XCBC-MAC-96 sign and verify roundtrip (truncated to 12 bytes)."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_XCBC_MAC_96"):
            pytest.skip("CKM_AES_XCBC_MAC_96 not supported")
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,  # XCBC-MAC-96 is defined for 128-bit keys
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        data = b"XCBC-MAC-96 test data for signing"
        try:
            mac = sign_single(rs.raw, rs.sh, key, CKM_AES_XCBC_MAC_96, data)
            assert len(mac) == 12  # truncated to 96 bits
            try:
                assert verify_single(rs.raw, rs.sh, key, CKM_AES_XCBC_MAC_96, data, mac)
            except AssertionError as exc:
                if is_known_error(exc, {int(CKR_KEY_TYPE_INCONSISTENT)}):
                    pytest.xfail(_XCBC_VERIFY_XFAIL_MSG)
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_xcbc_mac_different_keys(self, p11_raw_session: Any) -> None:
        """Different keys produce different XCBC-MAC values."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_XCBC_MAC"):
            pytest.skip("CKM_AES_XCBC_MAC not supported")
        key1 = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        key2 = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        data = b"XCBC key independence test"
        try:
            mac1 = sign_single(rs.raw, rs.sh, key1, CKM_AES_XCBC_MAC, data)
            mac2 = sign_single(rs.raw, rs.sh, key2, CKM_AES_XCBC_MAC, data)
            assert mac1 != mac2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


class TestAESKeyWrapPKCS7:
    """AES-KEY-WRAP-PKCS7 wrap/unwrap tests."""

    def test_aes_key_wrap_pkcs7_roundtrip(self, p11_raw_session: Any) -> None:
        """Wrap and unwrap an AES key with AES-KEY-WRAP-PKCS7, verify material matches."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_PKCS7"):
            pytest.skip("CKM_AES_KEY_WRAP_PKCS7 not supported")

        wrap_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )

        # Create a target key with known material (non-block-aligned size to test PKCS7 padding)
        import os

        key_bytes = os.urandom(24)  # 192-bit key
        target = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )

        try:
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrap_key_h,
                target,
                CKM_AES_KEY_WRAP_PKCS7,
            )
            assert wrapped != key_bytes

            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                wrap_key_h,
                wrapped,
                CKM_AES_KEY_WRAP_PKCS7,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE_LEN: 24,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
            )
            try:
                okm = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert okm == key_bytes
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, target)
            destroy_quietly(rs.raw, rs.sh, wrap_key_h)

    def test_aes_key_wrap_pkcs7_different_wrapping_keys(self, p11_raw_session: Any) -> None:
        """Different wrapping keys produce different wrapped outputs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_PKCS7"):
            pytest.skip("CKM_AES_KEY_WRAP_PKCS7 not supported")

        wrap_key1 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        wrap_key2 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )

        import os

        key_bytes = os.urandom(16)
        target = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )

        try:
            wrapped1 = wrap_key(
                rs.raw,
                rs.sh,
                wrap_key1,
                target,
                CKM_AES_KEY_WRAP_PKCS7,
            )
            wrapped2 = wrap_key(
                rs.raw,
                rs.sh,
                wrap_key2,
                target,
                CKM_AES_KEY_WRAP_PKCS7,
            )
            assert wrapped1 != wrapped2
        finally:
            destroy_quietly(rs.raw, rs.sh, target)
            destroy_quietly(rs.raw, rs.sh, wrap_key1)
            destroy_quietly(rs.raw, rs.sh, wrap_key2)
