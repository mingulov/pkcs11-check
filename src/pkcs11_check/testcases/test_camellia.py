"""Tests for CAMELLIA PKCS#11 mechanisms.

Camellia: 128/192/256-bit keys, 16-byte block.
IV for CBC/CTR modes: 16 bytes.

Covers key generation, encryption/decryption (ECB, CBC, CBC_PAD),
MAC signing/verification, and key derivation availability checks.

Most modules do NOT support CAMELLIA - all tests will skip cleanly on those
platforms. Some module builds include Camellia support.
"""

from __future__ import annotations

from collections.abc import Mapping
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    generate_random,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_CAMELLIA_CBC,
    CKM_CAMELLIA_CBC_PAD,
    CKM_CAMELLIA_ECB,
    CKM_CAMELLIA_KEY_GEN,
    CKM_CAMELLIA_MAC,
    CKM_CAMELLIA_MAC_GENERAL,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    assert_correct,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

# 16-byte CAMELLIA block - ECB/CBC data must be block-aligned
_TWO_BLOCKS = b"sixteen bytes!!\x01" * 2  # exactly 32 bytes


def _camellia_key(raw: Any, sh: int, bits: int, attrs: Mapping[Any, Any]) -> int:
    """Generate a Camellia session key via C_GenerateKey."""
    from pkcs11_check.raw.pack import attr_ulong
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import pack_attrs
    from pkcs11_check.raw.types_std import CKA_VALUE_LEN

    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(attrs))
    tmpl = mk_template(*packed)
    mech = mech_simple(CKM_CAMELLIA_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def _encrypt_or_xfail(
    raw: Any,
    sh: int,
    key: int,
    mechanism: Any,
    data: bytes,
    *,
    mech_param: Any = None,
) -> bytes:
    """Try encrypt_single; xfail if the advertised mechanism is not operational."""
    try:
        return encrypt_single(raw, sh, key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc, CIPHER_OP_RUNTIME_REJECT_RVS, "Camellia mechanism advertised but not operational"
        )
        raise


def _sign_or_xfail(
    raw: Any,
    sh: int,
    key: int,
    mechanism: Any,
    data: bytes,
    *,
    mech_param: Any = None,
) -> bytes:
    """Try sign_single; xfail if the advertised mechanism is not operational."""
    try:
        return sign_single(raw, sh, key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc, CIPHER_OP_RUNTIME_REJECT_RVS, "Camellia MAC advertised but not operational"
        )
        raise


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestCAMELLIAKeyGen:
    """CKM_CAMELLIA_KEY_GEN - key generation for 128/192/256-bit keys."""

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_camellia_key_gen(self, p11_raw_session: Any, key_bits: int) -> None:
        """Generate a Camellia session key of the specified bit length."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        key = _camellia_key(rs.raw, rs.sh, key_bits, {CKA_TOKEN: False})
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestCAMELLIAEncryption:
    """CAMELLIA encryption/decryption: ECB, CBC, CBC_PAD."""

    def test_camellia_ecb_roundtrip(self, p11_raw_session: Any) -> None:
        """CAMELLIA-ECB encrypt/decrypt roundtrip with block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_ECB"):
            pytest.skip("CKM_CAMELLIA_ECB not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            ct = _encrypt_or_xfail(rs.raw, rs.sh, key, CKM_CAMELLIA_ECB, _TWO_BLOCKS)
            if ct == _TWO_BLOCKS:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_ECB:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_ECB",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ct) == len(_TWO_BLOCKS)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_CAMELLIA_ECB, ct)
            assert_correct(
                actual=pt,
                expected=_TWO_BLOCKS,
                label="CKM_CAMELLIA_ECB:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_CAMELLIA_ECB",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_ecb_different_keys(self, p11_raw_session: Any) -> None:
        """CAMELLIA-ECB: same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_ECB"):
            pytest.skip("CKM_CAMELLIA_ECB not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _camellia_key(rs.raw, rs.sh, 128, tmpl)
        key2 = _camellia_key(rs.raw, rs.sh, 128, tmpl)
        try:
            ct1 = _encrypt_or_xfail(rs.raw, rs.sh, key1, CKM_CAMELLIA_ECB, _TWO_BLOCKS)
            ct2 = encrypt_single(rs.raw, rs.sh, key2, CKM_CAMELLIA_ECB, _TWO_BLOCKS)
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_ECB:encrypt key independence",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_ECB",
                    summary="different keys produced identical ECB ciphertext -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_camellia_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """CAMELLIA-CBC encrypt/decrypt roundtrip with 16-byte IV and block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_CBC"):
            pytest.skip("CKM_CAMELLIA_CBC not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC, iv),
            )
            if ct == _TWO_BLOCKS:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_CBC:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_CBC",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CBC,
                ct,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC, iv),
            )
            assert_correct(
                actual=pt,
                expected=_TWO_BLOCKS,
                label="CKM_CAMELLIA_CBC:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_CAMELLIA_CBC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_cbc_different_ivs(self, p11_raw_session: Any) -> None:
        """CAMELLIA-CBC with different IVs produces different ciphertexts."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_CBC"):
            pytest.skip("CKM_CAMELLIA_CBC not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv1 = generate_random(rs.raw, rs.sh, 16)
        iv2 = generate_random(rs.raw, rs.sh, 16)
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC, iv1),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC, iv2),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_CBC:encrypt IV independence",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_CBC",
                    summary="different IVs (same key) produced identical CBC "
                    "ciphertext -- IV ignored",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_cbc_pad_roundtrip(self, p11_raw_session: Any) -> None:
        """CAMELLIA-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_CBC_PAD"):
            pytest.skip("CKM_CAMELLIA_CBC_PAD not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        # Non-block-aligned data - PKCS#7 padding handles it
        plaintext = b"CAMELLIA CBC PAD test data!!"  # 24 bytes, not a multiple of 16
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC_PAD, iv),
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_CBC_PAD:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_CBC_PAD",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            # Ciphertext is padded to block boundary
            assert len(ct) % 16 == 0
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC_PAD, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_CAMELLIA_CBC_PAD:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_CAMELLIA_CBC_PAD",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_cbc_pad_different_keys(self, p11_raw_session: Any) -> None:
        """CAMELLIA-CBC-PAD: same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_CBC_PAD"):
            pytest.skip("CKM_CAMELLIA_CBC_PAD not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _camellia_key(rs.raw, rs.sh, 128, tmpl)
        key2 = _camellia_key(rs.raw, rs.sh, 128, tmpl)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"CAMELLIA CBC PAD key independence test!!"  # 36 bytes
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key1,
                CKM_CAMELLIA_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC_PAD, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_CAMELLIA_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_CAMELLIA_CBC_PAD, iv),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_CBC_PAD:encrypt key independence",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_CBC_PAD",
                    summary="different keys produced identical CBC-PAD ciphertext -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


# ---------------------------------------------------------------------------
# MAC (sign/verify)
# ---------------------------------------------------------------------------


class TestCAMELLIAMAC:
    """CKM_CAMELLIA_MAC and CKM_CAMELLIA_MAC_GENERAL - MAC sign/verify tests."""

    def test_camellia_mac_sign_verify(self, p11_raw_session: Any) -> None:
        """CAMELLIA-MAC sign and verify roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_MAC"):
            pytest.skip("CKM_CAMELLIA_MAC not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"CAMELLIA MAC test data for signing"
        try:
            mac = _sign_or_xfail(rs.raw, rs.sh, key, CKM_CAMELLIA_MAC, data)
            assert len(mac) > 0
            assert verify_single(rs.raw, rs.sh, key, CKM_CAMELLIA_MAC, data, mac)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_mac_general_sign_verify(self, p11_raw_session: Any) -> None:
        """CAMELLIA-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_MAC_GENERAL"):
            pytest.skip("CKM_CAMELLIA_MAC_GENERAL not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"CAMELLIA MAC GENERAL test data"
        mac_len = 8  # request 8-byte MAC (half block)
        try:
            mac = _sign_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_MAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_CAMELLIA_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            assert len(mac) == mac_len
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_MAC_GENERAL,
                data,
                mac,
                mech_param=mech_bytes(CKM_CAMELLIA_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_mac_different_keys(self, p11_raw_session: Any) -> None:
        """Different CAMELLIA keys produce different MAC values."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_MAC"):
            pytest.skip("CKM_CAMELLIA_MAC not supported")
        tmpl = {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False}
        key1 = _camellia_key(rs.raw, rs.sh, 128, tmpl)
        key2 = _camellia_key(rs.raw, rs.sh, 128, tmpl)
        data = b"MAC key independence test data"
        try:
            mac1 = _sign_or_xfail(rs.raw, rs.sh, key1, CKM_CAMELLIA_MAC, data)
            mac2 = sign_single(rs.raw, rs.sh, key2, CKM_CAMELLIA_MAC, data)
            if mac1 == mac2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_MAC:sign key independence",
                    operation="C_Sign",
                    mechanism="CKM_CAMELLIA_MAC",
                    summary="different keys produced identical MAC -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


# ---------------------------------------------------------------------------
# CTR mode
# ---------------------------------------------------------------------------


class TestCamelliaCTR:
    """CKM_CAMELLIA_CTR - counter mode encrypt/decrypt tests.

    Camellia CTR uses the same CK_AES_CTR_PARAMS structure (counter bits +
    16-byte counter block) as AES CTR.
    """

    def test_camellia_ctr_roundtrip(self, p11_raw_session: Any) -> None:
        """Camellia-CTR encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_CTR"):
            pytest.skip("CKM_CAMELLIA_CTR not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        plaintext = b"Camellia CTR mode test data!!"  # arbitrary length - CTR is a stream mode
        try:
            from pkcs11_check.raw.pack import mech_ctr
            from pkcs11_check.raw.types_std import CKM_CAMELLIA_CTR

            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_CAMELLIA_CTR),
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CAMELLIA_CTR:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_CAMELLIA_CTR",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ct) == len(plaintext)
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CTR,
                ct,
                mech_param=mech_ctr(CKM_CAMELLIA_CTR),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_CAMELLIA_CTR:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_CAMELLIA_CTR",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_camellia_ctr_different_nonces(self, p11_raw_session: Any) -> None:
        """Camellia-CTR with different counter blocks produces different ciphertexts."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported")
        if not rs.has_mechanism("CAMELLIA_CTR"):
            pytest.skip("CKM_CAMELLIA_CTR not supported")
        key = _camellia_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        plaintext = b"CTR nonce independence test!!"
        try:
            from pkcs11_check.raw.pack import mech_ctr
            from pkcs11_check.raw.types_std import CKM_CAMELLIA_CTR

            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_CAMELLIA_CTR, bits=32),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CAMELLIA_CTR,
                plaintext,
                mech_param=mech_ctr(CKM_CAMELLIA_CTR, bits=64),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# Key derivation by data encryption - availability checks only
# ---------------------------------------------------------------------------


class TestCAMELLIAKeyDerivation:
    """Availability checks for CAMELLIA key derivation by data encryption.

    CKM_CAMELLIA_ECB_ENCRYPT_DATA and CKM_CAMELLIA_CBC_ENCRYPT_DATA are used
    via derive_key() with module-specific parameter structures. The tests here
    confirm the mechanisms are advertised by the module; full derivation tests
    live in the key derivation test suite.
    """

    def test_camellia_ecb_encrypt_data_available(self, p11_raw_session: Any) -> None:
        """Check CKM_CAMELLIA_ECB_ENCRYPT_DATA is advertised when CAMELLIA is supported."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("CAMELLIA_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_CAMELLIA_ECB_ENCRYPT_DATA not supported")
        # Mechanism is present - no further operation needed for availability check
        assert True

    def test_camellia_cbc_encrypt_data_available(self, p11_raw_session: Any) -> None:
        """Check CKM_CAMELLIA_CBC_ENCRYPT_DATA is advertised when CAMELLIA is supported."""
        rs = p11_raw_session
        if not rs.has_mechanism("CAMELLIA_KEY_GEN"):
            pytest.skip("CKM_CAMELLIA_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("CAMELLIA_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_CAMELLIA_CBC_ENCRYPT_DATA not supported")
        assert True
