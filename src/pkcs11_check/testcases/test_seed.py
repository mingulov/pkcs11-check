"""Tests for SEED PKCS#11 mechanisms.

SEED: 128-bit key only, 16-byte block. Korean standard block cipher (RFC 4269).

Covers key generation, encryption/decryption (ECB, CBC, CBC_PAD),
MAC signing/verification, and key derivation availability checks.

Most modules do NOT support SEED - all tests will skip cleanly on those
platforms. Some Korean-standard-focused HSMs may include SEED support.
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
    CKM_SEED_CBC,
    CKM_SEED_CBC_PAD,
    CKM_SEED_ECB,
    CKM_SEED_KEY_GEN,
    CKM_SEED_MAC,
    CKM_SEED_MAC_GENERAL,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.full

# 16-byte SEED block - ECB/CBC data must be block-aligned
_TWO_BLOCKS = b"sixteen bytes!!\x01" * 2  # exactly 32 bytes


def _seed_key(raw: Any, sh: int, attrs: Mapping[Any, Any]) -> int:
    """Generate a SEED-128 session key via C_GenerateKey (fixed size)."""
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import pack_attrs

    packed = pack_attrs(attrs)
    tmpl = mk_template(*packed)
    mech = mech_simple(CKM_SEED_KEY_GEN)
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
    """Try encrypt_single; xfail if module returns CKR_MECHANISM_INVALID."""
    try:
        return encrypt_single(raw, sh, key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        if is_known_error(exc, {CKR_MECHANISM_INVALID}):
            classify(
                "not_operational",
                kind="crypto",
                label="SEED:C_Encrypt",
                operation="C_Encrypt",
                summary=f"Mechanism advertised but rejected at use: {exc}",
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
    """Try sign_single; xfail if module returns CKR_MECHANISM_INVALID."""
    try:
        return sign_single(raw, sh, key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        if is_known_error(exc, {CKR_MECHANISM_INVALID}):
            classify(
                "not_operational",
                kind="crypto",
                label="SEED:C_Sign",
                operation="C_Sign",
                summary=f"Mechanism advertised but rejected at use: {exc}",
            )
        raise


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestSEEDKeyGen:
    """CKM_SEED_KEY_GEN - key generation for 128-bit keys (fixed size)."""

    def test_seed_key_gen(self, p11_raw_session: Any) -> None:
        """Generate a SEED-128 session key."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        key = _seed_key(rs.raw, rs.sh, {CKA_TOKEN: False})
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestSEEDEncryption:
    """SEED encryption/decryption: ECB, CBC, CBC_PAD."""

    def test_seed_ecb_roundtrip(self, p11_raw_session: Any) -> None:
        """SEED-ECB encrypt/decrypt roundtrip with block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_ECB"):
            pytest.skip("CKM_SEED_ECB not supported")
        key = _seed_key(
            rs.raw,
            rs.sh,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            ct = _encrypt_or_xfail(rs.raw, rs.sh, key, CKM_SEED_ECB, _TWO_BLOCKS)
            assert ct != _TWO_BLOCKS
            assert len(ct) == len(_TWO_BLOCKS)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_SEED_ECB, ct)
            assert pt == _TWO_BLOCKS
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_seed_ecb_different_keys(self, p11_raw_session: Any) -> None:
        """SEED-ECB: same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_ECB"):
            pytest.skip("CKM_SEED_ECB not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _seed_key(rs.raw, rs.sh, tmpl)
        key2 = _seed_key(rs.raw, rs.sh, tmpl)
        try:
            ct1 = _encrypt_or_xfail(rs.raw, rs.sh, key1, CKM_SEED_ECB, _TWO_BLOCKS)
            ct2 = encrypt_single(rs.raw, rs.sh, key2, CKM_SEED_ECB, _TWO_BLOCKS)
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_seed_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """SEED-CBC encrypt/decrypt roundtrip with 16-byte IV and block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_CBC"):
            pytest.skip("CKM_SEED_CBC not supported")
        key = _seed_key(
            rs.raw,
            rs.sh,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_SEED_CBC, iv),
            )
            assert ct != _TWO_BLOCKS
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_CBC,
                ct,
                mech_param=mech_bytes(CKM_SEED_CBC, iv),
            )
            assert pt == _TWO_BLOCKS
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_seed_cbc_different_ivs(self, p11_raw_session: Any) -> None:
        """SEED-CBC with different IVs produces different ciphertexts."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_CBC"):
            pytest.skip("CKM_SEED_CBC not supported")
        key = _seed_key(
            rs.raw,
            rs.sh,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv1 = generate_random(rs.raw, rs.sh, 16)
        iv2 = generate_random(rs.raw, rs.sh, 16)
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_SEED_CBC, iv1),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_SEED_CBC, iv2),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_seed_cbc_pad_roundtrip(self, p11_raw_session: Any) -> None:
        """SEED-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_CBC_PAD"):
            pytest.skip("CKM_SEED_CBC_PAD not supported")
        key = _seed_key(
            rs.raw,
            rs.sh,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        # Non-block-aligned data - PKCS#7 padding handles it
        plaintext = b"SEED CBC PAD test data!!"  # 24 bytes, not a multiple of 16
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_SEED_CBC_PAD, iv),
            )
            assert ct != plaintext
            # Ciphertext is padded to block boundary
            assert len(ct) % 16 == 0
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_SEED_CBC_PAD, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_seed_cbc_pad_different_keys(self, p11_raw_session: Any) -> None:
        """SEED-CBC-PAD: same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_CBC_PAD"):
            pytest.skip("CKM_SEED_CBC_PAD not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _seed_key(rs.raw, rs.sh, tmpl)
        key2 = _seed_key(rs.raw, rs.sh, tmpl)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"SEED CBC PAD key independence test!!"  # 36 bytes
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key1,
                CKM_SEED_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_SEED_CBC_PAD, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_SEED_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_SEED_CBC_PAD, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


# ---------------------------------------------------------------------------
# MAC (sign/verify)
# ---------------------------------------------------------------------------


class TestSEEDMAC:
    """CKM_SEED_MAC and CKM_SEED_MAC_GENERAL - MAC sign/verify tests."""

    def test_seed_mac_sign_verify(self, p11_raw_session: Any) -> None:
        """SEED-MAC sign and verify roundtrip."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_MAC"):
            pytest.skip("CKM_SEED_MAC not supported")
        key = _seed_key(
            rs.raw,
            rs.sh,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"SEED MAC test data for signing"
        try:
            mac = _sign_or_xfail(rs.raw, rs.sh, key, CKM_SEED_MAC, data)
            assert len(mac) > 0
            assert verify_single(rs.raw, rs.sh, key, CKM_SEED_MAC, data, mac)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_seed_mac_general_sign_verify(self, p11_raw_session: Any) -> None:
        """SEED-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_MAC_GENERAL"):
            pytest.skip("CKM_SEED_MAC_GENERAL not supported")
        key = _seed_key(
            rs.raw,
            rs.sh,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"SEED MAC GENERAL test data"
        mac_len = 8  # request 8-byte MAC (half block)
        try:
            mac = _sign_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_MAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_SEED_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            assert len(mac) == mac_len
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SEED_MAC_GENERAL,
                data,
                mac,
                mech_param=mech_bytes(CKM_SEED_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_seed_mac_different_keys(self, p11_raw_session: Any) -> None:
        """Different SEED keys produce different MAC values."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported")
        if not rs.has_mechanism("SEED_MAC"):
            pytest.skip("CKM_SEED_MAC not supported")
        tmpl = {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False}
        key1 = _seed_key(rs.raw, rs.sh, tmpl)
        key2 = _seed_key(rs.raw, rs.sh, tmpl)
        data = b"MAC key independence test data"
        try:
            mac1 = _sign_or_xfail(rs.raw, rs.sh, key1, CKM_SEED_MAC, data)
            mac2 = sign_single(rs.raw, rs.sh, key2, CKM_SEED_MAC, data)
            assert mac1 != mac2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


# ---------------------------------------------------------------------------
# Key derivation by data encryption - availability checks only
# ---------------------------------------------------------------------------


class TestSEEDKeyDerivation:
    """Availability checks for SEED key derivation by data encryption.

    CKM_SEED_ECB_ENCRYPT_DATA and CKM_SEED_CBC_ENCRYPT_DATA are used
    via derive_key() with module-specific parameter structures. The tests here
    confirm the mechanisms are advertised by the module; full derivation tests
    live in the key derivation test suite.
    """

    def test_seed_ecb_encrypt_data_available(self, p11_raw_session: Any) -> None:
        """Check CKM_SEED_ECB_ENCRYPT_DATA is advertised when SEED is supported."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("SEED_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_SEED_ECB_ENCRYPT_DATA not supported")
        # Mechanism is present - no further operation needed for availability check
        assert True

    def test_seed_cbc_encrypt_data_available(self, p11_raw_session: Any) -> None:
        """Check CKM_SEED_CBC_ENCRYPT_DATA is advertised when SEED is supported."""
        rs = p11_raw_session
        if not rs.has_mechanism("SEED_KEY_GEN"):
            pytest.skip("CKM_SEED_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("SEED_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_SEED_CBC_ENCRYPT_DATA not supported")
        assert True
