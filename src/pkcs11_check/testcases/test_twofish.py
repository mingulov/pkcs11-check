"""Tests for Twofish PKCS#11 mechanisms.

Twofish: 128/192/256-bit keys, 16-byte block.
Only CBC and CBC_PAD are defined in the OASIS PKCS#11 spec - there is no
CKM_TWOFISH_ECB mechanism. IV for CBC modes is 8 bytes.

Most modules do NOT support Twofish - all tests will skip cleanly on those
platforms.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    generate_random,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_TWOFISH_CBC,
    CKM_TWOFISH_CBC_PAD,
    CKM_TWOFISH_KEY_GEN,
    CKR_OK,
)

pytestmark = pytest.mark.full

# Twofish block is 8 bytes - CBC data must be 16-byte aligned
_TWO_BLOCKS = b"sixteen bytes!!\x01" * 2  # exactly 32 bytes


def _tf_key(raw: Any, sh: int, bits: int, attrs: dict[int, Any]) -> int:
    """Generate a Twofish session key of the given bit length."""
    from pkcs11_check.raw.pack import attr_ulong
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import _pack_attrs

    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(_pack_attrs(attrs))
    tmpl = mk_template(*packed)
    mech = mech_simple(CKM_TWOFISH_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(int(rv), CKR_OK)
    return int(key.value)


def _encrypt_or_skip(
    raw: Any, sh: int, key: int, mechanism: Any, data: bytes,
    *, mech_param: Any = None,
) -> bytes:
    """Try encrypt_single; skip if module returns CKR_MECHANISM_INVALID."""
    try:
        return encrypt_single(raw, sh, key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        if "CKR_MECHANISM_INVALID" in str(exc):
            pytest.skip(f"Mechanism advertised but rejected at use: {exc}")
        raise


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestTwofishKeyGen:
    """CKM_TWOFISH_KEY_GEN - key generation for 128/192/256-bit Twofish keys."""

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_twofish_key_gen(self, p11_raw_session: Any, key_bits: int) -> None:
        """Generate a Twofish session key of the specified bit length."""
        rs = p11_raw_session
        if not rs.has_mechanism("TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        key = _tf_key(rs.raw, rs.sh, key_bits, {int(CKA_TOKEN): False})
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestTwofishEncryption:
    """Twofish encryption/decryption: CBC and CBC_PAD.

    Note: CKM_TWOFISH_ECB is not defined in the OASIS PKCS#11 spec.
    Only CBC and CBC_PAD mechanisms exist for Twofish.
    """

    def test_twofish_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """Twofish-CBC encrypt/decrypt roundtrip with 16-byte IV and block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not rs.has_mechanism("TWOFISH_CBC"):
            pytest.skip("CKM_TWOFISH_CBC not supported")
        key = _tf_key(
            rs.raw, rs.sh, 128,
            {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True, int(CKA_TOKEN): False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        try:
            ct = _encrypt_or_skip(
                rs.raw, rs.sh, key, CKM_TWOFISH_CBC, _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_TWOFISH_CBC, iv),
            )
            assert ct != _TWO_BLOCKS
            pt = decrypt_single(
                rs.raw, rs.sh, key, CKM_TWOFISH_CBC, ct,
                mech_param=mech_bytes(CKM_TWOFISH_CBC, iv),
            )
            assert pt == _TWO_BLOCKS
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_twofish_cbc_different_ivs(self, p11_raw_session: Any) -> None:
        """Twofish-CBC with different IVs produces different ciphertexts."""
        rs = p11_raw_session
        if not rs.has_mechanism("TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not rs.has_mechanism("TWOFISH_CBC"):
            pytest.skip("CKM_TWOFISH_CBC not supported")
        key = _tf_key(
            rs.raw, rs.sh, 128,
            {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True, int(CKA_TOKEN): False},
        )
        iv1 = generate_random(rs.raw, rs.sh, 16)
        iv2 = generate_random(rs.raw, rs.sh, 16)
        try:
            ct1 = _encrypt_or_skip(
                rs.raw, rs.sh, key, CKM_TWOFISH_CBC, _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_TWOFISH_CBC, iv1),
            )
            ct2 = encrypt_single(
                rs.raw, rs.sh, key, CKM_TWOFISH_CBC, _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_TWOFISH_CBC, iv2),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_twofish_cbc_pad_roundtrip(self, p11_raw_session: Any) -> None:
        """Twofish-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        rs = p11_raw_session
        if not rs.has_mechanism("TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not rs.has_mechanism("TWOFISH_CBC_PAD"):
            pytest.skip("CKM_TWOFISH_CBC_PAD not supported")
        key = _tf_key(
            rs.raw, rs.sh, 128,
            {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True, int(CKA_TOKEN): False},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        # Non-block-aligned data - PKCS#7 padding handles it
        plaintext = b"Twofish CBC PAD test!"  # 21 bytes, not a multiple of 16
        try:
            ct = _encrypt_or_skip(
                rs.raw, rs.sh, key, CKM_TWOFISH_CBC_PAD, plaintext,
                mech_param=mech_bytes(CKM_TWOFISH_CBC_PAD, iv),
            )
            assert ct != plaintext
            # Ciphertext is padded to 16-byte block boundary
            assert len(ct) % 16 == 0
            pt = decrypt_single(
                rs.raw, rs.sh, key, CKM_TWOFISH_CBC_PAD, ct,
                mech_param=mech_bytes(CKM_TWOFISH_CBC_PAD, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_twofish_cbc_pad_different_keys(self, p11_raw_session: Any) -> None:
        """Twofish-CBC-PAD: same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("TWOFISH_KEY_GEN"):
            pytest.skip("CKM_TWOFISH_KEY_GEN not supported")
        if not rs.has_mechanism("TWOFISH_CBC_PAD"):
            pytest.skip("CKM_TWOFISH_CBC_PAD not supported")
        tmpl = {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True, int(CKA_TOKEN): False}
        key1 = _tf_key(rs.raw, rs.sh, 128, tmpl)
        key2 = _tf_key(rs.raw, rs.sh, 128, tmpl)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"Twofish CBC PAD key independence!!"  # 34 bytes
        try:
            ct1 = _encrypt_or_skip(
                rs.raw, rs.sh, key1, CKM_TWOFISH_CBC_PAD, plaintext,
                mech_param=mech_bytes(CKM_TWOFISH_CBC_PAD, iv),
            )
            ct2 = encrypt_single(
                rs.raw, rs.sh, key2, CKM_TWOFISH_CBC_PAD, plaintext,
                mech_param=mech_bytes(CKM_TWOFISH_CBC_PAD, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)
