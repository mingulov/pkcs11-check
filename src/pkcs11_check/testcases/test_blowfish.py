"""Tests for Blowfish PKCS#11 mechanisms.

Blowfish: variable key size (32-448 bits), 8-byte block.
Only CBC and CBC_PAD are defined in the OASIS PKCS#11 spec - there is no
CKM_BLOWFISH_ECB mechanism. IV for CBC modes is 8 bytes.

Most modules do NOT support Blowfish - all tests will skip cleanly on those
platforms.
"""

from __future__ import annotations

from collections.abc import Mapping
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
    CKM_BLOWFISH_CBC,
    CKM_BLOWFISH_CBC_PAD,
    CKM_BLOWFISH_KEY_GEN,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.full

# Blowfish block is 8 bytes - CBC data must be 8-byte aligned
_TWO_BLOCKS = b"12345678abcdefgh"  # exactly 16 bytes (2 x 8-byte blocks)


def _bf_key(raw: Any, sh: int, bits: int, attrs: Mapping[Any, Any]) -> int:
    """Generate a Blowfish session key of the given bit length."""
    from pkcs11_check.raw.pack import attr_ulong
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import pack_attrs

    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(attrs))
    tmpl = mk_template(*packed)
    mech = mech_simple(CKM_BLOWFISH_KEY_GEN)
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
            pytest.xfail(f"Mechanism advertised but rejected at use: {exc}")
        raise


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestBlowfishKeyGen:
    """CKM_BLOWFISH_KEY_GEN - key generation for variable-length Blowfish keys."""

    @pytest.mark.parametrize("key_bits", [128, 256])
    def test_blowfish_key_gen(self, p11_raw_session: Any, key_bits: int) -> None:
        """Generate a Blowfish session key of the specified bit length."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        key = _bf_key(rs.raw, rs.sh, key_bits, {CKA_TOKEN: False})
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


class TestBlowfishEncryption:
    """Blowfish encryption/decryption: CBC and CBC_PAD.

    Note: CKM_BLOWFISH_ECB is not defined in the OASIS PKCS#11 spec.
    Only CBC and CBC_PAD mechanisms exist for Blowfish.
    """

    def test_blowfish_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """Blowfish-CBC encrypt/decrypt roundtrip with 8-byte IV and block-aligned data."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not rs.has_mechanism("BLOWFISH_CBC"):
            pytest.skip("CKM_BLOWFISH_CBC not supported")
        key = _bf_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_BLOWFISH_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC, iv),
            )
            assert ct != _TWO_BLOCKS
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_BLOWFISH_CBC,
                ct,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC, iv),
            )
            assert pt == _TWO_BLOCKS
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_blowfish_cbc_different_ivs(self, p11_raw_session: Any) -> None:
        """Blowfish-CBC with different IVs produces different ciphertexts."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not rs.has_mechanism("BLOWFISH_CBC"):
            pytest.skip("CKM_BLOWFISH_CBC not supported")
        key = _bf_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv1 = generate_random(rs.raw, rs.sh, 8)
        iv2 = generate_random(rs.raw, rs.sh, 8)
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_BLOWFISH_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC, iv1),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_BLOWFISH_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC, iv2),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_blowfish_cbc_pad_roundtrip(self, p11_raw_session: Any) -> None:
        """Blowfish-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not rs.has_mechanism("BLOWFISH_CBC_PAD"):
            pytest.skip("CKM_BLOWFISH_CBC_PAD not supported")
        key = _bf_key(
            rs.raw,
            rs.sh,
            128,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        # Non-block-aligned data - PKCS#7 padding handles it
        plaintext = b"Blowfish CBC PAD test!"  # 22 bytes, not a multiple of 8
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_BLOWFISH_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC_PAD, iv),
            )
            assert ct != plaintext
            # Ciphertext is padded to 8-byte block boundary
            assert len(ct) % 8 == 0
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_BLOWFISH_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC_PAD, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_blowfish_cbc_pad_different_keys(self, p11_raw_session: Any) -> None:
        """Blowfish-CBC-PAD: same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLOWFISH_KEY_GEN"):
            pytest.skip("CKM_BLOWFISH_KEY_GEN not supported")
        if not rs.has_mechanism("BLOWFISH_CBC_PAD"):
            pytest.skip("CKM_BLOWFISH_CBC_PAD not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _bf_key(rs.raw, rs.sh, 128, tmpl)
        key2 = _bf_key(rs.raw, rs.sh, 128, tmpl)
        iv = generate_random(rs.raw, rs.sh, 8)
        plaintext = b"Blowfish CBC PAD key independence!!"  # 35 bytes
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key1,
                CKM_BLOWFISH_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC_PAD, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_BLOWFISH_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_BLOWFISH_CBC_PAD, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)
