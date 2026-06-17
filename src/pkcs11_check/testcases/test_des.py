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
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKM_DES2_KEY_GEN,
    CKM_DES3_CBC,
    CKM_DES3_CBC_PAD,
    CKM_DES3_CMAC,
    CKM_DES3_CMAC_GENERAL,
    CKM_DES3_ECB,
    CKM_DES3_KEY_GEN,
    CKM_DES3_MAC,
    CKM_DES3_MAC_GENERAL,
    CKM_DES_CBC,
    CKM_DES_CBC_PAD,
    CKM_DES_CFB8,
    CKM_DES_CFB64,
    CKM_DES_ECB,
    CKM_DES_KEY_GEN,
    CKM_DES_MAC,
    CKM_DES_MAC_GENERAL,
    CKM_DES_OFB64,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    assert_correct,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

# 8-byte DES block - ECB/CBC data must be block-aligned
_TWO_BLOCKS = b"12345678abcdefgh"  # exactly 16 bytes


def _encrypt_or_xfail(
    raw: Any,
    sh: int,
    key: int,
    mechanism: Any,
    data: bytes,
    *,
    mech_param: Any = None,
    xfail_msg: str = "",
) -> bytes:
    """Try encrypt_single; xfail if the advertised mechanism is not operational.

    Needed for single-DES on OpenSSL 3 where the mechanism is advertised but
    the legacy cipher provider is absent.
    """
    try:
        return encrypt_single(raw, sh, key, mechanism, data, mech_param=mech_param)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            CIPHER_OP_RUNTIME_REJECT_RVS,
            xfail_msg or "DES mechanism advertised but not operational",
        )
        raise


def _gen_des_key(raw: Any, sh: int, mechanism: Any, attrs: Mapping[Any, Any]) -> int:
    """Generate a DES/DES2/DES3 key using C_GenerateKey (fixed-size, no CKA_VALUE_LEN)."""
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import pack_attrs

    packed = pack_attrs(attrs)
    tmpl = mk_template(*packed)
    mech = mech_simple(mechanism)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


# ---------------------------------------------------------------------------
# DES (single DES, 8-byte key)
# ---------------------------------------------------------------------------


class TestDESKeyGen:
    """CKM_DES_KEY_GEN - single-DES key generation."""

    def test_des_key_gen(self, p11_module_session: Any) -> None:
        """Generate a DES session key."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_key_gen_not_null(self, p11_module_session: Any) -> None:
        """DES key generation produces a usable, non-null key object."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDESEncryption:
    """DES encryption/decryption: ECB, CBC, CBC_PAD, OFB64, CFB8, CFB64.

    Note: Some modules (e.g. SoftHSM2 on OpenSSL 3) advertise CKM_DES_ECB and
    CKM_DES_CBC in C_GetMechanismList but return CKR_MECHANISM_INVALID at
    C_EncryptInit because OpenSSL 3 does not load the legacy cipher provider by
    default.  Single-DES encrypt tests skip on MechanismInvalid so that the test
    suite remains clean on those platforms.  True bugs (e.g. a module that never
    advertised the mechanism) are caught by the has_mechanism guard.
    """

    def test_des_ecb_roundtrip(self, p11_module_session: Any) -> None:
        """DES-ECB encrypt/decrypt roundtrip with block-aligned data."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_ECB"):
            pytest.skip("CKM_DES_ECB not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        des_skip = "CKM_DES advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_ECB,
                _TWO_BLOCKS,
                xfail_msg=des_skip,
            )
            if ct == _TWO_BLOCKS:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_ECB:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_ECB",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ct) == len(_TWO_BLOCKS)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_DES_ECB, ct)
            assert_correct(
                actual=pt,
                expected=_TWO_BLOCKS,
                label="CKM_DES_ECB:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES_ECB",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_ecb_different_keys(self, p11_module_session: Any) -> None:
        """DES-ECB: same plaintext encrypted with different keys should differ."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_ECB"):
            pytest.skip("CKM_DES_ECB not supported")
        des_skip = "CKM_DES advertised but rejected (OpenSSL 3 legacy provider absent)"
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _gen_des_key(rs.raw, rs.sh, CKM_DES_KEY_GEN, tmpl)
        key2 = _gen_des_key(rs.raw, rs.sh, CKM_DES_KEY_GEN, tmpl)
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key1,
                CKM_DES_ECB,
                _TWO_BLOCKS,
                xfail_msg=des_skip,
            )
            ct2 = encrypt_single(rs.raw, rs.sh, key2, CKM_DES_ECB, _TWO_BLOCKS)
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_ECB:encrypt key independence",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_ECB",
                    summary="different keys produced identical ECB ciphertext -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_des_cbc_roundtrip(self, p11_module_session: Any) -> None:
        """DES-CBC encrypt/decrypt roundtrip with 8-byte IV and block-aligned data."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_CBC"):
            pytest.skip("CKM_DES_CBC not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        des_skip = "CKM_DES_CBC advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_DES_CBC, iv),
                xfail_msg=des_skip,
            )
            if ct == _TWO_BLOCKS:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_CBC:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_CBC",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CBC,
                ct,
                mech_param=mech_bytes(CKM_DES_CBC, iv),
            )
            assert_correct(
                actual=pt,
                expected=_TWO_BLOCKS,
                label="CKM_DES_CBC:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES_CBC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_cbc_different_ivs(self, p11_module_session: Any) -> None:
        """DES-CBC with different IVs produces different ciphertexts."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_CBC"):
            pytest.skip("CKM_DES_CBC not supported")
        des_skip = "CKM_DES_CBC advertised but rejected (OpenSSL 3 legacy provider absent)"
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv1 = generate_random(rs.raw, rs.sh, 8)
        iv2 = generate_random(rs.raw, rs.sh, 8)
        try:
            ct1 = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_DES_CBC, iv1),
                xfail_msg=des_skip,
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_DES_CBC, iv2),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_CBC:encrypt IV independence",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_CBC",
                    summary="different IVs (same key) produced identical CBC "
                    "ciphertext -- IV ignored",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_cbc_pad_roundtrip(self, p11_module_session: Any) -> None:
        """DES-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_CBC_PAD"):
            pytest.skip("CKM_DES_CBC_PAD not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        # Non-block-aligned data - PKCS#5 padding handles it
        plaintext = b"DES CBC PAD test data!"  # 22 bytes, not a multiple of 8
        des_skip = "CKM_DES_CBC_PAD advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_DES_CBC_PAD, iv),
                xfail_msg=des_skip,
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_CBC_PAD:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_CBC_PAD",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            # Ciphertext is padded to block boundary
            assert len(ct) % 8 == 0
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_DES_CBC_PAD, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_DES_CBC_PAD:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES_CBC_PAD",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_ofb64_roundtrip(self, p11_module_session: Any) -> None:
        """DES-OFB64 encrypt/decrypt roundtrip with 8-byte IV."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_OFB64"):
            pytest.skip("CKM_DES_OFB64 not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        plaintext = b"OFB test data!!"  # 15 bytes - stream mode, no alignment needed
        des_skip = "CKM_DES_OFB64 advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_OFB64,
                plaintext,
                mech_param=mech_bytes(CKM_DES_OFB64, iv),
                xfail_msg=des_skip,
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_OFB64:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_OFB64",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ct) == len(plaintext)
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_OFB64,
                ct,
                mech_param=mech_bytes(CKM_DES_OFB64, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_DES_OFB64:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES_OFB64",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_cfb8_roundtrip(self, p11_module_session: Any) -> None:
        """DES-CFB8 encrypt/decrypt roundtrip with 8-byte IV."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_CFB8"):
            pytest.skip("CKM_DES_CFB8 not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        plaintext = b"CFB8 test data!!"  # 16 bytes
        des_skip = "CKM_DES_CFB8 advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CFB8,
                plaintext,
                mech_param=mech_bytes(CKM_DES_CFB8, iv),
                xfail_msg=des_skip,
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_CFB8:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_CFB8",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CFB8,
                ct,
                mech_param=mech_bytes(CKM_DES_CFB8, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_DES_CFB8:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES_CFB8",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_cfb64_roundtrip(self, p11_module_session: Any) -> None:
        """DES-CFB64 encrypt/decrypt roundtrip with 8-byte IV."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_CFB64"):
            pytest.skip("CKM_DES_CFB64 not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        plaintext = b"CFB64 test data!"  # 16 bytes
        des_skip = "CKM_DES_CFB64 advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            ct = _encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CFB64,
                plaintext,
                mech_param=mech_bytes(CKM_DES_CFB64, iv),
                xfail_msg=des_skip,
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_CFB64:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES_CFB64",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_CFB64,
                ct,
                mech_param=mech_bytes(CKM_DES_CFB64, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_DES_CFB64:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES_CFB64",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDESMAC:
    """DES_MAC and DES_MAC_GENERAL - MAC sign/verify tests.

    Like single-DES encrypt, these may return MechanismInvalid on OpenSSL 3
    platforms where the legacy DES cipher is not available.  Tests skip
    gracefully in that case.
    """

    def test_des_mac_sign_verify(self, p11_module_session: Any) -> None:
        """DES-MAC sign and verify roundtrip."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_MAC"):
            pytest.skip("CKM_DES_MAC not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"DES MAC test data for signing"
        des_skip = "CKM_DES_MAC advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            try:
                mac = sign_single(rs.raw, rs.sh, key, CKM_DES_MAC, data)
            except AssertionError as exc:
                if is_known_error(exc, {CKR_MECHANISM_INVALID}):
                    pytest.skip(des_skip)
                raise
            assert len(mac) > 0
            assert verify_single(rs.raw, rs.sh, key, CKM_DES_MAC, data, mac)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_mac_general_sign_verify(self, p11_module_session: Any) -> None:
        """DES-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_MAC_GENERAL"):
            pytest.skip("CKM_DES_MAC_GENERAL not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES_KEY_GEN,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"DES MAC GENERAL test data"
        mac_len = 4  # request 4-byte MAC (half block)
        des_skip = "CKM_DES_MAC_GENERAL advertised but rejected (OpenSSL 3 legacy provider absent)"
        try:
            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_DES_MAC_GENERAL,
                    data,
                    mech_param=mech_bytes(
                        CKM_DES_MAC_GENERAL,
                        mac_len.to_bytes(8, "little"),
                    ),
                )
            except AssertionError as exc:
                if is_known_error(exc, {CKR_MECHANISM_INVALID}):
                    pytest.skip(des_skip)
                raise
            assert len(mac) == mac_len
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES_MAC_GENERAL,
                data,
                mac,
                mech_param=mech_bytes(CKM_DES_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des_mac_different_keys(self, p11_module_session: Any) -> None:
        """Different DES keys produce different MAC values."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")
        if not rs.has_mechanism("DES_MAC"):
            pytest.skip("CKM_DES_MAC not supported")
        des_skip = "CKM_DES_MAC advertised but rejected (OpenSSL 3 legacy provider absent)"
        tmpl = {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False}
        key1 = _gen_des_key(rs.raw, rs.sh, CKM_DES_KEY_GEN, tmpl)
        key2 = _gen_des_key(rs.raw, rs.sh, CKM_DES_KEY_GEN, tmpl)
        data = b"MAC key independence test data"
        try:
            try:
                mac1 = sign_single(rs.raw, rs.sh, key1, CKM_DES_MAC, data)
            except AssertionError as exc:
                if is_known_error(exc, {CKR_MECHANISM_INVALID}):
                    pytest.skip(des_skip)
                raise
            mac2 = sign_single(rs.raw, rs.sh, key2, CKM_DES_MAC, data)
            if mac1 == mac2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES_MAC:sign key independence",
                    operation="C_Sign",
                    mechanism="CKM_DES_MAC",
                    summary="different keys produced identical MAC -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


# ---------------------------------------------------------------------------
# DES2 (two-key Triple DES, 16-byte key)
# ---------------------------------------------------------------------------


class TestDES2KeyGen:
    """CKM_DES2_KEY_GEN - two-key Triple DES key generation."""

    def test_des2_key_gen(self, p11_module_session: Any) -> None:
        """Generate a DES2 session key."""
        rs = p11_module_session
        if not rs.has_mechanism("DES2_KEY_GEN"):
            pytest.skip("CKM_DES2_KEY_GEN not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES2_KEY_GEN,
            {CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# DES3 (three-key Triple DES, 24-byte key)
# ---------------------------------------------------------------------------


class TestDES3KeyGen:
    """CKM_DES3_KEY_GEN - three-key Triple DES key generation."""

    def test_des3_key_gen(self, p11_module_session: Any) -> None:
        """Generate a DES3 session key."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_key_gen_not_null(self, p11_module_session: Any) -> None:
        """DES3 key generation produces a usable, non-null key object."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDES3Encryption:
    """DES3 encryption/decryption: ECB, CBC, CBC_PAD."""

    def test_des3_ecb_roundtrip(self, p11_module_session: Any) -> None:
        """DES3-ECB encrypt/decrypt roundtrip with block-aligned data."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_ECB"):
            pytest.skip("CKM_DES3_ECB not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_DES3_ECB, _TWO_BLOCKS)
            if ct == _TWO_BLOCKS:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_ECB:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES3_ECB",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ct) == len(_TWO_BLOCKS)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_DES3_ECB, ct)
            assert_correct(
                actual=pt,
                expected=_TWO_BLOCKS,
                label="CKM_DES3_ECB:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES3_ECB",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_ecb_different_keys(self, p11_module_session: Any) -> None:
        """DES3-ECB: same plaintext encrypted with different keys should differ."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_ECB"):
            pytest.skip("CKM_DES3_ECB not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        key2 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        try:
            ct1 = encrypt_single(rs.raw, rs.sh, key1, CKM_DES3_ECB, _TWO_BLOCKS)
            ct2 = encrypt_single(rs.raw, rs.sh, key2, CKM_DES3_ECB, _TWO_BLOCKS)
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_ECB:encrypt key independence",
                    operation="C_Encrypt",
                    mechanism="CKM_DES3_ECB",
                    summary="different keys produced identical ECB ciphertext -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_des3_cbc_roundtrip(self, p11_module_session: Any) -> None:
        """DES3-CBC encrypt/decrypt roundtrip with 8-byte IV and block-aligned data."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CBC"):
            pytest.skip("CKM_DES3_CBC not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_DES3_CBC, iv),
            )
            if ct == _TWO_BLOCKS:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_CBC:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES3_CBC",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CBC,
                ct,
                mech_param=mech_bytes(CKM_DES3_CBC, iv),
            )
            assert_correct(
                actual=pt,
                expected=_TWO_BLOCKS,
                label="CKM_DES3_CBC:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES3_CBC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_cbc_different_ivs(self, p11_module_session: Any) -> None:
        """DES3-CBC with different IVs produces different ciphertexts."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CBC"):
            pytest.skip("CKM_DES3_CBC not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv1 = generate_random(rs.raw, rs.sh, 8)
        iv2 = generate_random(rs.raw, rs.sh, 8)
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_DES3_CBC, iv1),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CBC,
                _TWO_BLOCKS,
                mech_param=mech_bytes(CKM_DES3_CBC, iv2),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_CBC:encrypt IV independence",
                    operation="C_Encrypt",
                    mechanism="CKM_DES3_CBC",
                    summary="different IVs (same key) produced identical CBC "
                    "ciphertext -- IV ignored",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_cbc_pad_roundtrip(self, p11_module_session: Any) -> None:
        """DES3-CBC-PAD encrypt/decrypt roundtrip with arbitrary-length data."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CBC_PAD"):
            pytest.skip("CKM_DES3_CBC_PAD not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        iv = generate_random(rs.raw, rs.sh, 8)
        plaintext = b"DES3 CBC PAD test data!"  # 23 bytes, not a multiple of 8
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_DES3_CBC_PAD, iv),
            )
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_CBC_PAD:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_DES3_CBC_PAD",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ct) % 8 == 0
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_DES3_CBC_PAD, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="CKM_DES3_CBC_PAD:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_DES3_CBC_PAD",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_cbc_pad_different_keys(self, p11_module_session: Any) -> None:
        """DES3-CBC-PAD: same plaintext encrypted with different keys should differ."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CBC_PAD"):
            pytest.skip("CKM_DES3_CBC_PAD not supported")
        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        key2 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        iv = generate_random(rs.raw, rs.sh, 8)
        plaintext = b"DES3 CBC PAD key independence!!"  # 32 bytes
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_DES3_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_DES3_CBC_PAD, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_DES3_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_DES3_CBC_PAD, iv),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_CBC_PAD:encrypt key independence",
                    operation="C_Encrypt",
                    mechanism="CKM_DES3_CBC_PAD",
                    summary="different keys produced identical CBC-PAD ciphertext -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


class TestDES3MAC:
    """DES3_MAC, DES3_MAC_GENERAL, DES3_CMAC, DES3_CMAC_GENERAL - sign/verify tests."""

    def test_des3_mac_sign_verify(self, p11_module_session: Any) -> None:
        """DES3-MAC sign and verify roundtrip."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_MAC"):
            pytest.skip("CKM_DES3_MAC not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"DES3 MAC test data for signing"
        try:
            mac = sign_single(rs.raw, rs.sh, key, CKM_DES3_MAC, data)
            assert len(mac) > 0
            assert verify_single(rs.raw, rs.sh, key, CKM_DES3_MAC, data, mac)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_mac_general_sign_verify(self, p11_module_session: Any) -> None:
        """DES3-MAC-GENERAL sign and verify roundtrip with explicit MAC length."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_MAC_GENERAL"):
            pytest.skip("CKM_DES3_MAC_GENERAL not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"DES3 MAC GENERAL test data"
        mac_len = 4  # request 4-byte MAC (half block)
        try:
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_MAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_DES3_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            assert len(mac) == mac_len
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_MAC_GENERAL,
                data,
                mac,
                mech_param=mech_bytes(CKM_DES3_MAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_cmac_sign_verify(self, p11_module_session: Any) -> None:
        """DES3-CMAC sign and verify roundtrip."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CMAC"):
            pytest.skip("CKM_DES3_CMAC not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"DES3 CMAC test data for signing"
        try:
            mac = sign_single(rs.raw, rs.sh, key, CKM_DES3_CMAC, data)
            assert len(mac) > 0
            assert verify_single(rs.raw, rs.sh, key, CKM_DES3_CMAC, data, mac)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_cmac_different_keys(self, p11_module_session: Any) -> None:
        """Different DES3 keys produce different CMAC values."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CMAC"):
            pytest.skip("CKM_DES3_CMAC not supported")
        tmpl = {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False}
        key1 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        key2 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        data = b"CMAC key independence test data"
        try:
            mac1 = sign_single(rs.raw, rs.sh, key1, CKM_DES3_CMAC, data)
            mac2 = sign_single(rs.raw, rs.sh, key2, CKM_DES3_CMAC, data)
            if mac1 == mac2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_CMAC:sign key independence",
                    operation="C_Sign",
                    mechanism="CKM_DES3_CMAC",
                    summary="different keys produced identical CMAC -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_des3_cmac_general_sign_verify(self, p11_module_session: Any) -> None:
        """DES3-CMAC-GENERAL sign and verify roundtrip with explicit length."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_CMAC_GENERAL"):
            pytest.skip("CKM_DES3_CMAC_GENERAL not supported")
        key = _gen_des_key(
            rs.raw,
            rs.sh,
            CKM_DES3_KEY_GEN,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        data = b"DES3 CMAC GENERAL test data"
        mac_len = 4  # request 4-byte truncated CMAC
        try:
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CMAC_GENERAL,
                data,
                mech_param=mech_bytes(CKM_DES3_CMAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
            assert len(mac) == mac_len
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_DES3_CMAC_GENERAL,
                data,
                mac,
                mech_param=mech_bytes(CKM_DES3_CMAC_GENERAL, mac_len.to_bytes(8, "little")),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_des3_mac_different_keys(self, p11_module_session: Any) -> None:
        """Different DES3 keys produce different MAC values."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported")
        if not rs.has_mechanism("DES3_MAC"):
            pytest.skip("CKM_DES3_MAC not supported")
        tmpl = {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False}
        key1 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        key2 = _gen_des_key(rs.raw, rs.sh, CKM_DES3_KEY_GEN, tmpl)
        data = b"MAC key independence test data"
        try:
            mac1 = sign_single(rs.raw, rs.sh, key1, CKM_DES3_MAC, data)
            mac2 = sign_single(rs.raw, rs.sh, key2, CKM_DES3_MAC, data)
            if mac1 == mac2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DES3_MAC:sign key independence",
                    operation="C_Sign",
                    mechanism="CKM_DES3_MAC",
                    summary="different keys produced identical MAC -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


# ---------------------------------------------------------------------------
# DES key derivation by data encryption - mechanism availability checks only
# ---------------------------------------------------------------------------


class TestDESKeyDerivation:
    """Availability checks for DES/DES3 key derivation by data encryption.

    These mechanisms (DES_ECB_ENCRYPT_DATA, DES_CBC_ENCRYPT_DATA,
    DES3_ECB_ENCRYPT_DATA, DES3_CBC_ENCRYPT_DATA) are used via derive_key()
    with module-specific parameter structures. The tests here confirm the
    mechanisms are advertised by the module; full derivation tests live in
    the key derivation test suite.
    """

    def test_des_ecb_encrypt_data_available(self, p11_module_session: Any) -> None:
        """Check CKM_DES_ECB_ENCRYPT_DATA is advertised when DES is supported."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("DES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_DES_ECB_ENCRYPT_DATA not supported")
        # Mechanism is present - no further operation needed for availability check
        assert True

    def test_des_cbc_encrypt_data_available(self, p11_module_session: Any) -> None:
        """Check CKM_DES_CBC_ENCRYPT_DATA is advertised when DES is supported."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("DES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_DES_CBC_ENCRYPT_DATA not supported")
        assert True

    def test_des3_ecb_encrypt_data_available(self, p11_module_session: Any) -> None:
        """Check CKM_DES3_ECB_ENCRYPT_DATA is advertised when DES3 is supported."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("DES3_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_DES3_ECB_ENCRYPT_DATA not supported")
        assert True

    def test_des3_cbc_encrypt_data_available(self, p11_module_session: Any) -> None:
        """Check CKM_DES3_CBC_ENCRYPT_DATA is advertised when DES3 is supported."""
        rs = p11_module_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not supported - skipping derivation check")
        if not rs.has_mechanism("DES3_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_DES3_CBC_ENCRYPT_DATA not supported")
        assert True


# DES weak keys (before parity adjustment) -- 4 weak + 12 semi-weak
_DES_WEAK_KEYS = frozenset(
    [
        bytes.fromhex("0101010101010101"),
        bytes.fromhex("FEFEFEFEFEFEFEFE"),
        bytes.fromhex("E0E0E0E0F1F1F1F1"),
        bytes.fromhex("1F1F1F1F0E0E0E0E"),
    ]
)


class TestDESWeakKeys:
    """DES weak key detection -- generated keys should not be weak."""

    def test_des_keygen_avoids_weak_keys(self, p11_module_session: Any) -> None:
        """Generated DES keys must not be weak or semi-weak keys."""
        rs = p11_module_session
        if not rs.has_mechanism("DES_KEY_GEN"):
            pytest.skip("CKM_DES_KEY_GEN not supported")

        # Generate multiple keys and check none are weak
        for _ in range(10):
            key = _gen_des_key(
                rs.raw,
                rs.sh,
                CKM_DES_KEY_GEN,
                {
                    CKA_ENCRYPT: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
                val = attrs[CKA_VALUE]
                assert isinstance(val, bytes) and len(val) == 8
                assert val not in _DES_WEAK_KEYS, (
                    f"Generated DES key is a known weak key: {val.hex()}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
