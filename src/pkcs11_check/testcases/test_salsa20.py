"""Standalone stream cipher tests - Salsa20, ChaCha20, Poly1305.

Covers:
  - CKM_SALSA20_KEY_GEN + CKM_SALSA20: Salsa20 stream cipher encrypt/decrypt
  - CKM_POLY1305_KEY_GEN + CKM_POLY1305: standalone Poly1305 MAC sign/verify
  - CKM_CHACHA20_KEY_GEN + CKM_CHACHA20: ChaCha20 stream cipher encrypt/decrypt

Note: CKM_CHACHA20_POLY1305 (AEAD combined) is tested in wycheproof/test_wycheproof_chacha.py.

OASIS PKCS#11 v3.2 spec: stream ciphers.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_chacha20, mech_salsa20, mech_simple
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
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
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKM_CHACHA20,
    CKM_CHACHA20_KEY_GEN,
    CKM_POLY1305,
    CKM_POLY1305_KEY_GEN,
    CKM_SALSA20,
    CKM_SALSA20_KEY_GEN,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    assert_correct,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

# ChaCha20 nonce: 12 bytes (96 bits) is the standard IETF nonce size.
_CHACHA20_NONCE = b"\x00" * 12

# Salsa20 nonce: 8 bytes (64 bits).
_SALSA20_NONCE = b"\x00" * 8

# Phase 5 P1b: widen the produce-leg reject set to the shared cipher-op set so
# any advertised-but-not-operational clean code (not just CKR_GENERAL_ERROR)
# becomes xfail.
_SALSA20_ENCRYPT_REJECT_RVS = CIPHER_OP_RUNTIME_REJECT_RVS


def _gen_stream_key(
    raw: Any,
    sh: int,
    mechanism: Any,
    bits: int,
    attrs: dict[int, Any],
) -> int:
    """Generate a stream cipher key via C_GenerateKey."""
    from pkcs11_check.raw.pack import attr_ulong
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import pack_attrs

    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(attrs))
    tmpl = mk_template(*packed)
    mech_p = mech_simple(mechanism)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech_p.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def _salsa20_encrypt_or_xfail(
    raw: Any,
    sh: int,
    key: int,
    plaintext: bytes,
    *,
    mech_param: Any,
) -> bytes:
    try:
        return encrypt_single(raw, sh, key, CKM_SALSA20, plaintext, mech_param=mech_param)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _SALSA20_ENCRYPT_REJECT_RVS, "CKM_SALSA20 encrypt not operational")
        raise


class TestSalsa20:
    """Tests for CKM_SALSA20_KEY_GEN and CKM_SALSA20 stream cipher."""

    def test_salsa20_key_gen(self, p11_raw_session: Any) -> None:
        """Generate a Salsa20 256-bit session key."""
        rs = p11_raw_session
        if not rs.has_mechanism("SALSA20_KEY_GEN"):
            pytest.skip("CKM_SALSA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_SALSA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_salsa20_encrypt_decrypt(self, p11_raw_session: Any) -> None:
        """Salsa20 encrypt/decrypt roundtrip produces original plaintext."""
        rs = p11_raw_session
        if not rs.has_mechanism("SALSA20"):
            pytest.skip("CKM_SALSA20 not supported")
        if not rs.has_mechanism("SALSA20_KEY_GEN"):
            pytest.skip("CKM_SALSA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_SALSA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"Salsa20 test plaintext data!!!!!"
            param = mech_salsa20(CKM_SALSA20, _SALSA20_NONCE)
            ciphertext = _salsa20_encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                plaintext,
                mech_param=param,
            )
            if ciphertext == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_SALSA20:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_SALSA20",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ciphertext) == len(plaintext)  # stream cipher: no padding
            recovered = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SALSA20,
                ciphertext,
                mech_param=param,
            )
            assert_correct(
                actual=recovered,
                expected=plaintext,
                label="CKM_SALSA20:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_SALSA20",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_salsa20_different_nonces_differ(self, p11_raw_session: Any) -> None:
        """Salsa20 with different nonces produces different ciphertext."""
        rs = p11_raw_session
        if not rs.has_mechanism("SALSA20"):
            pytest.skip("CKM_SALSA20 not supported")
        if not rs.has_mechanism("SALSA20_KEY_GEN"):
            pytest.skip("CKM_SALSA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_SALSA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"nonce differentiation test data!"
            nonce1 = b"\x00" * 8
            nonce2 = b"\x01" * 8
            ct1 = _salsa20_encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                plaintext,
                mech_param=mech_salsa20(CKM_SALSA20, nonce1),
            )
            ct2 = _salsa20_encrypt_or_xfail(
                rs.raw,
                rs.sh,
                key,
                plaintext,
                mech_param=mech_salsa20(CKM_SALSA20, nonce2),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_SALSA20:encrypt nonce independence",
                    operation="C_Encrypt",
                    mechanism="CKM_SALSA20",
                    summary="different nonces (same key) produced identical "
                    "ciphertext -- nonce ignored",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestPoly1305:
    """Tests for CKM_POLY1305_KEY_GEN and CKM_POLY1305 standalone MAC."""

    def test_poly1305_key_gen(self, p11_raw_session: Any) -> None:
        """Generate a Poly1305 256-bit session key."""
        rs = p11_raw_session
        if not rs.has_mechanism("POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_POLY1305_KEY_GEN,
            256,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_poly1305_sign_verify(self, p11_raw_session: Any) -> None:
        """Poly1305 sign and verify roundtrip succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("POLY1305"):
            pytest.skip("CKM_POLY1305 not supported")
        if not rs.has_mechanism("POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_POLY1305_KEY_GEN,
            256,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            data = b"Poly1305 MAC test message"
            tag = sign_single(rs.raw, rs.sh, key, CKM_POLY1305, data)
            assert len(tag) == 16  # Poly1305 always produces a 16-byte (128-bit) tag
            result = verify_single(rs.raw, rs.sh, key, CKM_POLY1305, data, tag)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_poly1305_tamper_detection(self, p11_raw_session: Any) -> None:
        """Poly1305 verification fails when data is tampered."""
        rs = p11_raw_session
        if not rs.has_mechanism("POLY1305"):
            pytest.skip("CKM_POLY1305 not supported")
        if not rs.has_mechanism("POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_POLY1305_KEY_GEN,
            256,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            data = b"original message"
            tampered = b"tampered message"
            tag = sign_single(rs.raw, rs.sh, key, CKM_POLY1305, data)
            result = verify_single(rs.raw, rs.sh, key, CKM_POLY1305, tampered, tag)
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_poly1305_different_keys_differ(self, p11_raw_session: Any) -> None:
        """Poly1305 MACs from different keys differ for the same message."""
        rs = p11_raw_session
        if not rs.has_mechanism("POLY1305"):
            pytest.skip("CKM_POLY1305 not supported")
        if not rs.has_mechanism("POLY1305_KEY_GEN"):
            pytest.skip("CKM_POLY1305_KEY_GEN not supported")
        key1 = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_POLY1305_KEY_GEN,
            256,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        key2 = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_POLY1305_KEY_GEN,
            256,
            {CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            data = b"same message for both keys"
            tag1 = sign_single(rs.raw, rs.sh, key1, CKM_POLY1305, data)
            tag2 = sign_single(rs.raw, rs.sh, key2, CKM_POLY1305, data)
            if tag1 == tag2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_POLY1305:sign key independence",
                    operation="C_Sign",
                    mechanism="CKM_POLY1305",
                    summary="different keys produced identical Poly1305 tag -- key not used",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


class TestChaCha20Standalone:
    """Tests for CKM_CHACHA20_KEY_GEN and CKM_CHACHA20 standalone stream cipher."""

    def test_chacha20_key_gen(self, p11_raw_session: Any) -> None:
        """Generate a ChaCha20 256-bit session key."""
        rs = p11_raw_session
        if not rs.has_mechanism("CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_CHACHA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_chacha20_encrypt_decrypt(self, p11_raw_session: Any) -> None:
        """ChaCha20 encrypt/decrypt roundtrip produces original plaintext."""
        rs = p11_raw_session
        if not rs.has_mechanism("CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not rs.has_mechanism("CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_CHACHA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"ChaCha20 standalone test message"
            param = mech_chacha20(CKM_CHACHA20, _CHACHA20_NONCE)
            ciphertext = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CHACHA20,
                plaintext,
                mech_param=param,
            )
            if ciphertext == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CHACHA20:encrypt confidentiality",
                    operation="C_Encrypt",
                    mechanism="CKM_CHACHA20",
                    summary="ciphertext equals plaintext -- encryption was a no-op",
                )
            assert len(ciphertext) == len(plaintext)  # stream cipher: no padding
            recovered = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CHACHA20,
                ciphertext,
                mech_param=param,
            )
            assert_correct(
                actual=recovered,
                expected=plaintext,
                label="CKM_CHACHA20:decrypt roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_CHACHA20",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_chacha20_different_nonces_differ(self, p11_raw_session: Any) -> None:
        """ChaCha20 with different nonces produces different ciphertext."""
        rs = p11_raw_session
        if not rs.has_mechanism("CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not rs.has_mechanism("CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_CHACHA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"nonce differentiation test data!"
            nonce1 = b"\x00" * 12
            nonce2 = b"\x01" * 12
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CHACHA20,
                plaintext,
                mech_param=mech_chacha20(CKM_CHACHA20, nonce1),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CHACHA20,
                plaintext,
                mech_param=mech_chacha20(CKM_CHACHA20, nonce2),
            )
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CHACHA20:encrypt nonce independence",
                    operation="C_Encrypt",
                    mechanism="CKM_CHACHA20",
                    summary="different nonces (same key) produced identical "
                    "ciphertext -- nonce ignored",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_chacha20_different_block_counters_differ(
        self,
        p11_raw_session: Any,
    ) -> None:
        """ChaCha20 with different block counters produces different ciphertext."""
        rs = p11_raw_session
        if not rs.has_mechanism("CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not rs.has_mechanism("CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")
        key = _gen_stream_key(
            rs.raw,
            rs.sh,
            CKM_CHACHA20_KEY_GEN,
            256,
            {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"block counter differentiation!  "
            ct0 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CHACHA20,
                plaintext,
                mech_param=mech_chacha20(CKM_CHACHA20, _CHACHA20_NONCE, counter=0),
            )
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_CHACHA20,
                plaintext,
                mech_param=mech_chacha20(CKM_CHACHA20, _CHACHA20_NONCE, counter=1),
            )
            if ct0 == ct1:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_CHACHA20:encrypt block-counter independence",
                    operation="C_Encrypt",
                    mechanism="CKM_CHACHA20",
                    summary="different block counters (same key/nonce) produced "
                    "identical ciphertext -- counter ignored",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
