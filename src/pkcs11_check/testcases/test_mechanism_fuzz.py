"""Mechanism parameter fuzzing tests.

Passes random/invalid bytes as mechanism_param to various operations.
The module must not crash (segfault) - it should return an error code.
These tests verify robustness against malformed parameters.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_KEY_TYPE,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
)

pytestmark = pytest.mark.security


class TestAESParameterFuzz:
    """Fuzz AES mechanism parameters."""

    @pytest.mark.parametrize(
        "bad_param",
        [
            b"",
            b"\x00",
            b"\xff" * 8,
            b"\xff" * 15,  # Wrong IV length (not 16)
            b"\xff" * 17,  # Wrong IV length
            b"\xff" * 256,  # Way too long
            os.urandom(7),  # Random short
        ],
        ids=["empty", "one-byte", "8-bytes", "15-bytes", "17-bytes", "256-bytes", "random-7"],
    )
    def test_aes_cbc_bad_iv(self, p11_raw_session: Any, bad_param: bytes) -> None:
        """AES-CBC with wrong-sized IV must fail, not crash."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256)
        data_buf = (ctypes.c_ubyte * 16)(*b"\x00" * 16)

        try:
            mech = mech_bytes(CKM_AES_CBC, bad_param)
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key_h))
            if rv == int(CKR_OK):
                out_len = CK_ULONG(0)
                rs.raw.C_Encrypt(rs.sh, data_buf, 16, None, byref(out_len))
            # Any non-crash result is acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_aes_ecb_with_param_should_fail_or_ignore(self, p11_raw_session: Any) -> None:
        """AES-ECB doesn't take a parameter - passing one should fail or be ignored."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256)
        data_buf = (ctypes.c_ubyte * 16)(*b"\x00" * 16)

        try:
            mech = mech_bytes(CKM_AES_ECB, b"\xff" * 16)
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key_h))
            if rv == int(CKR_OK):
                # Some modules silently ignore extra params
                out_len = CK_ULONG(256)
                out_buf = (ctypes.c_ubyte * 256)()
                rv2 = int(rs.raw.C_Encrypt(rs.sh, data_buf, 16, out_buf, byref(out_len)))
                if rv2 == int(CKR_OK):
                    assert out_len.value == 16
            # Any non-crash result is acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestDigestParameterFuzz:
    """Fuzz digest mechanism parameters."""

    @pytest.mark.parametrize(
        "bad_param",
        [b"", b"\x00" * 32, b"\xff" * 256, os.urandom(64)],
        ids=["empty", "32-zeros", "256-ff", "random-64"],
    )
    def test_sha256_with_param(self, p11_raw_session: Any, bad_param: bytes) -> None:
        """SHA-256 doesn't take parameters - extra params should fail or be ignored."""
        rs = p11_raw_session
        data_buf = (ctypes.c_ubyte * 9)(*b"test data")
        mech = mech_bytes(CKM_SHA256, bad_param)
        rv = int(rs.raw.C_DigestInit(rs.sh, mech.byref()))
        if rv == int(CKR_OK):
            out_len = CK_ULONG(64)
            out_buf = (ctypes.c_ubyte * 64)()
            rv2 = int(rs.raw.C_Digest(rs.sh, data_buf, 9, out_buf, byref(out_len)))
            if rv2 == int(CKR_OK):
                assert out_len.value == 32  # If it works, still correct output
        # Any non-crash result is acceptable


class TestSignParameterFuzz:
    """Fuzz signature mechanism parameters."""

    def test_rsa_pkcs_sign_with_random_param(self, p11_raw_session: Any) -> None:
        """RSA-PKCS sign with random mechanism_param should fail or be ignored."""
        rs = p11_raw_session
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data_buf = (ctypes.c_ubyte * 14)(*b"fuzz test data")

        try:
            mech = mech_bytes(CKM_SHA256_RSA_PKCS, os.urandom(32))
            rv = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv_h))
            if rv == int(CKR_OK):
                out_len = CK_ULONG(512)
                out_buf = (ctypes.c_ubyte * 512)()
                rv2 = int(rs.raw.C_Sign(rs.sh, data_buf, 14, out_buf, byref(out_len)))
                if rv2 == int(CKR_OK):
                    assert out_len.value == 256
            # Any non-crash result is acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestKeyGenParameterFuzz:
    """Fuzz key generation parameters."""

    @pytest.mark.parametrize(
        "bad_param",
        [b"\x00", b"\xff" * 32, os.urandom(128)],
        ids=["one-zero", "32-ff", "random-128"],
    )
    def test_aes_keygen_with_random_param(self, p11_raw_session: Any, bad_param: bytes) -> None:
        """AES key generation with random mechanism_param should fail or be ignored."""
        from pkcs11_check.raw.pack import attr_ulong, template
        from pkcs11_check.raw.types_std import (
            CK_OBJECT_HANDLE,
            CKA_VALUE_LEN,
            CKM_AES_KEY_GEN,
        )

        rs = p11_raw_session
        mech = mech_bytes(CKM_AES_KEY_GEN, bad_param)
        tmpl = template(attr_ulong(CKA_VALUE_LEN, 32))
        key_h = CK_OBJECT_HANDLE(0)
        rv = int(rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h)))
        if rv == int(CKR_OK):
            # If it works, key should still be valid
            attrs = read_attributes(rs.raw, rs.sh, int(key_h.value), [int(CKA_KEY_TYPE)])
            assert attrs[int(CKA_KEY_TYPE)] is not None
            destroy_quietly(rs.raw, rs.sh, int(key_h.value))
        # Any non-crash result is acceptable


class TestEncryptDataFuzz:
    """Fuzz data inputs to encryption."""

    def test_encrypt_empty_data(self, p11_raw_session: Any) -> None:
        """Encrypting empty data - module must handle gracefully."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key_h))
            if rv == int(CKR_OK):
                out_len = CK_ULONG(256)
                out_buf = (ctypes.c_ubyte * 256)()
                rv2 = int(rs.raw.C_Encrypt(rs.sh, None, 0, out_buf, byref(out_len)))
                # Any non-crash result is acceptable
                _ = rv2
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_encrypt_non_block_aligned(self, p11_raw_session: Any) -> None:
        """AES-ECB with non-block-aligned data must fail (no padding)."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key_h))
            if rv == int(CKR_OK):
                data_buf = (ctypes.c_ubyte * 15)(*b"\x00" * 15)  # 15, not 16
                out_len = CK_ULONG(256)
                out_buf = (ctypes.c_ubyte * 256)()
                rv2 = int(rs.raw.C_Encrypt(rs.sh, data_buf, 15, out_buf, byref(out_len)))
                assert rv2 != int(CKR_OK), f"Non-aligned AES-ECB should fail, got {ckr_name(rv2)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)
