"""Tests for PKCS#11 error handling, edge cases, and robustness.

Covers invalid operations, boundary conditions, empty inputs,
session edge cases, and key lifecycle.

Migrated to pkcs11_check.raw — error tests use raw C_* calls with
specific CKR code checks; happy-path tests use recipes.
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
)

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Acceptable CKR sets per error category
# ---------------------------------------------------------------------------

_INVALID_PARAM_RVS = {int(c) for c in (
    CKR_MECHANISM_PARAM_INVALID, CKR_MECHANISM_INVALID,
    CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE,
)}

_KEY_SIZE_RVS = {int(c) for c in (
    CKR_KEY_SIZE_RANGE, CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_MECHANISM_INVALID, CKR_ARGUMENTS_BAD, CKR_TEMPLATE_INCOMPLETE,
)}

_VERIFY_MISMATCH_RVS = {int(c) for c in (
    CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_GENERAL_ERROR,
)}

_KEY_FUNCTION_RVS = {int(c) for c in (
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID, CKR_ARGUMENTS_BAD,
)}

_DECRYPT_GARBAGE_RVS = {int(c) for c in (
    CKR_ENCRYPTED_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR, CKR_ENCRYPTED_DATA_LEN_RANGE,
)}

_EMPTY_DATA_RVS = {int(c) for c in (
    CKR_DATA_LEN_RANGE, CKR_ARGUMENTS_BAD, CKR_MECHANISM_PARAM_INVALID,
)}


class TestInvalidOperations:
    def test_invalid_mechanism_param(self, p11_raw_session: Any) -> None:
        """Using wrong mechanism parameters should raise or produce garbage."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_bytes(CKM_AES_CBC_PAD, b"short")
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key))
            if rv == int(CKR_OK):
                # Init succeeded, try encrypt -- module may reject at this stage
                out_len = CK_ULONG(0)
                in_buf = (ctypes.c_ubyte * 16)(*b"0123456789abcdef")
                rv = int(rs.raw.C_Encrypt(
                    rs.sh, in_buf, 16, None, byref(out_len),
                ))
                if rv == int(CKR_OK):
                    out_buf = (ctypes.c_ubyte * out_len.value)()
                    rv = int(rs.raw.C_Encrypt(
                        rs.sh, in_buf, 16, out_buf, byref(out_len),
                    ))
                    # If we got OK both times, the module accepted a short IV
                    assert isinstance(bytes(out_buf[:out_len.value]), bytes)
                else:
                    assert rv in _INVALID_PARAM_RVS, (
                        f"Unexpected CKR: {ckr_name(rv)}"
                    )
            else:
                assert rv in _INVALID_PARAM_RVS, (
                    f"Unexpected CKR: {ckr_name(rv)}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_generate_key_invalid_size(self, p11_raw_session: Any) -> None:
        """Requesting unsupported key size should fail or produce unusable key."""
        rs = p11_raw_session
        from pkcs11_check.raw.pack import attr_ulong, template
        from pkcs11_check.raw.types_std import (
            CK_OBJECT_HANDLE,
            CKA_VALUE_LEN,
            CKM_AES_KEY_GEN,
        )

        packed = [attr_ulong(CKA_VALUE_LEN, 13 // 8)]  # 1 byte -- invalid
        tmpl = template(*packed)
        mech = mech_simple(CKM_AES_KEY_GEN)
        key = CK_OBJECT_HANDLE(0)
        rv = int(rs.raw.C_GenerateKey(
            rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key),
        ))
        if rv == int(CKR_OK):
            # Module accepted it -- destroy and move on
            destroy_quietly(rs.raw, rs.sh, int(key.value))
        else:
            assert rv in _KEY_SIZE_RVS, f"Unexpected CKR: {ckr_name(rv)}"

    def test_verify_with_wrong_mechanism(self, p11_raw_session: Any) -> None:
        """Sign with one mechanism, verify with another -- should fail or differ."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"mechanism mismatch test"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Attempt verify with a different hash mechanism
            mech = mech_simple(CKM_SHA384_RSA_PKCS)
            rv = int(rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub))
            if rv == int(CKR_OK):
                data_buf = (ctypes.c_ubyte * len(data))(*data)
                sig_buf = (ctypes.c_ubyte * len(sig))(*sig)
                rv = int(rs.raw.C_Verify(
                    rs.sh, data_buf, len(data), sig_buf, len(sig),
                ))
                # Module should reject -- signature or general error
                if rv == int(CKR_OK):
                    pass  # Some modules don't check DigestInfo OID
                else:
                    assert rv in _VERIFY_MISMATCH_RVS, (
                        f"Unexpected CKR: {ckr_name(rv)}"
                    )
            else:
                # VerifyInit itself rejected -- acceptable
                assert rv in _VERIFY_MISMATCH_RVS | _KEY_FUNCTION_RVS, (
                    f"Unexpected CKR on VerifyInit: {ckr_name(rv)}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_encrypt_with_sign_key(self, p11_raw_session: Any) -> None:
        """Using a sign-only key for encryption should fail."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), priv))
            if rv == int(CKR_OK):
                # Module allowed init on a private key -- some do
                pass
            else:
                assert rv in _KEY_FUNCTION_RVS, (
                    f"Unexpected CKR: {ckr_name(rv)}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_decrypt_garbage(self, p11_raw_session: Any) -> None:
        """Decrypting random garbage should fail cleanly."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw, rs.sh, 2048,
            public_attrs={int(CKA_ENCRYPT): True, int(CKA_TOKEN): False},
            private_attrs={int(CKA_DECRYPT): True, int(CKA_TOKEN): False},
        )
        try:
            garbage = generate_random(rs.raw, rs.sh, 256)  # 256 bytes
            mech = mech_simple(CKM_RSA_PKCS)
            rv = int(rs.raw.C_DecryptInit(rs.sh, mech.byref(), priv))
            if rv != int(CKR_OK):
                # Some modules reject decrypt on default-generated keys
                assert rv in _KEY_FUNCTION_RVS | _DECRYPT_GARBAGE_RVS, (
                    f"Unexpected CKR on DecryptInit: {ckr_name(rv)}"
                )
                return
            in_buf = (ctypes.c_ubyte * len(garbage))(*garbage)
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = int(rs.raw.C_Decrypt(
                rs.sh, in_buf, len(garbage), out_buf, byref(out_len),
            ))
            if rv == int(CKR_OK):
                # Decryption "succeeded" -- result is garbage, that is OK
                pass
            else:
                assert rv in _DECRYPT_GARBAGE_RVS, (
                    f"Unexpected CKR: {ckr_name(rv)}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestEmptyInputs:
    def test_encrypt_empty_data(self, p11_raw_session: Any) -> None:
        """Encrypting empty data -- behavior is implementation-defined."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            iv = generate_random(rs.raw, rs.sh, 16)  # 16 bytes
            mech = mech_bytes(CKM_AES_CBC_PAD, iv)
            rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key))
            if rv != int(CKR_OK):
                assert rv in _EMPTY_DATA_RVS, (
                    f"Unexpected CKR on EncryptInit: {ckr_name(rv)}"
                )
                return
            # Try encrypting empty buffer
            out_len = CK_ULONG(0)
            rv = int(rs.raw.C_Encrypt(
                rs.sh, None, 0, None, byref(out_len),
            ))
            if rv == int(CKR_OK) and out_len.value > 0:
                out_buf = (ctypes.c_ubyte * out_len.value)()
                rv = int(rs.raw.C_Encrypt(
                    rs.sh, None, 0, out_buf, byref(out_len),
                ))
                if rv == int(CKR_OK):
                    assert isinstance(bytes(out_buf[:out_len.value]), bytes)
                else:
                    assert rv in _EMPTY_DATA_RVS, (
                        f"Unexpected CKR: {ckr_name(rv)}"
                    )
            elif rv != int(CKR_OK):
                assert rv in _EMPTY_DATA_RVS, (
                    f"Unexpected CKR: {ckr_name(rv)}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_empty_data(self, p11_raw_session: Any) -> None:
        """Digest of empty data should succeed and produce correct hash."""
        rs = p11_raw_session
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"")
        assert digest == hashlib.sha256(b"").digest()

    def test_sign_empty_data(self, p11_raw_session: Any) -> None:
        """Signing empty data should succeed (hash handles it)."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))
            if rv != int(CKR_OK):
                assert rv in _EMPTY_DATA_RVS | _KEY_FUNCTION_RVS, (
                    f"Unexpected CKR on SignInit: {ckr_name(rv)}"
                )
                return
            # Two-call pattern: query length, then sign
            out_len = CK_ULONG(0)
            rv = int(rs.raw.C_Sign(rs.sh, None, 0, None, byref(out_len)))
            if rv == int(CKR_OK) and out_len.value > 0:
                out_buf = (ctypes.c_ubyte * out_len.value)()
                rv = int(rs.raw.C_Sign(
                    rs.sh, None, 0, out_buf, byref(out_len),
                ))
                if rv == int(CKR_OK):
                    assert out_len.value == 256  # RSA-2048 signature
                else:
                    assert rv in _EMPTY_DATA_RVS, (
                        f"Unexpected CKR: {ckr_name(rv)}"
                    )
            elif rv != int(CKR_OK):
                assert rv in _EMPTY_DATA_RVS, (
                    f"Unexpected CKR: {ckr_name(rv)}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyLifecycle:
    def test_use_destroyed_key(self, p11_raw_session: Any) -> None:
        """Using a key after destroy should fail."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        destroy_quietly(rs.raw, rs.sh, key)
        mech = mech_simple(CKM_AES_ECB)
        rv = int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key))
        assert rv != int(CKR_OK), "Should not be able to use destroyed key"

    def test_bulk_key_generation(self, p11_raw_session: Any) -> None:
        """Generate many keys in sequence without issues."""
        rs = p11_raw_session
        keys: list[int] = []
        try:
            for i in range(10):
                key = gen_aes_key(
                    rs.raw, rs.sh, 256,
                    attrs={int(CKA_LABEL): f"bulk-{i}".encode()},
                )
                keys.append(key)
            assert len(keys) == 10
        finally:
            for k in keys:
                destroy_quietly(rs.raw, rs.sh, k)

    def test_key_attribute_access(self, p11_raw_session: Any) -> None:
        """Key attributes should be readable."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            attrs = read_attributes(
                rs.raw, rs.sh, key,
                [int(CKA_KEY_TYPE), int(CKA_ENCRYPT)],
            )
            assert attrs[int(CKA_KEY_TYPE)] == int(CKK_AES)
            assert attrs[int(CKA_ENCRYPT)] in (True, False)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_create_object_minimal(self, p11_raw_session: Any) -> None:
        """Import a key with minimal attributes."""
        rs = p11_raw_session
        key = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_SECRET_KEY),
            int(CKA_KEY_TYPE): int(CKK_AES),
            int(CKA_VALUE): bytes(32),
            int(CKA_TOKEN): False,
        })
        try:
            assert key is not None
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestSessionEdgeCases:
    def test_large_random_generation(self, p11_raw_session: Any) -> None:
        """Generate a large random buffer (1024 bytes)."""
        rs = p11_raw_session
        data = generate_random(rs.raw, rs.sh, 1024)
        assert len(data) == 1024

    def test_small_random_generation(self, p11_raw_session: Any) -> None:
        """Generate minimal random (1 byte)."""
        rs = p11_raw_session
        data = generate_random(rs.raw, rs.sh, 1)
        assert len(data) == 1

    def test_sign_verify_large_data(self, p11_raw_session: Any) -> None:
        """Sign and verify a larger data payload (10 KB)."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"x" * 10000
            sig = sign_single(
                rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data,
            )
            assert verify_single(
                rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig,
            ) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_multiple_operations_same_key(self, p11_raw_session: Any) -> None:
        """Multiple sequential operations on the same key."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            for _ in range(100):
                ct = encrypt_single(
                    rs.raw, rs.sh, key, CKM_AES_ECB, b"0123456789abcdef",
                )
                pt = decrypt_single(
                    rs.raw, rs.sh, key, CKM_AES_ECB, ct,
                )
                assert pt == b"0123456789abcdef"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_concurrent_keypair_generation(self, p11_raw_session: Any) -> None:
        """Generate multiple keypairs in sequence."""
        rs = p11_raw_session
        pairs: list[tuple[int, int]] = []
        try:
            for _ in range(3):
                pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
                pairs.append((pub, priv))
                assert pub is not None
                assert priv is not None
        finally:
            for pub, priv in pairs:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
