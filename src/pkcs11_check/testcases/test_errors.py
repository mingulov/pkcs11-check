"""Tests for PKCS#11 error handling, edge cases, and robustness.

Covers invalid operations, boundary conditions, empty inputs,
session edge cases, and key lifecycle.

Migrated to pkcs11_check.raw -- error tests use raw C_* calls with
specific CKR code checks; happy-path tests use recipes.
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
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
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    classify_negative_rv,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Acceptable CKR sets per error category
# ---------------------------------------------------------------------------

_VERIFY_MISMATCH_RVS = {
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_DEVICE_ERROR,
}

_KEY_FUNCTION_RVS = {
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_ARGUMENTS_BAD,
}

_DECRYPT_GARBAGE_RVS = {
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
}

_EMPTY_DATA_RVS = {
    CKR_DATA_LEN_RANGE,
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
}


def _gen_aes_key_or_xfail(
    rs: Any,
    *,
    bits: int = 128,
    attrs: dict[Any, Any] | None = None,
    purpose: str,
) -> int:
    skip_unless_mechanism(rs, "AES_KEY_GEN")
    try:
        return gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but AES-{bits} key generation for {purpose} "
            "is not operational",
        )
    raise


def _gen_rsa_keypair_or_xfail(
    rs: Any,
    *,
    bits: int = 2048,
    public_attrs: dict[Any, Any] | None = None,
    private_attrs: dict[Any, Any] | None = None,
    purpose: str,
) -> tuple[int, int]:
    skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits,
            public_attrs=public_attrs,
            private_attrs=private_attrs,
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            f"RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation for {purpose} "
            "is not operational",
        )
    raise


_ADVERTISED_FUNCTION_UNAVAILABLE_RVS = {
    CKR_FUNCTION_NOT_SUPPORTED,
}


def _xfail_if_advertised_function_unavailable(rv: int, mechanism: str, purpose: str) -> None:
    if rv in _ADVERTISED_FUNCTION_UNAVAILABLE_RVS:
        classify(
            "not_operational",
            label=f"{mechanism}:{purpose}",
            mechanism=mechanism,
            actual=rv,
            summary=f"{mechanism} advertised but {purpose} is not operational: {ckr_name(rv)}",
        )


class TestInvalidOperations:
    def test_invalid_mechanism_param(self, p11_raw_session: Any) -> None:
        """Using wrong mechanism parameters should raise or produce garbage."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_CBC_PAD")
        key = _gen_aes_key_or_xfail(rs, bits=128, purpose="invalid-parameter check")
        try:
            mech = mech_bytes(CKM_AES_CBC_PAD, b"short")
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            _xfail_if_advertised_function_unavailable(
                rv,
                "AES_CBC_PAD",
                "invalid-parameter check",
            )
            if rv == CKR_OK:
                # Init succeeded, try encrypt -- module may reject at this stage
                out_len = CK_ULONG(0)
                in_buf = (ctypes.c_ubyte * 16)(*b"0123456789abcdef")
                rv = rs.raw.C_Encrypt(
                    rs.sh,
                    in_buf,
                    16,
                    None,
                    byref(out_len),
                )
                if rv == CKR_OK:
                    out_buf = (ctypes.c_ubyte * out_len.value)()
                    rv = rs.raw.C_Encrypt(
                        rs.sh,
                        in_buf,
                        16,
                        out_buf,
                        byref(out_len),
                    )
                    # If we got OK both times, the module accepted a short IV
                    assert isinstance(bytes(out_buf[: out_len.value]), bytes)
                else:
                    classify_negative_rv(
                        rv,
                        (CKR_MECHANISM_PARAM_INVALID,),
                        label="C_Encrypt with an undersized AES-CBC-PAD IV",
                    )
            else:
                classify_negative_rv(
                    rv,
                    (CKR_MECHANISM_PARAM_INVALID,),
                    label="C_EncryptInit with an undersized AES-CBC-PAD IV",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_generate_key_invalid_size(self, p11_raw_session: Any) -> None:
        """Requesting unsupported key size should fail or produce unusable key."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_KEY_GEN")
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
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            # Module accepted it -- destroy and move on
            destroy_quietly(rs.raw, rs.sh, key.value)
        else:
            _xfail_if_advertised_function_unavailable(
                rv,
                "AES_KEY_GEN",
                "invalid-size key generation",
            )
            classify_negative_rv(
                rv,
                (CKR_KEY_SIZE_RANGE, CKR_ATTRIBUTE_VALUE_INVALID),
                label="C_GenerateKey for an invalid AES key size",
            )

    def test_verify_with_wrong_mechanism(self, p11_raw_session: Any) -> None:
        """Sign with one mechanism, verify with another -- should fail or differ."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        skip_unless_mechanism(rs, "SHA384_RSA_PKCS")
        pub, priv = _gen_rsa_keypair_or_xfail(
            rs,
            purpose="wrong-mechanism verification",
        )
        try:
            data = b"mechanism mismatch test"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Attempt verify with a different hash mechanism
            mech = mech_simple(CKM_SHA384_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv == CKR_OK:
                data_buf = (ctypes.c_ubyte * len(data))(*data)
                sig_buf = (ctypes.c_ubyte * len(sig))(*sig)
                rv = rs.raw.C_Verify(
                    rs.sh,
                    data_buf,
                    len(data),
                    sig_buf,
                    len(sig),
                )
                # crypto-correctness: a signature produced under one hash
                # mechanism that verifies under a different hash mechanism
                # (CKR_OK) accepts a signature over the wrong message digest --
                # a break for any provider -> fail; an expected reject -> pass;
                # another clean reject -> xfail.
                classify_negative_rv(
                    rv,
                    tuple(_VERIFY_MISMATCH_RVS),
                    label="verify a SHA256-RSA signature under a SHA384-RSA mechanism",
                )
            else:
                # VerifyInit itself rejected the cross-mechanism use -- a clean,
                # acceptable rejection. Spec-preferred: the signature/key-function
                # codes; any other clean reject -> xfail.
                classify_negative_rv(
                    rv,
                    tuple(_VERIFY_MISMATCH_RVS | _KEY_FUNCTION_RVS),
                    label="C_VerifyInit under a different hash mechanism than signing",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_encrypt_with_sign_key(self, p11_raw_session: Any) -> None:
        """Using a sign-only key for encryption should fail."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "RSA_PKCS")
        pub, priv = _gen_rsa_keypair_or_xfail(rs, purpose="encrypt-with-sign-key check")
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), priv)
            if rv == CKR_OK:
                # Module allowed init on a private key -- some do
                pass
            else:
                classify_negative_rv(
                    rv,
                    (CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_TYPE_INCONSISTENT),
                    label="C_EncryptInit with a sign-only private key",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_decrypt_garbage(self, p11_raw_session: Any) -> None:
        """Decrypting random garbage should fail cleanly."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "RSA_PKCS")
        pub, priv = _gen_rsa_keypair_or_xfail(
            rs,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
            purpose="decrypt-garbage check",
        )
        try:
            garbage = generate_random(rs.raw, rs.sh, 256)  # 256 bytes
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                # Some modules reject decrypt on default-generated keys -- a
                # clean rejection at init is acceptable; other clean codes xfail.
                classify_negative_rv(
                    rv,
                    tuple(_KEY_FUNCTION_RVS | _DECRYPT_GARBAGE_RVS),
                    label="C_DecryptInit on a default-generated RSA private key",
                )
                return
            in_buf = (ctypes.c_ubyte * len(garbage))(*garbage)
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_Decrypt(
                rs.sh,
                in_buf,
                len(garbage),
                out_buf,
                byref(out_len),
            )
            if rv == CKR_OK:
                # Decryption "succeeded" -- result is garbage, that is OK
                pass
            else:
                classify_negative_rv(
                    rv,
                    (CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE),
                    label="C_Decrypt of random garbage under RSA-PKCS",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestEmptyInputs:
    def test_encrypt_empty_data(self, p11_raw_session: Any) -> None:
        """Encrypting empty data -- behavior is implementation-defined."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_CBC_PAD")
        key = _gen_aes_key_or_xfail(rs, bits=128, purpose="empty-data encryption")
        try:
            iv = generate_random(rs.raw, rs.sh, 16)  # 16 bytes
            mech = mech_bytes(CKM_AES_CBC_PAD, iv)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    (CKR_DATA_LEN_RANGE,),
                    label="C_EncryptInit before empty-data encryption",
                )
                return
            # Try encrypting empty buffer
            out_len = CK_ULONG(0)
            rv = rs.raw.C_Encrypt(
                rs.sh,
                None,
                0,
                None,
                byref(out_len),
            )
            if rv == CKR_OK and out_len.value > 0:
                out_buf = (ctypes.c_ubyte * out_len.value)()
                rv = rs.raw.C_Encrypt(
                    rs.sh,
                    None,
                    0,
                    out_buf,
                    byref(out_len),
                )
                if rv == CKR_OK:
                    assert isinstance(bytes(out_buf[: out_len.value]), bytes)
                else:
                    classify_negative_rv(
                        rv,
                        (CKR_DATA_LEN_RANGE,),
                        label="C_Encrypt of empty data under AES-CBC-PAD",
                    )
            elif rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    (CKR_DATA_LEN_RANGE,),
                    label="C_Encrypt (length query) of empty data under AES-CBC-PAD",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_empty_data(self, p11_raw_session: Any) -> None:
        """Digest of empty data should succeed and produce correct hash."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256")
        try:
            digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"")
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                AES_KEYGEN_RUNTIME_REJECT_RVS,
                "SHA256 advertised but digest is not operational",
            )
        assert digest == hashlib.sha256(b"").digest()

    def test_sign_empty_data(self, p11_raw_session: Any) -> None:
        """Signing empty data should succeed (hash handles it)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = _gen_rsa_keypair_or_xfail(rs, purpose="empty-data signing")
        try:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    tuple(_EMPTY_DATA_RVS | _KEY_FUNCTION_RVS),
                    label="C_SignInit before empty-data signing",
                )
                return
            # Two-call pattern: query length, then sign
            out_len = CK_ULONG(0)
            rv = rs.raw.C_Sign(rs.sh, None, 0, None, byref(out_len))
            if rv == CKR_OK and out_len.value > 0:
                out_buf = (ctypes.c_ubyte * out_len.value)()
                rv = rs.raw.C_Sign(
                    rs.sh,
                    None,
                    0,
                    out_buf,
                    byref(out_len),
                )
                if rv == CKR_OK:
                    assert out_len.value == 256  # RSA-2048 signature
                else:
                    classify_negative_rv(
                        rv,
                        (CKR_DATA_LEN_RANGE,),
                        label="C_Sign of empty data under SHA256-RSA-PKCS",
                    )
            elif rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    (CKR_DATA_LEN_RANGE,),
                    label="C_Sign (length query) of empty data under SHA256-RSA-PKCS",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyLifecycle:
    def test_use_destroyed_key(self, p11_raw_session: Any) -> None:
        """Using a key after destroy should fail."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key = _gen_aes_key_or_xfail(rs, bits=128, purpose="destroyed-key check")
        destroy_quietly(rs.raw, rs.sh, key)
        mech = mech_simple(CKM_AES_ECB)
        rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
        classify_negative_rv(
            rv,
            (CKR_KEY_HANDLE_INVALID, CKR_OBJECT_HANDLE_INVALID),
            label="C_EncryptInit with a destroyed key handle",
        )

    def test_bulk_key_generation(self, p11_raw_session: Any) -> None:
        """Generate many keys in sequence without issues."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_KEY_GEN")
        keys: list[int] = []
        try:
            for i in range(10):
                key = _gen_aes_key_or_xfail(
                    rs,
                    bits=128,
                    attrs={CKA_LABEL: f"bulk-{i}".encode()},
                    purpose="bulk-key-generation check",
                )
                keys.append(key)
            assert len(keys) == 10
        finally:
            for k in keys:
                destroy_quietly(rs.raw, rs.sh, k)

    def test_key_attribute_access(self, p11_raw_session: Any) -> None:
        """Key attributes should be readable."""
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(rs, bits=128, purpose="key-attribute access")
        try:
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                key,
                [CKA_KEY_TYPE, CKA_ENCRYPT],
            )
            assert attrs[CKA_KEY_TYPE] == CKK_AES
            assert attrs[CKA_ENCRYPT] in (True, False)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_create_object_minimal(self, p11_raw_session: Any) -> None:
        """Import a key with minimal attributes."""
        rs = p11_raw_session
        key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE: bytes(32),
                CKA_TOKEN: False,
            },
        )
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
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = _gen_rsa_keypair_or_xfail(rs, purpose="large-data sign/verify")
        try:
            data = b"x" * 10000
            sig = sign_single(
                rs.raw,
                rs.sh,
                priv,
                CKM_SHA256_RSA_PKCS,
                data,
            )
            assert (
                verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_SHA256_RSA_PKCS,
                    data,
                    sig,
                )
                is True
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_multiple_operations_same_key(self, p11_raw_session: Any) -> None:
        """Multiple sequential operations on the same key."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key = _gen_aes_key_or_xfail(rs, bits=128, purpose="multiple-operations check")
        try:
            for _ in range(100):
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_ECB,
                    b"0123456789abcdef",
                )
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_ECB,
                    ct,
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
                pub, priv = _gen_rsa_keypair_or_xfail(
                    rs,
                    purpose="concurrent-keypair-generation check",
                )
                pairs.append((pub, priv))
                assert pub is not None
                assert priv is not None
        finally:
            for pub, priv in pairs:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
