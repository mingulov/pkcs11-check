"""Tests for PKCS#11 v3.0 message-based encrypt/decrypt/sign/verify functions."""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    gen_rsa_keypair,
    to_ubyte_buf,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKM_AES_CBC,
    CKM_SHA256_RSA_PKCS,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
)
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail, xfail_if_known_ckr

# Phase 6 P3: the v3.0 message functions are already gated by the function-list
# capability check (_skip_unless_message_functions). Past that gate the op is
# *advertised*, so a clean reject at use is advertised-but-rejecting -> xfail
# (not skip). A non-CKR error propagates as a real failure.
_MESSAGE_OP_REJECT_RVS = (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
)

MESSAGE_ENCRYPT_FUNCS = [
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_MessageEncryptFinal",
]

MESSAGE_DECRYPT_FUNCS = [
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_MessageDecryptFinal",
]

MESSAGE_SIGN_FUNCS = [
    "C_MessageSignInit",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_MessageSignFinal",
]

MESSAGE_VERIFY_FUNCS = [
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageVerifyFinal",
]

ALL_MESSAGE_FUNCS = (
    MESSAGE_ENCRYPT_FUNCS + MESSAGE_DECRYPT_FUNCS + MESSAGE_SIGN_FUNCS + MESSAGE_VERIFY_FUNCS
)

pytestmark = [pytest.mark.requires_v30]

_MESSAGE_UNSUPPORTED_RVS = (CKR_FUNCTION_NOT_SUPPORTED,)

_MESSAGE_ADVERTISED_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _skip_unless_message_functions(rs: Any, funcs: list[str]) -> None:
    for name in funcs:
        if not hasattr(rs.raw, name):
            pytest.skip(f"{name} not available")


def _handle_message_rv(rv: int, context: str) -> None:
    if rv in _MESSAGE_UNSUPPORTED_RVS:
        pytest.skip(f"{context} not supported: {ckr_name(rv)}")
    if rv in _MESSAGE_ADVERTISED_REJECT_RVS:
        pytest.xfail(f"{context} rejected advertised message operation: {ckr_name(rv)}")
    pytest.fail(f"{context} returned unexpected CKR: {ckr_name(rv)}")


def _message_sign(
    rs: Any,
    key: int,
    mechanism: int,
    data: bytes,
) -> bytes:
    mech = rs.raw._funcs["_pack_mech_simple"] if hasattr(rs.raw, "_pack_mech_simple") else None
    if mech is None:
        from pkcs11_check.raw.pack import mech_simple

        packed = mech_simple(mechanism)
    else:
        packed = mech(mechanism)

    rv = rs.raw.C_MessageSignInit(rs.sh, packed.byref(), key)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageSignInit")

    in_buf = to_ubyte_buf(data)
    sig_len = CK_ULONG(0)
    rv = rs.raw.C_SignMessage(rs.sh, None, 0, in_buf, len(data), None, byref(sig_len))
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessage (size)")
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = rs.raw.C_SignMessage(rs.sh, None, 0, in_buf, len(data), sig_buf, byref(sig_len))
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessage")
    return bytes(sig_buf[: sig_len.value])


def _message_verify(
    rs: Any,
    key: int,
    mechanism: int,
    data: bytes,
    signature: bytes,
    *,
    expect_valid: bool = True,
) -> bool:
    from pkcs11_check.raw.pack import mech_simple

    packed = mech_simple(mechanism)
    rv = rs.raw.C_MessageVerifyInit(rs.sh, packed.byref(), key)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageVerifyInit")

    in_buf = to_ubyte_buf(data)
    sig_buf = to_ubyte_buf(signature)
    rv = rs.raw.C_VerifyMessage(rs.sh, None, 0, in_buf, len(data), sig_buf, len(signature))
    if rv == CKR_OK:
        return True
    if not expect_valid:
        if rv in NON_CLEAN_SIGNATURE_REJECT_RVS:
            pytest.xfail(
                f"C_VerifyMessage rejected wrong signature with non-clean CKR: {ckr_name(rv)}"
            )
        return rv not in SIGNATURE_REJECT_RVS
    return False


def _message_sign_multipart(
    rs: Any,
    key: int,
    mechanism: int,
    parts: list[bytes],
) -> bytes:
    from pkcs11_check.raw.pack import mech_simple

    packed = mech_simple(mechanism)
    rv = rs.raw.C_MessageSignInit(rs.sh, packed.byref(), key)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageSignInit")

    for part in parts:
        in_buf = to_ubyte_buf(part)
        rv = rs.raw.C_SignMessageBegin(rs.sh, None, 0, in_buf, len(part))
        if rv != CKR_OK:
            _handle_message_rv(rv, "C_SignMessageBegin")

    sig_len = CK_ULONG(0)
    rv = rs.raw.C_SignMessageNext(rs.sh, None, 0, None, 0, None, byref(sig_len), 1)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessageNext (size)")
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = rs.raw.C_SignMessageNext(rs.sh, None, 0, None, 0, sig_buf, byref(sig_len), 1)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessageNext")

    rv = rs.raw.C_MessageSignFinal(rs.sh)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageSignFinal")

    return bytes(sig_buf[: sig_len.value])


class TestMessageEncryptDecrypt:
    """Test message-based encrypt/decrypt lifecycle."""

    def test_message_encrypt_single(self, p11_raw_session: Any) -> None:
        """C_MessageEncryptInit + C_EncryptMessage -- single-shot encrypt."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_ENCRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="message encrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.recipes import message_encrypt

            try:
                ct = message_encrypt(rs.raw, rs.sh, key, CKM_AES_CBC, plaintext)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise
            assert len(ct) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_decrypt_single(self, p11_raw_session: Any) -> None:
        """C_MessageDecryptInit + C_DecryptMessage -- single-shot decrypt."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_DECRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="message decrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.recipes import message_decrypt, message_encrypt

            try:
                ct = message_encrypt(rs.raw, rs.sh, key, CKM_AES_CBC, plaintext)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise
            try:
                pt = message_decrypt(rs.raw, rs.sh, key, CKM_AES_CBC, ct)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message decrypt rejected (CKM_AES_CBC)"
                )
                raise
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_encrypt_multipart(self, p11_raw_session: Any) -> None:
        """C_MessageEncryptInit + Begin + Next + Final multipart encrypt."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_ENCRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="message multipart encrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.pack import mech_simple

            packed = mech_simple(CKM_AES_CBC)
            rv = rs.raw.C_MessageEncryptInit(rs.sh, packed.byref(), key)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageEncryptInit")

            in_buf = to_ubyte_buf(plaintext)
            rv = rs.raw.C_EncryptMessageBegin(rs.sh, None, 0, in_buf, len(plaintext))
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_EncryptMessageBegin")

            out_len = CK_ULONG(0)
            rv = rs.raw.C_EncryptMessageNext(rs.sh, None, 0, None, 0, None, byref(out_len), 1)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_EncryptMessageNext (size)")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_EncryptMessageNext(rs.sh, None, 0, None, 0, out_buf, byref(out_len), 1)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_EncryptMessageNext")

            rv = rs.raw.C_MessageEncryptFinal(rs.sh)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageEncryptFinal")

            assert out_len.value > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_decrypt_multipart(self, p11_raw_session: Any) -> None:
        """C_MessageDecryptInit + Begin + Next + Final multipart decrypt."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_DECRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="message multipart decrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.recipes import message_encrypt

            try:
                ct = message_encrypt(rs.raw, rs.sh, key, CKM_AES_CBC, plaintext)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise

            from pkcs11_check.raw.pack import mech_simple

            packed = mech_simple(CKM_AES_CBC)
            rv = rs.raw.C_MessageDecryptInit(rs.sh, packed.byref(), key)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageDecryptInit")

            in_buf = to_ubyte_buf(ct)
            rv = rs.raw.C_DecryptMessageBegin(rs.sh, None, 0, in_buf, len(ct))
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_DecryptMessageBegin")

            out_len = CK_ULONG(0)
            rv = rs.raw.C_DecryptMessageNext(rs.sh, None, 0, None, 0, None, byref(out_len), 1)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_DecryptMessageNext (size)")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_DecryptMessageNext(rs.sh, None, 0, None, 0, out_buf, byref(out_len), 1)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_DecryptMessageNext")

            rv = rs.raw.C_MessageDecryptFinal(rs.sh)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageDecryptFinal")

            assert bytes(out_buf[: out_len.value]) == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_encrypt_decrypt_roundtrip(self, p11_raw_session: Any) -> None:
        """Encrypt with message API, decrypt with standard C_Decrypt API (cross-verification)."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_ENCRYPT_FUNCS + MESSAGE_DECRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256, purpose="message cross-verify setup")
        plaintext = b"cross-verify test data padding!!"
        try:
            from pkcs11_check.raw.recipes import message_encrypt

            try:
                ct = message_encrypt(rs.raw, rs.sh, key, CKM_AES_CBC, plaintext)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise
            assert ct != plaintext
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_CBC, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestMessageSignVerify:
    """Test message-based sign/verify lifecycle."""

    def test_message_sign_single(self, p11_raw_session: Any) -> None:
        """C_MessageSignInit + C_SignMessage -- single-shot sign."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"message sign test data"
        try:
            sig = _message_sign(rs, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) > 0
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_message_verify_single(self, p11_raw_session: Any) -> None:
        """C_MessageVerifyInit + C_VerifyMessage -- single-shot verify."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS + MESSAGE_VERIFY_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"message verify test data"
        try:
            sig = _message_sign(rs, priv, CKM_SHA256_RSA_PKCS, data)
            result = _message_verify(rs, pub, CKM_SHA256_RSA_PKCS, data, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_message_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """Sign with message API, verify with standard C_Verify API (cross-verification)."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"cross-verify sign data payload"
        try:
            sig = _message_sign(rs, priv, CKM_SHA256_RSA_PKCS, data)
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_message_sign_multipart(self, p11_raw_session: Any) -> None:
        """C_MessageSignInit + C_SignMessageBegin + C_SignMessageNext + C_MessageSignFinal."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            sig = _message_sign_multipart(
                rs, priv, CKM_SHA256_RSA_PKCS, [b"part one ", b"part two ", b"part three"]
            )
            assert len(sig) == 256
            assert verify_single(
                rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, b"part one part two part three", sig
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_message_verify_bad_signature(self, p11_raw_session: Any) -> None:
        """C_VerifyMessage with wrong signature should fail."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_VERIFY_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"correct data"
        bad_sig = b"\x00" * 256
        try:
            result = _message_verify(
                rs, pub, CKM_SHA256_RSA_PKCS, data, bad_sig, expect_valid=False
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestMessageAvailability:
    """Verify message-based functions are present in v3.0+ modules."""

    def test_message_functions_available(self, p11_raw_session: Any) -> None:
        """All 20 message functions should be present on v3.0+ modules."""
        rs = p11_raw_session
        available = rs.raw.available_function_names()
        missing = [name for name in ALL_MESSAGE_FUNCS if name not in available]
        if missing:
            pytest.skip(f"Message functions not available: {', '.join(missing)}")
        assert all(name in available for name in ALL_MESSAGE_FUNCS)
