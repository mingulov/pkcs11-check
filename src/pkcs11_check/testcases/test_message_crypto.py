"""Tests for PKCS#11 v3.0 message-based encrypt/decrypt/sign/verify functions."""

from __future__ import annotations

import ctypes
import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    gen_rsa_keypair,
    sign_single,
    to_ubyte_buf,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKF_END_OF_MESSAGE,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
    CKF_MULTI_MESSAGE,
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
from pkcs11_check.testcases.conftest import (
    assert_correct,
    gen_aes_key_or_xfail,
    xfail_if_known_ckr,
)

# Phase 6 P3: the v3.0 message functions are already gated by the function-list
# capability check (_skip_unless_message_functions), which only checks hasattr() --
# it cannot see a stub that returns CKR_FUNCTION_NOT_SUPPORTED at call time,
# so callers must check that case separately (_skip_if_message_op_not_implemented)
# before deciding a clean reject is advertised-but-rejecting -> xfail (not skip).
# A non-CKR error propagates as a real failure.
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


_MESSAGE_FLAG_NAMES = {
    int(CKF_MESSAGE_ENCRYPT): "CKF_MESSAGE_ENCRYPT",
    int(CKF_MESSAGE_DECRYPT): "CKF_MESSAGE_DECRYPT",
    int(CKF_MESSAGE_SIGN): "CKF_MESSAGE_SIGN",
    int(CKF_MESSAGE_VERIFY): "CKF_MESSAGE_VERIFY",
    int(CKF_MULTI_MESSAGE): "CKF_MULTI_MESSAGE",
}


def _require_message_flags(
    rs: Any, mechanism: str, required_flags: tuple[int, ...], context: str
) -> None:
    """Skip before setup when an advertised mechanism lacks a required v3 flag."""
    for flag in required_flags:
        if not rs.has_mechanism_flag(mechanism, flag):
            name = _MESSAGE_FLAG_NAMES.get(flag, f"0x{flag:x}")
            pytest.skip(f"{mechanism} does not advertise {name} for {context}")


def _skip_if_message_op_not_implemented(exc: AssertionError, context: str) -> None:
    """Skip when ``message_encrypt`` fails with CKR_FUNCTION_NOT_SUPPORTED.

    C_MessageEncryptInit / C_EncryptMessage are optional v3.0 functions: a module may
    expose non-null function-table pointers (passing ``_skip_unless_message_functions``,
    which only checks ``hasattr``) yet stub the call with CKR_FUNCTION_NOT_SUPPORTED --
    capability absence, not a deviation. Matches ``_handle_message_rv``'s own
    ``_MESSAGE_UNSUPPORTED_RVS`` skip for the same CKR on the raw per-call sites; must be
    checked before ``xfail_if_known_ckr(exc, _MESSAGE_OP_REJECT_RVS, ...)``, whose RV set
    also contains CKR_FUNCTION_NOT_SUPPORTED for the genuine mechanism-level rejects.
    """
    from pkcs11_check.raw.rv import CkrAssertionError

    if isinstance(exc, CkrAssertionError) and exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
        pytest.skip(f"{context}: not supported (CKR_FUNCTION_NOT_SUPPORTED)")


def _handle_message_rv(rv: int, context: str, *, advertised: bool = False) -> None:
    """Classify a message operation CK_RV without losing provider evidence."""
    if advertised and rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        classify(
            "self_contradiction",
            kind="metadata",
            label=context,
            operation=context,
            expected=CKR_OK,
            actual=rv,
            summary=(
                f"{context} advertised message operation returned {ckr_name(rv)} "
                "(metadata self-contradiction)"
            ),
        )
    if rv in _MESSAGE_UNSUPPORTED_RVS and not advertised:
        pytest.skip(f"{context} not supported: {ckr_name(rv)}")
    if rv in _MESSAGE_ADVERTISED_REJECT_RVS or is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        xfail_as(
            "not_operational",
            label=context,
            actual=rv,
            summary=f"{context} rejected advertised message operation: {ckr_name(rv)}",
        )
    if advertised:
        classify(
            "self_contradiction",
            kind="metadata",
            label=context,
            operation=context,
            expected=CKR_OK,
            actual=rv,
            summary=(
                f"{context} advertised message operation returned undefined "
                f"{ckr_name(rv)} (metadata self-contradiction)"
            ),
        )
    xfail_as(
        "not_operational",
        label=context,
        actual=rv,
        summary=f"{context} returned unexpected CKR for advertised message op: {ckr_name(rv)}",
    )


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
        _handle_message_rv(rv, "C_MessageSignInit", advertised=True)

    in_buf = to_ubyte_buf(data)
    sig_len = CK_ULONG(0)
    rv = rs.raw.C_SignMessage(rs.sh, None, 0, in_buf, len(data), None, byref(sig_len))
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessage (size)", advertised=True)
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = rs.raw.C_SignMessage(rs.sh, None, 0, in_buf, len(data), sig_buf, byref(sig_len))
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessage", advertised=True)
    rv = rs.raw.C_MessageSignFinal(rs.sh)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageSignFinal", advertised=True)
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
        _handle_message_rv(rv, "C_MessageVerifyInit", advertised=True)

    in_buf = to_ubyte_buf(data)
    sig_buf = to_ubyte_buf(signature)
    rv = rs.raw.C_VerifyMessage(rs.sh, None, 0, in_buf, len(data), sig_buf, len(signature))
    final_rv = rs.raw.C_MessageVerifyFinal(rs.sh)
    if rv == CKR_OK:
        if final_rv != CKR_OK:
            _handle_message_rv(final_rv, "C_MessageVerifyFinal", advertised=True)
        return True
    if not expect_valid:
        return _message_verify_rejection(rv, operation="C_VerifyMessage")
    # Preserve the primary verify CK_RV when both the message operation and Final
    # reject.  The operation result is the evidence for this test; Final must not
    # overwrite it with a secondary lifecycle error.
    _handle_message_rv(rv, "C_VerifyMessage", advertised=True)
    return False


def _message_verify_rejection(rv: int, *, operation: str) -> bool:
    if rv in NON_CLEAN_SIGNATURE_REJECT_RVS:
        xfail_as(
            "nonspec_reject",
            label=f"{operation}:wrong-signature",
            operation=operation,
            actual=rv,
            summary=(f"{operation} rejected wrong signature with non-clean CKR: {ckr_name(rv)}"),
        )
    return rv not in SIGNATURE_REJECT_RVS


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
        _handle_message_rv(rv, "C_MessageSignInit", advertised=True)
    if not parts:
        raise ValueError("multipart message signing requires at least one part")

    rv = rs.raw.C_SignMessageBegin(rs.sh, None, 0)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessageBegin", advertised=True)

    for part in parts[:-1]:
        in_buf = to_ubyte_buf(part)
        rv = rs.raw.C_SignMessageNext(rs.sh, None, 0, in_buf, len(part), None, None)
        if rv != CKR_OK:
            _handle_message_rv(rv, "C_SignMessageNext", advertised=True)

    final_buf = to_ubyte_buf(parts[-1])
    sig_len = CK_ULONG(0)
    rv = rs.raw.C_SignMessageNext(rs.sh, None, 0, final_buf, len(parts[-1]), None, byref(sig_len))
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessageNext (size)", advertised=True)
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = rs.raw.C_SignMessageNext(
        rs.sh, None, 0, final_buf, len(parts[-1]), sig_buf, byref(sig_len)
    )
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_SignMessageNext", advertised=True)

    rv = rs.raw.C_MessageSignFinal(rs.sh)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageSignFinal", advertised=True)

    return bytes(sig_buf[: sig_len.value])


def _message_verify_multipart(
    rs: Any,
    key: int,
    mechanism: int,
    parts: list[bytes],
    signature: bytes,
    *,
    expect_valid: bool = True,
) -> bool:
    """Verify one multipart message, supplying a signature only on final Next."""
    from pkcs11_check.raw.pack import mech_simple

    if not parts:
        raise ValueError("multipart message verification requires at least one part")
    packed = mech_simple(mechanism)
    rv = rs.raw.C_MessageVerifyInit(rs.sh, packed.byref(), key)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_MessageVerifyInit", advertised=True)

    rv = rs.raw.C_VerifyMessageBegin(rs.sh, None, 0)
    if rv != CKR_OK:
        _handle_message_rv(rv, "C_VerifyMessageBegin", advertised=True)

    for part in parts[:-1]:
        in_buf = to_ubyte_buf(part)
        rv = rs.raw.C_VerifyMessageNext(rs.sh, None, 0, in_buf, len(part), None, 0)
        if rv != CKR_OK:
            _handle_message_rv(rv, "C_VerifyMessageNext", advertised=True)

    final_buf = to_ubyte_buf(parts[-1])
    sig_buf = to_ubyte_buf(signature)
    message_rv = rs.raw.C_VerifyMessageNext(
        rs.sh, None, 0, final_buf, len(parts[-1]), sig_buf, len(signature)
    )
    final_rv = rs.raw.C_MessageVerifyFinal(rs.sh)
    if message_rv == CKR_OK:
        if final_rv != CKR_OK:
            _handle_message_rv(final_rv, "C_MessageVerifyFinal", advertised=True)
        return True
    if not expect_valid:
        return _message_verify_rejection(message_rv, operation="C_VerifyMessageNext")
    # Preserve a primary signature/setup rejection if Final also returns an error.
    _handle_message_rv(message_rv, "C_VerifyMessageNext", advertised=True)
    return False


@pytest.mark.needs_function("C_MessageEncryptInit")
class TestMessageEncryptDecrypt:
    """Test message-based encrypt/decrypt lifecycle."""

    def test_message_encrypt_single(self, p11_raw_session: Any) -> None:
        """C_MessageEncryptInit + C_EncryptMessage -- single-shot encrypt."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_ENCRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        _require_message_flags(
            rs,
            "AES_CBC",
            (int(CKF_MESSAGE_ENCRYPT),),
            "single message encrypt",
        )
        key = gen_aes_key_or_xfail(rs, 256, purpose="message encrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.pack import mech_bytes
            from pkcs11_check.raw.recipes import message_encrypt

            iv = os.urandom(16)
            try:
                ct = message_encrypt(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC,
                    plaintext,
                    mech_param=mech_bytes(CKM_AES_CBC, iv),
                    msg_param=iv,
                )
            except AssertionError as exc:
                _skip_if_message_op_not_implemented(exc, "message encrypt")
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
        _require_message_flags(
            rs,
            "AES_CBC",
            (int(CKF_MESSAGE_ENCRYPT), int(CKF_MESSAGE_DECRYPT)),
            "single message decrypt",
        )
        key = gen_aes_key_or_xfail(rs, 256, purpose="message decrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.pack import mech_bytes
            from pkcs11_check.raw.recipes import message_decrypt, message_encrypt

            iv = os.urandom(16)
            cbc_param = mech_bytes(CKM_AES_CBC, iv)
            try:
                ct = message_encrypt(
                    rs.raw, rs.sh, key, CKM_AES_CBC, plaintext, mech_param=cbc_param, msg_param=iv
                )
            except AssertionError as exc:
                _skip_if_message_op_not_implemented(exc, "message encrypt")
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise
            try:
                pt = message_decrypt(
                    rs.raw, rs.sh, key, CKM_AES_CBC, ct, mech_param=cbc_param, msg_param=iv
                )
            except AssertionError as exc:
                _skip_if_message_op_not_implemented(exc, "message decrypt")
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message decrypt rejected (CKM_AES_CBC)"
                )
                raise
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_CBC:message decrypt(encrypt(pt)) roundtrip",
                operation="C_DecryptMessage",
                mechanism="CKM_AES_CBC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_encrypt_multipart(self, p11_raw_session: Any) -> None:
        """C_MessageEncryptInit + Begin + Next + Final multipart encrypt."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_ENCRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        _require_message_flags(
            rs,
            "AES_CBC",
            (int(CKF_MESSAGE_ENCRYPT), int(CKF_MULTI_MESSAGE)),
            "multipart message encrypt",
        )
        key = gen_aes_key_or_xfail(rs, 256, purpose="message multipart encrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.pack import mech_bytes

            iv = os.urandom(16)
            iv_buf = to_ubyte_buf(iv)
            packed = mech_bytes(CKM_AES_CBC, iv)
            rv = rs.raw.C_MessageEncryptInit(rs.sh, packed.byref(), key)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageEncryptInit")

            in_buf = to_ubyte_buf(plaintext)
            rv = rs.raw.C_EncryptMessageBegin(rs.sh, iv_buf, len(iv), None, 0)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_EncryptMessageBegin")

            out_len = CK_ULONG(0)
            rv = rs.raw.C_EncryptMessageNext(
                rs.sh,
                iv_buf,
                len(iv),
                in_buf,
                len(plaintext),
                None,
                byref(out_len),
                CKF_END_OF_MESSAGE,
            )
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_EncryptMessageNext (size)")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_EncryptMessageNext(
                rs.sh,
                iv_buf,
                len(iv),
                in_buf,
                len(plaintext),
                out_buf,
                byref(out_len),
                CKF_END_OF_MESSAGE,
            )
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
        _require_message_flags(
            rs,
            "AES_CBC",
            (int(CKF_MESSAGE_ENCRYPT), int(CKF_MESSAGE_DECRYPT), int(CKF_MULTI_MESSAGE)),
            "multipart message decrypt",
        )
        key = gen_aes_key_or_xfail(rs, 256, purpose="message multipart decrypt setup")
        plaintext = b"A" * 32
        try:
            from pkcs11_check.raw.pack import mech_bytes
            from pkcs11_check.raw.recipes import message_encrypt

            iv = os.urandom(16)
            iv_buf = to_ubyte_buf(iv)
            cbc_param = mech_bytes(CKM_AES_CBC, iv)
            try:
                ct = message_encrypt(
                    rs.raw, rs.sh, key, CKM_AES_CBC, plaintext, mech_param=cbc_param, msg_param=iv
                )
            except AssertionError as exc:
                _skip_if_message_op_not_implemented(exc, "message encrypt")
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise

            packed = mech_bytes(CKM_AES_CBC, iv)
            rv = rs.raw.C_MessageDecryptInit(rs.sh, packed.byref(), key)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageDecryptInit")

            in_buf = to_ubyte_buf(ct)
            rv = rs.raw.C_DecryptMessageBegin(rs.sh, iv_buf, len(iv), None, 0)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_DecryptMessageBegin")

            out_len = CK_ULONG(0)
            rv = rs.raw.C_DecryptMessageNext(
                rs.sh,
                iv_buf,
                len(iv),
                in_buf,
                len(ct),
                None,
                byref(out_len),
                CKF_END_OF_MESSAGE,
            )
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_DecryptMessageNext (size)")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_DecryptMessageNext(
                rs.sh,
                iv_buf,
                len(iv),
                in_buf,
                len(ct),
                out_buf,
                byref(out_len),
                CKF_END_OF_MESSAGE,
            )
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_DecryptMessageNext")

            rv = rs.raw.C_MessageDecryptFinal(rs.sh)
            if rv != CKR_OK:
                _handle_message_rv(rv, "C_MessageDecryptFinal")

            assert_correct(
                actual=bytes(out_buf[: out_len.value]),
                expected=plaintext,
                label="AES_CBC:message multipart decrypt roundtrip",
                operation="C_DecryptMessageNext",
                mechanism="CKM_AES_CBC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_encrypt_decrypt_roundtrip(self, p11_raw_session: Any) -> None:
        """Encrypt with message API, decrypt with standard C_Decrypt API (cross-verification)."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_ENCRYPT_FUNCS)
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        _require_message_flags(
            rs,
            "AES_CBC",
            (int(CKF_MESSAGE_ENCRYPT),),
            "message cross-verify",
        )
        key = gen_aes_key_or_xfail(rs, 256, purpose="message cross-verify setup")
        plaintext = b"cross-verify test data padding!!"
        try:
            from pkcs11_check.raw.pack import mech_bytes
            from pkcs11_check.raw.recipes import message_encrypt

            iv = os.urandom(16)
            cbc_param = mech_bytes(CKM_AES_CBC, iv)
            try:
                ct = message_encrypt(
                    rs.raw, rs.sh, key, CKM_AES_CBC, plaintext, mech_param=cbc_param, msg_param=iv
                )
            except AssertionError as exc:
                _skip_if_message_op_not_implemented(exc, "message encrypt")
                xfail_if_known_ckr(
                    exc, _MESSAGE_OP_REJECT_RVS, "advertised message encrypt rejected (CKM_AES_CBC)"
                )
                raise
            if ct == plaintext:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="AES_CBC:message encrypt produced plaintext (no-op)",
                    operation="C_EncryptMessage",
                    mechanism="CKM_AES_CBC",
                    summary=(
                        "AES_CBC: message-API ciphertext equals the plaintext -- "
                        "encryption was a no-op (crypto break)"
                    ),
                )
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_CBC, ct, mech_param=cbc_param)
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_CBC:message-encrypt standard-decrypt cross-verify",
                operation="C_Decrypt",
                mechanism="CKM_AES_CBC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestMessageSignVerify:
    """Test message-based sign/verify lifecycle."""

    @pytest.mark.needs_function("C_MessageSignInit")
    def test_message_sign_single(self, p11_raw_session: Any) -> None:
        """C_MessageSignInit + C_SignMessage -- single-shot sign."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_SIGN),),
            "single message sign",
        )
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"message sign test data"
        try:
            sig = _message_sign(rs, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) > 0
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.needs_function("C_MessageVerifyInit")
    def test_message_verify_single(self, p11_raw_session: Any) -> None:
        """C_MessageVerifyInit + C_VerifyMessage -- single-shot verify."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_VERIFY_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_VERIFY),),
            "single message verify",
        )
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"message verify test data"
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            result = _message_verify(rs, pub, CKM_SHA256_RSA_PKCS, data, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.needs_function("C_MessageSignInit")
    def test_message_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """Sign with message API, verify with standard C_Verify API (cross-verification)."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_SIGN),),
            "single message sign cross-verification",
        )
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"cross-verify sign data payload"
        try:
            sig = _message_sign(rs, priv, CKM_SHA256_RSA_PKCS, data)
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.needs_function("C_MessageSignInit")
    def test_message_sign_multipart(self, p11_raw_session: Any) -> None:
        """C_MessageSignInit + C_SignMessageBegin + C_SignMessageNext + C_MessageSignFinal."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_SIGN_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_SIGN), int(CKF_MULTI_MESSAGE)),
            "multipart message sign",
        )
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

    @pytest.mark.needs_function("C_MessageVerifyInit")
    def test_message_verify_bad_signature(self, p11_raw_session: Any) -> None:
        """C_VerifyMessage with wrong signature should fail."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_VERIFY_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_VERIFY),),
            "single message verify bad signature",
        )
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

    @pytest.mark.needs_function("C_MessageVerifyInit")
    def test_message_verify_multipart(self, p11_raw_session: Any) -> None:
        """C_MessageVerifyInit + Begin + Next + Final verifies a multipart message."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_VERIFY_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_VERIFY), int(CKF_MULTI_MESSAGE)),
            "multipart message verify",
        )
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        parts = [b"part one ", b"part two ", b"part three"]
        try:
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"".join(parts))
            assert _message_verify_multipart(rs, pub, CKM_SHA256_RSA_PKCS, parts, signature) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.needs_function("C_MessageVerifyInit")
    def test_message_verify_multipart_bad_signature(self, p11_raw_session: Any) -> None:
        """A bad multipart signature follows the clean-versus-non-clean policy."""
        rs = p11_raw_session
        _skip_unless_message_functions(rs, MESSAGE_VERIFY_FUNCS)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_message_flags(
            rs,
            "SHA256_RSA_PKCS",
            (int(CKF_MESSAGE_VERIFY), int(CKF_MULTI_MESSAGE)),
            "multipart message verify bad signature",
        )
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        parts = [b"correct data ", b"with multiple parts"]
        try:
            signature = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"".join(parts))
            bad_signature = bytes([signature[0] ^ 0x01]) + signature[1:]
            assert (
                _message_verify_multipart(
                    rs,
                    pub,
                    CKM_SHA256_RSA_PKCS,
                    parts,
                    bad_signature,
                    expect_valid=False,
                )
                is False
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestMessageAvailability:
    """Verify message-based functions are present in v3.0+ modules."""

    @pytest.mark.needs_function("C_MessageEncryptInit")
    def test_message_functions_available(self, p11_raw_session: Any) -> None:
        """All 20 message functions should be present on v3.0+ modules."""
        rs = p11_raw_session
        available = rs.raw.available_function_names()
        missing = [name for name in ALL_MESSAGE_FUNCS if name not in available]
        if missing:
            pytest.skip(f"Message functions not available: {', '.join(missing)}")
        assert all(name in available for name in ALL_MESSAGE_FUNCS)
