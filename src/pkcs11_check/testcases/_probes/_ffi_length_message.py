"""ffi_length arm group: message-based API (C_*Message*) isize probes.

Moved verbatim from ffi_length.py (god-module split, 2026-07-17); dispatched via
ffi_length._DISPATCH.  Output protocol unchanged (TARGET_RV/SETUP_XFAIL lines).
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    sign_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_END_OF_MESSAGE,
    CKM_AES_GCM,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _setup_reject_or_raise,
    _SetupRejected,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
)


def _run_encrypt_message(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptMessage (AES-GCM) with an isize-boundary aad/plaintext input length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    aad_len = int(extra["aad_len"])
    plaintext_len = int(extra["plaintext_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        init_iv = (ctypes.c_ubyte * 12)(*range(12))
        init_tag = (ctypes.c_ubyte * 16)()
        init_params = CK_GCM_MESSAGE_PARAMS()
        init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
        init_params.ulIvLen = 12
        init_params.ulIvFixedBits = 0
        init_params.ivGenerator = 0
        init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
        init_params.ulTagBits = 128

        init_mech = CK_MECHANISM()
        init_mech.mechanism = CKM_AES_GCM
        init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
        init_mech.ulParameterLen = ctypes.sizeof(init_params)

        rv = raw.C_MessageEncryptInit(sh, ctypes.byref(init_mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageEncryptInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        msg_iv = (ctypes.c_ubyte * 12)(*range(12, 24))
        msg_tag = (ctypes.c_ubyte * 16)()
        msg_params = CK_GCM_MESSAGE_PARAMS()
        msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
        msg_params.ulIvLen = 12
        msg_params.ulIvFixedBits = 0
        msg_params.ivGenerator = 0
        msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
        msg_params.ulTagBits = 128

        aad = buf if aad_len != 16 else (ctypes.c_ubyte * 16)(*range(16))
        plaintext = buf if plaintext_len != 16 else (ctypes.c_ubyte * 16)(*range(16, 32))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()

        rv = raw.C_EncryptMessage(
            sh,
            ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
            ctypes.sizeof(msg_params),
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            out_buf,
            ctypes.byref(out_len),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageEncryptFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_message(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DecryptMessage (AES-GCM) with an isize-boundary aad/ciphertext input length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    aad_len = int(extra["aad_len"])
    ciphertext_len = int(extra["ciphertext_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        init_iv = (ctypes.c_ubyte * 12)(*range(12))
        init_tag = (ctypes.c_ubyte * 16)()
        init_params = CK_GCM_MESSAGE_PARAMS()
        init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
        init_params.ulIvLen = 12
        init_params.ulIvFixedBits = 0
        init_params.ivGenerator = 0
        init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
        init_params.ulTagBits = 128

        init_mech = CK_MECHANISM()
        init_mech.mechanism = CKM_AES_GCM
        init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
        init_mech.ulParameterLen = ctypes.sizeof(init_params)

        rv = raw.C_MessageDecryptInit(sh, ctypes.byref(init_mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageDecryptInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        msg_iv = (ctypes.c_ubyte * 12)(*range(12, 24))
        msg_tag = (ctypes.c_ubyte * 16)(*range(24, 40))
        msg_params = CK_GCM_MESSAGE_PARAMS()
        msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
        msg_params.ulIvLen = 12
        msg_params.ulIvFixedBits = 0
        msg_params.ivGenerator = 0
        msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
        msg_params.ulTagBits = 128

        aad = buf if aad_len != 16 else (ctypes.c_ubyte * 16)(*range(16))
        ciphertext = buf if ciphertext_len != 16 else (ctypes.c_ubyte * 16)(*range(40, 56))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()

        rv = raw.C_DecryptMessage(
            sh,
            ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
            ctypes.sizeof(msg_params),
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            out_buf,
            ctypes.byref(out_len),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageDecryptFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_message_multipart(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DecryptMessageBegin/Next (AES-GCM) with an isize-boundary ciphertext length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    op = extra["op"]
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        init_iv = (ctypes.c_ubyte * 12)(*range(12))
        init_tag = (ctypes.c_ubyte * 16)(*range(12, 28))
        init_params = CK_GCM_MESSAGE_PARAMS()
        init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
        init_params.ulIvLen = 12
        init_params.ulIvFixedBits = 0
        init_params.ivGenerator = 0
        init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
        init_params.ulTagBits = 128

        init_mech = CK_MECHANISM()
        init_mech.mechanism = CKM_AES_GCM
        init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
        init_mech.ulParameterLen = ctypes.sizeof(init_params)

        rv = raw.C_MessageDecryptInit(sh, ctypes.byref(init_mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageDecryptInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        msg_iv = (ctypes.c_ubyte * 12)(*range(28, 40))
        msg_tag = (ctypes.c_ubyte * 16)(*range(40, 56))
        msg_params = CK_GCM_MESSAGE_PARAMS()
        msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
        msg_params.ulIvLen = 12
        msg_params.ulIvFixedBits = 0
        msg_params.ivGenerator = 0
        msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
        msg_params.ulTagBits = 128

        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()

        if op == "C_DecryptMessageBegin":
            rv = raw.C_DecryptMessageBegin(
                sh,
                ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
                ctypes.sizeof(msg_params),
                buf,
                data_len,
            )
        else:
            ciphertext = (ctypes.c_ubyte * 16)(*range(56, 72))
            rv = raw.C_DecryptMessageBegin(
                sh,
                ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
                ctypes.sizeof(msg_params),
                ciphertext,
                16,
            )
            if rv != CKR_OK:
                print(f"{SETUP_XFAIL_PREFIX}C_DecryptMessageBegin rejected: {ckr_name(rv)}")
                raise _SetupRejected
            rv = raw.C_DecryptMessageNext(
                sh,
                None,
                0,
                buf,
                data_len,
                out_buf,
                ctypes.byref(out_len),
                CKF_END_OF_MESSAGE,
            )

        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageDecryptFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_sign_message(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SignMessage (RSA) with an isize-boundary data length over a honeypot data ptr."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_MessageSignInit(sh, ctypes.byref(mech), priv)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageSignInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        sig_len = CK_ULONG(512)
        sig_buf = (ctypes.c_ubyte * 512)()
        rv = raw.C_SignMessage(sh, None, 0, buf, data_len, sig_buf, ctypes.byref(sig_len))
        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageSignFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_verify_message(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_VerifyMessage (RSA) with an isize-boundary data/signature input length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    verify_data_len = int(extra["verify_data_len"])
    signature_len = int(extra["signature_len"])
    normal_data_len = 16

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected")

    try:
        data_bytes = bytes(range(normal_data_len))
        try:
            signature = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, data_bytes)
        except AssertionError as exc:
            rv_setup = getattr(exc, "rv", None)
            detail = ckr_name(rv_setup) if rv_setup is not None else str(exc)
            print(f"{SETUP_XFAIL_PREFIX}standard signature generation rejected: {detail}")
            raise _SetupRejected from exc

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_MessageVerifyInit(sh, ctypes.byref(mech), pub)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageVerifyInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        data = (
            buf
            if verify_data_len != normal_data_len
            else (ctypes.c_ubyte * normal_data_len)(*range(normal_data_len))
        )
        sig_buf = buf if signature_len != 256 else (ctypes.c_ubyte * len(signature))(*signature)
        rv = raw.C_VerifyMessage(
            sh,
            None,
            0,
            data,
            verify_data_len,
            sig_buf,
            signature_len,
        )
        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageVerifyFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_sign_message_multipart(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SignMessageBegin/Next (RSA) with an isize-boundary data length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    op = extra["op"]
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_MessageSignInit(sh, ctypes.byref(mech), priv)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageSignInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        sig_len = CK_ULONG(512)
        sig_buf = (ctypes.c_ubyte * 512)()

        if op == "C_SignMessageBegin":
            rv = raw.C_SignMessageBegin(sh, None, 0, buf, data_len)
        else:
            data = (ctypes.c_ubyte * 16)(*range(16))
            rv = raw.C_SignMessageBegin(sh, None, 0, data, 16)
            if rv != CKR_OK:
                print(f"{SETUP_XFAIL_PREFIX}C_SignMessageBegin rejected: {ckr_name(rv)}")
                raise _SetupRejected
            rv = raw.C_SignMessageNext(
                sh,
                None,
                0,
                buf,
                data_len,
                sig_buf,
                ctypes.byref(sig_len),
                CKF_END_OF_MESSAGE,
            )

        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageSignFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_verify_message_multipart(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_VerifyMessageBegin/Next (RSA) with an isize-boundary begin/data/signature length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    field = extra["field"]
    begin_param_len = int(extra["begin_param_len"])
    next_data_len = int(extra["next_data_len"])
    next_signature_len = int(extra["next_signature_len"])
    normal_data_len = 16

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected")

    try:
        data_bytes = bytes(range(normal_data_len))
        try:
            signature = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, data_bytes)
        except AssertionError as exc:
            rv_setup = getattr(exc, "rv", None)
            detail = ckr_name(rv_setup) if rv_setup is not None else str(exc)
            print(f"{SETUP_XFAIL_PREFIX}standard signature generation rejected: {detail}")
            raise _SetupRejected from exc

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_MessageVerifyInit(sh, ctypes.byref(mech), pub)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageVerifyInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        if field == "begin_parameter":
            rv = raw.C_VerifyMessageBegin(
                sh,
                ctypes.cast(buf, ctypes.c_void_p),
                begin_param_len,
            )
        else:
            rv = raw.C_VerifyMessageBegin(sh, None, 0)
            if rv != CKR_OK:
                print(f"{SETUP_XFAIL_PREFIX}C_VerifyMessageBegin rejected: {ckr_name(rv)}")
                raise _SetupRejected
            data = (
                buf
                if next_data_len != normal_data_len
                else (ctypes.c_ubyte * normal_data_len)(*range(normal_data_len))
            )
            sig_buf = (
                buf if next_signature_len != 256 else (ctypes.c_ubyte * len(signature))(*signature)
            )
            rv = raw.C_VerifyMessageNext(
                sh,
                None,
                0,
                data,
                next_data_len,
                sig_buf,
                next_signature_len,
                CKF_END_OF_MESSAGE,
            )

        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageVerifyFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_encrypt_message_multipart(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptMessageBegin/Next (AES-GCM) with an isize-boundary plaintext length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    op = extra["op"]
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        init_iv = (ctypes.c_ubyte * 12)(*range(12))
        init_tag = (ctypes.c_ubyte * 16)()
        init_params = CK_GCM_MESSAGE_PARAMS()
        init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
        init_params.ulIvLen = 12
        init_params.ulIvFixedBits = 0
        init_params.ivGenerator = 0
        init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
        init_params.ulTagBits = 128

        init_mech = CK_MECHANISM()
        init_mech.mechanism = CKM_AES_GCM
        init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
        init_mech.ulParameterLen = ctypes.sizeof(init_params)

        rv = raw.C_MessageEncryptInit(sh, ctypes.byref(init_mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}C_MessageEncryptInit rejected: {ckr_name(rv)}")
            raise _SetupRejected

        msg_iv = (ctypes.c_ubyte * 12)(*range(12, 24))
        msg_tag = (ctypes.c_ubyte * 16)()
        msg_params = CK_GCM_MESSAGE_PARAMS()
        msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
        msg_params.ulIvLen = 12
        msg_params.ulIvFixedBits = 0
        msg_params.ivGenerator = 0
        msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
        msg_params.ulTagBits = 128

        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()

        if op == "C_EncryptMessageBegin":
            rv = raw.C_EncryptMessageBegin(
                sh,
                ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
                ctypes.sizeof(msg_params),
                buf,
                data_len,
            )
        else:
            plaintext = (ctypes.c_ubyte * 16)(*range(16))
            rv = raw.C_EncryptMessageBegin(
                sh,
                ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
                ctypes.sizeof(msg_params),
                plaintext,
                16,
            )
            if rv != CKR_OK:
                print(f"{SETUP_XFAIL_PREFIX}C_EncryptMessageBegin rejected: {ckr_name(rv)}")
                raise _SetupRejected
            rv = raw.C_EncryptMessageNext(
                sh,
                None,
                0,
                buf,
                data_len,
                out_buf,
                ctypes.byref(out_len),
                CKF_END_OF_MESSAGE,
            )

        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        final_rv = raw.C_MessageEncryptFinal(sh)
        print(f"FINAL_RV:0x{final_rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


# ---------------------------------------------------------------------------
# NULL-inner-parameter probes (valid CK_MECHANISM; an inner struct field is NULL
# / an empty non-NULL pointer with a non-zero paired length -- the module must
# validate before dereferencing)
# ---------------------------------------------------------------------------
