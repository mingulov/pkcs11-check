"""ffi_length arm group: isize::MAX input/output/signature-length probes.

Moved verbatim from ffi_length.py (god-module split, 2026-07-17); dispatched via
ffi_length._DISPATCH.  Output protocol unchanged (TARGET_RV/SETUP_XFAIL lines).
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKR_OK,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _import_hmac_key,
    _import_hmac_key_notop,
    _setup_reject_or_raise,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
)


def _run_encrypt_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Encrypt with an isize-boundary ``ulDataLen`` over a honeypot data pointer."""
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
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_Encrypt(sh, buf, data_len, out_buf, ctypes.byref(out_len))
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_EncryptInit not operational 0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Decrypt with an isize-boundary ``ulEncryptedDataLen`` over a honeypot data pointer."""
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
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_Decrypt(sh, buf, data_len, out_buf, ctypes.byref(out_len))
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_DecryptInit not operational 0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_sign_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Sign (HMAC-SHA256) with an isize-boundary ``ulDataLen`` over a honeypot data ptr."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    key = _import_hmac_key_notop(ctx, sign=True)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            sig_len = CK_ULONG(64)
            sig_buf = (ctypes.c_ubyte * 64)()
            rv2 = raw.C_Sign(sh, buf, data_len, sig_buf, ctypes.byref(sig_len))
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_SignInit not operational 0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_verify_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Verify (HMAC-SHA256) with an isize-boundary ``ulDataLen`` over a honeypot data ptr."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    key = _import_hmac_key(ctx, verify=True)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            sig_buf = (ctypes.c_ubyte * 32)()
            rv2 = raw.C_Verify(sh, buf, data_len, sig_buf, 32)
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_VerifyInit not operational 0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_digest_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Digest (SHA256) with an isize-boundary ``ulDataLen`` over a honeypot data pointer."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv == CKR_OK:
        digest_len = CK_ULONG(64)
        digest_buf = (ctypes.c_ubyte * 64)()
        rv2 = raw.C_Digest(sh, buf, data_len, digest_buf, ctypes.byref(digest_len))
        print(f"TARGET_RV:0x{rv2:08x}")
    else:
        print(f"{SETUP_XFAIL_PREFIX}C_DigestInit not operational 0x{rv:08x}")


def _run_update_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_*Update with an isize-boundary ``ulPartLen`` (op selected by ``extra["op"]``)."""
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

    if op in ("C_EncryptUpdate", "C_DecryptUpdate"):
        init_op = "C_EncryptInit" if op == "C_EncryptUpdate" else "C_DecryptInit"
        try:
            key = gen_aes_key(raw, sh, 256)
        except AssertionError as exc:
            _setup_reject_or_raise(
                exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
            )
        try:
            mech = CK_MECHANISM()
            mech.mechanism = CKM_AES_ECB
            mech.pParameter = None
            mech.ulParameterLen = 0
            rv = getattr(raw, init_op)(sh, ctypes.byref(mech), key)
            if rv == CKR_OK:
                out_len = CK_ULONG(256)
                out_buf = (ctypes.c_ubyte * 256)()
                print(f"TARGET:{op}", flush=True)
                print(f"LEN:{data_len}", flush=True)
                rv2 = getattr(raw, op)(sh, buf, data_len, out_buf, ctypes.byref(out_len))
                print(f"TARGET_RV:0x{rv2:08x}")
            else:
                print(f"{SETUP_XFAIL_PREFIX}{init_op} not operational 0x{rv:08x}")
        finally:
            destroy_quietly(raw, sh, key)
    elif op == "C_SignUpdate":
        key = _import_hmac_key(ctx, sign=True)
        try:
            mech = CK_MECHANISM()
            mech.mechanism = CKM_SHA256_HMAC
            mech.pParameter = None
            mech.ulParameterLen = 0
            rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
            if rv == CKR_OK:
                print("TARGET:C_SignUpdate", flush=True)
                print(f"LEN:{data_len}", flush=True)
                rv2 = raw.C_SignUpdate(sh, buf, data_len)
                print(f"TARGET_RV:0x{rv2:08x}")
            else:
                print(f"{SETUP_XFAIL_PREFIX}C_SignInit not operational 0x{rv:08x}")
        finally:
            destroy_quietly(raw, sh, key)
    elif op == "C_VerifyUpdate":
        key = _import_hmac_key(ctx, verify=True)
        try:
            mech = CK_MECHANISM()
            mech.mechanism = CKM_SHA256_HMAC
            mech.pParameter = None
            mech.ulParameterLen = 0
            rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
            if rv == CKR_OK:
                print("TARGET:C_VerifyUpdate", flush=True)
                print(f"LEN:{data_len}", flush=True)
                rv2 = raw.C_VerifyUpdate(sh, buf, data_len)
                print(f"TARGET_RV:0x{rv2:08x}")
            else:
                print(f"{SETUP_XFAIL_PREFIX}C_VerifyInit not operational 0x{rv:08x}")
        finally:
            destroy_quietly(raw, sh, key)
    elif op == "C_DigestUpdate":
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_DigestInit(sh, ctypes.byref(mech))
        if rv == CKR_OK:
            print("TARGET:C_DigestUpdate", flush=True)
            print(f"LEN:{data_len}", flush=True)
            rv2 = raw.C_DigestUpdate(sh, buf, data_len)
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_DigestInit not operational 0x{rv:08x}")
    else:
        raise ValueError(f"Unhandled op: {op}")


def _run_seed_random_isize(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SeedRandom with an isize-boundary ``ulSeedLen`` over a honeypot data pointer."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    print("TARGET:C_SeedRandom", flush=True)
    print(f"LEN:{data_len}", flush=True)
    rv = raw.C_SeedRandom(sh, buf, data_len)
    print(f"TARGET_RV:0x{rv:08x}")
    print(f"rv_name={ckr_name(rv)}")


# ---------------------------------------------------------------------------
# Output-length probes (small real buffers; un-honorable value in the length field)
# ---------------------------------------------------------------------------


def _run_sign_isize_output(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Sign (HMAC-SHA256) with an isize-boundary claimed output-buffer length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    out_len_val = int(extra["out_len"])

    key = _import_hmac_key_notop(ctx, sign=True)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            data = (ctypes.c_ubyte * 16)(*range(16))
            sig_buf = (ctypes.c_ubyte * 64)()
            sig_len = CK_ULONG(out_len_val)
            rv2 = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_SignInit not operational 0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_digest_isize_output(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Digest (SHA256) with an isize-boundary claimed output-buffer length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    out_len_val = int(extra["out_len"])

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        digest_buf = (ctypes.c_ubyte * 64)()
        digest_len = CK_ULONG(out_len_val)
        rv2 = raw.C_Digest(sh, data, 16, digest_buf, ctypes.byref(digest_len))
        print(f"TARGET_RV:0x{rv2:08x}")
    else:
        print(f"{SETUP_XFAIL_PREFIX}C_DigestInit not operational 0x{rv:08x}")


def _run_verify_isize_sig_len(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Verify (HMAC-SHA256) with an isize-boundary claimed signature length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    sig_len_val = int(extra["sig_len"])

    key = _import_hmac_key_notop(ctx, verify=True)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            data = (ctypes.c_ubyte * 16)(*range(16))
            sig_buf = (ctypes.c_ubyte * 64)()
            rv2 = raw.C_Verify(sh, data, 16, sig_buf, sig_len_val)
            print(f"TARGET_RV:0x{rv2:08x}")
        else:
            print(f"{SETUP_XFAIL_PREFIX}C_VerifyInit not operational 0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


# ---------------------------------------------------------------------------
# v3.0 message-API probes (input-length; data pointer backed by the honeypot)
# ---------------------------------------------------------------------------
