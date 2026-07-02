"""Probe: isize::MAX (2^63) boundary lengths for PKCS#11 data / output functions.

Untrusted-caller probe.  On a 64-bit platform the largest valid byte count for a
contiguous slice is ``0x7FFFFFFFFFFFFFFF`` (2**63 - 1); passing that value (or one past
it) as a data/part/output length with a small real buffer must be rejected cleanly, never
form an out-of-bounds slice (CWE-681).  Input-length probes back the claimed length with a
demand-zero honeypot so a crash is unconditionally real (docs/probe-soundness.md); output-
length probes pass small real buffers and put the un-honorable value in the length field.
Output protocol is preserved verbatim for the parent classifiers in
security/test_ffi_length_boundary.py.

Dispatch on ``params.extra["probe"]``:
  ``"encrypt_isize"``       -- C_EncryptInit + C_Encrypt, honeypot data ptr, isize data_len
  ``"decrypt_isize"``       -- C_DecryptInit + C_Decrypt, honeypot data ptr, isize data_len
  ``"sign_isize"``          -- C_SignInit + C_Sign (HMAC), honeypot data ptr, isize data_len
  ``"verify_isize"``        -- C_VerifyInit + C_Verify (HMAC), honeypot data ptr, isize data_len
  ``"digest_isize"``        -- C_DigestInit + C_Digest, honeypot data ptr, isize data_len
  ``"update_isize"``        -- C_{Encrypt,Decrypt,Sign,Verify,Digest}Update, isize part len
  ``"seed_random_isize"``   -- C_SeedRandom, honeypot data ptr, isize seed len
  ``"sign_isize_output"``   -- C_Sign with isize CK_ULONG output-buffer length
  ``"digest_isize_output"`` -- C_Digest with isize CK_ULONG output-buffer length
  ``"verify_isize_sig_len"`` -- C_Verify with isize claimed signature length
  ``"encrypt_message"``     -- C_EncryptMessage (AES-GCM), honeypot aad/plaintext, isize input len
  ``"decrypt_message"``     -- C_DecryptMessage (AES-GCM), honeypot aad/ciphertext, isize input len
  ``"decrypt_message_multipart"`` -- C_DecryptMessageBegin/Next (AES-GCM), honeypot isize ciphertext
  ``"sign_message"``        -- C_SignMessage (RSA), honeypot data ptr, isize data len
  ``"verify_message"``      -- C_VerifyMessage (RSA), honeypot data/signature, isize input len
  ``"sign_message_multipart"`` -- C_SignMessageBegin/Next (RSA), honeypot isize data len
  ``"verify_message_multipart"`` -- C_VerifyMessageBegin/Next (RSA), honeypot isize begin/data/sig
  ``"encrypt_message_multipart"`` -- C_EncryptMessageBegin/Next (AES-GCM), honeypot isize plaintext

Required extra keys (in addition to ``"module_path"`` / ``"slot_id"`` handled by the runner):
  ``"probe"``     -- one of the dispatch keys above.
  ``"data_len"``  -- int (input-length probes: encrypt/decrypt/sign/verify/digest/update/seed and
                     ``"sign_message"`` / the ``"*_message_multipart"`` probes).
  ``"op"``        -- str for ``"update_isize"``: one of C_EncryptUpdate / C_DecryptUpdate /
                     C_SignUpdate / C_VerifyUpdate / C_DigestUpdate; also for
                     ``"encrypt_message_multipart"`` / ``"decrypt_message_multipart"`` /
                     ``"sign_message_multipart"`` (selects the *Begin vs *Next arm).
  ``"out_len"``   -- int for ``"sign_isize_output"`` / ``"digest_isize_output"``.
  ``"sig_len"``   -- int for ``"verify_isize_sig_len"``.
  ``"aad_len"`` / ``"plaintext_len"``   -- int for ``"encrypt_message"``.
  ``"aad_len"`` / ``"ciphertext_len"``  -- int for ``"decrypt_message"``.
  ``"verify_data_len"`` / ``"signature_len"``  -- int for ``"verify_message"``.
  ``"field"``     -- str for ``"verify_message_multipart"`` (begin_parameter / next_data /
                     next_signature), with ``"begin_param_len"`` / ``"next_data_len"`` /
                     ``"next_signature_len"`` (int).
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any, NoReturn

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, gen_rsa_keypair, sign_single
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKF_END_OF_MESSAGE,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    is_known_error,
)


class _SetupRejected(Exception):  # noqa: N818
    """A setup step (keygen / key import) cleanly errored; SETUP_XFAIL already printed.

    Raised by the child-side helpers so :func:`_main` can stop the probe and exit 0,
    replacing the legacy ``cleanup(); raise SystemExit(0)`` idiom (teardown is now done
    by ``probe_main`` via atexit).
    """


# ---------------------------------------------------------------------------
# Child-side setup helpers (ports of the legacy f-string fragments)
# ---------------------------------------------------------------------------


def _setup_reject_or_raise(
    exc: BaseException,
    known_ckrs: tuple[Any, ...],
    purpose: str,
) -> NoReturn:
    """Port of the legacy ``setup_xfail_if_known_ckr`` child helper.

    If ``exc`` matches one of ``known_ckrs`` (:func:`is_known_error`), print
    ``SETUP_XFAIL:<purpose>: <detail>`` -- where ``detail`` is ``ckr_name(exc.rv)`` when
    the exception carries a ``.rv`` else ``str(exc)`` -- and raise :class:`_SetupRejected`.
    Otherwise re-raise ``exc`` unchanged.
    """
    if is_known_error(exc, known_ckrs):
        rv = getattr(exc, "rv", None)
        detail = ckr_name(rv) if rv is not None else str(exc)
        print(f"{SETUP_XFAIL_PREFIX}{purpose}: {detail}")
        raise _SetupRejected
    raise exc


def _import_hmac_key(ctx: ProbeContext, *, sign: bool = False, verify: bool = False) -> int:
    """Import a 32-byte generic-secret HMAC key via C_CreateObject (6 attributes).

    Port of the legacy ``import_hmac_key`` helper.  On failure prints
    ``SETUP_XFAIL:HMAC key import rejected: <ckr_name>`` and raises :class:`_SetupRejected`.
    Returns the object handle.  Distinct from :func:`_import_hmac_key_notop` -- keep both
    messages verbatim (I5); do not unify.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    sign_val = ctypes.c_ubyte(1 if sign else 0)
    verify_val = ctypes.c_ubyte(1 if verify else 0)
    token_false = ctypes.c_ubyte(0)

    attrs = (CK_ATTRIBUTE * 6)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    attrs[2].ulValueLen = 32
    attrs[3].type = CKA_SIGN
    attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_val), ctypes.c_void_p)
    attrs[3].ulValueLen = 1
    attrs[4].type = CKA_VERIFY
    attrs[4].pValue = ctypes.cast(ctypes.pointer(verify_val), ctypes.c_void_p)
    attrs[4].ulValueLen = 1
    attrs[5].type = CKA_TOKEN
    attrs[5].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[5].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 6, ctypes.byref(key)
    )
    if rv != CKR_OK:
        print(f"{SETUP_XFAIL_PREFIX}HMAC key import rejected: {ckr_name(rv)}")
        raise _SetupRejected
    return key.value


def _import_hmac_key_notop(ctx: ProbeContext, *, sign: bool = False, verify: bool = False) -> int:
    """Import a 32-byte HMAC key via C_CreateObject (5 attributes, one of SIGN/VERIFY).

    Port of the legacy *inline* C_CreateObject used by ``test_sign_isize_boundary`` /
    ``test_sign_isize_output`` / ``test_verify_isize_sig_len``.  On failure prints
    ``SETUP_XFAIL:HMAC key import not operational 0x<rv>`` and raises :class:`_SetupRejected`.
    The message is deliberately distinct from :func:`_import_hmac_key` (do not unify; I5).
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    flag_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)

    attrs = (CK_ATTRIBUTE * 5)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    attrs[2].ulValueLen = 32
    if sign:
        attrs[3].type = CKA_SIGN
    elif verify:
        attrs[3].type = CKA_VERIFY
    else:
        raise ValueError("exactly one of sign / verify must be set")
    attrs[3].pValue = ctypes.cast(ctypes.pointer(flag_true), ctypes.c_void_p)
    attrs[3].ulValueLen = 1
    attrs[4].type = CKA_TOKEN
    attrs[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[4].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 5, ctypes.byref(key)
    )
    if rv != CKR_OK:
        print(f"{SETUP_XFAIL_PREFIX}HMAC key import not operational 0x{rv:08x}")
        raise _SetupRejected
    return key.value


# ---------------------------------------------------------------------------
# Input-length probes (data pointer backed by the demand-zero honeypot)
# ---------------------------------------------------------------------------


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


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "encrypt_isize": _run_encrypt_isize,
    "decrypt_isize": _run_decrypt_isize,
    "sign_isize": _run_sign_isize,
    "verify_isize": _run_verify_isize,
    "digest_isize": _run_digest_isize,
    "update_isize": _run_update_isize,
    "seed_random_isize": _run_seed_random_isize,
    "sign_isize_output": _run_sign_isize_output,
    "digest_isize_output": _run_digest_isize_output,
    "verify_isize_sig_len": _run_verify_isize_sig_len,
    "encrypt_message": _run_encrypt_message,
    "decrypt_message": _run_decrypt_message,
    "decrypt_message_multipart": _run_decrypt_message_multipart,
    "sign_message": _run_sign_message,
    "verify_message": _run_verify_message,
    "sign_message_multipart": _run_sign_message_multipart,
    "verify_message_multipart": _run_verify_message_multipart,
    "encrypt_message_multipart": _run_encrypt_message_multipart,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    fn = _DISPATCH.get(probe)
    if fn is None:
        raise ValueError(f"ffi_length probe: unknown probe {probe!r}")
    try:
        fn(ctx, extra)
    except _SetupRejected:
        return


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
