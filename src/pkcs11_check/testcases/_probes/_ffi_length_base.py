"""Shared setup primitives for the ffi_length arm-group probe modules.

Moved verbatim from ffi_length.py (god-module split, 2026-07-17): setup-reject
classification (_SetupRejected / _setup_reject_or_raise) and the key-import /
derive-template helpers used by several arm groups.
"""

from __future__ import annotations

import ctypes
from typing import Any, NoReturn

from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
)
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.conftest import (
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


def _import_generic_secret_derive_key(
    ctx: ProbeContext, *, value_len: int, reject_label: str
) -> int:
    """Import a generic-secret key with CKA_DERIVE for the KDF NULL-param probes.

    Port of the inline 5-attribute C_CreateObject shared by the HKDF / concat /
    TLS-KDF / SP800-108 derive probes.  ``value_len`` is the key byte count (32,
    or 48 for the TLS pre-master secret).  On failure prints
    ``SETUP_XFAIL:<reject_label> base key import not operational 0x<rv>`` (message
    kept verbatim per label; I5) and raises :class:`_SetupRejected`.  Returns the
    object handle.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    key_bytes = (ctypes.c_ubyte * value_len)(*range(value_len))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    derive_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)

    key_tmpl = (CK_ATTRIBUTE * 5)()
    key_tmpl[0].type = CKA_CLASS
    key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    key_tmpl[1].type = CKA_KEY_TYPE
    key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
    key_tmpl[2].type = CKA_VALUE
    key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    key_tmpl[2].ulValueLen = value_len
    key_tmpl[3].type = CKA_DERIVE
    key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
    key_tmpl[3].ulValueLen = 1
    key_tmpl[4].type = CKA_TOKEN
    key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    key_tmpl[4].ulValueLen = 1

    base_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 5, ctypes.byref(base_key)
    )
    if rv != CKR_OK:
        print(f"{SETUP_XFAIL_PREFIX}{reject_label} base key import not operational 0x{rv:08x}")
        raise _SetupRejected
    return base_key.value


def _derived_secret_key_template() -> tuple[Any, tuple[Any, ...]]:
    """Build the 4-attribute derived-key template shared by the KDF / ECDH probes.

    Returns ``(template_array, keepalive)``.  The scalar objects backing the
    ``pValue`` casts must outlive the ``C_DeriveKey`` call, so the caller must keep
    ``keepalive`` referenced until the derive returns (a ``c_void_p`` stores only
    the address, not a reference to the pointed-to object).
    """
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)

    tmpl = (CK_ATTRIBUTE * 4)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    tmpl[2].type = CKA_VALUE_LEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    tmpl[3].type = CKA_TOKEN
    tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    tmpl[3].ulValueLen = 1
    return tmpl, (d_cls, d_kt, d_vl, d_tok)


def _import_derive_base_key(ctx: ProbeContext, *, value_len: int, label: str) -> int:
    """Import a generic-secret CKA_DERIVE base key via C_CreateObject (5 attributes).

    Port of the inline base-key import shared by the TLS-KDF-random and SP800-108
    nested-count probes.  On failure prints
    ``SETUP_XFAIL:<label> base-key import rejected: <ckr_name>`` (message kept verbatim
    per ``label``; I5) and raises :class:`_SetupRejected`.  Distinct from
    :func:`_import_generic_secret_derive_key`, whose failure message differs (do not
    unify; I5).  Returns the object handle.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    key_bytes = (ctypes.c_ubyte * value_len)(*range(value_len))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    derive_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)

    key_tmpl = (CK_ATTRIBUTE * 5)()
    key_tmpl[0].type = CKA_CLASS
    key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    key_tmpl[1].type = CKA_KEY_TYPE
    key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
    key_tmpl[2].type = CKA_VALUE
    key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    key_tmpl[2].ulValueLen = value_len
    key_tmpl[3].type = CKA_DERIVE
    key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
    key_tmpl[3].ulValueLen = 1
    key_tmpl[4].type = CKA_TOKEN
    key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    key_tmpl[4].ulValueLen = 1

    base_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 5, ctypes.byref(base_key)
    )
    if rv != CKR_OK:
        print(f"{SETUP_XFAIL_PREFIX}{label} base-key import rejected: {ckr_name(rv)}")
        raise _SetupRejected
    return base_key.value


def _derived_aes_key_template() -> tuple[Any, tuple[Any, ...]]:
    """Build the 4-attribute AES derived-key template for the SP800-108 probes.

    Mirrors :func:`_derived_secret_key_template` but derives a 16-byte AES key
    (``CKK_AES`` / ``CKA_VALUE_LEN=16``) as the SP800-108 nested-count probes did.
    Returns ``(template_array, keepalive)``; keep ``keepalive`` referenced until the
    derive returns (the ``c_void_p`` casts store only addresses).
    """
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_AES)
    d_vl = CK_ULONG(16)
    d_tok = ctypes.c_ubyte(0)

    tmpl = (CK_ATTRIBUTE * 4)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    tmpl[2].type = CKA_VALUE_LEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    tmpl[3].type = CKA_TOKEN
    tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    tmpl[3].ulValueLen = 1
    return tmpl, (d_cls, d_kt, d_vl, d_tok)
