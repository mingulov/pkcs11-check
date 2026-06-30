"""Probe: API boundary probes -- invalid handles, NULL pointers, extreme sizes.

Ports the f-string child-script bodies from security/test_api_boundary.py into
dispatchable probe functions.  Output protocol lines are byte-identical to the
originals so the parent classifiers require no changes.

All probes run at Level.LOGIN.  The parent passes ``pin=None`` for the
``login_null_pin`` probe so that no auto-login occurs before the explicit
``C_Login(NULL-pin)`` call.

Dispatch on ``params.extra["which"]``:

Session-handle boundary (extra: ``func_name``, ``handle``):
  ``"session_handle"`` -- C_GetSessionInfo / C_CloseSession / C_GetOperationState

Object-handle boundary (extra: ``func_name``, ``handle``):
  ``"object_handle"`` -- C_GetAttributeValue / C_SetAttributeValue /
                         C_DestroyObject / C_CopyObject

NULL mechanism *Init (extra: ``func_name``):
  ``"null_mechanism_init"`` -- C_DigestInit / C_EncryptInit / C_DecryptInit /
                               C_SignInit / C_VerifyInit

Mechanism pParameter=NULL, ulParameterLen>0 (extra: ``func_name``):
  ``"mechanism_param_null"`` -- C_EncryptInit / C_DecryptInit / C_SignInit /
                                C_VerifyInit

NULL template, non-zero count (extra: ``func_name``):
  ``"null_template"`` -- C_CreateObject / C_FindObjectsInit /
                         C_GenerateKey / C_SetAttributeValue

Zero-length data (extra: ``operation``, ``mech_name``):
  ``"zero_length_aes"`` -- encrypt/decrypt with AES_ECB or AES_CBC; zero-length data
  ``"zero_length_rsa"`` -- C_Sign(CKM_SHA256_RSA_PKCS) with zero-length data
  ``"zero_length_ecdsa"`` -- C_Sign(CKM_ECDSA_SHA256) with zero-length data

Standalone boundary probes:
  ``"login_null_pin"`` -- C_Login(sh, CKU_USER, NULL, 8); parent passes pin=None
  ``"generate_rsa_extreme"`` -- C_GenerateKeyPair(CKA_MODULUS_BITS=0xFFFFFFFF)
  ``"generate_rsa_zero"`` -- C_GenerateKeyPair(CKA_MODULUS_BITS=0)
  ``"generate_aes_extreme"`` -- C_GenerateKey(CKA_VALUE_LEN=ULONG_MAX)

Output protocol (byte-identical to originals):
  ``rv:<integer>``        -- C_* return value (most probes)
  ``init_rv:<integer>``   -- Init call return value (zero-length probes)
  ``rv:<integer>``        -- operation return value (zero-length probes)
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
)
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_ECDSA_SHA256,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
    CKU_USER,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# CK_ULONG max for the host ABI (2^64-1 on LP64, 2^32-1 on Win64 LLP64).
_CK_ULONG_MAX: int = ctypes.c_ulong(-1).value

# secp256r1 curve OID bytes (computed once at module load; no session needed).
_SECP256R1_OID: bytes = encode_named_curve_parameters("secp256r1")


# ---------------------------------------------------------------------------
# Session-handle boundary probes
# ---------------------------------------------------------------------------


def _run_session_handle(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GetSessionInfo / C_CloseSession / C_GetOperationState with boundary handles.

    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    func_name: str = extra["func_name"]
    handle: int = int(extra["handle"])

    if func_name == "C_GetSessionInfo":
        info = CK_SESSION_INFO()
        rv = raw.C_GetSessionInfo(handle, ctypes.byref(info))
        print(f"rv={rv}")
    elif func_name == "C_CloseSession":
        rv = raw.C_CloseSession(handle)
        print(f"rv={rv}")
    elif func_name == "C_GetOperationState":
        out_len = CK_ULONG(0)
        rv = raw.C_GetOperationState(handle, None, ctypes.byref(out_len))
        print(f"rv={rv}")
    else:
        raise ValueError(f"api_boundary session_handle: unknown func_name {func_name!r}")


# ---------------------------------------------------------------------------
# Object-handle boundary probes
# ---------------------------------------------------------------------------


def _run_object_handle(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GetAttributeValue / C_SetAttributeValue / C_DestroyObject / C_CopyObject.

    Uses the valid open session handle (``ctx.sh``) and a boundary object handle.
    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    func_name: str = extra["func_name"]
    handle: int = int(extra["handle"])

    if func_name == "C_GetAttributeValue":
        from pkcs11_check.raw.types_std import CKA_CLASS

        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        attr.pValue = None
        attr.ulValueLen = 0
        rv = raw.C_GetAttributeValue(sh, handle, ctypes.pointer(attr), 1)
        print(f"rv={rv}")
    elif func_name == "C_SetAttributeValue":
        val = ctypes.c_ubyte(0)
        attr = CK_ATTRIBUTE()
        attr.type = CKA_TOKEN
        attr.pValue = ctypes.cast(ctypes.pointer(val), ctypes.c_void_p)
        attr.ulValueLen = 1
        rv = raw.C_SetAttributeValue(sh, handle, ctypes.pointer(attr), 1)
        print(f"rv={rv}")
    elif func_name == "C_DestroyObject":
        rv = raw.C_DestroyObject(sh, handle)
        print(f"rv={rv}")
    elif func_name == "C_CopyObject":
        new_handle = CK_OBJECT_HANDLE(0)
        rv = raw.C_CopyObject(sh, handle, None, 0, ctypes.byref(new_handle))
        print(f"rv={rv}")
    else:
        raise ValueError(f"api_boundary object_handle: unknown func_name {func_name!r}")


# ---------------------------------------------------------------------------
# NULL mechanism *Init probes
# ---------------------------------------------------------------------------


def _run_null_mechanism_init(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DigestInit / C_Encrypt|Decrypt|Sign|VerifyInit with NULL mechanism pointer.

    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    func_name: str = extra["func_name"]

    if func_name == "C_DigestInit":
        rv = raw.C_DigestInit(sh, None)
        print(f"rv={rv}")
    elif func_name == "C_EncryptInit":
        rv = raw.C_EncryptInit(sh, None, 0)
        print(f"rv={rv}")
    elif func_name == "C_DecryptInit":
        rv = raw.C_DecryptInit(sh, None, 0)
        print(f"rv={rv}")
    elif func_name == "C_SignInit":
        rv = raw.C_SignInit(sh, None, 0)
        print(f"rv={rv}")
    elif func_name == "C_VerifyInit":
        rv = raw.C_VerifyInit(sh, None, 0)
        print(f"rv={rv}")
    else:
        raise ValueError(f"api_boundary null_mechanism_init: unknown func_name {func_name!r}")


# ---------------------------------------------------------------------------
# Mechanism pParameter=NULL + ulParameterLen>0
# ---------------------------------------------------------------------------


def _run_mechanism_param_null(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_*Init with CKM_AES_CBC mechanism, pParameter=NULL, ulParameterLen=16.

    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    func_name: str = extra["func_name"]

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CBC
    mech.pParameter = None  # NULL pointer
    mech.ulParameterLen = 16  # Non-zero length -- mismatch!

    if func_name == "C_EncryptInit":
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), 0)
        print(f"rv={rv}")
    elif func_name == "C_DecryptInit":
        rv = raw.C_DecryptInit(sh, ctypes.byref(mech), 0)
        print(f"rv={rv}")
    elif func_name == "C_SignInit":
        rv = raw.C_SignInit(sh, ctypes.byref(mech), 0)
        print(f"rv={rv}")
    elif func_name == "C_VerifyInit":
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), 0)
        print(f"rv={rv}")
    else:
        raise ValueError(f"api_boundary mechanism_param_null: unknown func_name {func_name!r}")


# ---------------------------------------------------------------------------
# NULL template, non-zero count probes
# ---------------------------------------------------------------------------


def _run_null_template(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_CreateObject / C_FindObjectsInit / C_GenerateKey / C_SetAttributeValue.

    Passes a NULL template pointer with count=5.
    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    func_name: str = extra["func_name"]

    if func_name == "C_CreateObject":
        obj = CK_OBJECT_HANDLE(0)
        rv = raw.C_CreateObject(sh, None, 5, ctypes.byref(obj))
        print(f"rv={rv}")
    elif func_name == "C_FindObjectsInit":
        rv = raw.C_FindObjectsInit(sh, None, 5)
        print(f"rv={rv}")
    elif func_name == "C_GenerateKey":
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_KEY_GEN
        mech.pParameter = None
        mech.ulParameterLen = 0
        key = CK_OBJECT_HANDLE(0)
        rv = raw.C_GenerateKey(sh, ctypes.byref(mech), None, 5, ctypes.byref(key))
        print(f"rv={rv}")
    elif func_name == "C_SetAttributeValue":
        rv = raw.C_SetAttributeValue(sh, 0, None, 5)
        print(f"rv={rv}")
    else:
        raise ValueError(f"api_boundary null_template: unknown func_name {func_name!r}")


# ---------------------------------------------------------------------------
# Zero-length data probes
# ---------------------------------------------------------------------------


def _run_zero_length_aes(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Encrypt or C_Decrypt with AES_ECB/AES_CBC and zero-length data.

    Generates an AES-256 session key inside the child, calls Init then the
    operation with a zero-length input buffer, destroys the key.

    Prints ``init_rv:<int>`` then ``rv:<int>``.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    operation: str = extra["operation"]
    mech_name: str = extra["mech_name"]

    if mech_name == "CKM_AES_ECB":
        mech_id = CKM_AES_ECB
    elif mech_name == "CKM_AES_CBC":
        mech_id = CKM_AES_CBC
    else:
        raise ValueError(f"api_boundary zero_length_aes: unknown mech_name {mech_name!r}")

    if operation == "encrypt":
        c_func_name = "C_Encrypt"
        init_func_name = "C_EncryptInit"
    elif operation == "decrypt":
        c_func_name = "C_Decrypt"
        init_func_name = "C_DecryptInit"
    else:
        raise ValueError(f"api_boundary zero_length_aes: unknown operation {operation!r}")

    key = gen_aes_key(raw, sh, 256)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = mech_id
        mech.pParameter = None
        mech.ulParameterLen = 0
        if mech_name == "CKM_AES_CBC":
            iv = (ctypes.c_ubyte * 16)(*range(16))
            mech.pParameter = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
            mech.ulParameterLen = 16
        init_fn = getattr(raw, init_func_name)
        rv = init_fn(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            op_fn = getattr(raw, c_func_name)
            rv2 = op_fn(sh, None, 0, out_buf, ctypes.byref(out_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_zero_length_rsa(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Sign(CKM_SHA256_RSA_PKCS) with zero-length data.

    Generates an RSA-2048 session keypair inside the child, calls C_SignInit
    then C_Sign with zero-length input, destroys both keys.

    Prints ``init_rv:<int>`` then ``rv:<int>``.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            sig_len = CK_ULONG(512)
            sig_buf = (ctypes.c_ubyte * 512)()
            rv2 = raw.C_Sign(sh, None, 0, sig_buf, ctypes.byref(sig_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_zero_length_ecdsa(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Sign(CKM_ECDSA_SHA256) with zero-length data on secp256r1.

    Generates an EC session keypair inside the child, calls C_SignInit then
    C_Sign with zero-length input, destroys both keys.

    Prints ``init_rv:<int>`` then ``rv:<int>``.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    pub, priv = gen_ec_keypair(
        raw,
        sh,
        _SECP256R1_OID,
        private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDSA_SHA256
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            sig_len = CK_ULONG(256)
            sig_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_Sign(sh, None, 0, sig_buf, ctypes.byref(sig_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


# ---------------------------------------------------------------------------
# Login NULL pin probe
# ---------------------------------------------------------------------------


def _run_login_null_pin(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Login(sh, CKU_USER, NULL, 8) -- NULL pin pointer with non-zero length.

    Parent passes ``pin=None`` to ``run_probe`` so no auto-login occurs before
    this call (mirrors the original ``subprocess_session_preamble(pin=None)``).

    Prints ``rv:<int>`` unconditionally.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    rv = ctx.raw.C_Login(sh, int(CKU_USER), None, 8)
    print(f"rv={rv}")


# ---------------------------------------------------------------------------
# RSA extreme / zero key-size probes
# ---------------------------------------------------------------------------


def _run_generate_rsa_extreme(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateKeyPair with CKA_MODULUS_BITS=0xFFFFFFFF (extreme key size).

    A module that doesn't validate CKA_MODULUS_BITS before allocating memory
    could hang or exhaust resources.  The parent enforces a 5-second timeout.

    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    bits_val = ctypes.c_ulong(0xFFFFFFFF)
    exp_bytes = (ctypes.c_ubyte * 3)(0x01, 0x00, 0x01)
    token_false = ctypes.c_ubyte(0)

    pub_attrs = (CK_ATTRIBUTE * 4)()
    pub_attrs[0].type = CKA_MODULUS_BITS
    pub_attrs[0].pValue = ctypes.cast(ctypes.pointer(bits_val), ctypes.c_void_p)
    pub_attrs[0].ulValueLen = ctypes.sizeof(bits_val)
    pub_attrs[1].type = CKA_PUBLIC_EXPONENT
    pub_attrs[1].pValue = ctypes.cast(ctypes.pointer(exp_bytes), ctypes.c_void_p)
    pub_attrs[1].ulValueLen = 3
    pub_attrs[2].type = CKA_TOKEN
    pub_attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    pub_attrs[2].ulValueLen = 1
    enc_true = ctypes.c_ubyte(1)
    pub_attrs[3].type = CKA_ENCRYPT
    pub_attrs[3].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
    pub_attrs[3].ulValueLen = 1

    priv_attrs = (CK_ATTRIBUTE * 2)()
    priv_token = ctypes.c_ubyte(0)
    priv_attrs[0].type = CKA_TOKEN
    priv_attrs[0].pValue = ctypes.cast(ctypes.pointer(priv_token), ctypes.c_void_p)
    priv_attrs[0].ulValueLen = 1
    dec_true = ctypes.c_ubyte(1)
    priv_attrs[1].type = CKA_DECRYPT
    priv_attrs[1].pValue = ctypes.cast(ctypes.pointer(dec_true), ctypes.c_void_p)
    priv_attrs[1].ulValueLen = 1

    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        ctypes.byref(mech),
        ctypes.cast(pub_attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.cast(priv_attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        2,
        ctypes.byref(pub_h),
        ctypes.byref(priv_h),
    )
    print(f"rv={rv}")


def _run_generate_rsa_zero(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateKeyPair with CKA_MODULUS_BITS=0 (zero key size -- invalid).

    A zero modulus size is invalid; the module should reject it cleanly.

    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    bits_val = ctypes.c_ulong(0)
    exp_bytes = (ctypes.c_ubyte * 3)(0x01, 0x00, 0x01)
    token_false = ctypes.c_ubyte(0)

    pub_attrs = (CK_ATTRIBUTE * 4)()
    pub_attrs[0].type = CKA_MODULUS_BITS
    pub_attrs[0].pValue = ctypes.cast(ctypes.pointer(bits_val), ctypes.c_void_p)
    pub_attrs[0].ulValueLen = ctypes.sizeof(bits_val)
    pub_attrs[1].type = CKA_PUBLIC_EXPONENT
    pub_attrs[1].pValue = ctypes.cast(ctypes.pointer(exp_bytes), ctypes.c_void_p)
    pub_attrs[1].ulValueLen = 3
    pub_attrs[2].type = CKA_TOKEN
    pub_attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    pub_attrs[2].ulValueLen = 1
    enc_true = ctypes.c_ubyte(1)
    pub_attrs[3].type = CKA_ENCRYPT
    pub_attrs[3].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
    pub_attrs[3].ulValueLen = 1

    priv_attrs = (CK_ATTRIBUTE * 2)()
    priv_token = ctypes.c_ubyte(0)
    priv_attrs[0].type = CKA_TOKEN
    priv_attrs[0].pValue = ctypes.cast(ctypes.pointer(priv_token), ctypes.c_void_p)
    priv_attrs[0].ulValueLen = 1
    dec_true = ctypes.c_ubyte(1)
    priv_attrs[1].type = CKA_DECRYPT
    priv_attrs[1].pValue = ctypes.cast(ctypes.pointer(dec_true), ctypes.c_void_p)
    priv_attrs[1].ulValueLen = 1

    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        ctypes.byref(mech),
        ctypes.cast(pub_attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.cast(priv_attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        2,
        ctypes.byref(pub_h),
        ctypes.byref(priv_h),
    )
    print(f"rv={rv}")


# ---------------------------------------------------------------------------
# AES extreme key-size probe
# ---------------------------------------------------------------------------


def _run_generate_aes_extreme(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateKey with CKA_VALUE_LEN=ULONG_MAX.

    A module that doesn't validate CKA_VALUE_LEN before allocating memory could
    crash or exhaust resources.

    Prints ``rv:<int>`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_KEY_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    val_len = ctypes.c_ulong(_CK_ULONG_MAX)
    token_false = ctypes.c_ubyte(0)
    enc_true = ctypes.c_ubyte(1)

    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_VALUE_LEN
    attrs[0].pValue = ctypes.cast(ctypes.pointer(val_len), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(val_len)
    attrs[1].type = CKA_TOKEN
    attrs[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[1].ulValueLen = 1
    attrs[2].type = CKA_ENCRYPT
    attrs[2].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
    attrs[2].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(
        sh,
        ctypes.byref(mech),
        ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        3,
        ctypes.byref(key),
    )
    print(f"rv={rv}")


# ---------------------------------------------------------------------------
# Dispatch table and entry point
# ---------------------------------------------------------------------------


_DISPATCH = {
    "session_handle": _run_session_handle,
    "object_handle": _run_object_handle,
    "null_mechanism_init": _run_null_mechanism_init,
    "mechanism_param_null": _run_mechanism_param_null,
    "null_template": _run_null_template,
    "zero_length_aes": _run_zero_length_aes,
    "zero_length_rsa": _run_zero_length_rsa,
    "zero_length_ecdsa": _run_zero_length_ecdsa,
    "login_null_pin": _run_login_null_pin,
    "generate_rsa_extreme": _run_generate_rsa_extreme,
    "generate_rsa_zero": _run_generate_rsa_zero,
    "generate_aes_extreme": _run_generate_aes_extreme,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which: str = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"api_boundary probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
