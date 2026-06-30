"""Probe: NULL pointer + non-zero length crash probes for PKCS#11 data operations.

Ports the f-string child-script bodies from security/test_ffi_null_pointer.py into
dispatchable probe functions.  Output protocol lines are byte-identical to the
originals so the parent classifiers require no changes.

All probes run at Level.LOGIN.  Parent passes ``pin=None`` for no-login probes
(init_pin_null, set_pin_*, init_token_*) so no auto-login occurs before the
explicit C_Login / token-management call.

Dispatch on ``params.extra["which"]``:

NULL data in multi-part Update operations:
  ``"update_encrypt"``   -- C_EncryptInit + C_EncryptUpdate(data=NULL, len=32)
  ``"update_decrypt"``   -- C_DecryptInit + C_DecryptUpdate(data=NULL, len=32)
  ``"update_sign"``      -- C_SignInit + C_SignUpdate(data=NULL, len=32)
  ``"update_verify"``    -- C_VerifyInit + C_VerifyUpdate(data=NULL, len=32)
  ``"update_digest"``    -- C_DigestInit + C_DigestUpdate(data=NULL, len=32)

NULL output buffer in Final operations:
  ``"final_encrypt"``    -- C_EncryptInit + C_EncryptUpdate + C_EncryptFinal(out=NULL)
  ``"final_decrypt"``    -- C_DecryptInit + C_DecryptUpdate + C_DecryptFinal(out=NULL)
  ``"final_sign"``       -- C_SignInit + C_SignUpdate + C_SignFinal(out=NULL)
  ``"final_digest"``     -- C_DigestInit + C_DigestUpdate + C_DigestFinal(out=NULL)

NULL buffer in random operations:
  ``"seed_random"``      -- C_SeedRandom(data=NULL, len=32)
  ``"generate_random"``  -- C_GenerateRandom(buf=NULL, len=32)

NULL PIN / state / wrapped-key:
  ``"init_pin_null"``            -- C_InitPIN(pin=NULL, len=8); parent passes pin=None
  ``"set_pin_null_old_pin"``     -- C_SetPIN(old=NULL, old_len=8, new=valid, new_len=4)
  ``"set_pin_null_new_pin"``     -- C_SetPIN(old=valid, old_len=4, new=NULL, new_len=8)
  ``"set_operation_state_null"`` -- C_SetOperationState(state=NULL, len=32)
  ``"unwrap_key_null_data"``     -- C_UnwrapKey(wrapped=NULL, wrapped_len=32)

HMAC-General NULL mechanism parameter:
  ``"hmac_general_null_param"``  -- C_SignInit(CKM_SHA256_HMAC_GENERAL, pParam=NULL, len=8)

NULL data in one-shot operations:
  ``"oneshot_encrypt"``  -- C_EncryptInit + C_Encrypt(data=NULL, len=32)
  ``"oneshot_decrypt"``  -- C_DecryptInit + C_Decrypt(data=NULL, len=32)
  ``"oneshot_sign"``     -- C_SignInit + C_Sign(data=NULL, len=32)
  ``"oneshot_verify"``   -- C_VerifyInit + C_Verify(data=NULL, len=32)
  ``"oneshot_digest"``   -- C_DigestInit + C_Digest(data=NULL, len=32)

v3.0 Message API NULL plaintext/ciphertext:
  ``"encrypt_message_null_plaintext"``  -- C_EncryptMessage(plaintext=NULL, len=32)
  ``"decrypt_message_null_ciphertext"`` -- C_DecryptMessage(ciphertext=NULL, len=32)

v3.2 KEM NULL ciphertext:
  ``"decapsulate_key_null_ciphertext"`` -- C_DecapsulateKey(ct=NULL, ct_len=32)

NULL PIN / label in C_InitToken:
  ``"init_token_null_pin"``   -- C_InitToken(pin=NULL, pin_len=8, label=valid)
  ``"init_token_null_label"`` -- C_InitToken(pin=valid, pin_len=4, label=NULL)
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, import_secret_key
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UTF8CHAR_PTR,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKG_GENERATE,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_HMAC_GENERAL,
    CKO_SECRET_KEY,
    CKR_OK,
    CKU_SO,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# ---------------------------------------------------------------------------
# NULL data pointer in multi-part Update operations
# ---------------------------------------------------------------------------


def _run_update_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit + C_EncryptUpdate(data=NULL, len=32) via AES-CBC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = gen_aes_key(raw, sh, 256)
    try:
        iv = (ctypes.c_ubyte * 16)(*range(16))
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CBC
        mech.pParameter = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
        mech.ulParameterLen = 16
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_EncryptUpdate(sh, None, 32, out_buf, ctypes.byref(out_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_update_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptInit + C_DecryptUpdate(data=NULL, len=32) via AES-CBC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = gen_aes_key(raw, sh, 256)
    try:
        iv = (ctypes.c_ubyte * 16)(*range(16))
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CBC
        mech.pParameter = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
        mech.ulParameterLen = 16
        rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_DecryptUpdate(sh, None, 32, out_buf, ctypes.byref(out_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_update_sign(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignInit + C_SignUpdate(data=NULL, len=32) via SHA256-HMAC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = import_secret_key(
        raw,
        sh,
        CKK_GENERIC_SECRET,
        b"\x00" * 32,
        attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            rv2 = raw.C_SignUpdate(sh, None, 32)
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_update_verify(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_VerifyInit + C_VerifyUpdate(data=NULL, len=32) via SHA256-HMAC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = import_secret_key(
        raw,
        sh,
        CKK_GENERIC_SECRET,
        b"\x00" * 32,
        attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            rv2 = raw.C_VerifyUpdate(sh, None, 32)
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_update_digest(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DigestInit + C_DigestUpdate(data=NULL, len=32) via SHA-256."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        rv2 = raw.C_DigestUpdate(sh, None, 32)
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")


# ---------------------------------------------------------------------------
# NULL output buffer in Final operations
# ---------------------------------------------------------------------------


def _run_final_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit + C_EncryptUpdate + C_EncryptFinal(out=NULL) via AES-CBC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = gen_aes_key(raw, sh, 256)
    try:
        iv = (ctypes.c_ubyte * 16)(*range(16))
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CBC
        mech.pParameter = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
        mech.ulParameterLen = 16
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            data = (ctypes.c_ubyte * 16)(*range(16))
            upd_len = CK_ULONG(256)
            upd_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_EncryptUpdate(sh, data, 16, upd_buf, ctypes.byref(upd_len))
            print(f"update_rv={rv2}")
            if rv2 == CKR_OK:
                fin_len = CK_ULONG(32)
                rv3 = raw.C_EncryptFinal(sh, None, ctypes.byref(fin_len))
                print(f"rv={rv3}")
            else:
                print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_final_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptInit + C_DecryptUpdate + C_DecryptFinal(out=NULL) via AES-CBC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = gen_aes_key(raw, sh, 256)
    try:
        iv = (ctypes.c_ubyte * 16)(*range(16))
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CBC
        mech.pParameter = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
        mech.ulParameterLen = 16
        rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            data = (ctypes.c_ubyte * 16)(*range(16))
            upd_len = CK_ULONG(256)
            upd_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_DecryptUpdate(sh, data, 16, upd_buf, ctypes.byref(upd_len))
            print(f"update_rv={rv2}")
            if rv2 == CKR_OK:
                fin_len = CK_ULONG(32)
                rv3 = raw.C_DecryptFinal(sh, None, ctypes.byref(fin_len))
                print(f"rv={rv3}")
            else:
                print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_final_sign(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignInit + C_SignUpdate + C_SignFinal(out=NULL) via SHA256-HMAC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = import_secret_key(
        raw,
        sh,
        CKK_GENERIC_SECRET,
        b"\x00" * 32,
        attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            data = (ctypes.c_ubyte * 16)(*range(16))
            rv2 = raw.C_SignUpdate(sh, data, 16)
            print(f"update_rv={rv2}")
            if rv2 == CKR_OK:
                sig_len = CK_ULONG(512)
                rv3 = raw.C_SignFinal(sh, None, ctypes.byref(sig_len))
                print(f"rv={rv3}")
            else:
                print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_final_digest(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DigestInit + C_DigestUpdate + C_DigestFinal(out=NULL) via SHA-256."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        rv2 = raw.C_DigestUpdate(sh, data, 16)
        print(f"update_rv={rv2}")
        if rv2 == CKR_OK:
            dig_len = CK_ULONG(64)
            rv3 = raw.C_DigestFinal(sh, None, ctypes.byref(dig_len))
            print(f"rv={rv3}")
        else:
            print(f"rv={rv2}")
    else:
        print(f"rv={rv}")


# ---------------------------------------------------------------------------
# NULL buffer in random operations
# ---------------------------------------------------------------------------


def _run_seed_random(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SeedRandom(data=NULL, len=32)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    rv = raw.C_SeedRandom(sh, None, 32)
    print(f"rv={rv}")


def _run_generate_random(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateRandom(buf=NULL, len=32)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    rv = raw.C_GenerateRandom(sh, None, 32)
    print(f"rv={rv}")


# ---------------------------------------------------------------------------
# NULL PIN / state / wrapped-key
# ---------------------------------------------------------------------------


def _run_init_pin_null(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Login(SO, NULL, 0) then C_InitPIN(pin=NULL, len=8).

    Parent passes ``pin=None`` so no auto-login occurs before this call.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    rv_login = raw.C_Login(sh, CKU_SO, None, 0)
    print(f"so_login_rv={rv_login}")
    rv = raw.C_InitPIN(sh, None, 8)
    print(f"rv={rv}")


def _run_set_pin_null_old_pin(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SetPIN(old=NULL, old_len=8, new=valid, new_len=4).

    Parent passes ``pin=None`` so no auto-login occurs before this call.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    pin_buf = (ctypes.c_ubyte * 4)(0x31, 0x32, 0x33, 0x34)
    rv = raw.C_SetPIN(
        sh,
        None,
        8,
        ctypes.cast(ctypes.pointer(pin_buf), CK_UTF8CHAR_PTR),
        4,
    )
    print(f"rv={rv}")


def _run_set_pin_null_new_pin(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SetPIN(old=valid, old_len=4, new=NULL, new_len=8).

    Parent passes ``pin=None`` so no auto-login occurs before this call.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    pin_buf = (ctypes.c_ubyte * 4)(0x31, 0x32, 0x33, 0x34)
    rv = raw.C_SetPIN(
        sh,
        ctypes.cast(ctypes.pointer(pin_buf), CK_UTF8CHAR_PTR),
        4,
        None,
        8,
    )
    print(f"rv={rv}")


def _run_set_operation_state_null(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SetOperationState(state=NULL, len=32)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    rv = raw.C_SetOperationState(sh, None, 32, 0, 0)
    print(f"rv={rv}")


def _run_unwrap_key_null_data(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_UnwrapKey(wrapped=NULL, wrapped_len=32) with AES-ECB wrapping key."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    wrap_key = gen_aes_key(raw, sh, 256, attrs={CKA_UNWRAP: True})
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        token_false = ctypes.c_ubyte(0)
        attr = CK_ATTRIBUTE()
        attr.type = CKA_TOKEN
        attr.pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
        attr.ulValueLen = 1
        out_key = CK_OBJECT_HANDLE(0)
        rv = raw.C_UnwrapKey(
            sh,
            ctypes.byref(mech),
            wrap_key,
            None,
            32,
            ctypes.pointer(attr),
            1,
            ctypes.byref(out_key),
        )
        print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, wrap_key)


# ---------------------------------------------------------------------------
# HMAC-General NULL mechanism parameter
# ---------------------------------------------------------------------------


def _run_hmac_general_null_param(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignInit(CKM_SHA256_HMAC_GENERAL, pParameter=NULL, ulParameterLen=8)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = import_secret_key(
        raw,
        sh,
        CKK_GENERIC_SECRET,
        b"\x00" * 32,
        attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC_GENERAL
        mech.pParameter = None
        mech.ulParameterLen = 8  # sizeof(CK_ULONG) on 64-bit
        rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
        print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


# ---------------------------------------------------------------------------
# NULL data pointer in one-shot operations
# ---------------------------------------------------------------------------


def _run_oneshot_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit + C_Encrypt(data=NULL, len=32) via AES-ECB."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = gen_aes_key(raw, sh, 256)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_Encrypt(sh, None, 32, out_buf, ctypes.byref(out_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_oneshot_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptInit + C_Decrypt(data=NULL, len=32) via AES-ECB."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = gen_aes_key(raw, sh, 256)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_Decrypt(sh, None, 32, out_buf, ctypes.byref(out_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_oneshot_sign(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignInit + C_Sign(data=NULL, len=32) via SHA256-HMAC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = import_secret_key(
        raw,
        sh,
        CKK_GENERIC_SECRET,
        b"\x00" * 32,
        attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            sig_len = CK_ULONG(512)
            sig_buf = (ctypes.c_ubyte * 512)()
            rv2 = raw.C_Sign(sh, None, 32, sig_buf, ctypes.byref(sig_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_oneshot_verify(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_VerifyInit + C_Verify(data=NULL, len=32) via SHA256-HMAC."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    key = import_secret_key(
        raw,
        sh,
        CKK_GENERIC_SECRET,
        b"\x00" * 32,
        attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            fake_sig = (ctypes.c_ubyte * 32)(*([0xAA] * 32))
            rv2 = raw.C_Verify(sh, None, 32, fake_sig, 32)
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_oneshot_digest(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DigestInit + C_Digest(data=NULL, len=32) via SHA-256."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        dig_len = CK_ULONG(64)
        digest_buf = (ctypes.c_ubyte * 64)()
        rv2 = raw.C_Digest(sh, None, 32, digest_buf, ctypes.byref(dig_len))
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")


# ---------------------------------------------------------------------------
# v3.0 Message API NULL plaintext / ciphertext
# ---------------------------------------------------------------------------


def _run_encrypt_message_null_plaintext(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_MessageEncryptInit + C_EncryptMessage(plaintext=NULL, len=32) via AES-GCM.

    Prints ``not_supported`` and returns if C_MessageEncryptInit is absent.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    if "C_MessageEncryptInit" not in raw.available_function_names():
        print("not_supported")
        return
    key = gen_aes_key(raw, sh, 256)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_MessageEncryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            iv_buf = (ctypes.c_ubyte * 12)()
            tag_buf = (ctypes.c_ubyte * 16)()
            params = CK_GCM_MESSAGE_PARAMS()
            params.pIv = ctypes.cast(ctypes.pointer(iv_buf), ctypes.c_void_p)
            params.ulIvLen = 12
            params.ulIvFixedBits = 0
            params.ivGenerator = CKG_GENERATE
            params.pTag = ctypes.cast(ctypes.pointer(tag_buf), ctypes.c_void_p)
            params.ulTagBits = 128
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_EncryptMessage(
                sh,
                ctypes.cast(ctypes.pointer(params), ctypes.c_void_p),
                ctypes.sizeof(params),
                None,
                0,
                None,
                32,
                out_buf,
                ctypes.byref(out_len),
            )
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_message_null_ciphertext(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_MessageDecryptInit + C_DecryptMessage(ciphertext=NULL, len=32) via AES-GCM.

    Prints ``not_supported`` and returns if C_MessageDecryptInit is absent.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    if "C_MessageDecryptInit" not in raw.available_function_names():
        print("not_supported")
        return
    key = gen_aes_key(raw, sh, 256)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_MessageDecryptInit(sh, ctypes.byref(mech), key)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            iv_buf = (ctypes.c_ubyte * 12)(*range(12))
            tag_buf = (ctypes.c_ubyte * 16)()
            params = CK_GCM_MESSAGE_PARAMS()
            params.pIv = ctypes.cast(ctypes.pointer(iv_buf), ctypes.c_void_p)
            params.ulIvLen = 12
            params.ulIvFixedBits = 0
            params.ivGenerator = CKG_GENERATE
            params.pTag = ctypes.cast(ctypes.pointer(tag_buf), ctypes.c_void_p)
            params.ulTagBits = 128
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = raw.C_DecryptMessage(
                sh,
                ctypes.cast(ctypes.pointer(params), ctypes.c_void_p),
                ctypes.sizeof(params),
                None,
                0,
                None,
                32,
                out_buf,
                ctypes.byref(out_len),
            )
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


# ---------------------------------------------------------------------------
# v3.2 KEM NULL ciphertext
# ---------------------------------------------------------------------------


def _run_decapsulate_key_null_ciphertext(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecapsulateKey(ct=NULL, ct_len=32) with AES-ECB decap key.

    Prints ``not_supported`` and returns if C_DecapsulateKey is absent.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    if "C_DecapsulateKey" not in raw.available_function_names():
        print("not_supported")
        return
    key = gen_aes_key(raw, sh, 256)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        token_false = ctypes.c_ubyte(0)
        cls_val = CK_ULONG(CKO_SECRET_KEY)
        kt_val = CK_ULONG(CKK_AES)
        vl_val = CK_ULONG(16)
        attrs = (CK_ATTRIBUTE * 4)()
        attrs[0].type = CKA_CLASS
        attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        attrs[0].ulValueLen = ctypes.sizeof(CK_ULONG)
        attrs[1].type = CKA_KEY_TYPE
        attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
        attrs[1].ulValueLen = ctypes.sizeof(CK_ULONG)
        attrs[2].type = CKA_TOKEN
        attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
        attrs[2].ulValueLen = 1
        attrs[3].type = CKA_VALUE_LEN
        attrs[3].pValue = ctypes.cast(ctypes.pointer(vl_val), ctypes.c_void_p)
        attrs[3].ulValueLen = ctypes.sizeof(CK_ULONG)
        out_key = CK_OBJECT_HANDLE(0)
        rv = raw.C_DecapsulateKey(
            sh,
            ctypes.byref(mech),
            key,
            ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            None,
            32,
            ctypes.byref(out_key),
        )
        print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


# ---------------------------------------------------------------------------
# NULL PIN / label in C_InitToken
# ---------------------------------------------------------------------------


def _run_init_token_null_pin(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_InitToken(pin=NULL, pin_len=8, label=valid).

    Parent passes ``pin=None`` so no auto-login occurs.  Uses ``ctx.slot_id``
    which is always resolved by session.py before run_fn is called.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    assert ctx.slot_id is not None, "probe requires slot_id"
    slot_id = ctx.slot_id
    label_bytes = b"test_label" + b" " * 22  # 32-byte padded label
    label_buf = (ctypes.c_ubyte * 32)(*label_bytes)
    rv = raw.C_InitToken(
        slot_id,
        None,
        8,
        ctypes.cast(ctypes.pointer(label_buf), CK_UTF8CHAR_PTR),
    )
    print(f"rv={rv}")


def _run_init_token_null_label(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_InitToken(pin=valid, pin_len=4, label=NULL).

    Parent passes ``pin=None`` so no auto-login occurs.  Uses ``ctx.slot_id``
    which is always resolved by session.py before run_fn is called.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    assert ctx.slot_id is not None, "probe requires slot_id"
    slot_id = ctx.slot_id
    pin_buf = (ctypes.c_ubyte * 4)(0x31, 0x32, 0x33, 0x34)
    rv = raw.C_InitToken(
        slot_id,
        ctypes.cast(ctypes.pointer(pin_buf), CK_UTF8CHAR_PTR),
        4,
        None,
    )
    print(f"rv={rv}")


# ---------------------------------------------------------------------------
# Dispatch table and entry point
# ---------------------------------------------------------------------------


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "update_encrypt": _run_update_encrypt,
    "update_decrypt": _run_update_decrypt,
    "update_sign": _run_update_sign,
    "update_verify": _run_update_verify,
    "update_digest": _run_update_digest,
    "final_encrypt": _run_final_encrypt,
    "final_decrypt": _run_final_decrypt,
    "final_sign": _run_final_sign,
    "final_digest": _run_final_digest,
    "seed_random": _run_seed_random,
    "generate_random": _run_generate_random,
    "init_pin_null": _run_init_pin_null,
    "set_pin_null_old_pin": _run_set_pin_null_old_pin,
    "set_pin_null_new_pin": _run_set_pin_null_new_pin,
    "set_operation_state_null": _run_set_operation_state_null,
    "unwrap_key_null_data": _run_unwrap_key_null_data,
    "hmac_general_null_param": _run_hmac_general_null_param,
    "oneshot_encrypt": _run_oneshot_encrypt,
    "oneshot_decrypt": _run_oneshot_decrypt,
    "oneshot_sign": _run_oneshot_sign,
    "oneshot_verify": _run_oneshot_verify,
    "oneshot_digest": _run_oneshot_digest,
    "encrypt_message_null_plaintext": _run_encrypt_message_null_plaintext,
    "decrypt_message_null_ciphertext": _run_decrypt_message_null_ciphertext,
    "decapsulate_key_null_ciphertext": _run_decapsulate_key_null_ciphertext,
    "init_token_null_pin": _run_init_token_null_pin,
    "init_token_null_label": _run_init_token_null_label,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which: str = extra["which"]
    assert ctx.sh is not None, f"probe requires a session (Level.LOGIN), got which={which!r}"
    handler = _DISPATCH.get(which)
    if handler is None:
        raise ValueError(f"unknown which={which!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
