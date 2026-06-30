"""Probe: oversized ``CKA_VALUE_LEN`` in secret-key templates.

Covers entry points not exercised by the key-generation overflow probes.  The
target bug class is storing a caller-supplied secret-key length before validating
it, then reusing that stored length during cleanup, digest, derive, unwrap, copy,
or zeroization.

Output protocol (preserved verbatim for parent classifiers):
  SETUP_XFAIL:<reason>          -- setup rejected; parent xfails as not_operational
  TARGET_RV:0x%08x              -- return value from the probed call
  TARGET_RV_NAME:<name>         -- human-readable name (only some dispatch keys)
  VALUE_LEN_RV:0x%08x           -- C_GetAttributeValue rv for CKA_VALUE_LEN check
  VALUE_LEN_VALUE:<int>         -- actual CKA_VALUE_LEN if readable
  CONTROL_BEGIN:<n>             -- generate_generic_secret: begin control run
  CONTROL_RV:0x%08x             -- generate_generic_secret: rv for control run
  CONTROL_RV_NAME:<name>        -- generate_generic_secret: name for control rv
  CONTROL_VALUE_LEN_RV:0x%08x  -- get_value_len: rv for control key length read
  CONTROL_VALUE_LEN:<int>       -- get_value_len: length of control key
  TARGET_BEGIN:<n>              -- generate_generic_secret: begin target run
  TARGET_RV_NAME:<name>         -- generate_generic_secret: name for target rv

Dispatch on ``extra["which"]``:
  ``"create_object"``         -- C_CreateObject with oversized CKA_VALUE_LEN
  ``"copy_secret_key"``       -- C_CopyObject output template with oversized len
  ``"set_secret_key_attr"``   -- C_SetAttributeValue with oversized len
  ``"digest_key"``            -- C_DigestKey after importing a bad-length key
  ``"aes_ecb_unwrap"``        -- C_UnwrapKey output template with oversized len
  ``"generate_generic_secret"`` -- C_GenerateKey(GENERIC_SECRET) with oversized len
  ``"generate_pbkdf2"``       -- C_GenerateKey(PBKDF2) with oversized len
  ``"hkdf_derive"``           -- C_DeriveKey(HKDF) output template with large len

Required extra keys per dispatch value:
  ``"create_object"``:  ``key_type_name`` (str), ``include_value`` (bool)
  ``"hkdf_derive"``:    ``output_value_len`` (int)
  All others:           no extra keys required
"""

from __future__ import annotations

import ctypes
import hashlib
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.recipes import wrap_key as wrap_key_recipe
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    _CK_ULONG_MAX,
    CK_ATTRIBUTE,
    CK_HKDF_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKF_HKDF_SALT_NULL,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_HKDF_DERIVE,
    CKM_PKCS5_PBKD2,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    CKZ_SALT_SPECIFIED,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known

# CK_ULONG-width max (2^64-1 on LP64, 2^32-1 on Win64 LLP64).
_ULONG_MAX = int(_CK_ULONG_MAX)
_HKDF_SHA256_MAX_OUTPUT = 255 * 32

# Clean rejections acceptable when setting up the AES-ECB unwrap probe.
_WRAP_SETUP_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)

_KEY_TYPE_MAP = {
    "CKK_GENERIC_SECRET": CKK_GENERIC_SECRET,
    "CKK_AES": CKK_AES,
}


class _SetupXfailError(Exception):
    """Internal signal: a clean setup rejection was encountered; SETUP_XFAIL already printed."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _assert_value_len_not_toxic(raw: Any, sh: int, obj: int, context: str) -> None:
    """Assert that CKA_VALUE_LEN on *obj* does not equal the oversized probe value.

    Output protocol: VALUE_LEN_RV:0x%08x; if CKR_OK also VALUE_LEN_VALUE:%d.
    Raises AssertionError if the stored length is _ULONG_MAX (toxic).
    """
    actual_len = CK_ULONG(0)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_VALUE_LEN
    attr.pValue = ctypes.cast(ctypes.pointer(actual_len), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(actual_len)
    rv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(attr), 1)
    print(f"VALUE_LEN_RV:0x{rv:08x}")
    if rv == CKR_OK:
        print(f"VALUE_LEN_VALUE:{int(actual_len.value)}")
        if int(actual_len.value) == _ULONG_MAX:
            raise AssertionError(context + " stored oversized CKA_VALUE_LEN")


def _create_base_key(raw: Any, sh: int) -> int:
    """Create a valid 16-byte GENERIC_SECRET session key; return its handle.

    Prints SETUP_XFAIL: and raises _SetupXfailError if C_CreateObject rejects.
    """
    key_bytes = (ctypes.c_ubyte * 16)(*range(16))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_false = ctypes.c_ubyte(0)
    normal_value_len = CK_ULONG(16)

    base_tmpl = (CK_ATTRIBUTE * 5)()
    base_tmpl[0].type = CKA_CLASS
    base_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    base_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    base_tmpl[1].type = CKA_KEY_TYPE
    base_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    base_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    base_tmpl[2].type = CKA_TOKEN
    base_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    base_tmpl[2].ulValueLen = 1
    base_tmpl[3].type = CKA_VALUE
    base_tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    base_tmpl[3].ulValueLen = 16
    base_tmpl[4].type = CKA_VALUE_LEN
    base_tmpl[4].pValue = ctypes.cast(ctypes.pointer(normal_value_len), ctypes.c_void_p)
    base_tmpl[4].ulValueLen = ctypes.sizeof(normal_value_len)

    base_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(base_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(base_key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:secret-key import rejected: {ckr_name(rv)}")
        raise _SetupXfailError()
    return base_key.value


def _generate_generic_secret(
    raw: Any, sh: int, value_len: int, context: str
) -> tuple[Any, CK_OBJECT_HANDLE]:
    """Call C_GenerateKey(GENERIC_SECRET, value_len); print tagged output lines."""
    mech = CK_MECHANISM()
    mech.mechanism = CKM_GENERIC_SECRET_KEY_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    requested_len = CK_ULONG(value_len)
    token_false = ctypes.c_ubyte(0)
    sensitive_false = ctypes.c_ubyte(0)
    extractable_true = ctypes.c_ubyte(1)

    tmpl = (CK_ATTRIBUTE * 6)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    tmpl[2].type = CKA_VALUE_LEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(requested_len), ctypes.c_void_p)
    tmpl[2].ulValueLen = ctypes.sizeof(requested_len)
    tmpl[3].type = CKA_TOKEN
    tmpl[3].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    tmpl[3].ulValueLen = 1
    tmpl[4].type = CKA_SENSITIVE
    tmpl[4].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
    tmpl[4].ulValueLen = 1
    tmpl[5].type = CKA_EXTRACTABLE
    tmpl[5].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
    tmpl[5].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    print(f"{context}_BEGIN:{value_len}", flush=True)
    rv = raw.C_GenerateKey(
        sh,
        ctypes.byref(mech),
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        6,
        ctypes.byref(key),
    )
    print(f"{context}_RV:0x{rv:08x}", flush=True)
    print(f"{context}_RV_NAME:{ckr_name(rv)}", flush=True)
    return rv, key


def _get_value_len(raw: Any, sh: int, obj: int, context: str) -> int:
    """Read CKA_VALUE_LEN from *obj*; print tagged output; raise on error."""
    actual_len = CK_ULONG(0)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_VALUE_LEN
    attr.pValue = ctypes.cast(ctypes.pointer(actual_len), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(actual_len)
    rv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(attr), 1)
    print(f"{context}_VALUE_LEN_RV:0x{rv:08x}", flush=True)
    if rv != CKR_OK:
        raise AssertionError(
            f"{context} generated key but CKA_VALUE_LEN read returned {ckr_name(rv)}"
        )
    print(f"{context}_VALUE_LEN:{actual_len.value}", flush=True)
    return int(actual_len.value)


# ---------------------------------------------------------------------------
# Dispatch functions
# ---------------------------------------------------------------------------


def _run_create_object(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_CreateObject with oversized CKA_VALUE_LEN (no crash expected)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    key_type_name: str = extra["key_type_name"]
    include_value: bool = extra["include_value"]
    key_type = _KEY_TYPE_MAP[key_type_name]

    key_bytes = (ctypes.c_ubyte * 16)(*range(16))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(key_type)
    token_false = ctypes.c_ubyte(0)
    value_len = CK_ULONG(_ULONG_MAX)

    num_attrs = 5 if include_value else 4
    attrs = (CK_ATTRIBUTE * num_attrs)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(key_type_val)
    attrs[2].type = CKA_TOKEN
    attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[2].ulValueLen = 1
    attrs[3].type = CKA_VALUE_LEN
    attrs[3].pValue = ctypes.cast(ctypes.pointer(value_len), ctypes.c_void_p)
    attrs[3].ulValueLen = ctypes.sizeof(value_len)
    if include_value:
        attrs[4].type = CKA_VALUE
        attrs[4].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
        attrs[4].ulValueLen = 16

    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        num_attrs,
        ctypes.byref(handle),
    )
    print(f"TARGET_RV:0x{rv:08x}")
    if rv == CKR_OK:
        _assert_value_len_not_toxic(raw, sh, handle.value, "C_CreateObject")
        destroy_quietly(raw, sh, handle.value)


def _run_copy_secret_key(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CopyObject output template with oversized CKA_VALUE_LEN."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    try:
        base_key_handle = _create_base_key(raw, sh)
    except _SetupXfailError:
        return

    copy_key = CK_OBJECT_HANDLE(0)
    try:
        bad_value_len = CK_ULONG(_ULONG_MAX)
        bad_attr = CK_ATTRIBUTE()
        bad_attr.type = CKA_VALUE_LEN
        bad_attr.pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
        bad_attr.ulValueLen = ctypes.sizeof(bad_value_len)
        rv = raw.C_CopyObject(
            sh,
            base_key_handle,
            ctypes.byref(bad_attr),
            1,
            ctypes.byref(copy_key),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        if rv == CKR_OK:
            _assert_value_len_not_toxic(raw, sh, copy_key.value, "C_CopyObject")
    finally:
        if copy_key.value:
            destroy_quietly(raw, sh, copy_key.value)
        destroy_quietly(raw, sh, base_key_handle)


def _run_set_secret_key_attr(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SetAttributeValue must not persist an oversized CKA_VALUE_LEN."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    try:
        base_key_handle = _create_base_key(raw, sh)
    except _SetupXfailError:
        return

    try:
        bad_value_len = CK_ULONG(_ULONG_MAX)
        bad_attr = CK_ATTRIBUTE()
        bad_attr.type = CKA_VALUE_LEN
        bad_attr.pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
        bad_attr.ulValueLen = ctypes.sizeof(bad_value_len)
        rv = raw.C_SetAttributeValue(sh, base_key_handle, ctypes.byref(bad_attr), 1)
        print(f"TARGET_RV:0x{rv:08x}")
        if rv == CKR_OK:
            _assert_value_len_not_toxic(raw, sh, base_key_handle, "C_SetAttributeValue")
    finally:
        destroy_quietly(raw, sh, base_key_handle)


def _run_digest_key(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Digest a secret key imported with an oversized CKA_VALUE_LEN."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    if "C_DigestKey" not in raw.available_function_names():
        print("SETUP_XFAIL:C_DigestKey is not exposed by this interface")
        return

    key_material = bytes(range(16))
    key_bytes = (ctypes.c_ubyte * len(key_material)).from_buffer_copy(key_material)
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_false = ctypes.c_ubyte(0)
    sensitive_false = ctypes.c_ubyte(0)
    extractable_true = ctypes.c_ubyte(1)
    bad_value_len = CK_ULONG(_ULONG_MAX)

    key_tmpl = (CK_ATTRIBUTE * 7)()
    key_tmpl[0].type = CKA_CLASS
    key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    key_tmpl[1].type = CKA_KEY_TYPE
    key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    key_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    key_tmpl[2].type = CKA_TOKEN
    key_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    key_tmpl[2].ulValueLen = 1
    key_tmpl[3].type = CKA_VALUE_LEN
    key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
    key_tmpl[3].ulValueLen = ctypes.sizeof(bad_value_len)
    key_tmpl[4].type = CKA_VALUE
    key_tmpl[4].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    key_tmpl[4].ulValueLen = len(key_material)
    key_tmpl[5].type = CKA_SENSITIVE
    key_tmpl[5].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
    key_tmpl[5].ulValueLen = 1
    key_tmpl[6].type = CKA_EXTRACTABLE
    key_tmpl[6].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
    key_tmpl[6].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        7,
        ctypes.byref(key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:secret-key import rejected: {ckr_name(rv)}")
        return

    try:
        _assert_value_len_not_toxic(raw, sh, key.value, "C_CreateObject for C_DigestKey")

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_DigestInit(sh, ctypes.byref(mech))
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_DigestInit(CKM_SHA256) failed: {ckr_name(rv)}")
        else:
            rv = raw.C_DigestKey(sh, key.value)
            print(f"TARGET_RV:0x{rv:08x}")
            if rv == CKR_FUNCTION_NOT_SUPPORTED:
                print("SETUP_XFAIL:C_DigestKey returned CKR_FUNCTION_NOT_SUPPORTED")
            elif rv == CKR_OK:
                digest_len = CK_ULONG(0)
                rv = raw.C_DigestFinal(sh, None, ctypes.byref(digest_len))
                if rv != CKR_OK:
                    raise AssertionError(
                        "C_DigestKey returned CKR_OK but C_DigestFinal size query "
                        f"returned {ckr_name(rv)}"
                    )
                digest_buf = (ctypes.c_ubyte * digest_len.value)()
                rv = raw.C_DigestFinal(sh, digest_buf, ctypes.byref(digest_len))
                if rv != CKR_OK:
                    raise AssertionError(
                        f"C_DigestKey returned CKR_OK but C_DigestFinal returned {ckr_name(rv)}"
                    )
                actual = bytes(digest_buf[: digest_len.value])
                expected = hashlib.sha256(key_material).digest()
                if actual != expected:
                    raise AssertionError(
                        "C_DigestKey returned CKR_OK but digested bytes do not match "
                        "the imported key value"
                    )
    finally:
        destroy_quietly(raw, sh, key.value)


def _run_aes_ecb_unwrap(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_UnwrapKey output template with oversized CKA_VALUE_LEN."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    wrap_key_handle = 0
    target_key = 0
    new_key = CK_OBJECT_HANDLE(0)
    try:
        try:
            wrap_key_handle = gen_aes_key(
                raw,
                sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                },
            )
            target_key = gen_aes_key(
                raw,
                sh,
                128,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
            ):
                return
            raise

        try:
            wrapped_blob = wrap_key_recipe(raw, sh, wrap_key_handle, target_key, CKM_AES_ECB)
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, _WRAP_SETUP_REJECT_RVS, "AES-ECB key wrap setup rejected"
            ):
                return
            raise

        cls_val = CK_ULONG(CKO_SECRET_KEY)
        key_type_val = CK_ULONG(CKK_AES)
        token_false = ctypes.c_ubyte(0)
        encrypt_true = ctypes.c_ubyte(1)
        decrypt_true = ctypes.c_ubyte(1)
        bad_value_len = CK_ULONG(_ULONG_MAX)

        out_tmpl = (CK_ATTRIBUTE * 6)()
        out_tmpl[0].type = CKA_CLASS
        out_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        out_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
        out_tmpl[1].type = CKA_KEY_TYPE
        out_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
        out_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
        out_tmpl[2].type = CKA_TOKEN
        out_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
        out_tmpl[2].ulValueLen = 1
        out_tmpl[3].type = CKA_VALUE_LEN
        out_tmpl[3].pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
        out_tmpl[3].ulValueLen = ctypes.sizeof(bad_value_len)
        out_tmpl[4].type = CKA_ENCRYPT
        out_tmpl[4].pValue = ctypes.cast(ctypes.pointer(encrypt_true), ctypes.c_void_p)
        out_tmpl[4].ulValueLen = 1
        out_tmpl[5].type = CKA_DECRYPT
        out_tmpl[5].pValue = ctypes.cast(ctypes.pointer(decrypt_true), ctypes.c_void_p)
        out_tmpl[5].ulValueLen = 1

        data_buf = (ctypes.c_ubyte * len(wrapped_blob)).from_buffer_copy(wrapped_blob)
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_UnwrapKey(
            sh,
            ctypes.byref(mech),
            wrap_key_handle,
            data_buf,
            len(wrapped_blob),
            ctypes.cast(out_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            6,
            ctypes.byref(new_key),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        if rv == CKR_OK:
            _assert_value_len_not_toxic(raw, sh, new_key.value, "C_UnwrapKey")
    finally:
        if new_key.value:
            destroy_quietly(raw, sh, new_key.value)
        if target_key:
            destroy_quietly(raw, sh, target_key)
        if wrap_key_handle:
            destroy_quietly(raw, sh, wrap_key_handle)


def _run_generate_generic_secret(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateKey(GENERIC_SECRET) with oversized CKA_VALUE_LEN must reject cleanly."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    normal_key = CK_OBJECT_HANDLE(0)
    bad_key = CK_OBJECT_HANDLE(0)
    try:
        rv, normal_key = _generate_generic_secret(raw, sh, 32, "CONTROL")
        if rv != CKR_OK:
            print(
                f"SETUP_XFAIL:CKM_GENERIC_SECRET_KEY_GEN control rejected: {ckr_name(rv)}",
                flush=True,
            )
            return
        actual_len = _get_value_len(raw, sh, normal_key.value, "CONTROL")
        if actual_len != 32:
            raise AssertionError(
                f"CKM_GENERIC_SECRET_KEY_GEN generated {actual_len} bytes, expected 32"
            )

        rv, bad_key = _generate_generic_secret(raw, sh, _ULONG_MAX, "TARGET")
        if rv == CKR_OK:
            _assert_value_len_not_toxic(raw, sh, bad_key.value, "C_GenerateKey(GENERIC_SECRET)")
    finally:
        if bad_key.value:
            destroy_quietly(raw, sh, bad_key.value)
        if normal_key.value:
            destroy_quietly(raw, sh, normal_key.value)


def _run_generate_pbkdf2(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateKey(PBKDF2) with oversized CKA_VALUE_LEN must reject cleanly."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    password = (ctypes.c_ubyte * 8)(*b"password")
    salt = (ctypes.c_ubyte * 8)(*b"salt1234")

    params = CK_PKCS5_PBKD2_PARAMS2()
    params.saltSource = CKZ_SALT_SPECIFIED
    params.pSaltSourceData = ctypes.cast(salt, ctypes.c_void_p)
    params.ulSaltSourceDataLen = len(salt)
    params.iterations = 1024
    params.prf = CKP_PKCS5_PBKD2_HMAC_SHA256
    params.pPrfData = None
    params.ulPrfDataLen = 0
    params.pPassword = ctypes.cast(password, ctypes.c_void_p)
    params.ulPasswordLen = len(password)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_PKCS5_PBKD2
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    bad_value_len = CK_ULONG(_ULONG_MAX)
    token_false = ctypes.c_ubyte(0)
    sensitive_false = ctypes.c_ubyte(0)
    extractable_true = ctypes.c_ubyte(1)

    out_tmpl = (CK_ATTRIBUTE * 6)()
    out_tmpl[0].type = CKA_CLASS
    out_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    out_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    out_tmpl[1].type = CKA_KEY_TYPE
    out_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    out_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    out_tmpl[2].type = CKA_VALUE_LEN
    out_tmpl[2].pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
    out_tmpl[2].ulValueLen = ctypes.sizeof(bad_value_len)
    out_tmpl[3].type = CKA_TOKEN
    out_tmpl[3].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    out_tmpl[3].ulValueLen = 1
    out_tmpl[4].type = CKA_SENSITIVE
    out_tmpl[4].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
    out_tmpl[4].ulValueLen = 1
    out_tmpl[5].type = CKA_EXTRACTABLE
    out_tmpl[5].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
    out_tmpl[5].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(
        sh,
        ctypes.byref(mech),
        ctypes.cast(out_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        6,
        ctypes.byref(key),
    )
    print(f"TARGET_RV:0x{rv:08x}")
    print(f"TARGET_RV_NAME:{ckr_name(rv)}")
    if rv == CKR_OK:
        _assert_value_len_not_toxic(raw, sh, key.value, "C_GenerateKey(PBKDF2)")
        destroy_quietly(raw, sh, key.value)


def _run_hkdf_derive(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey(HKDF) with a large output CKA_VALUE_LEN must not crash or corrupt."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    output_value_len: int = extra["output_value_len"]

    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    derive_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)

    key_tmpl = (CK_ATTRIBUTE * 5)()
    key_tmpl[0].type = CKA_CLASS
    key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    key_tmpl[1].type = CKA_KEY_TYPE
    key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    key_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    key_tmpl[2].type = CKA_VALUE
    key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    key_tmpl[2].ulValueLen = 32
    key_tmpl[3].type = CKA_DERIVE
    key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
    key_tmpl[3].ulValueLen = 1
    key_tmpl[4].type = CKA_TOKEN
    key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    key_tmpl[4].ulValueLen = 1

    base_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(base_key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HKDF base-key import rejected: 0x{rv:08x}")
        return

    derived = CK_OBJECT_HANDLE(0)
    try:
        hkdf_params = CK_HKDF_PARAMS()
        hkdf_params.bExtract = 1
        hkdf_params.bExpand = 1
        hkdf_params.prfHashMechanism = CKM_SHA256
        hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL
        hkdf_params.pSalt = None
        hkdf_params.ulSaltLen = 0
        hkdf_params.hSaltKey = 0
        hkdf_params.pInfo = None
        hkdf_params.ulInfoLen = 0

        mech = CK_MECHANISM()
        mech.mechanism = CKM_HKDF_DERIVE
        mech.pParameter = ctypes.cast(ctypes.pointer(hkdf_params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(hkdf_params)

        out_cls = CK_ULONG(CKO_SECRET_KEY)
        out_key_type = CK_ULONG(CKK_GENERIC_SECRET)
        out_len = CK_ULONG(output_value_len)
        out_token = ctypes.c_ubyte(0)

        out_tmpl = (CK_ATTRIBUTE * 4)()
        out_tmpl[0].type = CKA_CLASS
        out_tmpl[0].pValue = ctypes.cast(ctypes.pointer(out_cls), ctypes.c_void_p)
        out_tmpl[0].ulValueLen = ctypes.sizeof(out_cls)
        out_tmpl[1].type = CKA_KEY_TYPE
        out_tmpl[1].pValue = ctypes.cast(ctypes.pointer(out_key_type), ctypes.c_void_p)
        out_tmpl[1].ulValueLen = ctypes.sizeof(out_key_type)
        out_tmpl[2].type = CKA_VALUE_LEN
        out_tmpl[2].pValue = ctypes.cast(ctypes.pointer(out_len), ctypes.c_void_p)
        out_tmpl[2].ulValueLen = ctypes.sizeof(out_len)
        out_tmpl[3].type = CKA_TOKEN
        out_tmpl[3].pValue = ctypes.cast(ctypes.pointer(out_token), ctypes.c_void_p)
        out_tmpl[3].ulValueLen = 1

        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key.value,
            ctypes.cast(out_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        if rv == CKR_OK:
            _assert_value_len_not_toxic(raw, sh, derived.value, "C_DeriveKey")
    finally:
        if derived.value:
            destroy_quietly(raw, sh, derived.value)
        destroy_quietly(raw, sh, base_key.value)


# ---------------------------------------------------------------------------
# Dispatch table and entry point
# ---------------------------------------------------------------------------

_DISPATCH = {
    "create_object": _run_create_object,
    "copy_secret_key": _run_copy_secret_key,
    "set_secret_key_attr": _run_set_secret_key_attr,
    "digest_key": _run_digest_key,
    "aes_ecb_unwrap": _run_aes_ecb_unwrap,
    "generate_generic_secret": _run_generate_generic_secret,
    "generate_pbkdf2": _run_generate_pbkdf2,
    "hkdf_derive": _run_hkdf_derive,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Dispatch to the sub-probe identified by ``extra["which"]``."""
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"secret_key_value_len probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
