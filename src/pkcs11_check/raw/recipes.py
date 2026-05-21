"""Readability recipes on top of pkcs11_check.raw.

These helpers simplify common test patterns without hiding the underlying
PKCS#11 operations. A recipe must be mentally expandable to its raw calls.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Mapping
from ctypes import byref
from typing import Any

from .api import RawPKCS11
from .attr_metadata import ATTR_VALUE_TYPES
from .bootstrap import get_slot_ids, login_user, open_session
from .pack import (
    PackedMechanism,
    attr_bytes,
    attr_ulong,
    mech_eddsa,
    mech_simple,
    template,
    template_ptr_count,
)
from .rv import expect_rv
from .types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_MECHANISM_INFO,
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_SLOT_INFO,
    CK_ULONG,
    CKA,
    CKA_BASE,
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_EXTRACTABLE,
    CKA_GOSTR3410_PARAMS,
    CKA_GOSTR3411_PARAMS,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PARAMETER_SET,
    CKA_PRIME,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK,
    CKK_AES,
    CKK_DSA,
    CKK_EC,
    CKK_GOSTR3410,
    CKK_RSA,
    CKM,
    CKM_AES_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EDDSA,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)

_VERIFY_FAIL_RVS = (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE)


def to_ubyte_buf(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    """Convert bytes to a ctypes c_ubyte array.

    Uses ``from_buffer_copy`` so large payloads (AEAD plaintext, wrapped keys,
    signed data) copy at memcpy speed instead of per-byte Python conversion
    that ``(c_ubyte * N)(*data)`` would impose.
    """
    n = len(data)
    if n == 0:
        return (ctypes.c_ubyte * 0)()
    return (ctypes.c_ubyte * n).from_buffer_copy(data)


def _resolve_mech(
    mechanism: CKM | int,
    mech_param: PackedMechanism | None,
) -> PackedMechanism:
    """Return mech_param if given, otherwise wrap mechanism as mech_simple.

    For CKM_EDDSA, always use mech_eddsa() with pure mode (no context)
    since some modules (NSS) require explicit params even for pure EdDSA.
    """
    if mech_param is not None:
        return mech_param
    if mechanism == CKM_EDDSA:
        return mech_eddsa(mechanism)
    return mech_simple(mechanism)


def _two_call_output(
    raw: RawPKCS11,
    call_fn: str,
    *args: Any,
    output_size_hint: int = 0,
    retry_on_buffer_too_small: bool = False,
) -> bytes:
    """Execute a PKCS#11 function using the standard two-call size pattern.

    ``args`` are ALL arguments before the output (buffer_ptr, buffer_len_ptr) pair,
    including session. The function appends the buffer pair automatically.

    Works for: C_Encrypt, C_Sign, C_Decrypt, C_Digest, C_WrapKey, C_GetOperationState,
    C_SignFinal, C_DigestFinal.

    NOT suitable for:
    - C_EncryptUpdate / C_DecryptUpdate (conditional zero-length output, use _multipart_output)
    - C_EncryptMessage / C_DecryptMessage (extra aad args, use _message_crypto)
    - C_EncapsulateKey (output buffer not the last arg, extra handle output after it)
    - C_GetMechanismList / C_GetSlotList / C_GetAttributeValue (non-byte array types)

    ``output_size_hint`` enables single-call mode for modules that do not support the
    NULL-buffer size-query pass (e.g. NSS softoken for AES-GCM / AES-KEY-WRAP-KWP).
    When provided, the NULL-buffer query is skipped entirely and a single call is made
    with a pre-allocated buffer of ``output_size_hint`` bytes.  The output is truncated
    to the length reported by the module after the call.

    ``retry_on_buffer_too_small`` when True, if the second call returns
    CKR_BUFFER_TOO_SMALL and the module provides a larger required size,
    re-allocates and retries once.  Needed for modules (e.g. NSS softoken)
    that under-report the required size on the NULL-buffer query (returning
    plaintext length without AEAD tag overhead).

    Per PKCS#11 spec section 5.2, the standard two-call pattern is used when
    ``output_size_hint`` is 0: first call with NULL buffer to obtain the required size,
    then second call with a properly allocated buffer.
    """
    fn = getattr(raw, call_fn)
    if output_size_hint > 0:
        # Single-call mode: allocate upfront and call once.
        # Required for modules (e.g. NSS softoken) where passing NULL on the first
        # call either fails to set the output length or consumes the operation state.
        out_len = CK_ULONG(output_size_hint)
        out_buf = (ctypes.c_ubyte * output_size_hint)()
        rv = fn(*args, out_buf, byref(out_len))
        expect_rv(rv, CKR_OK)
        return bytes(out_buf[: out_len.value])
    # Standard two-call pattern: query size with NULL, then allocate and call again.
    out_len = CK_ULONG(0)
    rv = fn(*args, None, byref(out_len))
    expect_rv(rv, CKR_OK)
    size = out_len.value
    out_buf = (ctypes.c_ubyte * size)()
    out_len = CK_ULONG(size)
    rv = fn(*args, out_buf, byref(out_len))
    if retry_on_buffer_too_small and rv == CKR_BUFFER_TOO_SMALL and out_len.value > size:
        # Module under-reported the required size but set out_len to the
        # correct value on failure.  Re-allocate and retry.
        size = out_len.value
        out_buf = (ctypes.c_ubyte * size)()
        out_len = CK_ULONG(size)
        rv = fn(*args, out_buf, byref(out_len))
    expect_rv(rv, CKR_OK)
    return bytes(out_buf[: out_len.value])


def quick_session(
    raw: RawPKCS11,
    slot_id: int | None = None,
    flags: int = CKF_SERIAL_SESSION | CKF_RW_SESSION,
    pin: bytes | None = None,
    user_type: int = 1,  # CKU_USER
) -> int:
    """Open a session and optionally login in one call.

    If slot_id is None, the first available slot with a token is used.
    """
    if slot_id is None:
        slots = get_slot_ids(raw)
        if not slots:
            raise RuntimeError("No slots with tokens found")
        slot_id = slots[0]

    sh = open_session(raw, slot_id, flags)

    if pin is not None:
        login_user(raw, sh, user_type, pin)

    return sh


def pack_attrs(
    attrs: Mapping[Any, Any] | None,
    *,
    skip: set[Any] | frozenset[Any] | None = None,
) -> list[Any]:
    """Convert a {attr_type: value} dict to a list of PackedAttributes.

    Uses attr_auto for spec-correct type packing based on ATTR_VALUE_TYPES.
    Skips attr types in skip set. Both `attrs` keys and `skip` members are
    treated as integers internally (CKA values are `int` subclasses); the
    parameter types are intentionally `Mapping[Any, Any]` / `set[Any]`
    because `dict`/`set` type parameters are invariant — narrower types
    would reject `dict[CKA, ...]` / `set[CKA]` at every callsite.
    """
    if not attrs:
        return []
    from .pack import attr_auto

    return [
        attr_auto(attr_type, value)
        for attr_type, value in attrs.items()
        if not (skip and attr_type in skip)
    ]


def gen_aes_key(
    raw: RawPKCS11,
    sh: int,
    bits: int = 256,
    attrs: Mapping[Any, Any] | None = None,
    mechanism: int = CKM_AES_KEY_GEN,
) -> int:
    """Generate an AES key with explicit attributes."""
    _defaults: dict[int, Any] = {
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
    }
    if mechanism == CKM_AES_KEY_GEN:
        _defaults[CKA_KEY_TYPE] = CKK_AES
    if attrs:
        _defaults.update(attrs)
    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(_defaults, skip={CKA_VALUE_LEN}))
    tmpl = template(*packed)
    mech = mech_simple(mechanism)
    key = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def gen_keypair(
    raw: RawPKCS11,
    session: int,
    mechanism: int,
    pub_base: list[Any],
    priv_base: list[Any],
    public_attrs: Mapping[Any, Any] | None,
    private_attrs: Mapping[Any, Any] | None,
    pub_skip: set[Any] | frozenset[Any] | None = None,
) -> tuple[int, int]:
    """Shared keypair generation logic."""
    pub_packed = pub_base + pack_attrs(public_attrs, skip=pub_skip)
    priv_packed = priv_base + pack_attrs(private_attrs)
    pub_tmpl = template(*pub_packed)
    priv_tmpl = template(*priv_packed)
    mech = mech_simple(mechanism)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKeyPair(
        session,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_handle),
        byref(priv_handle),
    )
    expect_rv(rv, CKR_OK)
    return pub_handle.value, priv_handle.value


def gen_rsa_keypair(
    raw: RawPKCS11,
    session: int,
    bits: int = 2048,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an RSA key pair. Returns (pub_handle, priv_handle)."""
    _pub_defaults: dict[CKA, Any] = {
        CKA_VERIFY: True,
        CKA_ENCRYPT: True,
        CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",  # 65537, required by NSS
    }
    _priv_defaults: dict[CKA, Any] = {CKA_SIGN: True, CKA_DECRYPT: True}
    if public_attrs:
        _pub_defaults.update(public_attrs)
    if private_attrs:
        _priv_defaults.update(private_attrs)
    return gen_keypair(
        raw,
        session,
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_MODULUS_BITS, bits)],
        priv_base=[],
        public_attrs=_pub_defaults,
        private_attrs=_priv_defaults,
        pub_skip={CKA_MODULUS_BITS},
    )


def gen_ec_keypair(
    raw: RawPKCS11,
    session: int,
    curve_oid: bytes,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an EC key pair. Returns (pub_handle, priv_handle)."""
    _pub_defaults: dict[CKA, Any] = {CKA_VERIFY: True}
    _priv_defaults: dict[CKA, Any] = {CKA_SIGN: True}
    if public_attrs:
        _pub_defaults.update(public_attrs)
    if private_attrs:
        _priv_defaults.update(private_attrs)
    return gen_keypair(
        raw,
        session,
        CKM_EC_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
        priv_base=[],
        public_attrs=_pub_defaults,
        private_attrs=_priv_defaults,
        pub_skip={CKA_EC_PARAMS},
    )


def import_secret_key(
    raw: RawPKCS11,
    session: int,
    key_type: CKK | int,
    value: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import a secret key by value using C_CreateObject."""
    base = {CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE}
    packed = [
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_bytes(CKA_VALUE, value),
    ]
    packed.extend(pack_attrs(attrs, skip=base))

    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)

    return handle.value


def import_rsa_private_key(
    raw: Any,
    session: int,
    *,
    n: bytes,
    e: bytes,
    d: bytes,
    p: bytes,
    q: bytes,
    dmp1: bytes,
    dmq1: bytes,
    iqmp: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import RSA private key from CRT components."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_MODULUS: n,
        CKA_PUBLIC_EXPONENT: e,
        CKA_PRIVATE_EXPONENT: d,
        CKA_PRIME_1: p,
        CKA_PRIME_2: q,
        CKA_EXPONENT_1: dmp1,
        CKA_EXPONENT_2: dmq1,
        CKA_COEFFICIENT: iqmp,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_rsa_public_key(
    raw: Any,
    session: int,
    *,
    n: bytes,
    e: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import RSA public key from modulus + exponent."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_TOKEN: False,
        CKA_MODULUS: n,
        CKA_PUBLIC_EXPONENT: e,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_ec_private_key(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    value: bytes,
    key_type: int = int(CKK_EC),
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import EC/Edwards/Montgomery private key from scalar.

    ``ec_params``: DER-encoded curve OID.
    ``value``: raw big-endian private scalar (or seed for EdDSA).
    ``key_type``: CKK_EC (default), CKK_EC_EDWARDS, or CKK_EC_MONTGOMERY.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_EC_PARAMS: ec_params,
        CKA_VALUE: value,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_ec_public_key(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    ec_point: bytes,
    key_type: int = int(CKK_EC),
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import EC/Edwards/Montgomery public key from point.

    ``ec_params``: DER-encoded curve OID.
    ``ec_point``: DER-wrapped public point (OCTET STRING wrapping).
    ``key_type``: CKK_EC (default), CKK_EC_EDWARDS, or CKK_EC_MONTGOMERY.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_EC_PARAMS: ec_params,
        CKA_EC_POINT: ec_point,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_pqc_private_key(
    raw: Any,
    session: int,
    *,
    key_type: int,
    value: bytes,
    parameter_set: int,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import PQC private key (ML-DSA, ML-KEM, SLH-DSA).

    ``key_type``: CKK_ML_DSA, CKK_ML_KEM, or CKK_SLH_DSA.
    ``value``: raw private key bytes.
    ``parameter_set``: CKP_* parameter set constant.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_VALUE: value,
        CKA_PARAMETER_SET: parameter_set,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_pqc_public_key(
    raw: Any,
    session: int,
    *,
    key_type: int,
    value: bytes,
    parameter_set: int,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import PQC public key (ML-DSA, SLH-DSA)."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_VALUE: value,
        CKA_PARAMETER_SET: parameter_set,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_dsa_public_key(
    raw: Any,
    session: int,
    *,
    prime: bytes,
    subprime: bytes,
    base_g: bytes,
    value: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import DSA public key from domain parameters + public value.

    ``prime``: p. ``subprime``: q. ``base_g``: g. ``value``: y.
    """
    base_attrs: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_DSA,
        CKA_TOKEN: False,
        CKA_PRIME: prime,
        CKA_SUBPRIME: subprime,
        CKA_BASE: base_g,
        CKA_VALUE: value,
    }
    if attrs:
        base_attrs.update(attrs)
    return create_object(raw, session, base_attrs)


def import_gost_private_key(
    raw: Any,
    session: int,
    *,
    gostr3410_params: bytes,
    value: bytes,
    gostr3411_params: bytes | None = None,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import GOST R 34.10-2012 private key.

    ``gostr3410_params``: DER-encoded OID for the curve parameters.
    ``value``: raw big-endian private key scalar.
    ``gostr3411_params``: optional DER-encoded hash parameter OID.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: CKK_GOSTR3410,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_GOSTR3410_PARAMS: gostr3410_params,
        CKA_VALUE: value,
    }
    if gostr3411_params is not None:
        base[CKA_GOSTR3411_PARAMS] = gostr3411_params
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_gost_public_key(
    raw: Any,
    session: int,
    *,
    gostr3410_params: bytes,
    value: bytes,
    gostr3411_params: bytes | None = None,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import GOST R 34.10-2012 public key."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_GOSTR3410,
        CKA_TOKEN: False,
        CKA_GOSTR3410_PARAMS: gostr3410_params,
        CKA_VALUE: value,
    }
    if gostr3411_params is not None:
        base[CKA_GOSTR3411_PARAMS] = gostr3411_params
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def create_object(
    raw: RawPKCS11,
    session: int,
    attrs: dict[int, Any],
) -> int:
    """Create a PKCS#11 object with arbitrary attributes. Returns handle.

    attrs maps CKA_* int constants to values (bool, int, bytes, or str).
    str values auto-encode to UTF-8. For secret key import, prefer
    import_secret_key() which handles CKA_CLASS/CKA_KEY_TYPE/CKA_VALUE.
    """
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)
    return handle.value


def destroy_quietly(raw: RawPKCS11, session: int, handle: int) -> None:
    """Destroy an object, silently ignoring any errors."""
    try:
        raw.C_DestroyObject(session, handle)
    except (AttributeError, OSError, ctypes.ArgumentError):
        pass


def encrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    plaintext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
    output_overhead: int = 0,
    retry_on_buffer_too_small: bool = False,
) -> bytes:
    """Encrypt data in a single operation. Returns ciphertext.

    ``output_overhead`` is the number of bytes the mechanism appends beyond the
    plaintext length (e.g. 16 for AES-GCM with a 128-bit tag).  This is only
    needed for modules (e.g. NSS softoken) that do not set the output length
    when called with a NULL buffer pointer during the size-query pass.

    ``retry_on_buffer_too_small`` when True, if the module returns
    CKR_BUFFER_TOO_SMALL with an updated size, re-allocates and retries once.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_EncryptInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(plaintext)
    hint = (len(plaintext) + output_overhead) if output_overhead > 0 else 0
    return _two_call_output(
        raw,
        "C_Encrypt",
        session,
        in_buf,
        len(plaintext),
        output_size_hint=hint,
        retry_on_buffer_too_small=retry_on_buffer_too_small,
    )


def sign_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign data in a single operation. Returns signature."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_SignInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(data)
    return _two_call_output(raw, "C_Sign", session, in_buf, len(data))


def decrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    ciphertext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
    retry_on_buffer_too_small: bool = False,
) -> bytes:
    """Decrypt data in a single operation. Returns plaintext.

    ``retry_on_buffer_too_small`` when True, if the module returns
    CKR_BUFFER_TOO_SMALL with an updated size, re-allocates and retries once.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_DecryptInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(ciphertext)
    return _two_call_output(
        raw,
        "C_Decrypt",
        session,
        in_buf,
        len(ciphertext),
        retry_on_buffer_too_small=retry_on_buffer_too_small,
    )


def verify_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    signature: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bool:
    """Verify a signature in a single operation.

    Returns True if verification succeeds (CKR_OK), False if CKR_SIGNATURE_INVALID
    or CKR_SIGNATURE_LEN_RANGE. Other errors raise AssertionError.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_VerifyInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)

    data_buf = to_ubyte_buf(data)
    sig_buf = to_ubyte_buf(signature)
    rv = raw.C_Verify(session, data_buf, len(data), sig_buf, len(signature))

    if rv == CKR_OK:
        return True
    if rv in _VERIFY_FAIL_RVS:
        return False
    expect_rv(rv, CKR_OK)
    return False  # unreachable


def sign_recover_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign and recover data in a single operation (C_SignRecoverInit + C_SignRecover)."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_SignRecoverInit(session, mech.byref(), key)
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        raise NotImplementedError("C_SignRecover not supported by this module")
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(data)
    return _two_call_output(raw, "C_SignRecover", session, in_buf, len(data))


def verify_recover_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    signature: bytes,
) -> tuple[bool, bytes]:
    """Verify and recover data (C_VerifyRecoverInit + C_VerifyRecover).

    Returns (True, recovered_data) on valid signature,
    (False, b"") on CKR_SIGNATURE_INVALID or CKR_SIGNATURE_LEN_RANGE.
    Raises on unexpected CKR values.

    Per PKCS#11 spec, CKR_SIGNATURE_INVALID has higher priority than
    CKR_BUFFER_TOO_SMALL for C_VerifyRecover.
    """
    mech = _resolve_mech(mechanism, None)
    rv = raw.C_VerifyRecoverInit(session, mech.byref(), key)
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        raise NotImplementedError("C_VerifyRecover not supported by this module")
    expect_rv(rv, CKR_OK)
    sig_buf = to_ubyte_buf(signature)
    rec_len = CK_ULONG(0)
    rv = raw.C_VerifyRecover(session, sig_buf, len(signature), None, byref(rec_len))
    if rv in _VERIFY_FAIL_RVS:
        return False, b""
    expect_rv(rv, CKR_OK)
    rec_buf = (ctypes.c_ubyte * rec_len.value)()
    rv = raw.C_VerifyRecover(session, sig_buf, len(signature), rec_buf, byref(rec_len))
    if rv in _VERIFY_FAIL_RVS:
        return False, b""
    expect_rv(rv, CKR_OK)
    return True, bytes(rec_buf[: rec_len.value])


def digest_single(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Digest data in a single operation. Returns digest."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(data)
    return _two_call_output(raw, "C_Digest", session, in_buf, len(data))


def digest_single_with_key(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM | int,
    key: int,
) -> bytes:
    """Digest a secret key value (C_DigestInit + C_DigestKey + C_DigestFinal).

    The key material is digested directly without exposing it outside the token.
    """
    mech = _resolve_mech(mechanism, None)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(rv, CKR_OK)
    rv = raw.C_DigestKey(session, key)
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        raise NotImplementedError("C_DigestKey not supported by this module")
    expect_rv(rv, CKR_OK)
    return _two_call_output(raw, "C_DigestFinal", session)


def read_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attr_types: list[int] | tuple[int, ...] | set[int] | frozenset[int],
) -> dict[int, Any]:
    """Read attribute values from an object.

    Returns a dict mapping attribute type to its value. Uses the generated
    ATTR_VALUE_TYPES table for spec-correct decoding: bool attrs as bool,
    ulong attrs as int, str attrs as str, date attrs as 'YYYYMMDD' str,
    ulong_array attrs as list[int], template and unknown attrs as bytes.

    Returns `dict[int, Any]` (not the precise union) because callers
    typically know the expected attribute type and call type-specific
    methods (`.hex()`, `len()`, etc.); a precise union would force
    `isinstance` narrowing at every callsite without adding safety.
    """
    count = len(attr_types)
    tmpl = (CK_ATTRIBUTE * count)()
    for i, at in enumerate(attr_types):
        tmpl[i].type = at
        tmpl[i].pValue = None
        tmpl[i].ulValueLen = 0

    # CK_UNAVAILABLE_INFORMATION sentinel: ulValueLen set to (CK_ULONG)-1 for
    # sensitive or type-invalid attributes. Some modules return 0xFFFFFFFF
    # (32-bit sentinel) even on 64-bit platforms.
    _ck_unavailable_64 = ctypes.c_ulong(-1).value  # 0xFFFFFFFFFFFFFFFF on 64-bit
    _ck_unavailable_32 = 0xFFFFFFFF

    def _is_unavailable(val: int) -> bool:
        return val == _ck_unavailable_64 or val == _ck_unavailable_32

    # First call: query sizes
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(rv, CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID)

    # Allocate buffers (skip unavailable attributes)
    buffers: list[Any] = []
    for i in range(count):
        size = tmpl[i].ulValueLen
        if _is_unavailable(size):
            buffers.append(None)
            continue
        buf = (ctypes.c_ubyte * size)()
        tmpl[i].pValue = ctypes.cast(buf, ctypes.c_void_p)
        tmpl[i].ulValueLen = size
        buffers.append(buf)

    # Second call: read values
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(rv, CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID)

    result: dict[int, bytes | int | bool | str | list[int]] = {}
    for i, at in enumerate(attr_types):
        size = tmpl[i].ulValueLen
        if _is_unavailable(size) or buffers[i] is None:
            continue  # Attribute sensitive or type invalid -- skip
        raw_bytes = bytes(buffers[i][:size])
        vtype = ATTR_VALUE_TYPES.get(at, "bytes")
        if vtype == "bool" and size == ctypes.sizeof(CK_BBOOL):
            result[at] = raw_bytes[0] != 0
        elif vtype == "ulong" and size == ctypes.sizeof(CK_ULONG):
            result[at] = int.from_bytes(raw_bytes, byteorder=sys.byteorder)
        elif vtype == "str":
            result[at] = raw_bytes.decode("utf-8")
        elif vtype == "date":
            # Return as str 'YYYYMMDD' -- callers can parse if needed
            result[at] = raw_bytes.decode("ascii") if raw_bytes else ""
        elif vtype == "ulong_array":
            # Decode CK_ULONG array
            ulong_size = ctypes.sizeof(CK_ULONG)
            count_elems = size // ulong_size
            result[at] = [
                int.from_bytes(
                    raw_bytes[j * ulong_size : (j + 1) * ulong_size],
                    byteorder=sys.byteorder,
                )
                for j in range(count_elems)
            ]
        elif vtype == "template":
            # Template attributes are complex -- return raw bytes
            # Proper decoding requires recursive CK_ATTRIBUTE parsing
            result[at] = raw_bytes
        else:
            # 'bytes' or any unrecognized type
            result[at] = raw_bytes
    return result


def get_object_size(
    raw: RawPKCS11,
    session: int,
    handle: int,
) -> int:
    """Return the size of an object in bytes."""
    size = CK_ULONG(0)
    rv = raw.C_GetObjectSize(session, handle, byref(size))
    expect_rv(rv, CKR_OK)
    return size.value


def find_objects(
    raw: RawPKCS11,
    session: int,
    tmpl: Any = None,
    *,
    max_count: int = 256,
) -> list[int]:
    """Find objects matching a template.

    tmpl can be a TemplateArg from pack.py, or None for all objects.
    Returns a list of object handles.
    """
    if tmpl is not None:
        rv = raw.C_FindObjectsInit(session, tmpl.ptr, tmpl.count)
    else:
        rv = raw.C_FindObjectsInit(session, None, 0)
    expect_rv(rv, CKR_OK)

    handles = (CK_OBJECT_HANDLE * max_count)()
    found = CK_ULONG(0)
    rv = raw.C_FindObjects(session, handles, max_count, byref(found))
    expect_rv(rv, CKR_OK)

    rv = raw.C_FindObjectsFinal(session)
    expect_rv(rv, CKR_OK)

    return [handles[i] for i in range(found.value)]


def wrap_key(
    raw: RawPKCS11,
    session: int,
    wrapping_key: int,
    target_key: int,
    mechanism: CKM | int,
    *,
    mech_param: PackedMechanism | None = None,
    output_size_hint: int = 0,
) -> bytes:
    """Wrap a key using C_WrapKey (two-call output pattern). Returns wrapped key.

    ``output_size_hint`` is used as the buffer allocation size when the module
    does not set the output length during the NULL-buffer size-query pass (e.g.
    NSS softoken for AES-KEY-WRAP-KWP).  It should be at least as large as the
    actual wrapped-key output.
    """
    mech = _resolve_mech(mechanism, mech_param)
    return _two_call_output(
        raw,
        "C_WrapKey",
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        output_size_hint=output_size_hint,
    )


def unwrap_key(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """Unwrap a key using C_UnwrapKey. Returns new key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    in_buf = to_ubyte_buf(wrapped_key)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        session,
        mech.byref(),
        unwrapping_key,
        in_buf,
        len(wrapped_key),
        *template_ptr_count(tmpl),
        byref(handle),
    )
    expect_rv(rv, CKR_OK)
    return handle.value


def derive_key(
    raw: RawPKCS11,
    session: int,
    base_key: int,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """Derive a key using C_DeriveKey. Returns new key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        session,
        mech.byref(),
        base_key,
        *template_ptr_count(tmpl),
        byref(handle),
    )
    expect_rv(rv, CKR_OK)
    return handle.value


def generate_random(raw: RawPKCS11, session: int, length: int) -> bytes:
    """Generate random bytes using C_GenerateRandom."""
    buf = (ctypes.c_ubyte * length)()
    rv = raw.C_GenerateRandom(session, buf, length)
    expect_rv(rv, CKR_OK)
    return bytes(buf)


def copy_object(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Copy an object using C_CopyObject. Returns new handle."""
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    new_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CopyObject(
        session,
        handle,
        *template_ptr_count(tmpl),
        byref(new_handle),
    )
    expect_rv(rv, CKR_OK)
    return new_handle.value


def set_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attrs: dict[int, Any],
) -> None:
    """Set attribute values on an object using C_SetAttributeValue."""
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    rv = raw.C_SetAttributeValue(session, handle, tmpl.ptr, tmpl.count)
    expect_rv(rv, CKR_OK)


# --- Multipart operation helpers ---


def _multipart_output(
    raw: RawPKCS11,
    session: int,
    init_fn: str,
    update_fn: str,
    final_fn: str,
    init_args: tuple[Any, ...],
    chunks: list[bytes] | tuple[bytes, ...],
) -> bytes:
    """Shared Init -> Update(chunks) -> Final for encrypt/decrypt.

    Only for operations where Update produces output (C_EncryptUpdate,
    C_DecryptUpdate). Sign/Digest Update calls do not produce output --
    use the manual Init+Update+_two_call_output(Final) pattern instead.
    """
    rv = getattr(raw, init_fn)(session, *init_args)
    expect_rv(rv, CKR_OK)
    parts: list[bytes] = []
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        # Allocate a conservative output buffer upfront (chunk + 256 bytes for
        # block cipher expansion). Do NOT use the two-call size-probe pattern for
        # Update functions -- probing feeds the same chunk twice, corrupting cipher
        # state. The Final two-call pattern remains correct.
        max_out = len(chunk) + 256
        out_buf = (ctypes.c_ubyte * max_out)()
        out_len = CK_ULONG(max_out)
        rv = getattr(raw, update_fn)(
            session,
            in_buf,
            len(chunk),
            out_buf,
            byref(out_len),
        )
        expect_rv(rv, CKR_OK)
        if out_len.value > 0:
            parts.append(bytes(out_buf[: out_len.value]))
    parts.append(_two_call_output(raw, final_fn, session))
    return b"".join(parts)


def encrypt_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Encrypt data in multiple parts. Returns ciphertext."""
    mech = _resolve_mech(mechanism, mech_param)
    return _multipart_output(
        raw,
        session,
        "C_EncryptInit",
        "C_EncryptUpdate",
        "C_EncryptFinal",
        (mech.byref(), key),
        chunks,
    )


def decrypt_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Decrypt data in multiple parts. Returns plaintext."""
    mech = _resolve_mech(mechanism, mech_param)
    return _multipart_output(
        raw,
        session,
        "C_DecryptInit",
        "C_DecryptUpdate",
        "C_DecryptFinal",
        (mech.byref(), key),
        chunks,
    )


def sign_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign data in multiple parts. Returns signature."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_SignInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        rv = raw.C_SignUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    return _two_call_output(raw, "C_SignFinal", session)


def verify_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    signature: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bool:
    """Verify a signature over multiple data parts.

    Returns True if valid, False if CKR_SIGNATURE_INVALID/CKR_SIGNATURE_LEN_RANGE.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_VerifyInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        rv = raw.C_VerifyUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    sig_buf = to_ubyte_buf(signature)
    rv = raw.C_VerifyFinal(session, sig_buf, len(signature))
    if rv == CKR_OK:
        return True
    if rv in _VERIFY_FAIL_RVS:
        return False
    expect_rv(rv, CKR_OK)
    return False  # unreachable


def digest_multipart(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Digest data in multiple parts. Returns digest."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        rv = raw.C_DigestUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    return _two_call_output(raw, "C_DigestFinal", session)


# --- Operation state ---


def save_operation_state(raw: RawPKCS11, session: int) -> bytes:
    """C_GetOperationState -- two-call output pattern."""
    return _two_call_output(raw, "C_GetOperationState", session)


def restore_operation_state(
    raw: RawPKCS11,
    session: int,
    state: bytes,
    encrypt_key: int = 0,
    auth_key: int = 0,
) -> None:
    """C_SetOperationState -- restore previously saved operation state."""
    buf = to_ubyte_buf(state)
    rv = raw.C_SetOperationState(session, buf, len(state), encrypt_key, auth_key)
    expect_rv(rv, CKR_OK)


# --- Token/PIN management ---


def init_token(raw: RawPKCS11, slot_id: int, so_pin: bytes, label: str) -> None:
    """Initialize a token with C_InitToken. Label is padded to 32 bytes with spaces."""
    label_bytes = label.encode().ljust(32)[:32]
    # ctypes c_char array constructor accepts bytes per-element at runtime; the
    # static type stub flags the splat as Iterable[c_char] mismatch.
    label_buf = (ctypes.c_char * 32)(*[bytes([b]) for b in label_bytes])
    pin_buf = to_ubyte_buf(so_pin)
    rv = raw.C_InitToken(slot_id, pin_buf, len(so_pin), label_buf)
    expect_rv(rv, CKR_OK)


def init_pin(raw: RawPKCS11, session: int, pin: bytes) -> None:
    """Set user PIN with C_InitPIN."""
    pin_buf = to_ubyte_buf(pin)
    rv = raw.C_InitPIN(session, pin_buf, len(pin))
    expect_rv(rv, CKR_OK)


def set_pin(raw: RawPKCS11, session: int, old_pin: bytes, new_pin: bytes) -> None:
    """Change PIN with C_SetPIN."""
    old_buf = to_ubyte_buf(old_pin)
    new_buf = to_ubyte_buf(new_pin)
    rv = raw.C_SetPIN(session, old_buf, len(old_pin), new_buf, len(new_pin))
    expect_rv(rv, CKR_OK)


def seed_random(
    raw: RawPKCS11, session: int, seed: bytes, *, extra_ok: tuple[int, ...] = ()
) -> int:
    """Seed the RNG with C_SeedRandom.  Returns the raw CK_RV."""
    buf = to_ubyte_buf(seed)
    rv = raw.C_SeedRandom(session, buf, len(seed))
    expect_rv(rv, CKR_OK, *extra_ok)  # type: ignore[arg-type]
    return int(rv)


def get_mechanism_list(raw: RawPKCS11, slot_id: int) -> list[int]:
    """Get mechanisms supported by a slot. Returns list of CKM_* ints."""
    count = CK_ULONG(0)
    rv = raw.C_GetMechanismList(slot_id, None, byref(count))
    expect_rv(rv, CKR_OK)
    if count.value == 0:
        return []
    from .types_std import CK_MECHANISM_TYPE

    mechs = (CK_MECHANISM_TYPE * count.value)()
    rv = raw.C_GetMechanismList(slot_id, mechs, byref(count))
    expect_rv(rv, CKR_OK)
    return [mechs[i] for i in range(count.value)]


def get_session_info(raw: RawPKCS11, session: int) -> dict[str, int]:
    """C_GetSessionInfo -- returns session info as dict."""
    info = CK_SESSION_INFO()
    expect_rv(raw.C_GetSessionInfo(session, byref(info)), CKR_OK)
    return {
        "slot_id": info.slotID,
        "state": info.state,
        "flags": info.flags,
        "device_error": info.ulDeviceError,
    }


def get_mechanism_info(raw: RawPKCS11, slot_id: int, mechanism: CKM | int) -> dict[str, int]:
    """C_GetMechanismInfo -- returns mechanism info as dict."""
    info = CK_MECHANISM_INFO()
    expect_rv(raw.C_GetMechanismInfo(slot_id, mechanism, byref(info)), CKR_OK)
    return {
        "min_key_size": info.ulMinKeySize,
        "max_key_size": info.ulMaxKeySize,
        "flags": info.flags,
    }


def get_slot_info(raw: RawPKCS11, slot_id: int) -> dict[str, Any]:
    """C_GetSlotInfo -- returns slot info as dict."""
    info = CK_SLOT_INFO()
    expect_rv(raw.C_GetSlotInfo(slot_id, byref(info)), CKR_OK)
    return {
        "description": bytes(info.slotDescription).decode("utf-8", errors="replace").rstrip("\x00"),
        "manufacturer": bytes(info.manufacturerID).decode("utf-8", errors="replace").rstrip("\x00"),
        "flags": info.flags,
        "hardware_version": (info.hardwareVersion.major, info.hardwareVersion.minor),
        "firmware_version": (info.firmwareVersion.major, info.firmwareVersion.minor),
    }


# --- v3.0 Message-based crypto ---


def _message_crypto(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    init_fn: str,
    msg_fn: str,
    *,
    aad: bytes | None = None,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Shared Init + two-call Message pattern for encrypt/decrypt."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = getattr(raw, init_fn)(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)

    aad_buf = to_ubyte_buf(aad) if aad else None
    aad_len = len(aad) if aad else 0
    in_buf = to_ubyte_buf(data)

    out_len = CK_ULONG(0)
    fn = getattr(raw, msg_fn)
    rv = fn(
        session,
        None,
        0,
        aad_buf,
        aad_len,
        in_buf,
        len(data),
        None,
        byref(out_len),
    )
    expect_rv(rv, CKR_OK)
    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = fn(
        session,
        None,
        0,
        aad_buf,
        aad_len,
        in_buf,
        len(data),
        out_buf,
        byref(out_len),
    )
    expect_rv(rv, CKR_OK)
    return bytes(out_buf[: out_len.value])


def message_encrypt(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    aad: bytes | None = None,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Single-message encrypt via C_MessageEncryptInit + C_EncryptMessage."""
    return _message_crypto(
        raw,
        session,
        key,
        mechanism,
        data,
        "C_MessageEncryptInit",
        "C_EncryptMessage",
        aad=aad,
        mech_param=mech_param,
    )


def message_decrypt(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    ciphertext: bytes,
    *,
    aad: bytes | None = None,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Single-message decrypt via C_MessageDecryptInit + C_DecryptMessage."""
    return _message_crypto(
        raw,
        session,
        key,
        mechanism,
        ciphertext,
        "C_MessageDecryptInit",
        "C_DecryptMessage",
        aad=aad,
        mech_param=mech_param,
    )


# --- v3.2 KEM operations ---


def encapsulate_key(
    raw: RawPKCS11,
    session: int,
    pub_key: int,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> tuple[int, bytes]:
    """C_EncapsulateKey -- returns (secret_key_handle, ciphertext).

    Uses the two-call pattern: first call with pCiphertext=NULL to get the required buffer
    size, second call with a properly allocated buffer.

    NSS-PQC returns CKR_BUFFER_TOO_SMALL (not CKR_OK) on the first NULL-buffer call, which
    is valid PKCS#11 behavior analogous to C_Encrypt.  Kryoptic may create the key on the
    first call and return CKR_OK -- we preserve that handle and reuse it on the second call.
    """
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None

    # First call: query ciphertext buffer size.
    # Accept both CKR_OK (Kryoptic: key may already be created) and
    # CKR_BUFFER_TOO_SMALL (NSS-PQC: standard two-pass indicator).
    ct_len = CK_ULONG(0)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_EncapsulateKey(
        session,
        mech.byref(),
        pub_key,
        *template_ptr_count(tmpl),
        None,  # pCiphertext -- NULL signals size query
        byref(ct_len),
        byref(key_handle),  # Kryoptic requires non-NULL even for size query
    )
    if rv not in (CKR_OK, CKR_BUFFER_TOO_SMALL):
        expect_rv(rv, CKR_OK)  # raises with descriptive error

    # Second call: pass properly sized buffer.
    # If the first call already created the key (Kryoptic, CKR_OK + non-zero handle),
    # reset the handle so the second call can overwrite it safely.
    first_call_handle = key_handle.value
    if rv == CKR_BUFFER_TOO_SMALL:
        key_handle = CK_OBJECT_HANDLE(0)  # NSS: key not yet created
    ct_buf = (ctypes.c_ubyte * ct_len.value)()
    rv = raw.C_EncapsulateKey(
        session,
        mech.byref(),
        pub_key,
        *template_ptr_count(tmpl),
        ct_buf,
        byref(ct_len),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    # Use the handle returned by whichever call actually created the key.
    final_handle = key_handle.value if key_handle.value else first_call_handle
    return final_handle, bytes(ct_buf[: ct_len.value])


def decapsulate_key(
    raw: RawPKCS11,
    session: int,
    priv_key: int,
    mechanism: CKM | int,
    ciphertext: bytes,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """C_DecapsulateKey -- returns secret_key_handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    ct_buf = to_ubyte_buf(ciphertext)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_DecapsulateKey(
        session,
        mech.byref(),
        priv_key,
        *template_ptr_count(tmpl),
        ct_buf,
        len(ciphertext),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    return key_handle.value


# --- v3.2 Authenticated wrapping ---


def wrap_key_authenticated(
    raw: RawPKCS11,
    session: int,
    wrapping_key: int,
    target_key: int,
    mechanism: CKM | int,
    *,
    aad: bytes = b"",
    mech_param: PackedMechanism | None = None,
    output_size_hint: int = 0,
) -> bytes:
    """C_WrapKeyAuthenticated — wrap ``target_key`` and return wrapped bytes.

    PKCS#11 v3.2 §5.13 signature:
        (hSession, pMechanism, hWrappingKey, hKey,
         pAssociatedData, ulAssociatedDataLen,
         pWrappedKey,      pulWrappedKeyLen)

    The C function does NOT return the authentication tag.  For AEAD modes
    (AES-GCM, AES-CCM) the tag is written into a buffer inside the mechanism
    parameter struct (e.g. ``CK_GCM_MESSAGE_PARAMS.pTag``).  Build the
    mech_param with a packer that registers a "tag" buffer (e.g.
    ``mech_gcm_message``) and retrieve it via
    ``mech_param.buffer_bytes("tag")`` after the call.  The classical
    ``mech_gcm`` packer has no pTag field and is NOT a valid mech_param for
    this function.

    ``output_size_hint`` skips the NULL-buffer size-query first call and
    issues a single call with a pre-allocated buffer of that size.  Needed
    for modules (e.g. NSS softoken) that either fail to report the required
    size on a NULL probe or consume operation state during it.
    """
    mech = _resolve_mech(mechanism, mech_param)
    aad_buf = to_ubyte_buf(aad) if aad else None
    return _two_call_output(
        raw,
        "C_WrapKeyAuthenticated",
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        aad_buf,
        len(aad),
        output_size_hint=output_size_hint,
    )


def unwrap_key_authenticated(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    aad: bytes = b"",
    mech_param: PackedMechanism | None = None,
) -> int:
    """C_UnwrapKeyAuthenticated — returns key handle.

    PKCS#11 v3.2 §5.13 signature:
        (hSession, pMechanism, hUnwrappingKey,
         pWrappedKey, ulWrappedKeyLen,
         pTemplate,   ulAttributeCount,
         pAssociatedData, ulAssociatedDataLen,
         phKey)

    The ``aad`` argument is the same AAD that was supplied to the corresponding
    ``wrap_key_authenticated`` call; AEAD modes cross-verify it.  The
    authentication tag is conveyed via the mechanism parameter struct
    (e.g. ``CK_GCM_MESSAGE_PARAMS.pTag``), not via this argument.
    """
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    wrapped_buf = to_ubyte_buf(wrapped_key)
    aad_buf = to_ubyte_buf(aad) if aad else None
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKeyAuthenticated(
        session,
        mech.byref(),
        unwrapping_key,
        wrapped_buf,
        len(wrapped_key),
        *template_ptr_count(tmpl),
        aad_buf,
        len(aad),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    return key_handle.value


__all__ = [
    "copy_object",
    "create_object",
    "decapsulate_key",
    "decrypt_multipart",
    "decrypt_single",
    "derive_key",
    "destroy_quietly",
    "digest_multipart",
    "digest_single",
    "encapsulate_key",
    "encrypt_multipart",
    "encrypt_single",
    "find_objects",
    "gen_aes_key",
    "gen_ec_keypair",
    "gen_keypair",
    "gen_rsa_keypair",
    "generate_random",
    "get_mechanism_list",
    "get_object_size",
    "import_dsa_public_key",
    "import_ec_private_key",
    "import_ec_public_key",
    "import_gost_private_key",
    "import_gost_public_key",
    "import_pqc_private_key",
    "import_pqc_public_key",
    "import_rsa_private_key",
    "import_rsa_public_key",
    "import_secret_key",
    "init_pin",
    "init_token",
    "message_decrypt",
    "message_encrypt",
    "pack_attrs",
    "quick_session",
    "read_attributes",
    "restore_operation_state",
    "save_operation_state",
    "seed_random",
    "set_attributes",
    "set_pin",
    "sign_multipart",
    "sign_recover_single",
    "sign_single",
    "to_ubyte_buf",
    "unwrap_key",
    "unwrap_key_authenticated",
    "verify_multipart",
    "verify_recover_single",
    "verify_single",
    "wrap_key",
    "wrap_key_authenticated",
]
