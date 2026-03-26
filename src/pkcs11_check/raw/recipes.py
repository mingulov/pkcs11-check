"""Readability recipes on top of pkcs11_check.raw.

These helpers simplify common test patterns without hiding the underlying
PKCS#11 operations. A recipe must be mentally expandable to its raw calls.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import byref
from typing import Any

from .api import RawPKCS11
from .attr_metadata import ATTR_VALUE_TYPES
from .bootstrap import get_slot_ids, login_user, open_session
from .pack import PackedMechanism, attr_bytes, attr_ulong, mech_simple, template
from .rv import expect_rv
from .types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK,
    CKM,
    CKM_AES_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKR_BUFFER_TOO_SMALL,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)

_VERIFY_FAIL_RVS = (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE)


def _resolve_mech(
    mechanism: CKM,
    mech_param: PackedMechanism | None,
) -> PackedMechanism:
    """Return mech_param if given, otherwise wrap mechanism as mech_simple."""
    return mech_param if mech_param is not None else mech_simple(mechanism)


def _two_call_output(
    raw: RawPKCS11,
    session: int,
    call_fn: str,
    *args: Any,
) -> bytes:
    """Execute a PKCS#11 function using the standard two-call size pattern."""
    fn = getattr(raw, call_fn)
    out_len = CK_ULONG(0)
    rv = fn(session, *args, None, byref(out_len))
    expect_rv(rv, CKR_OK)
    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = fn(session, *args, out_buf, byref(out_len))
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


def _pack_attrs(
    attrs: dict[int, Any] | None,
    *,
    skip: set[int] | None = None,
) -> list[Any]:
    """Convert a {attr_type: value} dict to a list of PackedAttributes.

    Uses attr_auto for spec-correct type packing based on ATTR_VALUE_TYPES.
    Skips attr types in skip set.
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
    attrs: dict[int, Any] | None = None,
    mechanism: int = CKM_AES_KEY_GEN,
) -> int:
    """Generate an AES key with explicit attributes."""
    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(_pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    tmpl = template(*packed)
    mech = mech_simple(mechanism)
    key = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def _gen_keypair(
    raw: RawPKCS11,
    session: int,
    mechanism: int,
    pub_base: list[Any],
    priv_base: list[Any],
    public_attrs: dict[CKA, Any] | None,
    private_attrs: dict[CKA, Any] | None,
    pub_skip: set[int] | None = None,
) -> tuple[int, int]:
    """Shared keypair generation logic."""
    pub_packed = pub_base + _pack_attrs(public_attrs, skip=pub_skip)
    priv_packed = priv_base + _pack_attrs(private_attrs)
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
    public_attrs: dict[CKA, Any] | None = None,
    private_attrs: dict[CKA, Any] | None = None,
) -> tuple[int, int]:
    """Generate an RSA key pair. Returns (pub_handle, priv_handle)."""
    return _gen_keypair(
        raw,
        session,
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_MODULUS_BITS, bits)],
        priv_base=[],
        public_attrs=public_attrs,
        private_attrs=private_attrs,
        pub_skip={CKA_MODULUS_BITS},
    )


def gen_ec_keypair(
    raw: RawPKCS11,
    session: int,
    curve_oid: bytes,
    public_attrs: dict[CKA, Any] | None = None,
    private_attrs: dict[CKA, Any] | None = None,
) -> tuple[int, int]:
    """Generate an EC key pair. Returns (pub_handle, priv_handle)."""
    return _gen_keypair(
        raw,
        session,
        CKM_EC_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
        priv_base=[],
        public_attrs=public_attrs,
        private_attrs=private_attrs,
        pub_skip={CKA_EC_PARAMS},
    )


def import_secret_key(
    raw: RawPKCS11,
    session: int,
    key_type: CKK,
    value: bytes,
    attrs: dict[CKA, Any] | None = None,
) -> int:
    """Import a secret key by value using C_CreateObject."""
    base = {CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE}
    packed = [
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_bytes(CKA_VALUE, value),
    ]
    packed.extend(_pack_attrs(attrs, skip=base))

    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)

    return handle.value


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
    packed = _pack_attrs(attrs)
    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)
    return handle.value


def destroy_quietly(raw: RawPKCS11, session: int, handle: int) -> None:
    """Destroy an object, silently ignoring any errors."""
    try:
        raw.C_DestroyObject(session, handle)
    except Exception:
        pass


def encrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    plaintext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Encrypt data in a single operation. Returns ciphertext."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_EncryptInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
    return _two_call_output(raw, session, "C_Encrypt", in_buf, len(plaintext))


def sign_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign data in a single operation. Returns signature."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_SignInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = (ctypes.c_ubyte * len(data))(*data)
    return _two_call_output(raw, session, "C_Sign", in_buf, len(data))


def decrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    ciphertext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Decrypt data in a single operation. Returns plaintext."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_DecryptInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    in_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    return _two_call_output(
        raw,
        session,
        "C_Decrypt",
        in_buf,
        len(ciphertext),
    )


def verify_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
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

    data_buf = (ctypes.c_ubyte * len(data))(*data)
    sig_buf = (ctypes.c_ubyte * len(signature))(*signature)
    rv = raw.C_Verify(session, data_buf, len(data), sig_buf, len(signature))

    if rv == CKR_OK:
        return True
    if rv in _VERIFY_FAIL_RVS:
        return False
    expect_rv(rv, CKR_OK)
    return False  # unreachable


def digest_single(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Digest data in a single operation. Returns digest."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(rv, CKR_OK)
    in_buf = (ctypes.c_ubyte * len(data))(*data)
    return _two_call_output(raw, session, "C_Digest", in_buf, len(data))


def read_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attr_types: list[int] | tuple[int, ...],
) -> dict[int, bytes | int | bool | str | list[int]]:
    """Read attribute values from an object.

    Returns a dict mapping attribute type to its value. Uses the generated
    ATTR_VALUE_TYPES table for spec-correct decoding: bool attrs as bool,
    ulong attrs as int, str attrs as str, date attrs as 'YYYYMMDD' str,
    ulong_array attrs as list[int], template and unknown attrs as bytes.
    """
    count = len(attr_types)
    tmpl = (CK_ATTRIBUTE * count)()
    for i, at in enumerate(attr_types):
        tmpl[i].type = at
        tmpl[i].pValue = None
        tmpl[i].ulValueLen = 0

    # First call: query sizes
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(rv, CKR_OK)

    # Allocate buffers
    buffers = []
    for i in range(count):
        size = tmpl[i].ulValueLen
        buf = (ctypes.c_ubyte * size)()
        tmpl[i].pValue = ctypes.cast(buf, ctypes.c_void_p)
        tmpl[i].ulValueLen = size
        buffers.append(buf)

    # Second call: read values
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(rv, CKR_OK)

    result: dict[int, bytes | int | bool | str | list[int]] = {}
    for i, at in enumerate(attr_types):
        size = tmpl[i].ulValueLen
        raw_bytes = bytes(buffers[i][:size])
        vtype = ATTR_VALUE_TYPES.get(at, "bytes")
        if vtype == "bool" and size == ctypes.sizeof(CK_BBOOL):
            result[at] = raw_bytes[0] != 0
        elif vtype == "ulong" and size == ctypes.sizeof(CK_ULONG):
            result[at] = int.from_bytes(raw_bytes, byteorder=sys.byteorder)
        elif vtype == "str":
            result[at] = raw_bytes.decode("utf-8")
        elif vtype == "date":
            # Return as str 'YYYYMMDD' — callers can parse if needed
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
            # Template attributes are complex — return raw bytes
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
    mechanism: CKM,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Wrap a key using C_WrapKey (two-call output pattern). Returns wrapped key."""
    mech = _resolve_mech(mechanism, mech_param)
    out_len = CK_ULONG(0)
    rv = raw.C_WrapKey(
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        None,
        byref(out_len),
    )
    expect_rv(rv, CKR_OK)
    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = raw.C_WrapKey(
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        out_buf,
        byref(out_len),
    )
    expect_rv(rv, CKR_OK)
    return bytes(out_buf[: out_len.value])


def unwrap_key(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: CKM,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """Unwrap a key using C_UnwrapKey. Returns new key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = _pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    in_buf = (ctypes.c_ubyte * len(wrapped_key))(*wrapped_key)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        session,
        mech.byref(),
        unwrapping_key,
        in_buf,
        len(wrapped_key),
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
        byref(handle),
    )
    expect_rv(rv, CKR_OK)
    return handle.value


def derive_key(
    raw: RawPKCS11,
    session: int,
    base_key: int,
    mechanism: CKM,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """Derive a key using C_DeriveKey. Returns new key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = _pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        session,
        mech.byref(),
        base_key,
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
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
    attrs: dict[int, Any] | None = None,
) -> int:
    """Copy an object using C_CopyObject. Returns new handle."""
    packed = _pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    new_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CopyObject(
        session,
        handle,
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
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
    packed = _pack_attrs(attrs)
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
    C_DecryptUpdate). Sign/Digest Update calls do not produce output —
    use the manual Init+Update+_two_call_output(Final) pattern instead.
    """
    rv = getattr(raw, init_fn)(session, *init_args)
    expect_rv(rv, CKR_OK)
    parts: list[bytes] = []
    for chunk in chunks:
        in_buf = (ctypes.c_ubyte * len(chunk))(*chunk)
        out_len = CK_ULONG(0)
        rv = getattr(raw, update_fn)(
            session,
            in_buf,
            len(chunk),
            None,
            byref(out_len),
        )
        expect_rv(rv, CKR_OK)
        if out_len.value > 0:
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = getattr(raw, update_fn)(
                session,
                in_buf,
                len(chunk),
                out_buf,
                byref(out_len),
            )
            expect_rv(rv, CKR_OK)
            parts.append(bytes(out_buf[: out_len.value]))
    # Final
    out_len = CK_ULONG(0)
    rv = getattr(raw, final_fn)(session, None, byref(out_len))
    expect_rv(rv, CKR_OK)
    if out_len.value > 0:
        out_buf = (ctypes.c_ubyte * out_len.value)()
        rv = getattr(raw, final_fn)(session, out_buf, byref(out_len))
        expect_rv(rv, CKR_OK)
        parts.append(bytes(out_buf[: out_len.value]))
    return b"".join(parts)


def encrypt_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
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
    mechanism: CKM,
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
    mechanism: CKM,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign data in multiple parts. Returns signature."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_SignInit(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = (ctypes.c_ubyte * len(chunk))(*chunk)
        rv = raw.C_SignUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    return _two_call_output(raw, session, "C_SignFinal")


def verify_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
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
        in_buf = (ctypes.c_ubyte * len(chunk))(*chunk)
        rv = raw.C_VerifyUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    sig_buf = (ctypes.c_ubyte * len(signature))(*signature)
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
    mechanism: CKM,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Digest data in multiple parts. Returns digest."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = (ctypes.c_ubyte * len(chunk))(*chunk)
        rv = raw.C_DigestUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    return _two_call_output(raw, session, "C_DigestFinal")


# --- Operation state ---


def save_operation_state(raw: RawPKCS11, session: int) -> bytes:
    """C_GetOperationState — two-call output pattern."""
    return _two_call_output(raw, session, "C_GetOperationState")


def restore_operation_state(
    raw: RawPKCS11,
    session: int,
    state: bytes,
    encrypt_key: int = 0,
    auth_key: int = 0,
) -> None:
    """C_SetOperationState — restore previously saved operation state."""
    buf = (ctypes.c_ubyte * len(state))(*state)
    rv = raw.C_SetOperationState(session, buf, len(state), encrypt_key, auth_key)
    expect_rv(rv, CKR_OK)


# --- Token/PIN management ---


def init_token(raw: RawPKCS11, slot_id: int, so_pin: bytes, label: str) -> None:
    """Initialize a token with C_InitToken. Label is padded to 32 bytes with spaces."""
    label_bytes = label.encode().ljust(32)[:32]
    label_buf = (ctypes.c_char * 32)(*label_bytes)
    pin_buf = (ctypes.c_ubyte * len(so_pin))(*so_pin)
    rv = raw.C_InitToken(slot_id, pin_buf, len(so_pin), label_buf)
    expect_rv(rv, CKR_OK)


def init_pin(raw: RawPKCS11, session: int, pin: bytes) -> None:
    """Set user PIN with C_InitPIN."""
    pin_buf = (ctypes.c_ubyte * len(pin))(*pin)
    rv = raw.C_InitPIN(session, pin_buf, len(pin))
    expect_rv(rv, CKR_OK)


def set_pin(raw: RawPKCS11, session: int, old_pin: bytes, new_pin: bytes) -> None:
    """Change PIN with C_SetPIN."""
    old_buf = (ctypes.c_ubyte * len(old_pin))(*old_pin)
    new_buf = (ctypes.c_ubyte * len(new_pin))(*new_pin)
    rv = raw.C_SetPIN(session, old_buf, len(old_pin), new_buf, len(new_pin))
    expect_rv(rv, CKR_OK)


def seed_random(raw: RawPKCS11, session: int, seed: bytes) -> None:
    """Seed the RNG with C_SeedRandom."""
    buf = (ctypes.c_ubyte * len(seed))(*seed)
    rv = raw.C_SeedRandom(session, buf, len(seed))
    expect_rv(rv, CKR_OK)


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


# --- v3.0 Message-based crypto ---


def _message_crypto(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
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

    aad_buf = (ctypes.c_ubyte * len(aad))(*aad) if aad else None
    aad_len = len(aad) if aad else 0
    in_buf = (ctypes.c_ubyte * len(data))(*data)

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
    mechanism: CKM,
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
    mechanism: CKM,
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
    mechanism: CKM,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> tuple[int, bytes]:
    """C_EncapsulateKey — returns (secret_key_handle, ciphertext)."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = _pack_attrs(attrs)
    tmpl = template(*packed) if packed else None

    # Two-call pattern for ciphertext output
    ct_len = CK_ULONG(0)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_EncapsulateKey(
        session,
        mech.byref(),
        pub_key,
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
        None,
        byref(ct_len),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    ct_buf = (ctypes.c_ubyte * ct_len.value)()
    rv = raw.C_EncapsulateKey(
        session,
        mech.byref(),
        pub_key,
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
        ct_buf,
        byref(ct_len),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    return key_handle.value, bytes(ct_buf[: ct_len.value])


def decapsulate_key(
    raw: RawPKCS11,
    session: int,
    priv_key: int,
    mechanism: CKM,
    ciphertext: bytes,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """C_DecapsulateKey — returns secret_key_handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = _pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    ct_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_DecapsulateKey(
        session,
        mech.byref(),
        priv_key,
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
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
    mechanism: CKM,
    *,
    mech_param: PackedMechanism | None = None,
) -> tuple[bytes, bytes]:
    """C_WrapKeyAuthenticated — returns (wrapped_key, tag).

    C_WrapKeyAuthenticated signature: (session, mech_ptr, wrapping_key, target_key,
    wrapped_ptr, wrapped_len[CK_ULONG], tag_ptr, tag_len_ptr[CK_ULONG_PTR]).
    wrapped_len is an input size; tag_len_ptr is an output pointer.
    Use NULL/0 for wrapped and NULL/byref for tag on first call to get sizes.
    """
    mech = _resolve_mech(mechanism, mech_param)

    # First call: get tag size; wrapped_len is input so pass 0 with NULL wrapped_ptr
    tag_len = CK_ULONG(0)
    rv = raw.C_WrapKeyAuthenticated(
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        None,
        0,
        None,
        byref(tag_len),
    )
    # CKR_BUFFER_TOO_SMALL is expected when NULL is passed for wrapped_ptr
    if rv not in (CKR_OK, CKR_BUFFER_TOO_SMALL):
        expect_rv(rv, CKR_OK)

    # For wrapped key size, C_WrapKey uses the same NULL pattern — try with large buffer
    # then retry if needed. Use C_WrapKey size as a heuristic first call.
    wrapped_len = CK_ULONG(0)
    rv2 = raw.C_WrapKey(
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        None,
        byref(wrapped_len),
    )
    expect_rv(rv2, CKR_OK)

    wrapped_buf = (ctypes.c_ubyte * wrapped_len.value)()
    tag_buf = (ctypes.c_ubyte * tag_len.value)()
    rv = raw.C_WrapKeyAuthenticated(
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        wrapped_buf,
        wrapped_len.value,
        tag_buf,
        byref(tag_len),
    )
    expect_rv(rv, CKR_OK)
    return bytes(wrapped_buf[: wrapped_len.value]), bytes(tag_buf[: tag_len.value])


def unwrap_key_authenticated(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    tag: bytes,
    mechanism: CKM,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """C_UnwrapKeyAuthenticated — returns key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = _pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    wrapped_buf = (ctypes.c_ubyte * len(wrapped_key))(*wrapped_key)
    tag_buf = (ctypes.c_ubyte * len(tag))(*tag)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKeyAuthenticated(
        session,
        mech.byref(),
        unwrapping_key,
        wrapped_buf,
        len(wrapped_key),
        tmpl.ptr if tmpl else None,
        tmpl.count if tmpl else 0,
        tag_buf,
        len(tag),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    return key_handle.value
