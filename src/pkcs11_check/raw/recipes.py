"""Readability recipes on top of pkcs11_check.raw.

These helpers simplify common test patterns without hiding the underlying
PKCS#11 operations. A recipe must be mentally expandable to its raw calls.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

from .api import RawPKCS11
from .bootstrap import get_slot_ids, login_user, open_session
from .pack import PackedMechanism, attr_bool, attr_bytes, attr_ulong, mech_simple, template
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
    CKR_OK,
)


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


def gen_aes_key(
    raw: RawPKCS11,
    sh: int,
    bits: int = 256,
    attrs: dict[int, Any] | None = None,
    mechanism: int = CKM_AES_KEY_GEN,
) -> int:
    """Generate an AES key with explicit attributes.

    The CKA_VALUE_LEN is automatically added based on 'bits'.
    Other attributes must be provided in 'attrs'.
    """
    packed_attrs = []

    # Always include value length from bits
    packed_attrs.append(attr_ulong(CKA_VALUE_LEN, bits // 8))

    if attrs:
        for attr_type, value in attrs.items():
            if attr_type == CKA_VALUE_LEN:
                continue  # Already added

            if isinstance(value, bool):
                packed_attrs.append(attr_bool(attr_type, value))
            elif isinstance(value, int):
                packed_attrs.append(attr_ulong(attr_type, value))
            else:
                raise TypeError(f"Recipe gen_aes_key doesn't handle {type(value)} for {attr_type}")

    tmpl = template(*packed_attrs)
    mech = mech_simple(mechanism)
    key = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(int(rv), CKR_OK)

    return int(key.value)


def gen_rsa_keypair(
    raw: RawPKCS11,
    session: int,
    bits: int = 2048,
    public_attrs: dict[CKA, Any] | None = None,
    private_attrs: dict[CKA, Any] | None = None,
) -> tuple[int, int]:
    """Generate an RSA key pair using CKM_RSA_PKCS_KEY_PAIR_GEN.

    Returns (pub_handle, priv_handle).
    """
    pub_packed = [attr_ulong(CKA_MODULUS_BITS, bits)]
    if public_attrs:
        for attr_type, value in public_attrs.items():
            if attr_type == CKA_MODULUS_BITS:
                continue
            if isinstance(value, bool):
                pub_packed.append(attr_bool(attr_type, value))
            elif isinstance(value, int):
                pub_packed.append(attr_ulong(attr_type, value))
            elif isinstance(value, (bytes, bytearray)):
                pub_packed.append(attr_bytes(attr_type, value))
            else:
                raise TypeError(f"gen_rsa_keypair: unsupported type {type(value)} for {attr_type}")

    priv_packed = []
    if private_attrs:
        for attr_type, value in private_attrs.items():
            if isinstance(value, bool):
                priv_packed.append(attr_bool(attr_type, value))
            elif isinstance(value, int):
                priv_packed.append(attr_ulong(attr_type, value))
            elif isinstance(value, (bytes, bytearray)):
                priv_packed.append(attr_bytes(attr_type, value))
            else:
                raise TypeError(f"gen_rsa_keypair: unsupported type {type(value)} for {attr_type}")

    pub_tmpl = template(*pub_packed)
    priv_tmpl = template(*priv_packed)
    mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKeyPair(
        session, mech.byref(),
        pub_tmpl.ptr, pub_tmpl.count,
        priv_tmpl.ptr, priv_tmpl.count,
        byref(pub_handle), byref(priv_handle),
    )
    expect_rv(int(rv), CKR_OK)

    return int(pub_handle.value), int(priv_handle.value)


def gen_ec_keypair(
    raw: RawPKCS11,
    session: int,
    curve_oid: bytes,
    public_attrs: dict[CKA, Any] | None = None,
    private_attrs: dict[CKA, Any] | None = None,
) -> tuple[int, int]:
    """Generate an EC key pair using CKM_EC_KEY_PAIR_GEN.

    curve_oid is the DER-encoded OID for the curve (e.g. P-256).
    Returns (pub_handle, priv_handle).
    """
    pub_packed = [attr_bytes(CKA_EC_PARAMS, curve_oid)]
    if public_attrs:
        for attr_type, value in public_attrs.items():
            if attr_type == CKA_EC_PARAMS:
                continue
            if isinstance(value, bool):
                pub_packed.append(attr_bool(attr_type, value))
            elif isinstance(value, int):
                pub_packed.append(attr_ulong(attr_type, value))
            elif isinstance(value, (bytes, bytearray)):
                pub_packed.append(attr_bytes(attr_type, value))
            else:
                raise TypeError(f"gen_ec_keypair: unsupported type {type(value)} for {attr_type}")

    priv_packed = []
    if private_attrs:
        for attr_type, value in private_attrs.items():
            if isinstance(value, bool):
                priv_packed.append(attr_bool(attr_type, value))
            elif isinstance(value, int):
                priv_packed.append(attr_ulong(attr_type, value))
            elif isinstance(value, (bytes, bytearray)):
                priv_packed.append(attr_bytes(attr_type, value))
            else:
                raise TypeError(f"gen_ec_keypair: unsupported type {type(value)} for {attr_type}")

    pub_tmpl = template(*pub_packed)
    priv_tmpl = template(*priv_packed)
    mech = mech_simple(CKM_EC_KEY_PAIR_GEN)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKeyPair(
        session, mech.byref(),
        pub_tmpl.ptr, pub_tmpl.count,
        priv_tmpl.ptr, priv_tmpl.count,
        byref(pub_handle), byref(priv_handle),
    )
    expect_rv(int(rv), CKR_OK)

    return int(pub_handle.value), int(priv_handle.value)


def import_secret_key(
    raw: RawPKCS11,
    session: int,
    key_type: CKK,
    value: bytes,
    attrs: dict[CKA, Any] | None = None,
) -> int:
    """Import a secret key by value using C_CreateObject.

    Returns the object handle.
    """
    packed = [
        attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)),
        attr_ulong(CKA_KEY_TYPE, int(key_type)),
        attr_bytes(CKA_VALUE, value),
    ]
    if attrs:
        skip = {int(CKA_CLASS), int(CKA_KEY_TYPE), int(CKA_VALUE)}
        for attr_type, attr_value in attrs.items():
            if int(attr_type) in skip:
                continue
            if isinstance(attr_value, bool):
                packed.append(attr_bool(attr_type, attr_value))
            elif isinstance(attr_value, int):
                packed.append(attr_ulong(attr_type, attr_value))
            elif isinstance(attr_value, (bytes, bytearray)):
                packed.append(attr_bytes(attr_type, attr_value))
            else:
                raise TypeError(
                    f"import_secret_key: unsupported type {type(attr_value)} for {attr_type}"
                )

    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(int(rv), CKR_OK)

    return int(handle.value)


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
    """Encrypt data in a single operation using the two-call size pattern.

    Returns the ciphertext as bytes.
    """
    mech = mech_param if mech_param is not None else mech_simple(mechanism)
    rv = raw.C_EncryptInit(session, mech.byref(), key)
    expect_rv(int(rv), CKR_OK)

    in_buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
    out_len = CK_ULONG(0)
    rv = raw.C_Encrypt(session, in_buf, len(plaintext), None, byref(out_len))
    expect_rv(int(rv), CKR_OK)

    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = raw.C_Encrypt(session, in_buf, len(plaintext), out_buf, byref(out_len))
    expect_rv(int(rv), CKR_OK)

    return bytes(out_buf[: out_len.value])


def sign_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign data in a single operation using the two-call size pattern.

    Returns the signature as bytes.
    """
    mech = mech_param if mech_param is not None else mech_simple(mechanism)
    rv = raw.C_SignInit(session, mech.byref(), key)
    expect_rv(int(rv), CKR_OK)

    in_buf = (ctypes.c_ubyte * len(data))(*data)
    sig_len = CK_ULONG(0)
    rv = raw.C_Sign(session, in_buf, len(data), None, byref(sig_len))
    expect_rv(int(rv), CKR_OK)

    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = raw.C_Sign(session, in_buf, len(data), sig_buf, byref(sig_len))
    expect_rv(int(rv), CKR_OK)

    return bytes(sig_buf[: sig_len.value])


def decrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM,
    ciphertext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Decrypt data in a single operation using the two-call size pattern.

    Returns the plaintext as bytes.
    """
    mech = mech_param if mech_param is not None else mech_simple(mechanism)
    rv = raw.C_DecryptInit(session, mech.byref(), key)
    expect_rv(int(rv), CKR_OK)

    in_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    out_len = CK_ULONG(0)
    rv = raw.C_Decrypt(session, in_buf, len(ciphertext), None, byref(out_len))
    expect_rv(int(rv), CKR_OK)

    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = raw.C_Decrypt(session, in_buf, len(ciphertext), out_buf, byref(out_len))
    expect_rv(int(rv), CKR_OK)

    return bytes(out_buf[: out_len.value])


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
    mech = mech_param if mech_param is not None else mech_simple(mechanism)
    rv = raw.C_VerifyInit(session, mech.byref(), key)
    expect_rv(int(rv), CKR_OK)

    data_buf = (ctypes.c_ubyte * len(data))(*data)
    sig_buf = (ctypes.c_ubyte * len(signature))(*signature)
    rv = int(raw.C_Verify(session, data_buf, len(data), sig_buf, len(signature)))

    if rv == CKR_OK:
        return True
    # CKR_SIGNATURE_INVALID = 0xC0, CKR_SIGNATURE_LEN_RANGE = 0xC1
    if rv in (0x000000C0, 0x000000C1):
        return False
    expect_rv(rv, CKR_OK)
    return False  # unreachable


def digest_single(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM,
    data: bytes,
) -> bytes:
    """Digest data in a single operation using the two-call size pattern.

    Returns the digest as bytes.
    """
    mech = mech_simple(mechanism)
    rv = raw.C_DigestInit(session, mech.byref())
    expect_rv(int(rv), CKR_OK)

    in_buf = (ctypes.c_ubyte * len(data))(*data)
    out_len = CK_ULONG(0)
    rv = raw.C_Digest(session, in_buf, len(data), None, byref(out_len))
    expect_rv(int(rv), CKR_OK)

    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = raw.C_Digest(session, in_buf, len(data), out_buf, byref(out_len))
    expect_rv(int(rv), CKR_OK)

    return bytes(out_buf[: out_len.value])


def read_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attr_types: list[int] | tuple[int, ...],
) -> dict[int, bytes | int | bool]:
    """Read attribute values from an object.

    Returns a dict mapping attribute type to its value. Boolean attributes
    are returned as bool, CK_ULONG-sized attributes as int, others as bytes.
    """
    count = len(attr_types)
    tmpl = (CK_ATTRIBUTE * count)()
    for i, at in enumerate(attr_types):
        tmpl[i].type = at
        tmpl[i].pValue = None
        tmpl[i].ulValueLen = 0

    # First call: query sizes
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(int(rv), CKR_OK)

    # Allocate buffers
    buffers = []
    for i in range(count):
        size = int(tmpl[i].ulValueLen)
        buf = (ctypes.c_ubyte * size)()
        tmpl[i].pValue = ctypes.cast(buf, ctypes.c_void_p)
        tmpl[i].ulValueLen = size
        buffers.append(buf)

    # Second call: read values
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(int(rv), CKR_OK)

    result: dict[int, bytes | int | bool] = {}
    for i, at in enumerate(attr_types):
        size = int(tmpl[i].ulValueLen)
        raw_bytes = bytes(buffers[i][:size])
        if size == ctypes.sizeof(CK_BBOOL):
            result[at] = raw_bytes[0] != 0
        elif size == ctypes.sizeof(CK_ULONG):
            result[at] = int.from_bytes(raw_bytes, byteorder="little")
        else:
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
    expect_rv(int(rv), CKR_OK)
    return int(size.value)


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
    expect_rv(int(rv), CKR_OK)

    handles = (CK_OBJECT_HANDLE * max_count)()
    found = CK_ULONG(0)
    rv = raw.C_FindObjects(session, handles, max_count, byref(found))
    expect_rv(int(rv), CKR_OK)

    rv = raw.C_FindObjectsFinal(session)
    expect_rv(int(rv), CKR_OK)

    return [int(handles[i]) for i in range(int(found.value))]
