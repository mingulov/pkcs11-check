"""Readability recipes on top of pkcs11_check.raw.

These helpers simplify common test patterns without hiding the underlying
PKCS#11 operations. A recipe must be mentally expandable to its raw calls.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

from .api import RawPKCS11
from .bootstrap import get_slot_ids, open_session, login_user
from .pack import attr_bool, attr_ulong, mech_simple, template
from .types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_KEY_GEN,
    CKA_VALUE_LEN,
    CK_OBJECT_HANDLE,
    CKR_OK,
)
from .rv import expect_rv


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
