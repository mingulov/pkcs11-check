"""Explicit raw PKCS#11 bootstrap helpers."""

from __future__ import annotations

import ctypes
from ctypes import byref

from .core import CKR_OK
from .rv import expect_rv
from .types_std import (
    CK_SESSION_HANDLE,
    CK_SLOT_ID,
    CK_ULONG,
    CK_UTF8CHAR,
    CK_UTF8CHAR_PTR,
)


def get_slot_ids(raw: object, token_present: bool = True) -> list[int]:
    count = CK_ULONG()
    present = 1 if token_present else 0
    expect_rv(int(raw.C_GetSlotList(present, None, byref(count))), CKR_OK)
    slots = (CK_SLOT_ID * int(count.value))()
    expect_rv(int(raw.C_GetSlotList(present, slots, byref(count))), CKR_OK)
    return [int(slots[index]) for index in range(int(count.value))]


def open_session(raw: object, slot_id: int, flags: int) -> int:
    session = CK_SESSION_HANDLE()
    expect_rv(
        int(
            raw.C_OpenSession(
                slot_id,
                flags,
                None,
                None,
                byref(session),
            )
        ),
        CKR_OK,
    )
    return int(session.value)


def login_user(raw: object, session: int, user_type: int, pin: str | bytes) -> None:
    pin_bytes = pin.encode("utf-8") if isinstance(pin, str) else pin
    pin_buffer = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    pin_ptr: CK_UTF8CHAR_PTR | None
    if pin_bytes:
        pin_ptr = pin_buffer
    else:
        pin_ptr = None
    expect_rv(
        int(
            raw.C_Login(
                session,
                user_type,
                pin_ptr,
                len(pin_bytes),
            )
        ),
        CKR_OK,
    )


def close_session_quietly(raw: object, session: int) -> None:
    try:
        raw.C_CloseSession(session)
    except Exception:
        return


__all__ = [
    "close_session_quietly",
    "get_slot_ids",
    "login_user",
    "open_session",
]
