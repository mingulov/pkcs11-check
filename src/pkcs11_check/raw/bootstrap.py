"""Explicit raw PKCS#11 bootstrap helpers."""

from __future__ import annotations

import ctypes
from ctypes import byref

from .api import RawPKCS11
from .rv import expect_rv
from .types_std import (
    CK_NOTIFY,
    CK_SESSION_HANDLE,
    CK_SLOT_ID,
    CK_TOKEN_INFO,
    CK_ULONG,
    CK_UTF8CHAR,
    CKR_OK,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
)


def get_slot_ids(raw: RawPKCS11, token_present: bool = True, label: str | None = None) -> list[int]:
    count = CK_ULONG()
    present = 1 if token_present else 0
    expect_rv(raw.C_GetSlotList(present, None, byref(count)), CKR_OK)
    if count.value == 0:
        return []
    slots = (CK_SLOT_ID * count.value)()
    expect_rv(raw.C_GetSlotList(present, slots, byref(count)), CKR_OK)

    found_slots = [slots[index] for index in range(count.value)]
    if label is None:
        return found_slots

    # Filter by label
    matching = []
    for slot_id in found_slots:
        info = CK_TOKEN_INFO()
        if raw.C_GetTokenInfo(slot_id, byref(info)) == CKR_OK:
            token_label = bytes(info.label).decode("utf-8").strip()
            if label in token_label:
                matching.append(slot_id)
    return matching


def open_session(raw: RawPKCS11, slot_id: int, flags: int) -> int:
    session = CK_SESSION_HANDLE()
    expect_rv(
        raw.C_OpenSession(
            slot_id,
            flags,
            None,
            CK_NOTIFY(),
            byref(session),
        ),
        CKR_OK,
    )
    return session.value


def login_user(
    raw: RawPKCS11, session: int, user_type: int, pin: bytes | bytearray | memoryview
) -> None:
    if isinstance(pin, str):
        raise TypeError("pin must be bytes-like")
    try:
        pin_bytes = bytes(memoryview(pin))
    except TypeError as exc:
        raise TypeError("pin must be bytes-like") from exc
    pin_buffer = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    expect_rv(
        raw.C_Login(
            session,
            user_type,
            pin_buffer,
            len(pin_bytes),
        ),
        CKR_OK,
        CKR_USER_ALREADY_LOGGED_IN,
    )


def close_session_quietly(raw: RawPKCS11, session: int) -> None:
    try:
        raw.C_CloseSession(session)
    except (AttributeError, OSError, ctypes.ArgumentError):
        return


def logout(raw: RawPKCS11, session: int) -> None:
    """C_Logout -- log out from a token session."""
    expect_rv(raw.C_Logout(session), CKR_OK, CKR_USER_NOT_LOGGED_IN)


def logout_quietly(raw: RawPKCS11, session: int) -> None:
    """C_Logout -- log out, ignoring errors (for use in finally blocks)."""
    try:
        raw.C_Logout(session)
    except (AttributeError, OSError, ctypes.ArgumentError):
        return


def login_user_with_name(
    raw: RawPKCS11,
    session: int,
    user_type: int,
    pin: bytes | bytearray | memoryview,
    username: bytes = b"",
) -> None:
    """C_LoginUser (v3.0+) -- login with an explicit username."""
    if isinstance(pin, str):
        raise TypeError("pin must be bytes-like")
    try:
        pin_bytes = bytes(memoryview(pin))
    except TypeError as exc:
        raise TypeError("pin must be bytes-like") from exc
    pin_buffer = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    user_buffer = (CK_UTF8CHAR * len(username))(*username) if username else None
    user_len = len(username) if username else 0
    fn = getattr(raw, "C_LoginUser", None)
    if fn is None:
        raise AttributeError("C_LoginUser not available in this module")
    expect_rv(
        fn(session, user_type, pin_buffer, len(pin_bytes), user_buffer, user_len),
        CKR_OK,
        CKR_USER_ALREADY_LOGGED_IN,
    )


__all__ = [
    "close_session_quietly",
    "get_slot_ids",
    "login_user",
    "login_user_with_name",
    "logout",
    "logout_quietly",
    "open_session",
]
