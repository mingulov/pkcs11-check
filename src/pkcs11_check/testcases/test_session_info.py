"""Session info tests.

Tests C_GetSessionInfo to verify session state, flags,
and login status are correctly reported.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import gen_aes_key
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKM_AES_KEY_GEN,
    CKO_SECRET_KEY,
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_USER_NOT_LOGGED_IN,
    CKU_USER,
)

pytestmark = pytest.mark.access


class TestSessionInfo:
    """Test C_GetSessionInfo via raw PKCS#11 calls."""

    def test_rw_session_is_rw(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/W session reports correct state."""
        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        pin = p11_config.pin
        if pin is not None:
            pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin
            login_user(rs.raw, test_sh, int(CKU_USER), pin_str.encode("utf-8"))
        try:
            info = CK_SESSION_INFO()
            rv = rs.raw.C_GetSessionInfo(test_sh, byref(info))
            expect_rv(int(rv), CKR_OK)
            is_rw = bool(info.flags & int(CKF_RW_SESSION))
            assert is_rw is True
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_is_not_rw(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/O session reports read-only state."""
        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION)
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        pin = p11_config.pin
        if pin is not None:
            pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin
            login_user(rs.raw, test_sh, int(CKU_USER), pin_str.encode("utf-8"))
        try:
            info = CK_SESSION_INFO()
            rv = rs.raw.C_GetSessionInfo(test_sh, byref(info))
            expect_rv(int(rv), CKR_OK)
            is_rw = bool(info.flags & int(CKF_RW_SESSION))
            assert is_rw is False
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_session_has_token(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Session is associated with a token — generate a session key."""
        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        pin = p11_config.pin
        if pin is not None:
            pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin
            login_user(rs.raw, test_sh, int(CKU_USER), pin_str.encode("utf-8"))
        try:
            key_h = gen_aes_key(rs.raw, test_sh, 128)
            assert key_h != 0
            rs.raw.C_DestroyObject(test_sh, key_h)
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_cannot_generate_token_objects(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """R/O session cannot create TOKEN=True objects."""
        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION)
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        pin = p11_config.pin
        if pin is not None:
            pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin
            login_user(rs.raw, test_sh, int(CKU_USER), pin_str.encode("utf-8"))
        try:
            # Session (non-token) object must succeed on RO session
            session_key_h = gen_aes_key(rs.raw, test_sh, 128)
            assert session_key_h != 0
            rs.raw.C_DestroyObject(test_sh, session_key_h)

            # TOKEN=True object must be rejected on RO session
            tmpl = template(
                attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)),
                attr_ulong(CKA_KEY_TYPE, int(CKK_AES)),
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_TOKEN, True),
            )
            mech = mech_simple(CKM_AES_KEY_GEN)
            key_h = CK_OBJECT_HANDLE(0)
            rv = int(
                rs.raw.C_GenerateKey(test_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
            )
            assert rv in (
                int(CKR_SESSION_READ_ONLY),
                int(CKR_USER_NOT_LOGGED_IN),
                int(CKR_SESSION_READ_ONLY_EXISTS),
            ), f"Expected CKR_SESSION_READ_ONLY, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, test_sh)
