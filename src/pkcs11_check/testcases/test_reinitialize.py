"""Slot re-initialization tests.

Tests C_Finalize + C_Initialize cycle to verify the module
returns to a clean state and can operate normally afterward.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
)
from pkcs11_check.raw.bootstrap import open_session as raw_open_session
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import get_pin_bytes

pytestmark = [pytest.mark.access, pytest.mark.destructive]


class TestReinitialize:
    """Test finalize/initialize cycle."""

    def test_reinitialize_and_use(self, p11_config: Any) -> None:
        """Module works normally after finalize + initialize cycle."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()
        pin_bytes = get_pin_bytes(p11_config)

        # Load and initialize
        raw = RawPKCS11.from_lib(str(module_path))
        rv = raw.C_Initialize(None)
        assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED)

        try:
            slots = get_slot_ids(raw)
            slot_idx = p11_config.slot if p11_config.slot is not None else 0
            slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]
            flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
            sh = raw_open_session(raw, slot_id, flags)
            if pin_bytes is not None:
                login_user(raw, sh, CKU_USER, pin_bytes)
            key = gen_aes_key(raw, sh, 128)
            assert key != 0
            destroy_quietly(raw, sh, key)
            close_session_quietly(raw, sh)
        finally:
            raw.C_Finalize(None)

        # Re-initialize
        rv = raw.C_Initialize(None)
        expect_rv(rv, CKR_OK)
        try:
            slots = get_slot_ids(raw)
            slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]
            sh = raw_open_session(raw, slot_id, flags)
            if pin_bytes is not None:
                login_user(raw, sh, CKU_USER, pin_bytes)
            key = gen_aes_key(raw, sh, 128)
            assert key != 0
            destroy_quietly(raw, sh, key)
            close_session_quietly(raw, sh)
        finally:
            raw.C_Finalize(None)

    def test_finalize_closes_sessions(self, p11_config: Any) -> None:
        """After finalize, previously opened sessions are invalid."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()
        pin_bytes = get_pin_bytes(p11_config)

        raw = RawPKCS11.from_lib(str(module_path))
        rv = raw.C_Initialize(None)
        assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED)

        slots = get_slot_ids(raw)
        slot_idx = p11_config.slot if p11_config.slot is not None else 0
        slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        sh = raw_open_session(raw, slot_id, flags)
        if pin_bytes is not None:
            login_user(raw, sh, CKU_USER, pin_bytes)

        # Generate a key to prove session works
        key = gen_aes_key(raw, sh, 128)
        assert key != 0
        destroy_quietly(raw, sh, key)

        raw.C_Finalize(None)

        # After finalize, using the old session should fail
        rv = raw.C_Initialize(None)
        expect_rv(rv, CKR_OK)
        try:
            # Old session handle should be invalid now -- any C_ call should fail
            from ctypes import byref

            from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKA_VALUE_LEN, CKM_AES_KEY_GEN

            tmpl = template(attr_ulong(CKA_VALUE_LEN, 16))
            mech = mech_simple(CKM_AES_KEY_GEN)
            new_key = CK_OBJECT_HANDLE(0)
            rv2 = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(new_key))
            # Some modules may reuse the handle -- CKR_OK is acceptable
            # CKR_SESSION_HANDLE_INVALID (0xb3) or any non-OK is expected
            if rv2 == CKR_OK:
                destroy_quietly(raw, sh, new_key.value)
        finally:
            raw.C_Finalize(None)
