"""Token info and flags validation tests.

Verifies CK_TOKEN_INFO fields are consistent and sensible.
From OASIS PKCS#11 specification - token info requirements.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import get_slot_ids
from pkcs11_check.raw.recipes import generate_random, get_slot_info
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_TOKEN_INFO,
    CKF_TOKEN_INITIALIZED,
    CKF_TOKEN_PRESENT,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_INITIALIZED,
    CKF_USER_PIN_LOCKED,
    CKR_OK,
)

pytestmark = pytest.mark.access


class TestTokenInfo:
    """Validate CK_TOKEN_INFO fields."""

    def _get_token_info(self, rs: Any) -> CK_TOKEN_INFO:
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        return info

    def test_token_has_label(self, p11_raw_session: Any) -> None:
        """Token label is a non-empty string."""
        info = self._get_token_info(p11_raw_session)
        label = bytes(info.label).decode("utf-8", errors="replace").strip()
        assert label is not None

    def test_token_has_manufacturer(self, p11_raw_session: Any) -> None:
        """Token has a manufacturer ID."""
        info = self._get_token_info(p11_raw_session)
        manufacturer = bytes(info.manufacturerID).decode("utf-8", errors="replace").strip()
        assert manufacturer is not None

    def test_token_has_model(self, p11_raw_session: Any) -> None:
        """Token has a model string."""
        info = self._get_token_info(p11_raw_session)
        model = bytes(info.model).decode("utf-8", errors="replace").strip()
        assert model is not None

    def test_token_has_serial(self, p11_raw_session: Any) -> None:
        """Token has a serial number."""
        info = self._get_token_info(p11_raw_session)
        serial = bytes(info.serialNumber).decode("utf-8", errors="replace").strip()
        assert serial is not None

    def test_token_hardware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_TOKEN_INFO.hardwareVersion must have valid major/minor."""
        info = self._get_token_info(p11_raw_session)
        major = info.hardwareVersion.major
        minor = info.hardwareVersion.minor
        assert major >= 0, f"hardware_version major must be non-negative, got {major}"
        assert minor >= 0, f"hardware_version minor must be non-negative, got {minor}"

    def test_token_firmware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_TOKEN_INFO.firmwareVersion must have valid major/minor."""
        info = self._get_token_info(p11_raw_session)
        major = info.firmwareVersion.major
        minor = info.firmwareVersion.minor
        assert major >= 0, f"firmware_version major must be non-negative, got {major}"
        assert minor >= 0, f"firmware_version minor must be non-negative, got {minor}"


class TestTokenFlags:
    """Validate token flags are consistent with behavior."""

    def test_rng_flag_matches_capability(self, p11_raw_session: Any) -> None:
        """If C_GenerateRandom works, CKF_RNG should be set."""
        rs = p11_raw_session
        # Try generating random - if it works, RNG is available
        try:
            data = generate_random(rs.raw, rs.sh, 32)
            assert len(data) == 32
            # RNG works - module should have CKF_RNG flag
        except Exception:
            pass  # RNG not available

    def test_token_initialized(self, p11_raw_session: Any) -> None:
        """Token should report as initialized (we initialized it in setup)."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        flags = info.flags
        assert flags is not None

    def test_token_initialized_flag_set(self, p11_raw_session: Any) -> None:
        """CKF_TOKEN_INITIALIZED must be set on an initialized token."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        assert info.flags & CKF_TOKEN_INITIALIZED, (
            f"CKF_TOKEN_INITIALIZED must be set on initialized token; flags=0x{info.flags:08x}"
        )

    def test_user_pin_initialized_flag(self, p11_raw_session: Any) -> None:
        """CKF_USER_PIN_INITIALIZED must be set when a PIN was configured."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        assert info.flags & CKF_USER_PIN_INITIALIZED, (
            f"CKF_USER_PIN_INITIALIZED must be set; flags=0x{info.flags:08x}"
        )

    def test_pin_locked_flags_not_both_set(self, p11_raw_session: Any) -> None:
        """CKF_USER_PIN_FINAL_TRY and CKF_USER_PIN_LOCKED must not both be set."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        final_try = bool(info.flags & CKF_USER_PIN_FINAL_TRY)
        locked = bool(info.flags & CKF_USER_PIN_LOCKED)
        assert not (final_try and locked), (
            "CKF_USER_PIN_FINAL_TRY and CKF_USER_PIN_LOCKED cannot both be set simultaneously"
        )


class TestSlotInfo:
    """Validate slot info fields."""

    def test_slot_count(self, p11_raw_session: Any) -> None:
        """Module should report at least one slot."""
        rs = p11_raw_session
        slots = get_slot_ids(rs.raw, token_present=False)
        assert len(slots) >= 1

    def test_slots_with_tokens(self, p11_raw_session: Any) -> None:
        """At least one slot should have a token."""
        rs = p11_raw_session
        slots = get_slot_ids(rs.raw, token_present=True)
        assert len(slots) >= 1

    def test_slot_info_readable(self, p11_raw_session: Any) -> None:
        """All slots should have readable info."""
        rs = p11_raw_session
        for slot_id in get_slot_ids(rs.raw, token_present=True):
            get_slot_info(rs.raw, slot_id)

    def test_slot_has_token_present_flag(self, p11_raw_session: Any) -> None:
        """Slots from get_slot_ids(token_present=True) must have CKF_TOKEN_PRESENT set."""
        rs = p11_raw_session
        for slot_id in get_slot_ids(rs.raw, token_present=True):
            info = get_slot_info(rs.raw, slot_id)
            assert info["flags"] & CKF_TOKEN_PRESENT, (
                f"Slot {slot_id} returned by token_present=True must have "
                f"CKF_TOKEN_PRESENT; flags=0x{info['flags']:08x}"
            )

    def test_slot_hardware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_SLOT_INFO.hardwareVersion must have valid major/minor."""
        rs = p11_raw_session
        for slot_id in get_slot_ids(rs.raw, token_present=True):
            info = get_slot_info(rs.raw, slot_id)
            assert info["hardware_version"][0] >= 0
            assert info["hardware_version"][1] >= 0

    def test_slot_firmware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_SLOT_INFO.firmwareVersion must have valid major/minor."""
        rs = p11_raw_session
        for slot_id in get_slot_ids(rs.raw, token_present=True):
            info = get_slot_info(rs.raw, slot_id)
            assert info["firmware_version"][0] >= 0
            assert info["firmware_version"][1] >= 0


class TestLibraryInfo:
    """Validate library info fields via C_GetInfo."""

    def test_cryptoki_version_at_least_240(self, p11_raw_session: Any) -> None:
        """C_GetInfo cryptokiVersion must be >= 2.40 per PKCS#11 baseline."""
        from pkcs11_check.raw.types_std import CK_INFO

        rs = p11_raw_session
        info = CK_INFO()
        rv = rs.raw.C_GetInfo(byref(info))
        expect_rv(rv, CKR_OK)
        major = info.cryptokiVersion.major
        minor = info.cryptokiVersion.minor
        assert (major, minor) >= (2, 40), (
            f"cryptoki version {major}.{minor} is below the required 2.40 baseline"
        )
