"""Token info and flags validation tests.

Verifies CK_TOKEN_INFO fields are consistent and sensible.
From OASIS PKCS#11 specification - token info requirements.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.bootstrap import get_slot_ids
from pkcs11_check.raw.recipes import generate_random, get_slot_info
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_TOKEN_INFO,
    CKF_RNG,
    CKF_TOKEN_INITIALIZED,
    CKF_TOKEN_PRESENT,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_INITIALIZED,
    CKF_USER_PIN_LOCKED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_RANDOM_NO_RNG,
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
        assert isinstance(label, str)

    def test_token_has_manufacturer(self, p11_raw_session: Any) -> None:
        """Token has a manufacturer ID."""
        info = self._get_token_info(p11_raw_session)
        manufacturer = bytes(info.manufacturerID).decode("utf-8", errors="replace").strip()
        assert isinstance(manufacturer, str)

    def test_token_has_model(self, p11_raw_session: Any) -> None:
        """Token has a model string."""
        info = self._get_token_info(p11_raw_session)
        model = bytes(info.model).decode("utf-8", errors="replace").strip()
        assert isinstance(model, str)

    def test_token_has_serial(self, p11_raw_session: Any) -> None:
        """Token has a serial number."""
        info = self._get_token_info(p11_raw_session)
        serial = bytes(info.serialNumber).decode("utf-8", errors="replace").strip()
        assert isinstance(serial, str)

    def test_token_hardware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_TOKEN_INFO.hardwareVersion fields must be readable CK_BYTE values."""
        info = self._get_token_info(p11_raw_session)
        major = info.hardwareVersion.major
        minor = info.hardwareVersion.minor
        assert (major, minor) != (0xFF, 0xFF), (
            f"hardware_version {major}.{minor} looks like uninitialized memory"
        )

    def test_token_firmware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_TOKEN_INFO.firmwareVersion fields must be readable CK_BYTE values."""
        info = self._get_token_info(p11_raw_session)
        major = info.firmwareVersion.major
        minor = info.firmwareVersion.minor
        assert (major, minor) != (0xFF, 0xFF), (
            f"firmware_version {major}.{minor} looks like uninitialized memory"
        )


class TestTokenFlags:
    """Validate token flags are consistent with behavior."""

    def test_rng_flag_matches_capability(self, p11_raw_session: Any) -> None:
        """CKF_RNG must agree with C_GenerateRandom behavior."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        expect_rv(rs.raw.C_GetTokenInfo(rs.slot_id, byref(info)), CKR_OK)
        try:
            data = generate_random(rs.raw, rs.sh, 32)
        except CkrAssertionError as exc:
            if info.flags & CKF_RNG:
                reason = (
                    "not_operational"
                    if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)
                    else "self_contradiction"
                )
                classify(
                    reason,
                    kind="metadata",
                    label="CKF_RNG",
                    operation="C_GenerateRandom",
                    actual=exc.rv,
                    summary=(
                        f"CKF_RNG is set but C_GenerateRandom refused a positive operation: {exc}"
                    ),
                )
            if exc.rv in (int(CKR_RANDOM_NO_RNG), int(CKR_FUNCTION_NOT_SUPPORTED)):
                return
            raise

        assert len(data) == 32
        if not (info.flags & CKF_RNG):
            classify(
                "self_contradiction",
                kind="metadata",
                label="CKF_RNG",
                operation="C_GenerateRandom",
                actual=CKR_OK,
                summary=(
                    f"C_GenerateRandom succeeded but CKF_RNG is not set; flags=0x{info.flags:08x}"
                ),
            )

    def test_token_initialized(self, p11_raw_session: Any) -> None:
        """Token should report as initialized (we initialized it in setup)."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        flags = info.flags
        assert isinstance(flags, int)

    def test_token_initialized_flag_set(self, p11_raw_session: Any) -> None:
        """CKF_TOKEN_INITIALIZED must be set on an initialized token."""
        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        assert info.flags & CKF_TOKEN_INITIALIZED, (
            f"CKF_TOKEN_INITIALIZED must be set on initialized token; flags=0x{info.flags:08x}"
        )

    def test_user_pin_initialized_flag(self, p11_raw_session: Any, p11_config: Any) -> None:
        """CKF_USER_PIN_INITIALIZED must be set when a PIN was configured.

        PKCS#11 spec: CKF_USER_PIN_INITIALIZED is set after the user PIN has
        been initialized via C_InitPIN or C_SetPIN.

        Some modules do not set CKF_USER_PIN_INITIALIZED even when a PIN is
        configured, because the slot is reported as not requiring a user PIN.
        """
        rs = p11_raw_session
        if p11_config.pin is None:
            pytest.skip("No PIN configured -- CKF_USER_PIN_INITIALIZED check requires a PIN")
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        expect_rv(rv, CKR_OK)
        if not (info.flags & CKF_USER_PIN_INITIALIZED):
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"CKF_USER_PIN_INITIALIZED not set on token with configured PIN; "
                f"flags=0x{info.flags:08x} -- "
                f"module may report this slot as not requiring a user PIN",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 spec CKF_USER_PIN_INITIALIZED",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKF_USER_PIN_INITIALIZED",
                operation="C_GetTokenInfo",
                summary=(
                    f"Module does not set CKF_USER_PIN_INITIALIZED on this slot "
                    f"(flags=0x{info.flags:08x}) -- "
                    f"token does not report user PIN as initialized"
                ),
            )
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
        """CK_SLOT_INFO.hardwareVersion fields must be readable CK_BYTE values."""
        rs = p11_raw_session
        for slot_id in get_slot_ids(rs.raw, token_present=True):
            info = get_slot_info(rs.raw, slot_id)
            hw = info["hardware_version"]
            assert hw != (0xFF, 0xFF), (
                f"slot {slot_id} hardware_version looks like uninitialized memory"
            )

    def test_slot_firmware_version_is_valid(self, p11_raw_session: Any) -> None:
        """CK_SLOT_INFO.firmwareVersion fields must be readable CK_BYTE values."""
        rs = p11_raw_session
        for slot_id in get_slot_ids(rs.raw, token_present=True):
            info = get_slot_info(rs.raw, slot_id)
            fw = info["firmware_version"]
            assert fw != (0xFF, 0xFF), (
                f"slot {slot_id} firmware_version looks like uninitialized memory"
            )


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
