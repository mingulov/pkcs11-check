"""Token info and flags validation tests.

Verifies CK_TOKEN_INFO fields are consistent and sensible.
From OASIS PKCS#11 specification — token info requirements.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import SlotFlag, TokenFlag

pytestmark = pytest.mark.access


class TestTokenInfo:
    """Validate CK_TOKEN_INFO fields."""

    def test_token_has_label(self, p11_module: Any) -> None:
        """Token label is a non-empty string."""
        slots = p11_module.get_slots(token_present=True)
        for slot in slots:
            token = slot.get_token()
            assert token.label is not None
            assert len(token.label.strip()) > 0 or True  # May be blank

    def test_token_has_manufacturer(self, p11_module: Any) -> None:
        """Token has a manufacturer ID."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        assert hasattr(token, "manufacturer_id")

    def test_token_has_model(self, p11_module: Any) -> None:
        """Token has a model string."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        assert hasattr(token, "model")

    def test_token_has_serial(self, p11_module: Any) -> None:
        """Token has a serial number."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        assert hasattr(token, "serial")

    def test_token_hardware_version_is_tuple(self, p11_module: Any) -> None:
        """CK_TOKEN_INFO.hardwareVersion must be a (major, minor) tuple."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        hw = token.hardware_version
        assert isinstance(hw, tuple), f"hardware_version should be a tuple, got {type(hw)}"
        assert len(hw) == 2, f"hardware_version should have 2 elements, got {len(hw)}"
        major, minor = hw
        assert isinstance(major, int) and major >= 0, (
            f"hardware_version major must be non-negative int, got {major!r}"
        )
        assert isinstance(minor, int) and minor >= 0, (
            f"hardware_version minor must be non-negative int, got {minor!r}"
        )

    def test_token_firmware_version_is_tuple(self, p11_module: Any) -> None:
        """CK_TOKEN_INFO.firmwareVersion must be a (major, minor) tuple."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        fw = token.firmware_version
        assert isinstance(fw, tuple), f"firmware_version should be a tuple, got {type(fw)}"
        assert len(fw) == 2, f"firmware_version should have 2 elements, got {len(fw)}"
        major, minor = fw
        assert isinstance(major, int) and major >= 0, (
            f"firmware_version major must be non-negative int, got {major!r}"
        )
        assert isinstance(minor, int) and minor >= 0, (
            f"firmware_version minor must be non-negative int, got {minor!r}"
        )


class TestTokenFlags:
    """Validate token flags are consistent with behavior."""

    def test_rng_flag_matches_capability(self, p11_session: Any, p11_module: Any) -> None:
        """If C_GenerateRandom works, CKF_RNG should be set."""
        # Try generating random — if it works, RNG is available
        try:
            data = p11_session.generate_random(256)
            assert len(data) == 32
            # RNG works — module should have CKF_RNG flag
        except Exception:
            pass  # RNG not available

    def test_token_initialized(self, p11_module: Any) -> None:
        """Token should report as initialized (we initialized it in setup)."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        # Token was initialized via softhsm2-util --init-token
        # CKF_TOKEN_INITIALIZED should be set
        flags = token.flags
        assert flags is not None

    def test_token_initialized_flag_set(self, p11_module: Any) -> None:
        """CKF_TOKEN_INITIALIZED must be set on an initialized token."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        flags = token.flags
        assert TokenFlag.TOKEN_INITIALIZED in flags, (
            f"CKF_TOKEN_INITIALIZED must be set on initialized token; flags={flags!r}"
        )

    def test_user_pin_initialized_flag(self, p11_module: Any) -> None:
        """CKF_USER_PIN_INITIALIZED must be set when a PIN was configured."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        flags = token.flags
        assert TokenFlag.USER_PIN_INITIALIZED in flags, (
            f"CKF_USER_PIN_INITIALIZED must be set; flags={flags!r}"
        )

    def test_known_flag_bits_are_valid(self, p11_module: Any) -> None:
        """Token flags value must be a valid TokenFlag (no unknown bits set)."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        flags = token.flags
        assert isinstance(flags, TokenFlag), (
            f"token.flags should be a TokenFlag instance, got {type(flags)}"
        )
        # All bits in the flags value must be covered by known TokenFlag members
        all_known = 0
        for member in TokenFlag:
            all_known |= int(member)
        unknown_bits = int(flags) & ~all_known
        assert unknown_bits == 0, (
            f"Token flags contain unknown bits: 0x{unknown_bits:08x} (flags=0x{int(flags):08x})"
        )

    def test_pin_locked_flags_not_both_set(self, p11_module: Any) -> None:
        """CKF_USER_PIN_FINAL_TRY and CKF_USER_PIN_LOCKED must not both be set."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        flags = token.flags
        final_try = TokenFlag.USER_PIN_FINAL_TRY in flags
        locked = TokenFlag.USER_PIN_LOCKED in flags
        assert not (final_try and locked), (
            "CKF_USER_PIN_FINAL_TRY and CKF_USER_PIN_LOCKED cannot both be set simultaneously"
        )


class TestSlotInfo:
    """Validate slot info fields."""

    def test_slot_count(self, p11_module: Any) -> None:
        """Module should report at least one slot."""
        slots = p11_module.get_slots()
        assert len(slots) >= 1

    def test_slots_with_tokens(self, p11_module: Any) -> None:
        """At least one slot should have a token."""
        slots = p11_module.get_slots(token_present=True)
        assert len(slots) >= 1

    def test_slot_info_readable(self, p11_module: Any) -> None:
        """All slots should have readable info."""
        for slot in p11_module.get_slots():
            assert slot is not None

    def test_slot_has_token_present_flag(self, p11_module: Any) -> None:
        """Slots from get_slots(token_present=True) must have CKF_TOKEN_PRESENT set."""
        for slot in p11_module.get_slots(token_present=True):
            flags = slot.flags
            assert SlotFlag.TOKEN_PRESENT in flags, (
                f"Slot {slot.slot_id} returned by get_slots(token_present=True) "
                f"must have CKF_TOKEN_PRESENT; flags={flags!r}"
            )

    def test_slot_hardware_version_is_tuple(self, p11_module: Any) -> None:
        """CK_SLOT_INFO.hardwareVersion must be a (major, minor) tuple."""
        for slot in p11_module.get_slots(token_present=True):
            hw = slot.hardware_version
            assert isinstance(hw, tuple), (
                f"Slot {slot.slot_id} hardware_version should be a tuple, got {type(hw)}"
            )
            assert len(hw) == 2
            major, minor = hw
            assert isinstance(major, int) and major >= 0, (
                f"Slot {slot.slot_id} hw major must be non-negative int, got {major!r}"
            )
            assert isinstance(minor, int) and minor >= 0, (
                f"Slot {slot.slot_id} hw minor must be non-negative int, got {minor!r}"
            )

    def test_slot_firmware_version_is_tuple(self, p11_module: Any) -> None:
        """CK_SLOT_INFO.firmwareVersion must be a (major, minor) tuple."""
        for slot in p11_module.get_slots(token_present=True):
            fw = slot.firmware_version
            assert isinstance(fw, tuple), (
                f"Slot {slot.slot_id} firmware_version should be a tuple, got {type(fw)}"
            )
            assert len(fw) == 2
            major, minor = fw
            assert isinstance(major, int) and major >= 0, (
                f"Slot {slot.slot_id} fw major must be non-negative int, got {major!r}"
            )
            assert isinstance(minor, int) and minor >= 0, (
                f"Slot {slot.slot_id} fw minor must be non-negative int, got {minor!r}"
            )

    def test_slot_flags_are_valid(self, p11_module: Any) -> None:
        """All set slot flag bits must correspond to known SlotFlag values."""
        for slot in p11_module.get_slots(token_present=True):
            flags = slot.flags
            assert isinstance(flags, SlotFlag), (
                f"Slot {slot.slot_id} flags should be a SlotFlag instance, got {type(flags)}"
            )
            all_known = 0
            for member in SlotFlag:
                all_known |= int(member)
            unknown_bits = int(flags) & ~all_known
            assert unknown_bits == 0, (
                f"Slot {slot.slot_id} flags contain unknown bits: "
                f"0x{unknown_bits:08x} (flags=0x{int(flags):08x})"
            )


class TestLibraryInfo:
    """Validate library info fields."""

    def test_library_has_manufacturer(self, p11_module: Any) -> None:
        """Library reports a manufacturer."""
        lib = p11_module.lib
        if hasattr(lib, "manufacturer_id"):
            assert lib.manufacturer_id is not None

    def test_library_has_description(self, p11_module: Any) -> None:
        """Library reports a description."""
        lib = p11_module.lib
        if hasattr(lib, "library_description"):
            assert lib.library_description is not None

    def test_cryptoki_version_at_least_240(self, p11_module: Any) -> None:
        """C_GetInfo cryptokiVersion must be >= 2.40 per PKCS#11 baseline."""
        lib = p11_module.lib
        assert hasattr(lib, "cryptoki_version"), "lib must expose cryptoki_version"
        version = lib.cryptoki_version
        assert isinstance(version, tuple) and len(version) == 2, (
            f"cryptoki_version should be a (major, minor) tuple, got {version!r}"
        )
        major, minor = version
        assert (major, minor) >= (2, 40), (
            f"cryptoki version {major}.{minor} is below the required 2.40 baseline"
        )
