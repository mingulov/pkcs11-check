"""Mechanism flag validation tests.

Parametrized by mech_any_entry — checks every mechanism advertised by the
module against the OASIS PKCS#11 spec expectations stored in the registry.

Tests:
  - Expected CKF_* flags from the registry are a subset of reported flags
  - min_key_size <= max_key_size (sanity check on C_GetMechanismInfo output)
"""

from __future__ import annotations

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.testcases.mechanism_catalog import MechEntry

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.flag_validation]

# Mechanism-flag names for readable failure messages.
# These are the standard CKF_* flags returned by C_GetMechanismInfo.
_MECH_FLAG_NAMES: dict[int, str] = {
    0x00000001: "CKF_HW",
    0x00000002: "CKF_MESSAGE_ENCRYPT",
    0x00000004: "CKF_MESSAGE_DECRYPT",
    0x00000008: "CKF_MESSAGE_SIGN",
    0x00000010: "CKF_MESSAGE_VERIFY",
    0x00000020: "CKF_MULTI_MESSAGE",
    0x00000040: "CKF_FIND_OBJECTS",
    0x00000100: "CKF_ENCRYPT",
    0x00000200: "CKF_DECRYPT",
    0x00000400: "CKF_DIGEST",
    0x00000800: "CKF_SIGN",
    0x00001000: "CKF_SIGN_RECOVER",
    0x00002000: "CKF_VERIFY",
    0x00004000: "CKF_VERIFY_RECOVER",
    0x00008000: "CKF_GENERATE",
    0x00010000: "CKF_GENERATE_KEY_PAIR",
    0x00020000: "CKF_WRAP",
    0x00040000: "CKF_UNWRAP",
    0x00080000: "CKF_DERIVE",
    0x10000000: "CKF_ENCAPSULATE",
    0x20000000: "CKF_DECAPSULATE",
    0x80000000: "CKF_EXTENSION",
}


def _flag_names(mask: int) -> list[str]:
    """Convert a bitmask to a sorted list of CKF_* flag name strings."""
    names = []
    bit = 1
    while bit <= mask:
        if mask & bit:
            names.append(_MECH_FLAG_NAMES.get(bit, f"0x{bit:08x}"))
        bit <<= 1
    return names


class TestMechFlags:
    """Validate mechanism flags reported by C_GetMechanismInfo."""

    def test_expected_flags_present(
        self, p11_raw_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """Every expected CKF_* flag from the registry must appear in actual flags.

        The registry records the minimum flags the OASIS spec mandates for each
        mechanism.  A module may advertise additional flags (e.g. CKF_HW), but
        must not be missing required ones.
        """
        entry = mech_any_entry
        if entry.config is None:
            pytest.skip("No registry config for flag validation")
        if entry.config.expected_flags == 0:
            pytest.skip("No expected flags defined in registry for this mechanism")

        expected = entry.config.expected_flags
        actual = entry.flags
        missing = expected & ~actual
        if missing:
            missing_names = _flag_names(missing)
            pytest.fail(
                f"{entry.mech_name}: missing expected flags {missing_names} "
                f"(registry expected=0x{expected:08x}, "
                f"module reported=0x{actual:08x})"
            )

    def test_min_le_max_key_size(
        self, p11_raw_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """min_key_size must be <= max_key_size from C_GetMechanismInfo.

        Both being 0 is valid (digest mechanisms or mechanisms with no key size
        constraints return 0/0 per spec).
        """
        entry = mech_any_entry
        if entry.min_key_size == 0 and entry.max_key_size == 0:
            return  # 0/0 means "no key size constraint" — valid
        assert entry.min_key_size <= entry.max_key_size, (
            f"{entry.mech_name}: min_key_size ({entry.min_key_size}) > "
            f"max_key_size ({entry.max_key_size}) — invalid C_GetMechanismInfo output"
        )
