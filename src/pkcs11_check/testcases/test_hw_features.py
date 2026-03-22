"""CKO_HW_FEATURE object enumeration and attribute tests.

OASIS PKCS#11 defines hardware feature objects (CKO_HW_FEATURE) with
CKA_HW_FEATURE_TYPE describing the feature kind:

  CKH_MONOTONIC_COUNTER (0x01) - monotonic counter with CKA_VALUE,
      CKA_RESET_ON_INIT, CKA_HAS_RESET
  CKH_CLOCK (0x02) - hardware clock with CKA_VALUE (16-char UTC time)
  CKH_USER_INTERFACE (0x03) - UI with CKA_PIXEL_X, CKA_PIXEL_Y, etc.

Most software HSMs expose no hardware feature objects.  Tests skip
gracefully when none are found.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

# Hardware feature type constants (no enum in python-pkcs11)
CKH_MONOTONIC_COUNTER = 0x00000001
CKH_CLOCK = 0x00000002
CKH_USER_INTERFACE = 0x00000003
CKH_VENDOR_DEFINED = 0x80000000

_KNOWN_HW_FEATURE_TYPES = {
    CKH_MONOTONIC_COUNTER,
    CKH_CLOCK,
    CKH_USER_INTERFACE,
}

pytestmark = pytest.mark.object


class TestHwFeatureEnumeration:
    """Enumerate CKO_HW_FEATURE objects and validate attributes."""

    def _get_hw_features(self, p11_session: Any) -> list[Any]:
        """Enumerate hardware feature objects, xfail if unsupported."""
        try:
            return list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.HW_FEATURE})
            )
        except PKCS11Error as e:
            pytest.xfail(f"Module does not support CKO_HW_FEATURE enumeration: {e}")
            return []  # unreachable, satisfies mypy

    def test_hw_feature_enumeration(self, p11_session: Any) -> None:
        """Enumerate CKO_HW_FEATURE objects without error."""
        features = self._get_hw_features(p11_session)
        assert isinstance(features, list)

    def test_hw_feature_type_readable(self, p11_session: Any) -> None:
        """Each HW_FEATURE object has a readable CKA_HW_FEATURE_TYPE."""
        features = self._get_hw_features(p11_session)
        if not features:
            pytest.skip("No CKO_HW_FEATURE objects present")
        for feat in features:
            try:
                hw_type = feat[Attribute.HW_FEATURE_TYPE]
                assert isinstance(hw_type, int), (
                    f"Expected int HW_FEATURE_TYPE, got {type(hw_type)}"
                )
            except PKCS11Error as e:
                pytest.xfail(f"Cannot read CKA_HW_FEATURE_TYPE from HW_FEATURE object: {e}")

    def test_known_hw_feature_types(self, p11_session: Any) -> None:
        """HW feature types are known standard values or vendor-defined."""
        features = self._get_hw_features(p11_session)
        if not features:
            pytest.skip("No CKO_HW_FEATURE objects present")
        for feat in features:
            try:
                hw_type = int(feat[Attribute.HW_FEATURE_TYPE])
            except PKCS11Error:
                continue
            if hw_type < CKH_VENDOR_DEFINED:
                assert hw_type in _KNOWN_HW_FEATURE_TYPES, (
                    f"Unknown non-vendor HW feature type 0x{hw_type:08X}"
                )


class TestHwFeatureClock:
    """Tests for CKH_CLOCK hardware feature objects."""

    def _get_clock_features(self, p11_session: Any) -> list[Any]:
        """Find CKH_CLOCK hardware feature objects."""
        try:
            features = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.HW_FEATURE})
            )
        except PKCS11Error as e:
            pytest.xfail(f"Module does not support CKO_HW_FEATURE enumeration: {e}")
            return []
        clocks = []
        for feat in features:
            try:
                if int(feat[Attribute.HW_FEATURE_TYPE]) == CKH_CLOCK:
                    clocks.append(feat)
            except PKCS11Error:
                continue
        return clocks

    def test_clock_value_format(self, p11_session: Any) -> None:
        """Clock objects have CKA_VALUE as 16-char YYYYMMDDhhmmssxx UTC string."""
        clocks = self._get_clock_features(p11_session)
        if not clocks:
            pytest.skip("No CKH_CLOCK hardware feature objects present")
        for clock in clocks:
            value = clock[Attribute.VALUE]
            # CKA_VALUE for clock is a 16-byte UTC time string
            if isinstance(value, bytes):
                value_str = value.decode("ascii", errors="replace")
            else:
                value_str = str(value)
            assert len(value_str) == 16, (
                f"Clock CKA_VALUE should be 16 chars, got {len(value_str)}"
            )
            # Format: YYYYMMDDhhmmssxx - first 14 chars are digits
            assert re.match(r"^\d{14}", value_str), (
                f"Clock CKA_VALUE doesn't match YYYYMMDDhhmmss format: {value_str!r}"
            )


class TestHwFeatureCounter:
    """Tests for CKH_MONOTONIC_COUNTER hardware feature objects."""

    def _get_counter_features(self, p11_session: Any) -> list[Any]:
        """Find CKH_MONOTONIC_COUNTER hardware feature objects."""
        try:
            features = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.HW_FEATURE})
            )
        except PKCS11Error as e:
            pytest.xfail(f"Module does not support CKO_HW_FEATURE enumeration: {e}")
            return []
        counters = []
        for feat in features:
            try:
                if int(feat[Attribute.HW_FEATURE_TYPE]) == CKH_MONOTONIC_COUNTER:
                    counters.append(feat)
            except PKCS11Error:
                continue
        return counters

    def test_counter_has_value(self, p11_session: Any) -> None:
        """Counter objects have a readable CKA_VALUE."""
        counters = self._get_counter_features(p11_session)
        if not counters:
            pytest.skip("No CKH_MONOTONIC_COUNTER hardware feature objects present")
        for counter in counters:
            value = counter[Attribute.VALUE]
            assert value is not None, "Counter CKA_VALUE should not be None"

    def test_counter_reset_attributes(self, p11_session: Any) -> None:
        """Counter objects have CKA_RESET_ON_INIT and CKA_HAS_RESET attributes."""
        counters = self._get_counter_features(p11_session)
        if not counters:
            pytest.skip("No CKH_MONOTONIC_COUNTER hardware feature objects present")
        for counter in counters:
            try:
                reset_on_init = counter[Attribute.RESET_ON_INIT]
                assert isinstance(reset_on_init, bool), (
                    f"CKA_RESET_ON_INIT should be bool, got {type(reset_on_init)}"
                )
            except PKCS11Error as e:
                pytest.xfail(f"Cannot read CKA_RESET_ON_INIT from counter object: {e}")
            try:
                has_reset = counter[Attribute.HAS_RESET]
                assert isinstance(has_reset, bool), (
                    f"CKA_HAS_RESET should be bool, got {type(has_reset)}"
                )
            except PKCS11Error as e:
                pytest.xfail(f"Cannot read CKA_HAS_RESET from counter object: {e}")
