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

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import find_objects, read_attributes
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_HAS_RESET,
    CKA_HW_FEATURE_TYPE,
    CKA_RESET_ON_INIT,
    CKA_VALUE,
    CKH_CLOCK,
    CKH_MONOTONIC_COUNTER,
    CKH_USER_INTERFACE,
    CKH_VENDOR_DEFINED,
    CKO_HW_FEATURE,
)

_KNOWN_HW_FEATURE_TYPES = {
    CKH_MONOTONIC_COUNTER,
    CKH_CLOCK,
    CKH_USER_INTERFACE,
}

pytestmark = pytest.mark.object


class TestHwFeatureEnumeration:
    """Enumerate CKO_HW_FEATURE objects and validate attributes."""

    def _get_hw_features(self, rs: Any) -> list[int]:
        """Enumerate hardware feature objects, xfail if unsupported."""
        try:
            return find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_HW_FEATURE}),
            )
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_HW_FEATURE enumeration: {e}")
            return []

    def test_hw_feature_enumeration(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_HW_FEATURE objects without error."""
        features = self._get_hw_features(p11_raw_session)
        assert isinstance(features, list)

    def test_hw_feature_type_readable(self, p11_raw_session: Any) -> None:
        """Each HW_FEATURE object has a readable CKA_HW_FEATURE_TYPE."""
        rs = p11_raw_session
        features = self._get_hw_features(rs)
        if not features:
            pytest.skip("No CKO_HW_FEATURE objects present")
        for feat in features:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    feat,
                    [CKA_HW_FEATURE_TYPE],
                )
                hw_type = attrs[CKA_HW_FEATURE_TYPE]
                assert isinstance(hw_type, (int, bytes))
            except AssertionError as e:
                classify(
                    "not_operational",
                    kind="metadata",
                    label="CKO_HW_FEATURE:CKA_HW_FEATURE_TYPE",
                    operation="C_GetAttributeValue",
                    summary=f"Cannot read CKA_HW_FEATURE_TYPE: {e}",
                )

    def test_known_hw_feature_types(self, p11_raw_session: Any) -> None:
        """HW feature types are known standard values or vendor-defined."""
        rs = p11_raw_session
        features = self._get_hw_features(rs)
        if not features:
            pytest.skip("No CKO_HW_FEATURE objects present")
        for feat in features:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    feat,
                    [CKA_HW_FEATURE_TYPE],
                )
                raw_val = attrs[CKA_HW_FEATURE_TYPE]
                hw_type = (
                    int.from_bytes(raw_val, "little")
                    if isinstance(raw_val, bytes)
                    else int(raw_val)
                )
            except (AssertionError, KeyError):
                continue
            if hw_type < CKH_VENDOR_DEFINED:
                assert hw_type in _KNOWN_HW_FEATURE_TYPES, (
                    f"Unknown non-vendor HW feature type 0x{hw_type:08X}"
                )


class TestHwFeatureClock:
    """Tests for CKH_CLOCK hardware feature objects."""

    def _get_clock_features(self, rs: Any) -> list[int]:
        """Find CKH_CLOCK hardware feature objects."""
        try:
            features = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_HW_FEATURE}),
            )
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_HW_FEATURE enumeration: {e}")
            return []
        clocks = []
        for feat in features:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    feat,
                    [CKA_HW_FEATURE_TYPE],
                )
                raw_val = attrs[CKA_HW_FEATURE_TYPE]
                hw_type = (
                    int.from_bytes(raw_val, "little")
                    if isinstance(raw_val, bytes)
                    else int(raw_val)
                )
                if hw_type == CKH_CLOCK:
                    clocks.append(feat)
            except (AssertionError, KeyError):
                continue
        return clocks

    def test_clock_value_format(self, p11_raw_session: Any) -> None:
        """Clock objects have CKA_VALUE as 16-char YYYYMMDDhhmmssxx."""
        rs = p11_raw_session
        clocks = self._get_clock_features(rs)
        if not clocks:
            pytest.skip("No CKH_CLOCK hardware feature objects present")
        for clock in clocks:
            attrs = read_attributes(rs.raw, rs.sh, clock, [CKA_VALUE])
            value = attrs[CKA_VALUE]
            if isinstance(value, bytes):
                value_str = value.decode("ascii", errors="replace")
            else:
                value_str = str(value)
            assert len(value_str) == 16, f"Clock CKA_VALUE should be 16 chars, got {len(value_str)}"
            assert re.match(r"^\d{14}", value_str), (
                f"Clock CKA_VALUE doesn't match YYYYMMDDhhmmss: {value_str!r}"
            )


class TestHwFeatureCounter:
    """Tests for CKH_MONOTONIC_COUNTER hardware feature objects."""

    def _get_counter_features(self, rs: Any) -> list[int]:
        """Find CKH_MONOTONIC_COUNTER hardware feature objects."""
        try:
            features = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_HW_FEATURE}),
            )
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_HW_FEATURE enumeration: {e}")
            return []
        counters = []
        for feat in features:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    feat,
                    [CKA_HW_FEATURE_TYPE],
                )
                raw_val = attrs[CKA_HW_FEATURE_TYPE]
                hw_type = (
                    int.from_bytes(raw_val, "little")
                    if isinstance(raw_val, bytes)
                    else int(raw_val)
                )
                if hw_type == CKH_MONOTONIC_COUNTER:
                    counters.append(feat)
            except (AssertionError, KeyError):
                continue
        return counters

    def test_counter_has_value(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        counters = self._get_counter_features(rs)
        if not counters:
            pytest.skip("No CKH_MONOTONIC_COUNTER objects present")
        for counter in counters:
            attrs = read_attributes(rs.raw, rs.sh, counter, [CKA_VALUE])
            value = attrs[CKA_VALUE]
            assert value is not None

    def test_counter_reset_attributes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        counters = self._get_counter_features(rs)
        if not counters:
            pytest.skip("No CKH_MONOTONIC_COUNTER objects present")
        for counter in counters:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    counter,
                    [CKA_RESET_ON_INIT, CKA_HAS_RESET],
                )
                assert CKA_RESET_ON_INIT in attrs
                assert CKA_HAS_RESET in attrs
            except AssertionError as e:
                classify(
                    "not_operational",
                    kind="metadata",
                    label="CKH_MONOTONIC_COUNTER:reset attributes",
                    operation="C_GetAttributeValue",
                    summary=f"Cannot read reset attrs from counter: {e}",
                )
