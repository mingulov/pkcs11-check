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
import sys
from typing import Any

import pytest

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import find_objects, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
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
from pkcs11_check.testcases.conftest import reject_or_classify

_KNOWN_HW_FEATURE_TYPES = {
    CKH_MONOTONIC_COUNTER,
    CKH_CLOCK,
    CKH_USER_INTERFACE,
}

pytestmark = pytest.mark.object


def _hw_features(rs: Any) -> list[int]:
    try:
        return find_objects(
            rs.raw,
            rs.sh,
            template_from_dict({CKA_CLASS: CKO_HW_FEATURE}),
        )
    except CkrAssertionError as exc:
        reject_or_classify(exc, (), label="CKO_HW_FEATURE enumeration", kind="metadata")
        raise


def _hw_type(rs: Any, handle: int) -> int:
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_HW_FEATURE_TYPE])
    except CkrAssertionError as exc:
        reject_or_classify(
            exc,
            (),
            label="CKO_HW_FEATURE CKA_HW_FEATURE_TYPE read",
            kind="metadata",
        )
        raise
    raw_value = attrs[CKA_HW_FEATURE_TYPE]
    assert isinstance(raw_value, (int, bytes)), (
        f"Expected int or bytes CKA_HW_FEATURE_TYPE, got {type(raw_value)}"
    )
    return (
        int.from_bytes(raw_value, byteorder=sys.byteorder)
        if isinstance(raw_value, bytes)
        else raw_value
    )


class TestHwFeatureEnumeration:
    """Enumerate CKO_HW_FEATURE objects and validate attributes."""

    def _get_hw_features(self, rs: Any) -> list[int]:
        """Enumerate hardware feature objects, xfail if unsupported."""
        return _hw_features(rs)

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
            _hw_type(rs, feat)

    def test_known_hw_feature_types(self, p11_raw_session: Any) -> None:
        """HW feature types are known standard values or vendor-defined."""
        rs = p11_raw_session
        features = self._get_hw_features(rs)
        if not features:
            pytest.skip("No CKO_HW_FEATURE objects present")
        for feat in features:
            hw_type = _hw_type(rs, feat)
            if hw_type < CKH_VENDOR_DEFINED:
                assert hw_type in _KNOWN_HW_FEATURE_TYPES, (
                    f"Unknown non-vendor HW feature type 0x{hw_type:08X}"
                )


class TestHwFeatureClock:
    """Tests for CKH_CLOCK hardware feature objects."""

    def _get_clock_features(self, rs: Any) -> list[int]:
        """Find CKH_CLOCK hardware feature objects."""
        features = _hw_features(rs)
        clocks = []
        for feat in features:
            if _hw_type(rs, feat) == CKH_CLOCK:
                clocks.append(feat)
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
        features = _hw_features(rs)
        counters = []
        for feat in features:
            if _hw_type(rs, feat) == CKH_MONOTONIC_COUNTER:
                counters.append(feat)
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
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKH_MONOTONIC_COUNTER reset-attribute read",
                    kind="metadata",
                )
