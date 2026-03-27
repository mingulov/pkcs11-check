"""PKCS#11 v3.0 profile object tests.

CKO_PROFILE objects are supported from PKCS#11 v3.0.  These objects expose
which conformance profiles a token claims to support.  Tests auto-skip on
v2.40 modules.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import find_objects, read_attributes
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_PROFILE_ID,
    CKO_PROFILE,
    CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER,
    CKP_VENDOR_DEFINED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = pytest.mark.requires_v30

# CKR codes acceptable when profile attribute reads fail
_PROFILE_ATTR_ERROR_CKRS = (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)

# Known standard profile IDs
_KNOWN_PROFILE_IDS = {
    CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER,
    # Authentication Token and Public Certificates Token profiles
    0x00000003,  # CKP_AUTHENTICATION_TOKEN
    0x00000004,  # CKP_PUBLIC_CERTIFICATES_TOKEN
}


class TestProfileObjects:
    """Tests for CKO_PROFILE object enumeration (PKCS#11 v3.0+)."""

    def _get_profiles(self, rs: Any) -> list[int]:
        """Enumerate CKO_PROFILE objects."""
        try:
            return find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_PROFILE}),
            )
        except AssertionError as exc:
            if "CKR_" in str(exc):
                pytest.skip(f"Profile enumeration not supported: {exc}")
            raise

    def test_profile_object_enumeration(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_PROFILE objects without error."""
        profiles = self._get_profiles(p11_raw_session)
        assert isinstance(profiles, list)

    def test_profile_objects_have_profile_id(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Each CKO_PROFILE object has a readable CKA_PROFILE_ID."""
        rs = p11_raw_session
        profiles = self._get_profiles(rs)
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        for prof in profiles:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    prof,
                    [CKA_PROFILE_ID],
                )
                pid = attrs[CKA_PROFILE_ID]
                assert pid is not None
            except (AssertionError, Exception) as exc:
                xfail_if_known_ckr(exc, _PROFILE_ATTR_ERROR_CKRS, "Cannot read CKA_PROFILE_ID")

    def test_known_profile_ids(self, p11_raw_session: Any) -> None:
        """Profile IDs are known PKCS#11 values or vendor-defined."""
        rs = p11_raw_session
        profiles = self._get_profiles(rs)
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        for prof in profiles:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    prof,
                    [CKA_PROFILE_ID],
                )
                raw_val = attrs[CKA_PROFILE_ID]
                if isinstance(raw_val, bytes):
                    pid = int.from_bytes(raw_val, "little")
                else:
                    pid = int(raw_val)
            except (AssertionError, KeyError):
                continue
            if pid < CKP_VENDOR_DEFINED:
                assert pid in _KNOWN_PROFILE_IDS, f"Unknown non-vendor profile ID 0x{pid:08X}"

    def test_baseline_or_extended_profile_present(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Module advertises Baseline or Extended Provider profile."""
        rs = p11_raw_session
        profiles = self._get_profiles(rs)
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        pids: set[int] = set()
        for prof in profiles:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    prof,
                    [CKA_PROFILE_ID],
                )
                raw_val = attrs[CKA_PROFILE_ID]
                if isinstance(raw_val, bytes):
                    pids.add(int.from_bytes(raw_val, "little"))
                else:
                    pids.add(int(raw_val))
            except (AssertionError, KeyError):
                pass
        standard = {CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER}
        if not pids & standard:
            pytest.xfail(
                "Module does not advertise Baseline or Extended Provider "
                f"profile - profiles present: {[hex(p) for p in sorted(pids)]}"
            )
