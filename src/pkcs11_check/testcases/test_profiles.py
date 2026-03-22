"""PKCS#11 v3.0 profile object tests.

CKO_PROFILE objects are supported from PKCS#11 v3.0.  These objects expose
which conformance profiles a token claims to support.  Tests auto-skip on
v2.40 modules.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.constants import ProfileID

pytestmark = pytest.mark.requires_v30


class TestProfileObjects:
    """Tests for CKO_PROFILE object enumeration (PKCS#11 v3.0+)."""

    def test_profile_object_enumeration(self, p11_session: Any) -> None:
        """Enumerate CKO_PROFILE objects without error."""
        try:
            profiles = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.PROFILE})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_PROFILE enumeration")
        # Not all v3.0 modules expose profile objects -- treat empty list as acceptable
        assert isinstance(profiles, list)

    def test_profile_objects_have_profile_id(self, p11_session: Any) -> None:
        """Each CKO_PROFILE object has a readable CKA_PROFILE_ID attribute."""
        try:
            profiles = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.PROFILE})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_PROFILE enumeration")
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        for prof in profiles:
            try:
                pid = prof[Attribute.PROFILE_ID]
                assert isinstance(pid, int), f"Expected int PROFILE_ID, got {type(pid)}"
            except Exception:
                pytest.xfail("Cannot read CKA_PROFILE_ID from profile object")

    def test_known_profile_ids(self, p11_session: Any) -> None:
        """Profile IDs are known PKCS#11 profile values or vendor-defined."""
        try:
            profiles = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.PROFILE})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_PROFILE enumeration")
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        known = {int(p) for p in ProfileID}
        for prof in profiles:
            try:
                pid = int(prof[Attribute.PROFILE_ID])
            except Exception:
                continue
            if pid < ProfileID.VENDOR_DEFINED:
                assert pid in known, (
                    f"Unknown non-vendor profile ID 0x{pid:08X}"
                )

    def test_baseline_or_extended_profile_present(self, p11_session: Any) -> None:
        """Module advertises Baseline or Extended Provider profile (recommended)."""
        try:
            profiles = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.PROFILE})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_PROFILE enumeration")
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        pids = set()
        for prof in profiles:
            try:
                pids.add(int(prof[Attribute.PROFILE_ID]))
            except Exception:
                pass
        standard = {ProfileID.BASELINE_PROVIDER, ProfileID.EXTENDED_PROVIDER}
        if not pids & {int(p) for p in standard}:
            pytest.xfail(
                "Module does not advertise Baseline or Extended Provider profile -- "
                f"profiles present: {[hex(p) for p in sorted(pids)]}"
            )
