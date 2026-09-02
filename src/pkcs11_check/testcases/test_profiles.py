"""PKCS#11 v3.0 profile object tests.

CKO_PROFILE objects are supported from PKCS#11 v3.0.  These objects expose
which conformance profiles a token claims to support.  Tests auto-skip on
v2.40 modules.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import find_objects, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_PROFILE_ID,
    CKO_PROFILE,
    CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER,
    CKP_VENDOR_DEFINED,
)
from pkcs11_check.testcases.conftest import reject_or_classify

# Known standard profile IDs
_KNOWN_PROFILE_IDS = {
    CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER,
    # Authentication Token and Public Certificates Token profiles
    0x00000003,  # CKP_AUTHENTICATION_TOKEN
    0x00000004,  # CKP_PUBLIC_CERTIFICATES_TOKEN
}

pytestmark = [pytest.mark.object, pytest.mark.v30]


@pytest.fixture(autouse=True)
def _requires_v30(p11_interface_version: str) -> None:
    if p11_interface_version == "2.40":
        pytest.skip("CKO_PROFILE requires PKCS#11 v3.0+")


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
        except CkrAssertionError as exc:
            reject_or_classify(exc, (), label="CKO_PROFILE enumeration", kind="metadata")
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
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_PROFILE CKA_PROFILE_ID read",
                    kind="metadata",
                )

    def test_known_profile_ids(self, p11_raw_session: Any) -> None:
        """Profile IDs are known PKCS#11 values or vendor-defined."""
        rs = p11_raw_session
        profiles = self._get_profiles(rs)
        if not profiles:
            pytest.skip("No CKO_PROFILE objects present")
        for prof in profiles:
            try:
                attrs = read_attributes(rs.raw, rs.sh, prof, [CKA_PROFILE_ID])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_PROFILE CKA_PROFILE_ID read",
                    kind="metadata",
                )
                raise
            raw_val = attrs[CKA_PROFILE_ID]
            pid = (
                int.from_bytes(raw_val, byteorder=sys.byteorder)
                if isinstance(raw_val, bytes)
                else int(raw_val)
            )
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
                attrs = read_attributes(rs.raw, rs.sh, prof, [CKA_PROFILE_ID])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_PROFILE CKA_PROFILE_ID read",
                    kind="metadata",
                )
                raise
            raw_val = attrs[CKA_PROFILE_ID]
            pids.add(
                int.from_bytes(raw_val, byteorder=sys.byteorder)
                if isinstance(raw_val, bytes)
                else int(raw_val)
            )
        standard = {CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER}
        if not pids & standard:
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKO_PROFILE:baseline-or-extended",
                summary=(
                    "Module does not advertise Baseline or Extended Provider "
                    f"profile - profiles present: {[hex(p) for p in sorted(pids)]}"
                ),
            )


def _read_profile_ids(rs: Any) -> set[int]:
    """Enumerate CKO_PROFILE objects and return the set of their CKA_PROFILE_IDs.

    Returns an empty set only when no profile objects exist. Read and
    enumeration failures remain visible findings.
    """
    try:
        handles = find_objects(rs.raw, rs.sh, template_from_dict({CKA_CLASS: CKO_PROFILE}))
    except CkrAssertionError as exc:
        reject_or_classify(exc, (), label="CKO_PROFILE enumeration", kind="metadata")
        raise

    pids: set[int] = set()
    for h in handles:
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_PROFILE_ID])
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                (),
                label="CKO_PROFILE CKA_PROFILE_ID read",
                kind="metadata",
            )
            raise
        assert CKA_PROFILE_ID in attrs, "CKO_PROFILE object is missing CKA_PROFILE_ID"
        raw_val = attrs[CKA_PROFILE_ID]
        if isinstance(raw_val, bytes):
            pids.add(int.from_bytes(raw_val, byteorder=sys.byteorder))
        else:
            pids.add(int(raw_val))
    return pids


class TestProfileBehavioralConformance:
    """For each advertised CKO_PROFILE, verify the module supports the
    mandatory functions, object classes, and mechanisms the OASIS
    PKCS#11 Profiles v3.2 spec requires for that profile.

    A module that advertises CKP_BASELINE_PROVIDER but doesn't expose
    `C_GetSessionInfo` in its function list is non-conformant; this
    test surfaces such inconsistencies.

    Source: OASIS PKCS#11 Profiles v3.2 §5 (Base Profiles).
    """

    def test_advertised_profiles_have_required_functions(self, p11_raw_session: Any) -> None:
        """Every advertised profile's mandatory functions must be in the
        module's function list (`C_GetInterface`-resolved)."""
        from pkcs11_check.compliance_profiles import (
            PROFILE_TEST_EXCLUDED,
            lookup_profile,
        )

        rs = p11_raw_session
        pids = _read_profile_ids(rs)
        if not pids:
            pytest.skip("No CKO_PROFILE objects present")

        available = set(rs.raw.available_function_names())
        failures: list[str] = []
        tested_any = False

        for pid in pids:
            if pid in PROFILE_TEST_EXCLUDED:
                continue
            profile = lookup_profile(pid)
            if profile is None:
                continue  # unknown / vendor profile — not our table to enforce
            tested_any = True

            missing = profile.required_functions - available
            # Authentication Token spec allows either C_Sign or
            # (C_SignUpdate + C_SignFinal) as the data-signing path; relax.
            if pid == 0x00000003:  # CKP_AUTHENTICATION_TOKEN
                if "C_Sign" in available or (
                    "C_SignUpdate" in available and "C_SignFinal" in available
                ):
                    pass  # signing path present in some form
                else:
                    missing = missing | {"C_Sign (or C_SignUpdate + C_SignFinal)"}

            if missing:
                failures.append(
                    f"{profile.profile_name} (0x{pid:08X}): missing required "
                    f"functions {sorted(missing)}"
                )

        if not tested_any:
            pytest.skip("No tabulated profile IDs advertised by module")
        if failures:
            # An advertised profile missing mandatory functions is
            # provider-incompleteness -> honest_deviation (noted xfail), not a hard
            # fail: the suite is provider-general with no single reference
            # implementation to declare the module broken (see Phase 5 P1a and
            # tests/test_profiles_classification.py).
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKO_PROFILE:required-functions",
                summary="Profile conformance failures:\n  " + "\n  ".join(failures),
            )

    def test_advertised_profiles_have_required_mechanisms(self, p11_raw_session: Any) -> None:
        """Profiles that mandate specific mechanisms (HKDF TLS Token) must
        advertise them in C_GetMechanismList."""
        from pkcs11_check.compliance_profiles import (
            PROFILE_TEST_EXCLUDED,
            lookup_profile,
        )
        from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

        rs = p11_raw_session
        pids = _read_profile_ids(rs)
        if not pids:
            pytest.skip("No CKO_PROFILE objects present")

        failures: list[str] = []
        tested_any = False

        for pid in pids:
            if pid in PROFILE_TEST_EXCLUDED:
                continue
            profile = lookup_profile(pid)
            if profile is None or not profile.required_mechanisms:
                continue
            tested_any = True

            missing_mechs: list[str] = []
            for mech_id in profile.required_mechanisms:
                # has_mechanism takes short or full name
                mech_name = MECHANISM_NAMES.get(mech_id, f"0x{mech_id:08X}")
                short = mech_name.removeprefix("CKM_")
                if not (rs.has_mechanism(short) or rs.has_mechanism(mech_name)):
                    missing_mechs.append(mech_name)

            if missing_mechs:
                failures.append(
                    f"{profile.profile_name} (0x{pid:08X}): missing required "
                    f"mechanisms {missing_mechs}"
                )

        if not tested_any:
            pytest.skip(
                "No advertised profile mandates specific mechanisms "
                "(Baseline / Extended / Authentication / PublicCert all have "
                "'None specified' for mechs)"
            )
        if failures:
            # An advertised profile missing mandatory mechanisms is
            # provider-incompleteness -> honest_deviation (noted xfail), not a hard
            # fail: the suite is provider-general with no single reference
            # implementation to declare the module broken (see Phase 5 P1a and
            # tests/test_profiles_classification.py).
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKO_PROFILE:required-mechanisms",
                summary="Profile mechanism-conformance failures:\n  " + "\n  ".join(failures),
            )

    def test_advertised_profiles_have_required_object_classes(self, p11_raw_session: Any) -> None:
        """Profiles that mandate specific object classes must be able to
        enumerate at least one object of each (where the class is
        token-resident by nature)."""
        from pkcs11_check.compliance_profiles import (
            PROFILE_TEST_EXCLUDED,
            lookup_profile,
        )
        from pkcs11_check.raw.types_std import (
            CKO_CERTIFICATE,
        )

        rs = p11_raw_session
        pids = _read_profile_ids(rs)
        if not pids:
            pytest.skip("No CKO_PROFILE objects present")

        tested_any = False
        # We only check classes that are *required to be present* per the
        # profile semantics (e.g. Public Certificates Token requires at
        # least the existence of CKO_CERTIFICATE-class objects).  Object
        # classes that are "supported" but not "required to be present"
        # (e.g. CKO_PRIVATE_KEY for Authentication Token) are skipped —
        # the token might be unprovisioned.

        for pid in pids:
            if pid in PROFILE_TEST_EXCLUDED:
                continue
            profile = lookup_profile(pid)
            if profile is None:
                continue

            # Public Certificates Token: spec §5.5 requires certificates
            # to be present and publicly readable.
            if pid == 0x00000004:  # CKP_PUBLIC_CERTIFICATES_TOKEN
                tested_any = True
                try:
                    certs = find_objects(
                        rs.raw,
                        rs.sh,
                        template_from_dict({CKA_CLASS: CKO_CERTIFICATE}),
                    )
                except CkrAssertionError as exc:
                    # A clean enumeration error for an advertised profile is an
                    # advertised-but-not-operational read -> xfail (noted deviation).
                    reject_or_classify(
                        exc,
                        (),
                        kind="metadata",
                        label="CKP_PUBLIC_CERTIFICATES_TOKEN:C_FindObjects",
                    )
                if not certs:
                    # An advertised profile with no required objects present (e.g. an
                    # unprovisioned token) is a harmless honest deviation -> xfail.
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="CKP_PUBLIC_CERTIFICATES_TOKEN:certificate-presence",
                        summary=(
                            "Public Certificates Token profile advertised, but "
                            "no CKO_CERTIFICATE objects are present on token. "
                            "Spec §5.5 requires certificates be present and "
                            "publicly readable."
                        ),
                    )

        if not tested_any:
            pytest.skip(
                "No advertised profile requires class-presence checks (only "
                "Public Certificates Token does)"
            )
