"""Registry coverage meta-check (gap-analysis Q2 gap #1).

An advertised mechanism with no registry entry gets no per-(mechanism,
operation) operability verdict from the test_mech_* claim layer. That is a
HARNESS blind spot, not a module deviation -- this test always passes and
makes each blind spot visible as a compliance note, so missing coverage can
never be mistaken for verified conformance.
"""

from __future__ import annotations

import pytest

from pkcs11_check import compliance
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.fixtures import RawSession
from pkcs11_check.plugin import _ensure_mechanism_catalog
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog

pytestmark = [pytest.mark.mechanism_coverage]


def _note_registry_blind_spots(catalog: MechanismCatalog) -> int:
    """Emit a compliance note for each advertised mechanism with no registry config.

    Returns the count of blind-spot entries (always >= 0). The product test
    always passes -- registration gaps are harness work (registry Phases B-D),
    surfaced via notes so missing coverage cannot be mistaken for verified
    conformance.
    """
    unregistered = catalog.filter_unregistered()
    for entry in unregistered:
        compliance.note(
            f"{entry.mech_name} (0x{entry.mech_id:08x}) advertised but has "
            "no registry config -- no per-(mechanism, operation) operability verdict "
            "(harness blind spot, not a module deviation)",
            ComplianceLevel.STANDARD,
            reference="docs/findings/advertised-not-operational-gap-analysis.md Q2",
        )
    return len(unregistered)


class TestMechanismRegistryCoverage:
    def test_advertised_mechanisms_have_registry_coverage(
        self, request: pytest.FixtureRequest, p11_module_session: RawSession
    ) -> None:
        """Diff C_GetMechanismList x CK_MECHANISM_INFO flags against the registry.

        Advertised mechanisms with no registry entry produce a compliance note
        naming the mechanism, its hex id, and the harness blind-spot rationale.
        The test always passes: a blind spot is harness work, not a module
        deviation. The assertion-message count aids report reading.
        """
        catalog = _ensure_mechanism_catalog(request.config)
        if catalog is None:
            pytest.skip("No mechanism catalog (module mechanisms not enumerated)")
        blind_spots = _note_registry_blind_spots(catalog)
        # Always passes: blind spots are surfaced via notes, not failures.
        assert blind_spots >= 0
