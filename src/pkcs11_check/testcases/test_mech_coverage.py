"""Registry coverage meta-check (gap-analysis Q2 gap #1).

An advertised mechanism with no registry entry gets no per-(mechanism,
operation) operability verdict from the test_mech_* claim layer. That is a
HARNESS blind spot, not a module deviation -- this test always passes and
makes each blind spot visible as a compliance note, so missing coverage for
name-resolvable mechanisms can never be mistaken for verified conformance.

Note: MechanismCatalog.from_manifest drops manifest entries whose names
cannot be resolved via MECHANISM_NAMES (vendor 0x80000000+ ids and a few
unassigned standard ids), so those never reach filter_unregistered(). This
check covers name-resolvable mechanisms only. Unresolvable names are a
separate gap; vendor mechanisms get partial visibility via
test_vendor_extensions.py.
"""

from __future__ import annotations

import pytest

from pkcs11_check import compliance
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.fixtures import RawSession
from pkcs11_check.plugin import _ensure_mechanism_catalog
from pkcs11_check.testcases._capability_claims import _enclosing_test_qualname
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog

pytestmark = [pytest.mark.mechanism_coverage]


def _note_registry_blind_spots(catalog: MechanismCatalog) -> int:
    """Emit a compliance note for each advertised mechanism with no registry config.

    Attributes each note to the enclosing test (not this helper) via
    _enclosing_test_qualname, then emits one summary note when any blind spots
    are found. Returns the count of blind-spot entries (always >= 0). The
    product test always passes -- registration gaps are harness work (registry
    Phases B-D), surfaced via notes so missing coverage cannot be mistaken for
    verified conformance.
    """
    caller_qualname = _enclosing_test_qualname()
    unregistered = catalog.filter_unregistered()
    for entry in unregistered:
        compliance.note(
            f"{entry.mech_name} (0x{entry.mech_id:08x}) advertised but has "
            "no registry config -- no per-(mechanism, operation) operability verdict "
            "(harness blind spot, not a module deviation)",
            ComplianceLevel.STANDARD,
            reference="docs/findings/advertised-not-operational-gap-analysis.md Q2",
            test_id=caller_qualname,
        )
    if unregistered:
        n = len(unregistered)
        noun = "mechanism" if n == 1 else "mechanisms"
        compliance.note(
            f"{n} advertised {noun} lack registry coverage "
            "(harness blind spots -- see per-mechanism notes above)",
            ComplianceLevel.STANDARD,
            reference="docs/findings/advertised-not-operational-gap-analysis.md Q2",
            test_id=caller_qualname,
        )
    return len(unregistered)


class TestMechanismRegistryCoverage:
    def test_advertised_mechanisms_have_registry_coverage(
        self, request: pytest.FixtureRequest, p11_module_session: RawSession
    ) -> None:
        """Diff the registered mechanism set against the catalog from C_GetMechanismList.

        Advertised mechanisms with no registry entry produce a compliance note
        naming the mechanism, its hex id, and the harness blind-spot rationale.
        The test always passes: a blind spot is harness work, not a module
        deviation. Scope: name-resolvable mechanisms only (see module docstring).
        """
        catalog: MechanismCatalog | None = _ensure_mechanism_catalog(request.config)
        if catalog is None:
            pytest.skip("No mechanism catalog (module mechanisms not enumerated)")
        _note_registry_blind_spots(catalog)
        # always passes: blind spots are harness work, not module deviations
