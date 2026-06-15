"""Guards the capability-gating safety net.

Verify tests are skipped when a module omits CKF_VERIFY. That is only honest
because test_mech_flags.py::test_expected_flags_present still records the
deviation -- which requires the mechanism to carry CKF_VERIFY in its registry
expected_flags. If that is ever removed, gating would hide the finding. This
test fails loudly in that case.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import CKF_VERIFY, CKM_RSA_PKCS
from pkcs11_check.testcases.mechanism_registry import get_config

# Mechanisms whose on-module verify tests are gated on CKF_VERIFY (Task 3).
GATED_VERIFY_MECHANISMS = [CKM_RSA_PKCS]


def test_gated_mechanisms_mandate_verify_flag():
    for mech in GATED_VERIFY_MECHANISMS:
        config = get_config(int(mech))
        assert config is not None, f"{mech!r} missing from mechanism registry"
        assert config.expected_flags & int(CKF_VERIFY), (
            f"{mech!r} no longer mandates CKF_VERIFY in expected_flags -- gating "
            f"its verify tests would now HIDE the deviation. Restore the flag or "
            f"remove the gate."
        )
