"""Guards the capability-gating safety net.

Verify tests are skipped when a module omits CKF_VERIFY. That is only honest
because test_mech_flags.py::test_expected_flags_present still records the
deviation -- which requires the mechanism to carry CKF_VERIFY in its registry
expected_flags. If that is ever removed, gating would hide the finding. This
test fails loudly in that case.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_VERIFY,
    CKM_ECDSA_SHA256,
    CKM_EDDSA,
    CKM_ML_DSA,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS,
    CKM_SLH_DSA,
)
from pkcs11_check.testcases.mechanism_registry import get_config

# Mechanisms whose on-module verify tests are gated on CKF_VERIFY (one
# representative per gated suite: test_verify_signature, ckr/test_ckr_verify,
# and the ACVP *_sigver suites for ECDSA/RSA-PSS/EdDSA/ML-DSA/SLH-DSA). Each
# must keep CKF_VERIFY in its registry expected_flags or gating its verify
# tests would hide the deviation that test_expected_flags_present records.
GATED_VERIFY_MECHANISMS = [
    CKM_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_ECDSA_SHA256,
    CKM_RSA_PKCS_PSS,
    CKM_EDDSA,
    CKM_ML_DSA,
    CKM_SLH_DSA,
]


def test_gated_mechanisms_mandate_verify_flag():
    for mech in GATED_VERIFY_MECHANISMS:
        config = get_config(int(mech))
        assert config is not None, f"{mech!r} missing from mechanism registry"
        assert config.expected_flags & int(CKF_VERIFY), (
            f"{mech!r} no longer mandates CKF_VERIFY in expected_flags -- gating "
            f"its verify tests would now HIDE the deviation. Restore the flag or "
            f"remove the gate."
        )
