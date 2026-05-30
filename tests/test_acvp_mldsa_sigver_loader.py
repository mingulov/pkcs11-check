"""Regression test for ACVP ML-DSA sigVer vector filtering (PC-2).

PKCS#11 v3.2 exposes only the *external* ML-DSA Sign/Verify interface
(CKM_ML_DSA and CKM_HASH_ML_DSA_*), which internally constructs the
M' representative from (M, ctx) per FIPS 204 Algorithm 2. ACVP also
ships vectors for the *internal* Sign_internal/Verify_internal that
operate on a pre-formatted message (`externalMu=false`) or on a
pre-computed mu (`externalMu=true`). Those vectors cannot be tested
through PKCS#11 — feeding their `message` field to CKM_ML_DSA wraps
it again and verification fails for the wrong reason.

This filter was missing in v0.1.1, producing 36 cross-provider
'rejected a VALID' false-fails on the 3 valid tcs of groups 8/10/12
(ML-DSA-44 tc108/112/116, ML-DSA-65 tc139/141/142, ML-DSA-87
tc169/172/174).
"""

from __future__ import annotations

import pytest

from pkcs11_check.testcases.acvp._mldsa_helpers import load_mldsa_sigver_vectors
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE

pytestmark = pytest.mark.skipif(not ACVP_AVAILABLE, reason="ACVP vectors not cloned")

# tcIds that belong to signatureInterface=internal groups and were
# emitting false-fails. Listed verbatim from artifacts/softhsm2-main/.
_INTERNAL_INTERFACE_FALSE_FAILS: tuple[tuple[str, int], ...] = (
    ("ML-DSA-44", 108),
    ("ML-DSA-44", 112),
    ("ML-DSA-44", 116),
    ("ML-DSA-65", 139),
    ("ML-DSA-65", 141),
    ("ML-DSA-65", 142),
    ("ML-DSA-87", 169),
    ("ML-DSA-87", 172),
    ("ML-DSA-87", 174),
)


def test_sigver_loader_drops_internal_interface_vectors() -> None:
    """No vector from signatureInterface=internal groups must reach the test."""
    vectors = load_mldsa_sigver_vectors()
    if not vectors:
        pytest.skip("ML-DSA-sigVer ACVP vectors not present")

    seen_param_tcs: set[tuple[str, int]] = {(v["param_set"], v["tc_id"]) for _, v in vectors}

    for entry in _INTERNAL_INTERFACE_FALSE_FAILS:
        assert entry not in seen_param_tcs, (
            f"{entry} is from a signatureInterface=internal group and is "
            "not representable through CKM_ML_DSA; loader must skip it."
        )

    # Sanity: external-interface vectors are still included.
    assert ("ML-DSA-44", 1) in seen_param_tcs
    assert ("ML-DSA-65", 31) in seen_param_tcs
    assert ("ML-DSA-87", 61) in seen_param_tcs
