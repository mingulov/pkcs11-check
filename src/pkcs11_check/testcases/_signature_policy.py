"""Shared result policy for signature-vector verification tests."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_ACTIVE,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

SIGNATURE_REJECT_RVS = (
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)

NON_CLEAN_SIGNATURE_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    # Digest-length pinning (corePKCS11 accepts exactly 32B for CKM_ECDSA): the
    # module rejected the request before evaluating the signature -- xfail
    # evidence, never a clean signature-reject pass (PKCS#11 §2.3.1 requires
    # accepting any hash length, truncating to the group order).
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    # Collateral of a stale verify operation the provider leaked after a prior
    # reject (kryoptic/tpm2 spec violation; reported as a FAIL by
    # test_operation_termination.py): the poisoned C_*Init never evaluated this
    # vector's signature, so the invalid vector was not accepted -- xfail
    # evidence attributed to the leak, not a finding on the innocent vector.
    CKR_OPERATION_ACTIVE,
)


def signature_rejected_or_xfail(exc: AssertionError, label: str) -> bool:
    """Classify an exception from invalid-signature verification.

    Clean PKCS#11 signature-reject CKRs are ordinary vector passes. Generic
    failure CKRs still mean the provider did not accept the invalid signature,
    but they are not clean conformance and must be reported as xfail evidence.
    """
    if is_known_error(exc, SIGNATURE_REJECT_RVS):
        return False
    xfail_if_known_ckr(
        exc,
        NON_CLEAN_SIGNATURE_REJECT_RVS,
        f"{label}: signature verification rejected with non-clean CKR",
    )
    raise exc
