"""Shared result policy for signature-vector verification tests."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
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
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
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
