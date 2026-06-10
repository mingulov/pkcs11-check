"""Shared result policy for signature-vector verification tests."""

from __future__ import annotations

from typing import NoReturn

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


# An advertised mechanism whose positive (sign / sign-verify roundtrip)
# operation cleanly refuses at runtime -- the mechanism is listed but is not
# operational in this configuration (e.g. FIPS 140-3 deprecates SHA-1 for
# signature generation, so kryoptic-FIPS advertises CKM_ECDSA_SHA1 yet returns
# CKR_DEVICE_ERROR on the actual sign). A clean refusal produces no signature,
# so per the classification model it is an "advertised but not operational"
# deviation (xfail), never a crypto break. Wrong output (a produced signature
# that does not verify) is caught by the runner's verify assertion, not here.
SIGN_NOT_OPERATIONAL_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
)


def xfail_if_sign_not_operational(exc: AssertionError, label: str) -> NoReturn:
    """Classify a clean runtime refusal of an ADVERTISED sign/roundtrip op.

    xfails a known runtime-reject CK_RV as 'advertised but not operational';
    re-raises anything else (including a non-CKR harness/ctypes error, which
    must never be read as not-operational).
    """
    xfail_if_known_ckr(
        exc,
        SIGN_NOT_OPERATIONAL_RVS,
        f"{label}: advertised mechanism not operational (sign refused at runtime)",
    )
    raise exc


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
