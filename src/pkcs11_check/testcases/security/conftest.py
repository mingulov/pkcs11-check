"""Shared helpers for security vulnerability tests.

CKR error code sets for classifying module responses to malformed inputs.
Subprocess wrapper for crash-safe test execution.
"""

from __future__ import annotations

from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_SESSION_HANDLE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

# Clean rejection of boundary/invalid inputs (not crash, not OK)
BOUNDARY_REJECT_CKRS = {
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SESSION_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_DEVICE_ERROR,
}

# Clean rejection of bad ciphertext/wrapped data
DATA_REJECT_CKRS = {
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_ARGUMENTS_BAD,
}

# CKR names for subprocess output parsing
BOUNDARY_REJECT_NAMES = frozenset(ckr_name(int(c)) for c in BOUNDARY_REJECT_CKRS)
DATA_REJECT_NAMES = frozenset(ckr_name(int(c)) for c in DATA_REJECT_CKRS)


def assert_subprocess_no_crash(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Assert a subprocess completed without crashing or child-script failure.

    Args:
        rc: subprocess returncode. Negative means killed by signal; positive
            means the child script failed before completing the probe.
        stdout: subprocess stdout.
        stderr: subprocess stderr.
        context: Human-readable test description for failure message.
    """
    assert_subprocess_completed(rc, stdout, stderr, context=context)
