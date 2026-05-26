"""Regression tests for interop/crossverify runtime classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR
from pkcs11_check.testcases._interop_runtime import xfail_if_interop_operation_reject


def test_interop_general_error_operation_reject_is_xfail() -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_GENERAL_ERROR",
        int(CKR_GENERAL_ERROR),
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_ECB encrypt"):
        xfail_if_interop_operation_reject(exc, "AES_ECB encrypt")


def test_interop_unlisted_operation_reject_stays_failure() -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_FAILED",
        int(CKR_FUNCTION_FAILED),
    )

    try:
        raise exc
    except AssertionError as caught:
        with pytest.raises(CkrAssertionError, match="CKR_FUNCTION_FAILED"):
            xfail_if_interop_operation_reject(caught, "AES_ECB encrypt")
