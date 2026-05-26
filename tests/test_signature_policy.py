"""Regression tests for shared invalid-signature result classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail


@pytest.mark.parametrize(
    ("rv", "name"),
    [
        (CKR_ARGUMENTS_BAD, "CKR_ARGUMENTS_BAD"),
        (CKR_KEY_TYPE_INCONSISTENT, "CKR_KEY_TYPE_INCONSISTENT"),
        (CKR_MECHANISM_INVALID, "CKR_MECHANISM_INVALID"),
        (CKR_MECHANISM_PARAM_INVALID, "CKR_MECHANISM_PARAM_INVALID"),
    ],
)
def test_invalid_signature_non_clean_explicit_ckrs_are_xfail(rv: int, name: str) -> None:
    exc = CkrAssertionError(f"Unexpected CK_RV {name}", int(rv))

    with pytest.raises(pytest.xfail.Exception, match=name):
        signature_rejected_or_xfail(exc, "tc-invalid")
