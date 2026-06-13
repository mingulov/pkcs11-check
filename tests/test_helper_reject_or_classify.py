"""Tests for reject_or_classify emitting structured Classification records."""

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_SIGNATURE_INVALID
from pkcs11_check.testcases.conftest import reject_or_classify


def test_no_exception_means_accepted_invalid_fail() -> None:
    C.clear()
    with pytest.raises(Failed):
        reject_or_classify(None, (CKR_SIGNATURE_INVALID,), label="verify", kind="crypto")
    assert C.get_records()[-1].reason == "accepted_invalid"


def test_wrong_clean_code_is_nonspec_reject_xfail() -> None:
    C.clear()
    exc = CkrAssertionError("rejected with CKR_DEVICE_ERROR", CKR_DEVICE_ERROR)
    with pytest.raises(XFailed):
        reject_or_classify(exc, (CKR_SIGNATURE_INVALID,), label="verify")
    assert C.get_records()[-1].reason == "nonspec_reject"
