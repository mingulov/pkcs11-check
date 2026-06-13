"""Tests for classify_negative_rv emitting structured Classification records."""

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OK, CKR_SIGNATURE_INVALID
from pkcs11_check.testcases.conftest import classify_negative_rv


def test_accepted_invalid_emits_fail() -> None:
    C.clear()
    with pytest.raises(Failed):
        classify_negative_rv(CKR_OK, (CKR_SIGNATURE_INVALID,), label="verify", kind="crypto")
    assert C.get_records()[-1].reason == "accepted_invalid"


def test_nonspec_reject_emits_xfail() -> None:
    C.clear()
    with pytest.raises(XFailed):
        classify_negative_rv(CKR_DEVICE_ERROR, (CKR_SIGNATURE_INVALID,), label="verify")
    assert C.get_records()[-1].reason == "nonspec_reject"


def test_expected_code_passes_silently() -> None:
    C.clear()
    classify_negative_rv(CKR_SIGNATURE_INVALID, (CKR_SIGNATURE_INVALID,), label="verify")
    assert C.get_records() == []
