import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C


def test_classify_fail_records_and_raises():
    C.clear()
    with pytest.raises(Failed):
        C.classify(
            "accepted_invalid",
            kind="crypto",
            label="RSA:decrypt",
            operation="C_Decrypt",
            expected=["CKR_ENCRYPTED_DATA_INVALID"],
            actual="CKR_OK",
        )
    rec = C.get_records()[-1]
    assert rec.outcome == "fail" and rec.severity == "CRITICAL"
    assert rec.summary


def test_classify_xfail_records_and_raises():
    C.clear()
    with pytest.raises(XFailed):
        C.classify("nonspec_reject", label="ECDSA:verify", actual="CKR_DEVICE_ERROR")
    assert C.get_records()[-1].outcome == "xfail"


def test_classify_pass_returns_without_raising():
    C.clear()
    C.classify("sanctioned_refusal", label="ML-DSA:sign", actual="CKR_OPERATION_NOT_VALIDATED")
    assert C.get_records()[-1].outcome == "pass"


def test_explicit_summary_overrides_template():
    C.clear()
    with pytest.raises(Failed):
        C.classify("wrong_result", kind="crypto", label="x", summary="custom phrase")
    assert C.get_records()[-1].summary == "custom phrase"
