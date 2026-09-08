import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID


def test_record_as_records_fail_and_xfail_without_raising() -> None:
    for reason, expected_outcome in (
        ("accepted_invalid", "fail"),
        ("honest_deviation", "xfail"),
        ("sanctioned_refusal", "pass"),
    ):
        C.clear()
        rec = C.record_as(reason, kind="crypto", label="record-only")

        assert rec.outcome == expected_outcome
        assert C.get_records() == [rec]


def test_record_as_inherits_context_and_matches_classify_metadata() -> None:
    C.clear()
    C.set_params({"curve": "P-256"})
    C.set_vector("vector.json", "id=7")
    C.set_mechanism("CKM_ECDSA", operation="C_Verify")

    rec = C.record_as(
        "honest_deviation",
        kind="metadata",
        label="attribute",
        expected=[CKR_ATTRIBUTE_VALUE_INVALID],
        actual=0x6,
    )

    assert rec.params == {"curve": "secp256r1"}
    assert rec.source == "vector.json" and rec.vector_id == "id=7"
    assert rec.mechanism == "CKM_ECDSA" and rec.operation == "C_Verify"
    assert rec.expected_ckr == ["CKR_ATTRIBUTE_VALUE_INVALID"]
    assert rec.actual_ckr == "CKR_FUNCTION_FAILED"
    assert rec.spec_ref == "PKCS#11 v3.2 · C_Verify · CKM_ECDSA"


def test_record_as_serialization_is_stable_and_records_once() -> None:
    C.clear()
    rec = C.record_as(
        "not_operational",
        label="missing",
        summary="stable summary",
        detail={"key": "value"},
    )

    assert len(C.get_records()) == 1
    assert C.serialize([rec]) == C.serialize(C.get_records())
    assert C.serialize([rec])[0] == {
        "reason": "not_operational",
        "outcome": "xfail",
        "severity": "LOW",
        "kind": None,
        "label": "missing",
        "summary": "stable summary",
        "operation": None,
        "mechanism": None,
        "expected_ckr": None,
        "actual_ckr": None,
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "params": None,
        "detail": {"key": "value"},
        "schema": 1,
    }


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


def test_classify_resolves_int_ckr_codes_to_names():
    from pkcs11_check.raw.types_std import CKR_OK, CKR_SIGNATURE_INVALID

    C.clear()
    with pytest.raises(Failed):
        C.classify(
            "accepted_invalid",
            kind="crypto",
            label="verify",
            expected=(CKR_SIGNATURE_INVALID,),
            actual=CKR_OK,
        )
    rec = C.get_records()[-1]
    assert rec.expected_ckr == ["CKR_SIGNATURE_INVALID"]
    assert rec.actual_ckr == "CKR_OK"
