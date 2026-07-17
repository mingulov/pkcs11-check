"""build_quality_audit must surface a hollow_coverage finding when passing tests
claim an operation their run barely invoked productively (the kmsp11 pattern)."""

from __future__ import annotations

from pkcs11_check.core.quality_audit import build_quality_audit


def _passed_sign_record(n: int) -> dict:
    return {
        "$report_type": "TestReport",
        "when": "call",
        "outcome": "passed",
        "nodeid": f"t.py::test_sign[{n}]",
        "user_properties": [["pkcs11_claimed_op", "C_Sign"]],
    }


def test_hollow_coverage_flags_kmsp11_pattern() -> None:
    # 100 passing tests claim C_Sign, but only 1 productive (CKR_OK) C_Sign invocation.
    records = [_passed_sign_record(i) for i in range(100)]
    coverage = {"function_coverage": {"ok_counts": {"C_Sign": 1}}}
    audit = build_quality_audit(coverage=coverage, report_log_records=records)

    hollow = audit["hollow_coverage"]
    assert len(hollow) == 1
    assert hollow[0]["operation"] == "C_Sign"
    assert hollow[0]["claimed_passes"] == 100
    assert hollow[0]["productive_ok"] == 1
    assert any("HOLLOW COVERAGE" in w for w in audit["data_quality_warnings"])


def test_healthy_run_has_no_hollow_finding() -> None:
    records = [_passed_sign_record(i) for i in range(100)]
    coverage = {"function_coverage": {"ok_counts": {"C_Sign": 100}}}
    audit = build_quality_audit(coverage=coverage, report_log_records=records)
    assert audit["hollow_coverage"] == []


def test_multipart_family_counts_as_productive() -> None:
    # A C_Sign claim satisfied by multipart C_SignUpdate must not be flagged.
    records = [_passed_sign_record(i) for i in range(100)]
    coverage = {"function_coverage": {"ok_counts": {"C_SignUpdate": 100}}}
    audit = build_quality_audit(coverage=coverage, report_log_records=records)
    assert audit["hollow_coverage"] == []


def test_no_claimed_op_no_finding() -> None:
    # Passing records without a pkcs11_claimed_op property contribute nothing.
    records = [
        {
            "$report_type": "TestReport",
            "when": "call",
            "outcome": "passed",
            "nodeid": f"t.py::test_x[{i}]",
            "user_properties": [],
        }
        for i in range(100)
    ]
    audit = build_quality_audit(
        coverage={"function_coverage": {"ok_counts": {}}}, report_log_records=records
    )
    assert audit["hollow_coverage"] == []
