"""End-to-end guard for the hollow-pass oracle through the REAL pipeline.

The three HIGH bugs this locks all hid behind unit tests that hand-build report records and a
coverage dict, bypassing the real plumbing. This test runs an actual pytest session (report-log
JSONL), then feeds the real records + the real coverage-merge output into build_quality_audit:

- HIGH-1: pkcs11_claimed_op must land on the passing test's ``when=="call"`` record (an earlier
  version attached it in teardown, so it landed on the teardown record the collector never reads
  -> the oracle's denominator was always empty).
- HIGH-3: a passing negative/rejection vector (expect_success=False) must NOT carry a claim.
- HIGH-2: extract_coverage_from_jsonl must carry ok_counts, so productive_ok is non-empty.

If any of the three regresses, the oracle silently stops working; this test fails instead.
"""

from __future__ import annotations

import json

import pytest

pytest_plugins = ["pytester"]

# A file under a "testcases" dir so the plugin's _is_testcase_item() gate matches.
_INNER_TEST = """
from pkcs11_check.classification import set_mechanism

import pytest


@pytest.mark.parametrize("i", range(25))
def test_positive_vector(i):
    # A positive vector: a pass here claims a productive C_Verify (expect_success=True).
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=True)
    assert True


def test_negative_vector_rejected():
    # A negative vector: passes by correct rejection, no productive CKR_OK -> no claim.
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=False)
    assert True
"""


def test_hollow_oracle_end_to_end(pytester: pytest.Pytester) -> None:
    # The auto-loaded pkcs11-check plugin skips every testcases/ test when no --module is set,
    # so disable it and drive the REAL _attach_claimed_op_to_report from a local makereport hook
    # (the same function the plugin calls in production, in the same phase). This exercises the
    # real emission -> report-log -> call-record path without needing a live PKCS#11 module.
    pytester.makeconftest(
        """
        import pytest
        from pkcs11_check.plugin import _attach_claimed_op_to_report

        @pytest.hookimpl(hookwrapper=True)
        def pytest_runtest_makereport(item, call):
            outcome = yield
            _attach_claimed_op_to_report(item, outcome.get_result())
        """
    )
    tc = pytester.mkpydir("testcases")
    (tc / "test_wyche.py").write_text(_INNER_TEST, encoding="utf-8")

    result = pytester.runpytest_subprocess(
        "-p", "no:pkcs11-check", "--report-log=report.jsonl", "-q", "testcases/"
    )
    result.assert_outcomes(passed=26)

    log = pytester.path / "report.jsonl"
    records = [
        json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    passed_calls = [
        r
        for r in records
        if r.get("$report_type", "TestReport") == "TestReport"
        and r.get("when") == "call"
        and r.get("outcome") == "passed"
    ]
    assert len(passed_calls) == 26

    def _claimed(rec: dict) -> str | None:
        for name, value in rec.get("user_properties", []) or []:
            if name == "pkcs11_claimed_op":
                return str(value)
        return None

    with_claim = [r for r in passed_calls if _claimed(r) is not None]
    without_claim = [r for r in passed_calls if _claimed(r) is None]

    # HIGH-1: the 25 positive-vector passes carry the claim on their CALL records.
    assert len(with_claim) == 25, f"expected 25 claimed-op call records, got {len(with_claim)}"
    assert all(_claimed(r) == "C_Verify" for r in with_claim)
    # HIGH-3: the single negative-vector pass carries no claim.
    assert len(without_claim) == 1

    # HIGH-2 + full chain: a real coverage JSONL round-tripped through the real merge keeps
    # ok_counts, and build_quality_audit computes the hollow finding from the real records.
    from pkcs11_check.core.file_runner import extract_coverage_from_jsonl
    from pkcs11_check.core.quality_audit import build_quality_audit

    cov_path = pytester.path / "coverage.jsonl"
    cov_path.write_text(
        json.dumps(
            {
                "$report_type": "CoverageReport",
                "function_coverage": {
                    "available": 5,
                    "called_names": ["C_Verify"],
                    "called_counts": {"C_Verify": 25},
                    "ok_counts": {"C_Verify": 1},  # only 1 productive across 25 claims
                    "uncalled_names": [],
                },
                "mechanism_coverage": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    coverage = extract_coverage_from_jsonl(cov_path)
    assert coverage is not None
    assert coverage["function_coverage"]["ok_counts"] == {"C_Verify": 1}

    audit = build_quality_audit(coverage=coverage, report_log_records=records)
    hollow = audit["hollow_coverage"]
    assert len(hollow) == 1
    assert hollow[0]["operation"] == "C_Verify"
    assert hollow[0]["claimed_passes"] == 25
    assert hollow[0]["productive_ok"] == 1
    assert any("HOLLOW COVERAGE" in w for w in audit["data_quality_warnings"])
