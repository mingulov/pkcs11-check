"""Tests for compliance report parsing and note isolation."""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.compliance import ComplianceLevel, clear_notes, get_notes, note
from pkcs11_check.compliance_report import (
    _ckr_coverage_summary,
    _classify_functions,
    _classify_functions_from_observed_coverage,
    _load_observed_function_coverage,
    _parse_test_results,
    generate_report,
)


class _FakeSlot:
    def get_mechanisms(self) -> list[object]:
        return []


class _FakeModule:
    interface_version = "3.2"

    def get_slots(self, *, token_present: bool) -> list[_FakeSlot]:
        assert token_present is True
        return [_FakeSlot()]


def test_parse_test_results_unified_format(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"passed": 3, "failed": 1, "skipped": 1, "xfailed": 1, "total": 6},
                "units": [
                    {
                        "target": "src/pkcs11_check/testcases/test_sign.py",
                        "status": "passed",
                        "counts": {"passed": 2, "failed": 0, "skipped": 1, "xfailed": 1},
                    },
                    {
                        "target": "src/pkcs11_check/testcases/test_encrypt.py",
                        "status": "failed",
                        "counts": {"passed": 1, "failed": 1, "skipped": 0, "xfailed": 0},
                    },
                    {
                        "target": "src/pkcs11_check/testcases/test_crash.py",
                        "status": "crashed",
                        "counts": {"failed": 1},
                    },
                ],
            }
        )
    )

    counts = _parse_test_results(results_file)

    assert "test_sign" in counts
    assert counts["test_sign"]["passed"] == 2
    assert counts["test_sign"]["failed"] == 0
    assert counts["test_sign"]["skipped"] == 1
    assert counts["test_sign"]["xfailed"] == 1
    assert "test_encrypt" in counts
    assert counts["test_encrypt"]["passed"] == 1
    assert counts["test_encrypt"]["failed"] == 1
    assert counts["test_crash"]["failed"] == 1
    assert counts["test_crash"]["crashed"] == 1
    assert counts["test_crash"]["tests"] == 2


def test_parse_test_results_unified_format_without_counts(tmp_path: Path) -> None:
    """Status-only units still carry crash/timeout evidence."""
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {},
                "units": [
                    {"target": "test_crash.py", "status": "crashed"},
                ],
            }
        )
    )

    counts = _parse_test_results(results_file)
    assert counts["test_crash"]["crashed"] == 1
    assert counts["test_crash"]["tests"] == 1


def test_parse_test_results_preserves_non_pass_fail_outcomes(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tests": [
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_encrypt.py::test_clean_xfail",
                        "outcome": "skipped",
                        "wasxfail": "clean provider rejection",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_encrypt.py::test_setup_error",
                        "outcome": "error",
                    },
                    {
                        "nodeid": (
                            "src/pkcs11_check/testcases/test_encrypt.py::test_unexpected_pass"
                        ),
                        "outcome": "passed",
                        "wasxfail": "known bug",
                    },
                ],
            }
        )
    )

    counts = _parse_test_results(results_file)

    assert counts["test_encrypt"]["xfailed"] == 1
    assert counts["test_encrypt"]["error"] == 1
    assert counts["test_encrypt"]["xpassed"] == 1
    assert counts["test_encrypt"]["skipped"] == 0
    assert counts["test_encrypt"]["tests"] == 3


def test_classify_functions_does_not_report_xfail_as_pass() -> None:
    functions = _classify_functions(
        {
            "test_encrypt": {
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "xfailed": 2,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
                "tests": 3,
            }
        }
    )

    assert functions["C_Encrypt"]["status"] == "XFAIL"
    assert functions["C_Encrypt"]["tests"] == 3
    assert functions["C_Encrypt"]["passed"] == 1
    assert functions["C_Encrypt"]["xfailed"] == 2


def test_classify_functions_crash_and_timeout_precede_pass() -> None:
    functions = _classify_functions(
        {
            "test_encrypt": {
                "passed": 10,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 1,
                "timeout": 1,
                "tests": 12,
            }
        }
    )

    assert functions["C_Encrypt"]["status"] == "TIMEOUT"
    assert functions["C_Encrypt"]["crashed"] == 1
    assert functions["C_Encrypt"]["timeout"] == 1


def test_observed_coverage_prevents_filename_heuristic_overstatement(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"passed": 1, "total": 1},
                "coverage": {
                    "function_coverage": {
                        "called_names": ["C_GetInfo"],
                        "called_counts": {"C_GetInfo": 1},
                        "uncalled_names": ["C_Encrypt"],
                    }
                },
                "units": [
                    {
                        "target": "src/pkcs11_check/testcases/test_encrypt.py",
                        "status": "passed",
                        "counts": {"passed": 1},
                    }
                ],
            }
        )
    )

    observed = _load_observed_function_coverage(results_file)
    assert observed is not None

    functions = _classify_functions_from_observed_coverage(
        observed,
    )

    assert functions["C_GetInfo"]["status"] == "NOT_TESTED"
    assert functions["C_GetInfo"]["tests"] == 1
    assert functions["C_GetInfo"]["passed"] == 0
    assert functions["C_Encrypt"]["status"] == "NOT_TESTED"
    assert functions["C_Encrypt"]["tests"] == 0


def test_observed_coverage_only_counts_do_not_imply_pass(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"passed": 1, "total": 1},
                "units": [{"target": "test_unknown.py", "status": "passed"}],
            }
        )
    )
    (tmp_path / "coverage.json").write_text(
        json.dumps(
            {
                "function_coverage": {
                    "called_names": ["C_Encrypt"],
                    "called_counts": {"C_Encrypt": 2},
                    "uncalled_names": ["C_GetInfo"],
                }
            }
        )
    )

    observed = _load_observed_function_coverage(results_file)

    assert observed == {"C_Encrypt": {"tests": 2}}

    functions = _classify_functions_from_observed_coverage(observed)
    assert functions["C_Encrypt"]["status"] == "NOT_TESTED"
    assert functions["C_Encrypt"]["tests"] == 2
    assert functions["C_Encrypt"]["passed"] == 0


def test_observed_coverage_can_come_from_sibling_report_jsonl_trace(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"xfailed": 1, "total": 1},
                "units": [{"target": "test_custom.py", "status": "xfailed"}],
            }
        )
    )
    (tmp_path / "report.jsonl").write_text(
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "src/pkcs11_check/testcases/test_custom.py::test_x",
                "when": "call",
                "outcome": "skipped",
                "wasxfail": "provider clean rejection",
                "user_properties": [["pkcs11_rv_trace", [{"fn": "C_Encrypt", "rv": 48}]]],
            }
        )
        + "\n"
    )

    observed = _load_observed_function_coverage(results_file)

    assert observed is not None
    assert observed["C_Encrypt"]["xfailed"] == 1
    assert observed["C_Encrypt"]["tests"] == 1


def test_ckr_coverage_does_not_count_unrelated_results_as_tested() -> None:
    summary = _ckr_coverage_summary(
        {
            "test_encrypt": {
                "passed": 10,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
                "tests": 10,
            }
        }
    )

    assert summary["total_specs"] > 0
    assert summary["tested"] == 0
    assert summary["untested"] == summary["total_specs"] - summary["untestable"]


def test_ckr_coverage_does_not_count_all_skipped_ckr_file_as_tested() -> None:
    summary = _ckr_coverage_summary(
        {
            "test_ckr_encrypt": {
                "passed": 0,
                "failed": 0,
                "skipped": 40,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
                "tests": 40,
            }
        }
    )

    assert summary["tested"] == 0
    assert summary["untested"] == summary["total_specs"] - summary["untestable"]


def test_ckr_coverage_counts_executed_ckr_file_spec_group_only() -> None:
    summary = _ckr_coverage_summary(
        {
            "test_ckr_encrypt": {
                "passed": 1,
                "failed": 0,
                "skipped": 39,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
                "tests": 40,
            }
        }
    )

    assert summary["tested"] == 40
    assert summary["untested"] == summary["total_specs"] - summary["untestable"] - 40


class TestComplianceNoteIsolation:
    """Verify clear_notes() works and the teardown hook is wired correctly."""

    def test_clear_notes_functionally(self) -> None:
        note("clear test note", ComplianceLevel.STANDARD)
        assert len(get_notes()) >= 1
        clear_notes()
        assert get_notes() == []

    def test_teardown_hook_clears_notes_for_testcase_items(self) -> None:
        from pkcs11_check.plugin import pytest_runtest_teardown

        note("hook test note", ComplianceLevel.VENDOR)
        assert len(get_notes()) >= 1

        fake_item = type(
            "FakeItem",
            (),
            {
                "path": Path("src/pkcs11_check/testcases/test_something.py"),
                "fspath": Path("src/pkcs11_check/testcases/test_something.py"),
            },
        )()
        pytest_runtest_teardown(fake_item, None)
        assert get_notes() == []

    def test_teardown_hook_skips_meta_test_items(self) -> None:
        from pkcs11_check.plugin import pytest_runtest_teardown

        note("meta test note", ComplianceLevel.STANDARD)
        assert len(get_notes()) >= 1

        fake_item = type(
            "FakeItem",
            (),
            {
                "path": Path("tests/test_compliance_report.py"),
                "fspath": Path("tests/test_compliance_report.py"),
            },
        )()
        pytest_runtest_teardown(fake_item, None)
        assert len(get_notes()) >= 1
        clear_notes()


def test_compliance_notes_attach_to_testcase_call_reports() -> None:
    from pkcs11_check.plugin import _attach_compliance_notes_to_report

    clear_notes()
    note(
        "validation policy refused advertised encrypt",
        ComplianceLevel.STANDARD,
        reference="PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED",
        test_id="test_encrypt",
    )
    fake_item = type(
        "FakeItem",
        (),
        {
            "nodeid": "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt",
            "path": Path("src/pkcs11_check/testcases/test_mech_encrypt.py"),
            "fspath": Path("src/pkcs11_check/testcases/test_mech_encrypt.py"),
        },
    )()
    fake_report = type(
        "FakeReport",
        (),
        {"when": "call", "user_properties": []},
    )()

    _attach_compliance_notes_to_report(fake_item, fake_report)

    assert fake_report.user_properties == [
        (
            "pkcs11_compliance_notes",
            [
                {
                    "description": "validation policy refused advertised encrypt",
                    "level": "standard",
                    "reference": "PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED",
                    "test_id": "test_encrypt",
                    "nodeid": "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt",
                }
            ],
        )
    ]
    clear_notes()


def test_generate_report_includes_compliance_notes_from_result_units(tmp_path: Path) -> None:
    clear_notes()
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"passed": 1, "total": 1},
                "units": [
                    {
                        "target": "src/pkcs11_check/testcases/test_mech_encrypt.py",
                        "status": "passed",
                        "counts": {"passed": 1},
                        "compliance_notes": [
                            {
                                "description": "validation policy refused advertised encrypt",
                                "level": "standard",
                                "reference": "PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED",
                                "test_id": "test_encrypt",
                                "nodeid": (
                                    "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt"
                                ),
                            }
                        ],
                    }
                ],
            }
        )
    )

    report = generate_report(
        module_path="/fake-pkcs11.so",
        module=_FakeModule(),
        test_results_path=results_file,
    )

    assert report["compliance_notes"] == [
        {
            "description": "validation policy refused advertised encrypt",
            "level": "standard",
            "reference": "PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED",
            "test_id": "test_encrypt",
            "nodeid": "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt",
        }
    ]


def test_crash_limited_unit_is_skip_class_not_error(tmp_path: Path) -> None:
    """A crash_limited-only unit must yield a SKIP-class status, not ERROR.

    Regression guard: _outcome_from_status used to fall through to 'error' for
    'crash_limited' (which was absent from _OUTCOME_KEYS), causing abandoned tests
    to inflate the error counter and produce an ERROR function classification.
    """
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"crash_limited": 5},
                "units": [
                    {
                        "target": "src/pkcs11_check/testcases/test_sign.py",
                        "status": "crash_limited",
                    }
                ],
            }
        )
    )

    counts = _parse_test_results(results_file)

    # The abandoned tests must land in crash_limited, not error
    assert counts["test_sign"]["error"] == 0
    assert counts["test_sign"]["crash_limited"] == 1
    assert counts["test_sign"]["tests"] == 1

    # Function classification must be SKIP (not ERROR) for a crash_limited-only file
    functions = _classify_functions(counts)
    # C_Sign maps to "test_sign" (via _FUNCTION_KEYWORDS); its status must be SKIP
    assert functions["C_Sign"]["status"] == "SKIP"
    assert functions["C_Sign"]["error"] == 0


def test_generate_report_includes_compliance_notes_from_report_jsonl(tmp_path: Path) -> None:
    clear_notes()
    results_file = tmp_path / "results.json"
    results_file.write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"xfailed": 1, "total": 1},
                "units": [
                    {
                        "target": "src/pkcs11_check/testcases/test_mech_encrypt.py",
                        "status": "xfailed",
                        "counts": {"xfailed": 1},
                    }
                ],
            }
        )
    )
    (tmp_path / "report.jsonl").write_text(
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt",
                "when": "call",
                "outcome": "skipped",
                "wasxfail": "provider clean rejection",
                "user_properties": [
                    [
                        "pkcs11_compliance_notes",
                        [
                            {
                                "description": "advertised mechanism refused operation",
                                "level": "vendor",
                                "reference": "PKCS#11 operation contract",
                                "test_id": "test_encrypt",
                                "nodeid": (
                                    "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt"
                                ),
                            }
                        ],
                    ]
                ],
            }
        )
        + "\n"
    )

    report = generate_report(
        module_path="/fake-pkcs11.so",
        module=_FakeModule(),
        test_results_path=results_file,
    )

    assert report["compliance_notes"] == [
        {
            "description": "advertised mechanism refused operation",
            "level": "vendor",
            "reference": "PKCS#11 operation contract",
            "test_id": "test_encrypt",
            "nodeid": "src/pkcs11_check/testcases/test_mech_encrypt.py::test_encrypt",
        }
    ]
