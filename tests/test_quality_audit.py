"""Tests for the quality audit analysis core."""

from __future__ import annotations

from pkcs11_check.core.quality_audit import build_quality_audit, classify_skip_reason


def test_classify_skip_reason_falls_back_to_unknown() -> None:
    assert classify_skip_reason("something unexpected happened") == "unknown"


def test_classify_skip_reason_is_conservative_for_ambiguous_import_decode_failures() -> None:
    assert (
        classify_skip_reason("Cannot import Ed25519 public key: Unexpected CK_RV 0x00000030")
        == "unknown"
    )
    assert classify_skip_reason("Cannot decode asn XDH vector: ValueError") == "unknown"


def test_build_quality_audit_results_only_degrades_gracefully() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {
            "passed": 1,
            "failed": 1,
            "skipped": 2,
            "xfailed": 0,
            "xpassed": 0,
            "error": 0,
            "total": 4,
        },
        "units": [
            {
                "target": "src/pkcs11_check/testcases/test_demo.py",
                "status": "failed",
                "counts": {
                    "passed": 1,
                    "failed": 1,
                    "skipped": 2,
                    "xfailed": 0,
                    "xpassed": 0,
                    "error": 0,
                },
                "tests": [
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_flaky",
                        "outcome": "skipped",
                        "longrepr": "Skipped: CKM_AES_CBC not supported",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_flaky",
                        "outcome": "passed",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_never_passed",
                        "outcome": "skipped",
                        "longrepr": "Skipped: No --p11-module specified",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_fails",
                        "outcome": "failed",
                        "longrepr": "AssertionError: boom",
                    },
                ],
                "skip_reasons": {
                    "CKM_AES_CBC not supported": 1,
                    "No --p11-module specified": 1,
                },
            }
        ],
    }

    report = build_quality_audit(results=results)

    assert report["schema_version"] == "1"
    assert report["summary"]["passed"] == 1
    assert report["summary"]["failed"] == 1
    assert report["summary"]["skipped"] == 2
    assert report["never_passed_nodeids"] == [
        "src/pkcs11_check/testcases/test_demo.py::test_fails",
        "src/pkcs11_check/testcases/test_demo.py::test_never_passed",
    ]
    assert any(
        finding["category"] == "missing_capability"
        and finding["reason"] == "CKM_AES_CBC not supported"
        for finding in report["framework_skip_candidates"]
    )
    assert any(
        finding["category"] == "framework_constraint"
        and finding["reason"] == "No --p11-module specified"
        for finding in report["framework_skip_candidates"]
    )
    assert any("coverage" in warning.lower() for warning in report["data_quality_warnings"])


def test_build_quality_audit_uses_coverage_for_mechanism_findings() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [],
    }
    coverage = {
        "function_coverage": {
            "available": 1,
            "called": 1,
            "called_names": ["C_Encrypt"],
            "called_counts": {"C_Encrypt": 1},
            "bootstrap_counts": {},
            "uncalled_names": [],
        },
        "mechanism_coverage": {
            "available": 2,
            "available_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
            "invoked": 1,
            "invoked_names": ["CKM_AES_CBC"],
            "invoked_counts": {"CKM_AES_CBC": 1},
            "not_invoked": 1,
            "not_invoked_names": ["CKM_AES_GCM"],
            "invoked_detail": ["encrypt_roundtrip"],
            "invoked_detail_counts": {"encrypt_roundtrip": 1},
        },
    }

    report = build_quality_audit(results=results, coverage=coverage)

    assert any(
        finding["mechanism"] == "CKM_AES_GCM" and finding["status"] == "not_invoked"
        for finding in report["mechanism_findings"]
    )
    assert report["selection_findings"] == []
    assert "selection telemetry not provided" in report["data_quality_warnings"]


def test_build_quality_audit_selection_report_enables_selected_but_not_invoked() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [],
    }
    coverage = {
        "mechanism_coverage": {
            "available": 2,
            "available_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
            "invoked": 1,
            "invoked_names": ["CKM_AES_CBC"],
            "invoked_counts": {"CKM_AES_CBC": 1},
            "not_invoked": 1,
            "not_invoked_names": ["CKM_AES_GCM"],
            "invoked_detail": ["encrypt_roundtrip"],
            "invoked_detail_counts": {"encrypt_roundtrip": 1},
        },
    }
    selection_record = {
        "$report_type": "SelectionReport",
        "selection_coverage": {
            "encrypt_roundtrip": {
                "selected_mechanisms": ["CKM_AES_CBC", "CKM_AES_GCM"],
                "rejected_mechanisms": ["CKM_AES_XTS"],
                "rejected_reason_counts": {"unsupported_multi_part": 2},
            }
        },
    }

    report = build_quality_audit(
        results=results,
        coverage=coverage,
        report_log_records=[selection_record],
    )

    assert report["selection_findings"]
    finding = report["selection_findings"][0]
    assert finding["scenario"] == "encrypt_roundtrip"
    assert finding["selected_but_not_invoked"] == ["CKM_AES_GCM"]
    assert finding["rejected_reason_categories"] == {"framework_constraint": 2}


def test_build_quality_audit_merges_selection_reports_by_scenario() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [],
    }
    coverage = {
        "mechanism_coverage": {
            "available": 4,
            "available_names": [
                "CKM_AES_CBC",
                "CKM_AES_GCM",
                "CKM_AES_CMAC",
                "CKM_AES_XTS",
            ],
            "invoked": 1,
            "invoked_names": ["CKM_AES_CBC"],
            "invoked_counts": {"CKM_AES_CBC": 1},
            "not_invoked": 3,
            "not_invoked_names": ["CKM_AES_CMAC", "CKM_AES_GCM", "CKM_AES_XTS"],
            "invoked_detail": ["encrypt_roundtrip"],
            "invoked_detail_counts": {"encrypt_roundtrip": 1},
        },
    }
    report_records = [
        {
            "$report_type": "SelectionReport",
            "selection_coverage": {
                "encrypt_roundtrip": {
                    "selected_mechanisms": ["CKM_AES_CBC"],
                    "rejected_mechanisms": ["CKM_AES_XTS"],
                    "rejected_reason_counts": {"unsupported_multi_part": 1},
                }
            },
        },
        {
            "$report_type": "SelectionReport",
            "selection_coverage": {
                "encrypt_roundtrip": {
                    "selected_mechanisms": ["CKM_AES_GCM"],
                    "rejected_mechanisms": ["CKM_AES_CMAC", "CKM_AES_XTS"],
                    "rejected_reason_counts": {
                        "unsupported_multi_part": 2,
                        "not_implemented": 1,
                    },
                }
            },
        },
    ]

    report = build_quality_audit(
        results=results,
        coverage=coverage,
        report_log_records=report_records,
    )

    assert report["summary"]["selection_scenarios"] == 1
    assert len(report["selection_findings"]) == 1

    finding = report["selection_findings"][0]
    assert finding["scenario"] == "encrypt_roundtrip"
    assert finding["selected_mechanisms"] == ["CKM_AES_CBC", "CKM_AES_GCM"]
    assert finding["rejected_mechanisms"] == ["CKM_AES_CMAC", "CKM_AES_XTS"]
    assert finding["selected_but_not_invoked"] == ["CKM_AES_GCM"]
    assert finding["rejected_reason_counts"] == {
        "not_implemented": 1,
        "unsupported_multi_part": 3,
    }
    assert finding["rejected_reason_categories"] == {
        "framework_constraint": 3,
        "not_implemented": 1,
    }
    mechanism_findings = {finding["mechanism"]: finding for finding in report["mechanism_findings"]}
    assert mechanism_findings == {
        "CKM_AES_CBC": {
            "mechanism": "CKM_AES_CBC",
            "status": "invoked",
            "selected_in_scenarios": ["encrypt_roundtrip"],
            "available": True,
            "invoked": True,
        },
        "CKM_AES_CMAC": {
            "mechanism": "CKM_AES_CMAC",
            "status": "not_invoked",
            "selected_in_scenarios": [],
            "available": True,
            "invoked": False,
        },
        "CKM_AES_GCM": {
            "mechanism": "CKM_AES_GCM",
            "status": "selected_but_not_invoked",
            "selected_in_scenarios": ["encrypt_roundtrip"],
            "available": True,
            "invoked": False,
        },
        "CKM_AES_XTS": {
            "mechanism": "CKM_AES_XTS",
            "status": "not_invoked",
            "selected_in_scenarios": [],
            "available": True,
            "invoked": False,
        },
    }


def test_build_quality_audit_classifies_input_constraint_rejections() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [],
    }
    coverage = {
        "mechanism_coverage": {
            "available": 1,
            "available_names": ["CKM_AES_KEY_WRAP"],
            "invoked": 0,
            "invoked_names": [],
            "invoked_counts": {},
            "not_invoked": 1,
            "not_invoked_names": ["CKM_AES_KEY_WRAP"],
            "invoked_detail": ["encrypt_roundtrip"],
            "invoked_detail_counts": {"encrypt_roundtrip": 1},
        },
    }
    selection_record = {
        "$report_type": "SelectionReport",
        "selection_coverage": {
            "encrypt_roundtrip": {
                "selected_mechanisms": [],
                "rejected_mechanisms": ["CKM_AES_KEY_WRAP"],
                "rejected_reason_counts": {"unsupported_input_constraint": 1},
            }
        },
    }

    report = build_quality_audit(
        results=results,
        coverage=coverage,
        report_log_records=[selection_record],
    )

    assert report["selection_findings"][0]["rejected_reason_categories"] == {
        "framework_constraint": 1
    }


def test_build_quality_audit_includes_teardown_only_failure() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [],
    }
    report_records = [
        {
            "$report_type": "TestReport",
            "nodeid": "src/pkcs11_check/testcases/test_cleanup.py::test_teardown",
            "when": "teardown",
            "outcome": "failed",
            "longrepr": "AssertionError: teardown failed",
        }
    ]

    report = build_quality_audit(results=results, report_log_records=report_records)

    assert report["never_passed_nodeids"] == [
        "src/pkcs11_check/testcases/test_cleanup.py::test_teardown",
    ]


def test_build_quality_audit_dedupes_skip_evidence_across_artifacts() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 1, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [
            {
                "target": "src/pkcs11_check/testcases/test_demo.py",
                "status": "passed",
                "counts": {
                    "passed": 0,
                    "failed": 0,
                    "skipped": 1,
                    "xfailed": 0,
                    "xpassed": 0,
                    "error": 0,
                },
                "tests": [
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_skip",
                        "outcome": "skipped",
                        "longrepr": "Skipped: CKM_AES_CBC not supported",
                    }
                ],
                "skip_reasons": {
                    "CKM_AES_CBC not supported": 1,
                },
            }
        ],
    }
    report_records = [
        {
            "$report_type": "TestReport",
            "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_skip",
            "when": "call",
            "outcome": "skipped",
            "longrepr": "Skipped: CKM_AES_CBC not supported",
        }
    ]

    report = build_quality_audit(results=results, report_log_records=report_records)

    candidates = [
        finding
        for finding in report["framework_skip_candidates"]
        if finding["reason"] == "CKM_AES_CBC not supported"
    ]
    assert len(candidates) == 1
    assert candidates[0]["count"] == 1
    assert candidates[0]["category"] == "missing_capability"


def test_build_quality_audit_keeps_distinct_aggregated_skip_reasons_for_same_unit() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 2, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [
            {
                "target": "src/pkcs11_check/testcases/test_demo.py",
                "status": "passed",
                "counts": {
                    "passed": 0,
                    "failed": 0,
                    "skipped": 2,
                    "xfailed": 0,
                    "xpassed": 0,
                    "error": 0,
                },
                "tests": [
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_skip",
                        "outcome": "skipped",
                        "longrepr": "Skipped: CKM_AES_CBC not supported",
                    }
                ],
                "skip_reasons": {
                    "CKM_AES_CBC not supported": 1,
                    "No mechanism catalog": 1,
                },
            }
        ],
    }

    report = build_quality_audit(results=results)

    by_reason = {finding["reason"]: finding for finding in report["framework_skip_candidates"]}
    assert by_reason["CKM_AES_CBC not supported"]["count"] == 1
    assert by_reason["No mechanism catalog"]["count"] == 1
    assert by_reason["No mechanism catalog"]["category"] == "framework_constraint"


def test_build_quality_audit_counts_multi_phase_failure_once_in_summary() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 1},
        "units": [],
    }
    report_records = [
        {
            "$report_type": "TestReport",
            "nodeid": "src/pkcs11_check/testcases/test_cleanup.py::test_teardown",
            "when": "call",
            "outcome": "failed",
            "longrepr": "AssertionError: call failed",
        },
        {
            "$report_type": "TestReport",
            "nodeid": "src/pkcs11_check/testcases/test_cleanup.py::test_teardown",
            "when": "teardown",
            "outcome": "failed",
            "longrepr": "AssertionError: teardown failed",
        },
    ]

    report = build_quality_audit(results=results, report_log_records=report_records)

    assert report["summary"]["test_records"] == 1
    assert report["never_passed_nodeids"] == [
        "src/pkcs11_check/testcases/test_cleanup.py::test_teardown",
    ]


def test_build_quality_audit_never_passed_nodeids_are_conservative() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 1, "failed": 1, "skipped": 1, "xfailed": 0, "xpassed": 0, "error": 0},
        "units": [
            {
                "target": "src/pkcs11_check/testcases/test_demo.py",
                "status": "passed",
                "counts": {
                    "passed": 1,
                    "failed": 1,
                    "skipped": 1,
                    "xfailed": 0,
                    "xpassed": 0,
                    "error": 0,
                },
                "tests": [
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_flaky",
                        "outcome": "skipped",
                        "longrepr": "Skipped: CKM_AES_CBC not supported",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_flaky",
                        "outcome": "passed",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_failed",
                        "outcome": "failed",
                        "longrepr": "AssertionError: boom",
                    },
                ],
            }
        ],
    }

    report = build_quality_audit(results=results)

    assert report["never_passed_nodeids"] == [
        "src/pkcs11_check/testcases/test_demo.py::test_failed",
    ]


def test_build_quality_audit_understands_crashed_and_timeout_outcomes() -> None:
    results = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "error": 0,
            "crashed": 1,
            "timeout": 1,
            "total": 2,
        },
        "units": [
            {
                "target": "src/pkcs11_check/testcases/test_demo.py",
                "status": "failed",
                "counts": {
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "xfailed": 0,
                    "xpassed": 0,
                    "error": 0,
                    "crashed": 1,
                    "timeout": 1,
                },
                "tests": [
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_crash",
                        "outcome": "crashed",
                        "longrepr": "segmentation fault",
                    },
                    {
                        "nodeid": "src/pkcs11_check/testcases/test_demo.py::test_timeout",
                        "outcome": "timeout",
                        "longrepr": "timed out after 120s",
                    },
                ],
            }
        ],
    }

    report = build_quality_audit(results=results)

    assert report["summary"]["crashed"] == 1
    assert report["summary"]["timeout"] == 1
    assert report["summary"]["error"] == 0
    assert report["summary"]["total"] == 2
    assert report["never_passed_nodeids"] == [
        "src/pkcs11_check/testcases/test_demo.py::test_crash",
        "src/pkcs11_check/testcases/test_demo.py::test_timeout",
    ]
