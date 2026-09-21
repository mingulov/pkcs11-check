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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        + "\n",
        encoding="utf-8",
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
    # Fixture counts mirror the CKR_ENCRYPT group size (37 after H-2 removed
    # the 3 inverted empty-input entries); only the all-skipped shape matters.
    summary = _ckr_coverage_summary(
        {
            "test_ckr_encrypt": {
                "passed": 0,
                "failed": 0,
                "skipped": 37,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
                "tests": 37,
            }
        }
    )

    assert summary["tested"] == 0
    assert summary["untested"] == summary["total_specs"] - summary["untestable"]


def test_ckr_coverage_counts_executed_ckr_file_spec_group_only() -> None:
    # 37 = len(CKR_ENCRYPT) after H-2 removed the 3 inverted empty-input
    # entries (data_empty, data_invalid_cbc_padding, data_gcm_aad_only).
    summary = _ckr_coverage_summary(
        {
            "test_ckr_encrypt": {
                "passed": 1,
                "failed": 0,
                "skipped": 36,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
                "tests": 37,
            }
        }
    )

    assert summary["tested"] == 37
    assert summary["untested"] == summary["total_specs"] - summary["untestable"] - 37


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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        ),
        encoding="utf-8",
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
        + "\n",
        encoding="utf-8",
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


class TestComplianceReportIsolation:
    """H-11: compliance-report must not load the untrusted module in-process.

    Every sibling command (info, test, doctor) probes via spawned children; a
    segfaulting module must surface as a reported finding (exit 3), never take
    down the CLI process itself.
    """

    def test_probe_collector_returns_plain_json_data(self, monkeypatch) -> None:
        """The isolation payload must be picklable plain data, not a module."""
        import pkcs11_check.core.loader as loader_mod
        from pkcs11_check.compliance_report import (
            STANDARD_MECHANISMS,
            collect_compliance_module_probe,
        )

        monkeypatch.setattr(loader_mod, "load_module", lambda *a, **k: _FakeModule())
        probe = collect_compliance_module_probe("/fake-pkcs11.so", "auto", 0)

        assert probe["interface_version"] == "3.2"
        assert probe["mechanisms"] == {m: "NOT_SUPPORTED" for m in STANDARD_MECHANISMS}
        json.dumps(probe)  # must survive the spawn boundary

    def test_report_from_probe_matches_report_from_module(self, monkeypatch) -> None:
        """generate_report(module_probe=...) is equivalent to the live module path."""
        import pkcs11_check.core.loader as loader_mod
        from pkcs11_check.compliance_report import collect_compliance_module_probe

        monkeypatch.setattr(loader_mod, "load_module", lambda *a, **k: _FakeModule())
        probe = collect_compliance_module_probe("/fake-pkcs11.so", "auto", 0)

        from_probe = generate_report(module_path="/fake-pkcs11.so", module_probe=probe)
        from_module = generate_report(module_path="/fake-pkcs11.so", module=_FakeModule())
        from_probe.pop("timestamp")
        from_module.pop("timestamp")
        assert from_probe == from_module

    def test_cli_never_loads_module_in_parent(self, tmp_path: Path, monkeypatch) -> None:
        """The parent CLI process must not touch native module code at all."""
        import pkcs11_check.cli.compliance_cmd as compliance_cmd_mod
        import pkcs11_check.core.loader as loader_mod
        from pkcs11_check.cli.app import app
        from pkcs11_check.compliance_report import STANDARD_MECHANISMS
        from tests._plain_cli_runner import PlainCliRunner

        def _boom(*args: object, **kwargs: object) -> object:
            raise AssertionError("load_module must not run in the CLI parent process")

        monkeypatch.setattr(loader_mod, "load_module", _boom)
        canned = {
            "interface_version": "3.2",
            "mechanisms": {m: "NOT_SUPPORTED" for m in STANDARD_MECHANISMS},
        }
        monkeypatch.setattr(compliance_cmd_mod, "_run_isolated", lambda *a, **k: canned)

        module = tmp_path / "fake.so"
        module.write_bytes(b"not a real module")
        result = PlainCliRunner().invoke(app, ["compliance-report", "--module", str(module)])

        assert result.exit_code == 0, result.output
        assert '"interface_version": "3.2"' in result.output
        assert '"mechanisms_supported": 0' in result.output

    def test_cli_reports_child_crash_as_error(self, tmp_path: Path, monkeypatch) -> None:
        """A segfaulting module is a clean exit-3 finding, not a dead CLI."""
        import pkcs11_check.cli.compliance_cmd as compliance_cmd_mod
        from pkcs11_check.cli.app import app
        from pkcs11_check.cli.info_cmd import InfoQueryCrashError
        from tests._plain_cli_runner import PlainCliRunner

        def _crash(*args: object, **kwargs: object) -> object:
            raise InfoQueryCrashError(-11)

        monkeypatch.setattr(compliance_cmd_mod, "_run_isolated", _crash)

        module = tmp_path / "fake.so"
        module.write_bytes(b"not a real module")
        result = PlainCliRunner().invoke(app, ["compliance-report", "--module", str(module)])

        assert result.exit_code == 3, result.output
        assert "crash" in result.output.lower()

    def test_cli_reports_child_error_as_load_error(self, tmp_path: Path, monkeypatch) -> None:
        """A child-side load failure keeps the historical exit-3 behavior."""
        import pkcs11_check.cli.compliance_cmd as compliance_cmd_mod
        from pkcs11_check.cli.app import app
        from pkcs11_check.cli.info_cmd import InfoQueryError
        from tests._plain_cli_runner import PlainCliRunner

        def _fail(*args: object, **kwargs: object) -> object:
            raise InfoQueryError("ValueError: bad-magic-marker")

        monkeypatch.setattr(compliance_cmd_mod, "_run_isolated", _fail)

        module = tmp_path / "fake.so"
        module.write_bytes(b"not a real module")
        result = PlainCliRunner().invoke(app, ["compliance-report", "--module", str(module)])

        assert result.exit_code == 3, result.output
        assert "bad-magic-marker" in result.output
