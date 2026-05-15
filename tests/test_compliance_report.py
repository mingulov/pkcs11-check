"""Tests for compliance report parsing and note isolation."""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.compliance import ComplianceLevel, clear_notes, get_notes, note
from pkcs11_check.compliance_report import _parse_test_results


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
                ],
            }
        )
    )

    counts = _parse_test_results(results_file)

    assert "test_sign" in counts
    assert counts["test_sign"]["passed"] == 2
    assert counts["test_sign"]["failed"] == 0
    assert counts["test_sign"]["skipped"] == 1
    assert "test_encrypt" in counts
    assert counts["test_encrypt"]["passed"] == 1
    assert counts["test_encrypt"]["failed"] == 1


def test_parse_test_results_unified_format_without_counts(tmp_path: Path) -> None:
    """Units without counts (e.g., crashed) should be handled gracefully."""
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
    # Crashed unit has no counts -> not included
    assert counts == {}


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
