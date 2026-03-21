"""Tests for compliance report parsing."""
from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.compliance_report import _parse_test_results


def test_parse_test_results_unified_format(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(json.dumps({
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
    }))

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
    results_file.write_text(json.dumps({
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {},
        "units": [
            {"target": "test_crash.py", "status": "crashed"},
        ],
    }))

    counts = _parse_test_results(results_file)
    # Crashed unit has no counts -> not included
    assert counts == {}
