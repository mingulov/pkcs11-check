"""Tests for extract_provisioning_from_jsonl (provisioning.json sidecar)."""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import extract_provisioning_from_jsonl

_METHODS = ("ran_via_create", "ran_via_unwrap", "ran_via_external", "skipped_no_path")


def _write_jsonl(path: Path, records: list[dict]) -> None:  # type: ignore[type-arg]
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def test_merge_two_provisioning_records(tmp_path: Path) -> None:
    """Two ProvisioningReport records are merged by summing counts."""
    jsonl = tmp_path / "report.jsonl"
    _write_jsonl(
        jsonl,
        [
            # Unrelated record — must be ignored
            {"$report_type": "CoverageReport", "function_coverage": {}},
            {
                "$report_type": "ProvisioningReport",
                "by_class": {
                    "secret": {"ran_via_create": 2},
                },
                "totals": {
                    "ran_via_create": 2,
                    "ran_via_unwrap": 0,
                    "ran_via_external": 0,
                    "skipped_no_path": 0,
                },
            },
            # Another unrelated record
            {"nodeid": "some_test::foo", "outcome": "passed"},
            {
                "$report_type": "ProvisioningReport",
                "by_class": {
                    "secret": {"ran_via_create": 1},
                    "private": {"ran_via_unwrap": 3},
                },
                "totals": {
                    "ran_via_create": 1,
                    "ran_via_unwrap": 3,
                    "ran_via_external": 0,
                    "skipped_no_path": 0,
                },
            },
        ],
    )

    result = extract_provisioning_from_jsonl(jsonl)
    assert result is not None

    by_class = result["by_class"]
    assert by_class["secret"]["ran_via_create"] == 3
    assert by_class["private"]["ran_via_unwrap"] == 3

    totals = result["totals"]
    assert totals["ran_via_create"] == 3
    assert totals["ran_via_unwrap"] == 3
    # All four total keys must be present
    for method in _METHODS:
        assert method in totals, f"missing totals key: {method}"


def test_returns_none_when_no_provisioning_record(tmp_path: Path) -> None:
    """Returns None when JSONL contains no ProvisioningReport entries."""
    jsonl = tmp_path / "report.jsonl"
    _write_jsonl(
        jsonl,
        [
            {"$report_type": "CoverageReport", "function_coverage": {}},
            {"nodeid": "some_test::foo", "outcome": "passed"},
        ],
    )
    assert extract_provisioning_from_jsonl(jsonl) is None


def test_returns_none_for_missing_file(tmp_path: Path) -> None:
    """Returns None when the JSONL file does not exist."""
    assert extract_provisioning_from_jsonl(tmp_path / "nonexistent.jsonl") is None


def test_all_four_totals_keys_present_single_record(tmp_path: Path) -> None:
    """All four total method keys are present even if counts are zero."""
    jsonl = tmp_path / "report.jsonl"
    _write_jsonl(
        jsonl,
        [
            {
                "$report_type": "ProvisioningReport",
                "by_class": {
                    "secret": {"ran_via_create": 5, "skipped_no_path": 1},
                },
                "totals": {
                    "ran_via_create": 5,
                    "ran_via_unwrap": 0,
                    "ran_via_external": 0,
                    "skipped_no_path": 1,
                },
            },
        ],
    )
    result = extract_provisioning_from_jsonl(jsonl)
    assert result is not None
    for method in _METHODS:
        assert method in result["totals"]
    assert result["totals"]["ran_via_create"] == 5
    assert result["totals"]["skipped_no_path"] == 1
    assert result["totals"]["ran_via_external"] == 0
