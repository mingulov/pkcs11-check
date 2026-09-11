"""Regression: a corrupt byte mid-stream must lose at most that one line.

Four JSONL extraction paths opened their source in TEXT mode (``for line in fh``
after ``path.open(encoding="utf-8")``), so a single undecodable byte anywhere in
the file raised an uncaught ``UnicodeDecodeError`` -- destroying every remaining
record, including ones written well before the process that produced the bad
byte crashed. ``core.report_log.iter_report_log_records`` already fixed this
(binary-mode, per-line decode: a bad line is skipped, every other line -- earlier
or later -- still yields) for the plugin's own reader; these four call sites
never got that hardening. This file pins that all four now survive a corrupt
byte on both sides:

- ``core._report_records.extract_quality_report_records_from_jsonl``
- ``core.merge._stream_records`` (exercised via ``_promote_rv_traces_to_outcome_reports``)
- ``core._jsonl_extract.extract_coverage_from_jsonl``
- ``core._jsonl_extract.extract_provisioning_from_jsonl``

Mutation check performed by hand for each test below (see docstrings): reverting
the corresponding fix to the old text-mode `for line in fh` loop makes the test
raise ``UnicodeDecodeError`` instead of passing.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core._jsonl_extract import (
    extract_coverage_from_jsonl,
    extract_provisioning_from_jsonl,
)
from pkcs11_check.core._report_records import extract_quality_report_records_from_jsonl
from pkcs11_check.core.merge import _promote_rv_traces_to_outcome_reports

# Not a valid UTF-8 continuation anywhere: 0xFF and 0xFE are never valid lead
# bytes, so this always raises UnicodeDecodeError under text-mode decoding.
_BAD_BYTES = b"\xff\xfe this line is not valid utf-8 at all\n"


def test_quality_report_records_survive_corrupt_byte_mid_stream(tmp_path: Path) -> None:
    """core._report_records.extract_quality_report_records_from_jsonl (defect 1a)."""
    path = tmp_path / "report.jsonl"
    before = json.dumps(
        {
            "$report_type": "TestReport",
            "nodeid": "t.py::before",
            "when": "call",
            "outcome": "passed",
        }
    ).encode("utf-8")
    after = json.dumps(
        {"$report_type": "TestReport", "nodeid": "t.py::after", "when": "call", "outcome": "failed"}
    ).encode("utf-8")
    path.write_bytes(before + b"\n" + _BAD_BYTES + after + b"\n")

    records = extract_quality_report_records_from_jsonl(path)

    nodeids = {r["nodeid"] for r in records}
    assert nodeids == {"t.py::before", "t.py::after"}


def test_merge_stream_records_survive_corrupt_byte_mid_stream(tmp_path: Path) -> None:
    """core.merge._stream_records via _promote_rv_traces_to_outcome_reports (defect 1b).

    A failed report (no trace of its own) precedes the corrupt line; the teardown
    record carrying the trace to promote onto it follows the corrupt line. Both
    passes over `_stream_records` must see both records around the bad line for
    the promotion to happen at all -- so a successful promotion is proof that
    records before AND after the bad line survived.
    """
    path = tmp_path / "report.jsonl"
    failed = json.dumps(
        {
            "$report_type": "TestReport",
            "nodeid": "t::a",
            "when": "call",
            "outcome": "failed",
            "user_properties": [],
        }
    ).encode("utf-8")
    trace = [{"fn": "C_Encrypt", "rv": 6}]
    teardown = json.dumps(
        {
            "$report_type": "TestReport",
            "nodeid": "t::a",
            "when": "teardown",
            "outcome": "passed",
            "user_properties": [["pkcs11_rv_trace", trace]],
        }
    ).encode("utf-8")
    path.write_bytes(failed + b"\n" + _BAD_BYTES + teardown + b"\n")

    _promote_rv_traces_to_outcome_reports(path)

    lines = path.read_text(encoding="utf-8").splitlines()
    recs = [json.loads(line) for line in lines if line.strip()]
    assert len(recs) == 2
    promoted = next(r for r in recs if r["when"] == "call")
    assert ["pkcs11_rv_trace", trace] in promoted["user_properties"]


def test_extract_coverage_survives_corrupt_byte_mid_stream(tmp_path: Path) -> None:
    """core._jsonl_extract.extract_coverage_from_jsonl (defect 1c)."""
    path = tmp_path / "report.jsonl"
    before = json.dumps(
        {
            "$report_type": "CoverageReport",
            "function_coverage": {"available": 5, "called_names": ["C_Before"]},
            "mechanism_coverage": {"available_names": ["CKM_BEFORE"], "invoked_names": []},
        }
    ).encode("utf-8")
    after = json.dumps(
        {
            "$report_type": "CoverageReport",
            "function_coverage": {"available": 10, "called_names": ["C_After"]},
            "mechanism_coverage": {"available_names": ["CKM_AFTER"], "invoked_names": []},
        }
    ).encode("utf-8")
    path.write_bytes(before + b"\n" + _BAD_BYTES + after + b"\n")

    coverage = extract_coverage_from_jsonl(path)

    assert coverage is not None
    assert coverage["function_coverage"]["available"] == 10  # max(5, 10) -> both seen
    assert set(coverage["function_coverage"]["called_names"]) == {"C_Before", "C_After"}


def test_extract_provisioning_survives_corrupt_byte_mid_stream(tmp_path: Path) -> None:
    """core._jsonl_extract.extract_provisioning_from_jsonl (defect 1d)."""
    path = tmp_path / "report.jsonl"
    before = json.dumps(
        {
            "$report_type": "ProvisioningReport",
            "by_class": {"RSA": {"ran_via_create": 1}},
        }
    ).encode("utf-8")
    after = json.dumps(
        {
            "$report_type": "ProvisioningReport",
            "by_class": {"EC": {"ran_via_unwrap": 2}},
        }
    ).encode("utf-8")
    path.write_bytes(before + b"\n" + _BAD_BYTES + after + b"\n")

    provisioning = extract_provisioning_from_jsonl(path)

    assert provisioning is not None
    assert provisioning["by_class"]["RSA"]["ran_via_create"] == 1
    assert provisioning["by_class"]["EC"]["ran_via_unwrap"] == 2
