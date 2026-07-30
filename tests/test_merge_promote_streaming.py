"""Characterization tests for merge._promote_rv_traces_to_outcome_reports.

T4: this host-side merge step load-all'd the whole report.jsonl. These tests pin
its exact behaviour so the streaming rewrite stays byte-identical:
- old-style artifacts (failed report without its own trace, trace only on the
  teardown record) get the trace promoted onto the failed report;
- current-style artifacts (failed report already carries its trace) are left
  byte-for-byte unchanged (no rewrite).
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.merge import _promote_rv_traces_to_outcome_reports

_TRACE = [{"fn": "C_Encrypt", "rv": 6}]


def _write(tmp_path: Path, records: list[dict]) -> Path:
    p = tmp_path / "report.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return p


def test_promotes_teardown_trace_onto_failed_report(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        [
            {
                "$report_type": "TestReport",
                "nodeid": "t::a",
                "when": "call",
                "outcome": "failed",
                "user_properties": [],
            },
            {
                "$report_type": "TestReport",
                "nodeid": "t::a",
                "when": "teardown",
                "outcome": "passed",
                "user_properties": [["pkcs11_rv_trace", _TRACE]],
            },
        ],
    )
    _promote_rv_traces_to_outcome_reports(p)
    recs = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    failed = next(r for r in recs if r["when"] == "call")
    assert ["pkcs11_rv_trace", _TRACE] in failed["user_properties"]


def test_no_rewrite_when_failed_report_already_has_trace(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        [
            {
                "$report_type": "TestReport",
                "nodeid": "t::b",
                "when": "call",
                "outcome": "failed",
                "user_properties": [["pkcs11_rv_trace", _TRACE]],
            },
        ],
    )
    before = p.read_bytes()
    _promote_rv_traces_to_outcome_reports(p)
    assert p.read_bytes() == before  # unchanged -> not rewritten
    # The single-pass rewrite writes a temp then discards it when nothing
    # changed -- it must not leave the .tmp behind.
    assert not p.with_suffix(p.suffix + ".tmp").exists()


def test_passing_reports_are_not_touched(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        [
            {
                "$report_type": "TestReport",
                "nodeid": "t::c",
                "when": "call",
                "outcome": "passed",
                "user_properties": [["pkcs11_rv_trace", _TRACE]],
            },
        ],
    )
    before = p.read_bytes()
    _promote_rv_traces_to_outcome_reports(p)
    assert p.read_bytes() == before
