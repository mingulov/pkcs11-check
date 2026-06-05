"""Lock the single-pass JSONL refactors (review findings E1/E2).

These functions used to parse the same JSONL twice; the refactor parses once and
feeds both consumers. The behaviour must be byte-for-byte equivalent to the
prior path-based helpers.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import (
    _identify_crash_culprit,
    _identify_crash_culprit_from_records,
    _load_report_log_records,
    postprocess_jsonl_to_unified,
)


def _write(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def _report(nodeid: str, when: str, outcome: str = "passed") -> dict[str, object]:
    return {"$report_type": "TestReport", "nodeid": nodeid, "when": when, "outcome": outcome}


def test_culprit_records_core_matches_path_wrapper(tmp_path: Path) -> None:
    # test_a fully ran (setup+call+teardown); test_b started but never tore down
    # (the crash culprit); a scalar noise line must be ignored by both paths.
    jsonl = tmp_path / "report.jsonl"
    records = [
        _report("f.py::test_a", "setup"),
        _report("f.py::test_a", "call"),
        _report("f.py::test_a", "teardown"),
        _report("f.py::test_b", "setup"),
    ]
    jsonl.write_text("5\n" + "".join(json.dumps(r) + "\n" for r in records))

    path_result = _identify_crash_culprit(jsonl)
    core_result = _identify_crash_culprit_from_records(_load_report_log_records(jsonl))

    assert path_result == core_result
    assert path_result == ("f.py::test_b", ["f.py::test_a"])


def test_postprocess_single_pass_per_file_counts(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    _write(
        jsonl,
        [
            _report("a.py::t1", "call", "passed"),
            _report("a.py::t2", "call", "failed"),
            _report("b.py::t1", "call", "passed"),
        ],
    )

    payload = postprocess_jsonl_to_unified(jsonl, tmp_path / "results.json")

    assert payload is not None
    assert payload["summary"]["passed"] == 2
    assert payload["summary"]["failed"] == 1
    units = {u["target"]: u for u in payload["units"]}
    assert units["a.py"]["status"] == "failed"
    assert units["a.py"]["counts"]["passed"] == 1
    assert units["a.py"]["counts"]["failed"] == 1
    assert units["b.py"]["status"] == "passed"
