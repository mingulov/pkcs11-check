"""Lock the single-pass JSONL refactors (review findings E1/E2).

These functions used to parse the same JSONL twice; the refactor parses once and
feeds both consumers. The behaviour must be byte-for-byte equivalent to the
prior path-based helpers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core.file_runner import (
    _identify_crash_culprit,
    _identify_crash_culprit_from_records,
    _load_report_log_records,
    _read_jsonl_results,
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


def test_culprit_path_wrapper_streams_without_load_all(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    jsonl = tmp_path / "report.jsonl"
    _write(
        jsonl,
        [
            _report("f.py::test_a", "setup"),
            _report("f.py::test_a", "teardown"),
            _report("f.py::test_b", "setup"),
        ],
    )

    def _load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("_identify_crash_culprit must stream records")

    monkeypatch.setattr(file_runner_mod, "_load_report_log_records", _load_all_forbidden)

    assert _identify_crash_culprit(jsonl) == ("f.py::test_b", ["f.py::test_a"])


def test_read_jsonl_results_streams_without_load_all(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    jsonl = tmp_path / "report.jsonl"
    _write(
        jsonl,
        [
            _report("a.py::test_ok", "call", "passed"),
            _report("a.py::test_bad", "call", "failed"),
        ],
    )

    def _load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("_read_jsonl_results must stream records")

    monkeypatch.setattr(file_runner_mod, "_load_report_log_records", _load_all_forbidden)

    detail = _read_jsonl_results(jsonl)

    assert detail is not None
    assert detail["counts"]["passed"] == 1
    assert detail["counts"]["failed"] == 1
    assert detail["tests"] == [
        {"nodeid": "a.py::test_bad", "outcome": "failed", "duration": 0.0}
    ]


def test_postprocess_single_pass_per_file_counts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    jsonl = tmp_path / "report.jsonl"
    _write(
        jsonl,
        [
            _report("a.py::t1", "call", "passed"),
            _report("a.py::t2", "call", "failed"),
            _report("b.py::t1", "call", "passed"),
        ],
    )

    def _load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("postprocess_jsonl_to_unified must stream records")

    monkeypatch.setattr(file_runner_mod, "_load_report_log_records", _load_all_forbidden)

    payload = postprocess_jsonl_to_unified(jsonl, tmp_path / "results.json")

    assert payload is not None
    assert payload["summary"]["passed"] == 2
    assert payload["summary"]["failed"] == 1
    units = {u["target"]: u for u in payload["units"]}
    assert units["a.py"]["status"] == "failed"
    assert units["a.py"]["counts"]["passed"] == 1
    assert units["a.py"]["counts"]["failed"] == 1
    assert units["b.py"]["status"] == "passed"


def test_analyze_report_jsonl_streams_detail_culprit_and_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    jsonl = tmp_path / "report.jsonl"
    records = [
        _report("f.py::test_a", "setup"),
        _report("f.py::test_a", "call"),
        _report("f.py::test_a", "teardown"),
        _report("f.py::test_b", "call", "failed"),
        _report("f.py::test_c", "setup"),
    ]
    jsonl.write_text("".join(json.dumps(r) + "\n" for r in records))

    def _load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("_analyze_report_jsonl must stream records")

    monkeypatch.setattr(file_runner_mod, "_load_report_log_records", _load_all_forbidden)

    analyze = getattr(file_runner_mod, "_analyze_report_jsonl")
    detail, culprit, completed = analyze(
        jsonl,
        state_file=tmp_path / "state.json",
        unit="f.py",
    )

    assert culprit == "f.py::test_c"
    assert completed == ["f.py::test_a"]
    assert detail is not None
    assert detail["counts"]["passed"] == 1
    assert detail["counts"]["failed"] == 1
    assert detail["tests"] == [
        {"nodeid": "f.py::test_b", "outcome": "failed", "duration": 0.0}
    ]

    cache_path = file_runner_mod._report_record_cache_path(tmp_path / "state.json", "f.py")
    assert [json.loads(line) for line in cache_path.read_text().splitlines()] == records
