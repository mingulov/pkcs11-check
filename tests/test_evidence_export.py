"""Tests for the evidence ledger streaming exporter (schema v1)."""

from __future__ import annotations

import io
import json
import random
import tracemalloc
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core.evidence import export_ledger

TRACEMALLOC_LIMIT_BYTES = 64 * 1024 * 1024


def _report(
    nodeid: str,
    when: str = "call",
    outcome: str = "passed",
    **extra: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": outcome,
        "duration": 0.012,
        "user_properties": [],
    }
    record.update(extra)
    return record


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _classified(record: dict[str, Any], **fields: Any) -> dict[str, Any]:
    classification: dict[str, Any] = {
        "reason": "wrong_result",
        "outcome": "fail",
        "severity": "CRITICAL",
        "kind": "crypto",
        "label": "",
        "summary": "",
        "operation": None,
        "mechanism": "CKM_AES_CBC",
        "expected_ckr": ["CKR_OK"],
        "actual_ckr": "CKR_DATA_INVALID",
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "params": None,
        "detail": None,
        "schema": 1,
    }
    classification.update(fields)
    record["user_properties"] = [("pkcs11_classification", [classification])]
    return record


def _export_lines(records: list[Any], identity: dict[str, str]) -> list[str]:
    sink = io.StringIO()
    export_ledger(records, identity, sink)
    return sink.getvalue().splitlines()


def test_export_header_first_and_sorted() -> None:
    records: list[Any] = [
        {"$report_type": "SessionStart"},
        _marker("tests/a.py", 1),
        _report("tests/b.py::test_two", shard_id="shard-1"),
        _report("tests/a.py::test_one", when="setup", shard_id="shard-0"),
        _marker("tests/a.py", 2),
        _classified(_report("tests/a.py::test_one", outcome="failed", shard_id="shard-0")),
        _report("tests/a.py::test_one", when="teardown", shard_id="shard-0"),
        _report("tests/b.py::test_two", when="setup", outcome="skipped", shard_id="shard-1"),
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]
    shuffled = list(records)
    random.Random(7).shuffle(shuffled)
    lines = _export_lines(shuffled, {"lane": "soft", "lane_os": "linux", "lane_arch": "x64"})
    assert lines, "export must emit at least the header"
    header = json.loads(lines[0])
    assert header["record"] == "header"
    rows = [json.loads(line) for line in lines[1:]]
    assert rows, "export must emit case rows"
    assert all(row["record"] == "case" for row in rows)
    keys = [(row["node_id"], row["phase"], row["attempt"]) for row in rows]
    assert keys == sorted(keys)
    assert {row["shard_id"] for row in rows} == {"shard-0", "shard-1"}


def test_export_counts_every_occurrence() -> None:
    records: list[Any] = []
    outcomes = ["passed", "failed", "passed"]
    for attempt, outcome in enumerate(outcomes, start=1):
        records.append(_marker("tests/x.py", attempt))
        records.append(_report("tests/x.py::test_flaky", when="setup"))
        records.append(_report("tests/x.py::test_flaky", when="call", outcome=outcome))
    sink = io.StringIO()
    header = export_ledger(records, {"lane": "soft"}, sink)
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert len(rows) == 6
    assert sorted(row["attempt"] for row in rows) == [1, 1, 2, 2, 3, 3]
    assert {row["attempts_total"] for row in rows} == {3}
    assert header.counters["passed"] == 5
    assert header.counters["failed"] == 1
    assert sum(header.counters[outcome] for outcome in ("passed", "failed")) == 6


def test_export_byte_stable() -> None:
    seg1: list[Any] = [
        _classified(_report("tests/a.py::test_one", outcome="failed")),
        _report("tests/b.py::test_two", when="setup"),
        _report("tests/a.py::test_one", when="teardown", outcome="skipped"),
    ]
    seg2: list[Any] = [
        _report("tests/b.py::test_two", duration=1.5),
        _report("tests/c.py::test_three", outcome="failed"),
    ]
    identity = {"lane": "soft", "framework_sha": "abc", "planned_count": "6"}
    first = _export_lines(
        [_marker("tests/a.py", 1)] + seg1 + [_marker("tests/b.py", 2)] + seg2, identity
    )
    # Shuffle within each marker scope (cross-marker shuffles are a different
    # stream: attempt attribution follows marker order, as documented).
    seg1_shuffled = list(seg1)
    random.Random(3).shuffle(seg1_shuffled)
    seg2_shuffled = list(seg2)
    random.Random(11).shuffle(seg2_shuffled)
    second = _export_lines(
        [_marker("tests/a.py", 1)] + seg1_shuffled + [_marker("tests/b.py", 2)] + seg2_shuffled,
        identity,
    )
    assert first == second


def test_export_counts_malformed_not_drops_silently() -> None:
    records: list[Any] = [
        _report("tests/a.py::test_one"),
        "not-a-mapping",
        {"$report_type": "TestReport", "when": "call", "outcome": "passed"},
        _report("tests/a.py::test_two", outcome="failed"),
    ]
    sink = io.StringIO()
    header = export_ledger(records, {"lane": "soft"}, sink)
    assert header.malformed_lines == 2
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert [row["node_id"] for row in rows] == [
        "tests/a.py::test_one",
        "tests/a.py::test_two",
    ]


def test_export_identity_echo() -> None:
    identity = {
        "lane": "optee-qemu",
        "lane_os": "linux",
        "lane_arch": "arm64",
        "framework_sha": "fw123",
        "p11lab_sha": "lab456",
        "image_digest": "sha256:aaa",
        "corpus_hash": "ccc",
        "disabled_hash": "ddd",
        "planned_collection_hash": "eee",
        "planned_count": "42",
        "raw_stream_bytes": "1024",
        "raw_stream_sha256": "fff",
        "created_by": "p11lab",
    }
    sink = io.StringIO()
    header = export_ledger([_report("tests/a.py::test_one")], identity, sink)
    assert header.lane == "optee-qemu"
    assert header.lane_os == "linux"
    assert header.lane_arch == "arm64"
    assert header.framework_sha == "fw123"
    assert header.p11lab_sha == "lab456"
    assert header.image_digest == "sha256:aaa"
    assert header.corpus_hash == "ccc"
    assert header.disabled_hash == "ddd"
    assert header.planned_collection_hash == "eee"
    assert header.planned_count == 42
    assert header.raw_stream_bytes == 1024
    assert header.raw_stream_sha256 == "fff"
    assert header.created_by == "p11lab"
    # Absent keys default ("" / 0 / "pkcs11-check"); unparseable ints are 0.
    sparse = export_ledger(
        [_report("tests/a.py::test_one")],
        {"lane": "soft", "planned_count": "bogus"},
        io.StringIO(),
    )
    assert sparse.lane_os == ""
    assert sparse.framework_sha == ""
    assert sparse.raw_stream_sha256 == ""
    assert sparse.planned_count == 0
    assert sparse.raw_stream_bytes == 0
    assert sparse.created_by == "pkcs11-check"


def _ledger_text(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def _header_line(schema_v: Any = 1) -> str:
    return json.dumps(
        {
            "record": "header",
            "schema_v": schema_v,
            "lane": "soft",
            "lane_os": "",
            "lane_arch": "",
            "framework_sha": "",
            "p11lab_sha": "",
            "image_digest": "",
            "corpus_hash": "",
            "disabled_hash": "",
            "planned_collection_hash": "",
            "planned_count": 0,
            "raw_stream_bytes": 0,
            "raw_stream_sha256": "",
            "malformed_lines": 0,
            "counters": {},
            "created_by": "pkcs11-check",
        },
        sort_keys=True,
    )


def _row_line(node_id: str, phase: str = "call", attempt: int = 1, **overrides: Any) -> str:
    row: dict[str, Any] = {
        "record": "case",
        "node_id": node_id,
        "phase": phase,
        "attempt": attempt,
        "attempts_total": 1,
        "shard_id": "",
        "outcome": "passed",
        "duration_ms": 0,
        "reason": "",
        "class_reason": "",
        "category": "",
        "ckr_expected": "",
        "ckr_actual": "",
        "mechanism": "",
        "stimulus_rev": "",
        "oracle_rev": "",
        "reach": "",
        "effect": "",
        "cleanup": "",
        "termination": "",
        "flags": [],
    }
    row.update(overrides)
    return json.dumps(row, sort_keys=True)


@pytest.mark.parametrize(
    ("lines", "match"),
    [
        ([_header_line(schema_v=2)], "schema_v"),
        ([_row_line("tests/a.py::t"), _header_line()], "header"),
        (
            [_header_line(), _row_line("tests/b.py::t"), _row_line("tests/a.py::t")],
            "unsorted",
        ),
        (
            [
                _header_line(),
                _row_line("tests/a.py::t"),
                _row_line("tests/a.py::t"),
            ],
            "duplicate",
        ),
        ([_header_line(), _row_line("tests/a.py::t", outcome="bogus")], "outcome"),
    ],
)
def test_load_rejects(tmp_path: Path, lines: list[str], match: str) -> None:
    from pkcs11_check.core.evidence import load_ledger

    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(_ledger_text(lines), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        load_ledger(ledger)


class _NullSink(io.TextIOBase):
    def __init__(self) -> None:
        self.bytes_written = 0

    def write(self, text: str) -> int:
        self.bytes_written += len(text)
        return len(text)


def test_export_streams_constant_memory() -> None:
    def generate() -> Any:
        yield {"$report_type": "SessionStart"}
        for index in range(200_000):
            yield {
                "$report_type": "TestReport",
                "nodeid": f"tests/gen.py::test_case_{index}",
                "when": "call",
                "outcome": "passed",
                "duration": 0.001,
                "user_properties": [],
            }
        yield {"$report_type": "SessionFinish", "exitstatus": 0}

    sink = _NullSink()
    tracemalloc.start()
    try:
        _, baseline_peak = tracemalloc.get_traced_memory()
        del baseline_peak
        baseline, _ = tracemalloc.get_traced_memory()
        export_ledger(generate(), {"lane": "soft"}, sink)  # type: ignore[arg-type]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert sink.bytes_written > 0
    assert peak - baseline < TRACEMALLOC_LIMIT_BYTES
