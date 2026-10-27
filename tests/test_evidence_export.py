"""Tests for the evidence ledger streaming exporter (schema v1)."""

from __future__ import annotations

import io
import json
import random
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core.crash_codes import CTYPES_ACCESS_VIOLATION
from pkcs11_check.core.evidence import export_ledger
from pkcs11_check.core.report_log import iter_report_log_records

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
    """Build a producer-shaped marker: ``attempt`` is the SOURCE 0-based value."""
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _classification_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
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
    fields.update(overrides)
    return fields


def _classified(record: dict[str, Any], **fields: Any) -> dict[str, Any]:
    record["user_properties"] = [("pkcs11_classification", [_classification_fields(**fields)])]
    return record


def _multi_classified(record: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    record["user_properties"] = [("pkcs11_classification", entries)]
    return record


def _export_lines(records: list[Any], identity: dict[str, str], **kwargs: Any) -> list[str]:
    sink = io.StringIO()
    export_ledger(records, identity, sink, **kwargs)
    return sink.getvalue().splitlines()


def test_export_header_first_and_sorted() -> None:
    records: list[Any] = [
        {"$report_type": "SessionStart"},
        _marker("tests/a.py", 0),
        _report("tests/b.py::test_two", shard_id="shard-1"),
        _report("tests/a.py::test_one", when="setup", shard_id="shard-0"),
        _marker("tests/a.py", 1),
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
    # Producer-shaped 0-based markers: source 0/1/2 -> ledger attempts 1/2/3.
    for raw_attempt, outcome in enumerate(outcomes):
        records.append(_marker("tests/x.py", raw_attempt))
        records.append(_report("tests/x.py::test_flaky", when="setup"))
        records.append(_report("tests/x.py::test_flaky", when="call", outcome=outcome))
    sink = io.StringIO()
    header = export_ledger(records, {"lane": "soft"}, sink)
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert len(rows) == 6
    assert sorted(row["attempt"] for row in rows) == [1, 1, 2, 2, 3, 3]
    assert {row["attempts_total"] for row in rows} == {3}
    assert header.malformed_lines == 0
    assert header.counters["passed"] == 5
    assert header.counters["failed"] == 1
    assert sum(header.counters[outcome] for outcome in ("passed", "failed")) == 6


def test_export_maps_zero_based_markers_to_one_based_attempts(tmp_path: Path) -> None:
    from pkcs11_check.core.evidence import load_ledger

    # Finding 1: real producers emit 0-based markers; ledger attempts are
    # 1-based (source marker + 1). Markers 0,1 must NOT count as malformed and
    # must NOT collapse into a loader-rejected duplicate.
    records: list[Any] = [
        {"$report_type": "SessionStart"},
        _marker("tests/z.py", 0),
        _report("tests/z.py::test_retry", outcome="failed"),
        _marker("tests/z.py", 1),
        _report("tests/z.py::test_retry", outcome="passed"),
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]
    sink = io.StringIO()
    header = export_ledger(records, {"lane": "soft"}, sink)
    assert header.malformed_lines == 0
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert [row["attempt"] for row in rows] == [1, 2]
    assert [row["attempts_total"] for row in rows] == [2, 2]
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(sink.getvalue(), encoding="utf-8")
    _, loaded = load_ledger(ledger)
    assert [row.attempt for row in loaded] == [1, 2]

    # Escalation: a later well-formed marker supersedes earlier provenance.
    escalated = _export_lines(
        [
            _marker("tests/f.py", 0),
            _report("tests/f.py::test_a"),
            _marker("tests/f.py::test_b", 1),
            _report("tests/f.py::test_b"),
        ],
        {"lane": "soft"},
    )
    by_node = {json.loads(line)["node_id"]: json.loads(line) for line in escalated[1:]}
    assert by_node["tests/f.py::test_a"]["attempt"] == 1
    assert by_node["tests/f.py::test_b"]["attempt"] == 2

    # Recovery: a malformed marker resets provenance to unattributed (attempt 1)
    # and counts exactly one malformed line. Negative and bool attempts are
    # malformed: no producer emits them (emission sites start at 0 and increment).
    sink = io.StringIO()
    header = export_ledger(
        [_marker("tests/z.py", -1), _report("tests/z.py::test_t")],
        {"lane": "soft"},
        sink,
    )
    assert header.malformed_lines == 1
    assert json.loads(sink.getvalue().splitlines()[1])["attempt"] == 1
    sink = io.StringIO()
    header = export_ledger(
        [_marker("tests/z.py", True), _report("tests/z.py::test_t")],  # type: ignore[list-item]
        {"lane": "soft"},
        sink,
    )
    assert header.malformed_lines == 1
    assert json.loads(sink.getvalue().splitlines()[1])["attempt"] == 1


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
        [_marker("tests/a.py", 0)] + seg1 + [_marker("tests/b.py", 1)] + seg2, identity
    )
    # Shuffle within each marker scope (cross-marker shuffles are a different
    # stream: attempt attribution follows marker order, as documented).
    seg1_shuffled = list(seg1)
    random.Random(3).shuffle(seg1_shuffled)
    seg2_shuffled = list(seg2)
    random.Random(11).shuffle(seg2_shuffled)
    second = _export_lines(
        [_marker("tests/a.py", 0)] + seg1_shuffled + [_marker("tests/b.py", 1)] + seg2_shuffled,
        identity,
    )
    assert first == second

    # Marker-free streams carry no attribution, so a REAL any-order shuffle of
    # the whole input must produce identical bytes.
    bare: list[Any] = [
        _classified(_report("tests/m.py::test_one", outcome="failed")),
        _report("tests/m.py::test_two", when="setup", outcome="skipped"),
        _report("tests/n.py::test_three", when="teardown"),
        _report("tests/n.py::test_four"),
    ]
    canonical = _export_lines(list(bare), identity)
    for seed in (1, 2, 3, 17, 99):
        shuffled = list(bare)
        random.Random(seed).shuffle(shuffled)
        assert _export_lines(shuffled, identity) == canonical
    assert _export_lines(list(reversed(bare)), identity) == canonical

    # Finding 6: duplicate occurrence keys fail explicitly and deterministically.
    # Equal keys with conflicting outcomes can never be byte-stable under the
    # loader's uniqueness contract, so every input order raises the same error
    # and writes nothing (no order-dependent, self-loader-rejectable output).
    conflicting: list[Any] = [
        _marker("tests/e.py", 0),
        _report("tests/e.py::test_t", outcome="passed"),
        _report("tests/e.py::test_t", outcome="failed"),
    ]
    messages: set[str] = set()
    orders = [list(conflicting), list(reversed(conflicting))]
    for seed in (5, 6):
        shuffled = list(conflicting)
        random.Random(seed).shuffle(shuffled)
        orders.append(shuffled)
    for order in orders:
        sink = io.StringIO()
        with pytest.raises(ValueError, match="duplicate") as excinfo:
            export_ledger(order, identity, sink)
        messages.add(str(excinfo.value))
        assert sink.getvalue() == ""
    assert len(messages) == 1

    # Overlapping shards (same occurrence key, different shard tags) are the
    # same duplicate-key defect: deterministic failure, never silent ordering.
    overlapping: list[Any] = [
        _marker("tests/s.py", 0),
        _report("tests/s.py::test_t", shard_id="shard-a"),
        _report("tests/s.py::test_t", shard_id="shard-b"),
    ]
    for seed in (9, 10):
        shuffled = list(overlapping)
        random.Random(seed).shuffle(shuffled)
        with pytest.raises(ValueError, match="duplicate"):
            export_ledger(shuffled, identity, io.StringIO())
    with pytest.raises(ValueError, match="duplicate"):
        export_ledger(list(overlapping), identity, io.StringIO())


def test_export_counts_malformed_not_drops_silently(tmp_path: Path) -> None:
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

    # Finding 2: lines the REAL reader skips (invalid JSON, non-object JSON,
    # invalid UTF-8) count into malformed_lines via the threaded on_invalid
    # channel -- parsed-dict validation alone cannot see them.
    log = tmp_path / "report.jsonl"
    log.write_bytes(
        b'{"$report_type": "TestReport", "nodeid": "tests/r.py::t1",'
        b' "when": "call", "outcome": "passed"}\n'
        b"{this is not json}\n"
        b"[1, 2, 3]\n"
        b"\xff\xfe not utf-8\n"
        b'{"$report_type": "TestReport", "nodeid": "tests/r.py::t2",'
        b' "when": "call", "outcome": "failed"}\n'
    )
    reader_invalid = 0

    def _count_invalid() -> None:
        nonlocal reader_invalid
        reader_invalid += 1

    stream = iter_report_log_records(log, on_invalid=_count_invalid)
    sink = io.StringIO()
    header = export_ledger(
        stream, {"lane": "soft"}, sink, reader_invalid_lines=lambda: reader_invalid
    )
    assert reader_invalid == 3
    assert header.malformed_lines == 3
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert [row["node_id"] for row in rows] == ["tests/r.py::t1", "tests/r.py::t2"]


def test_export_reader_invalid_count_forms() -> None:
    records = [_report("tests/a.py::test_one")]
    # Plain-int form (caller materialized the stream and counted already).
    header = export_ledger(records, {"lane": "soft"}, io.StringIO(), reader_invalid_lines=2)
    assert header.malformed_lines == 2
    # Thunk form (streaming caller): evaluated once, after records are consumed.
    calls = 0

    def _thunk() -> int:
        nonlocal calls
        calls += 1
        return 3

    header = export_ledger(
        list(records), {"lane": "soft"}, io.StringIO(), reader_invalid_lines=_thunk
    )
    assert header.malformed_lines == 3
    assert calls == 1
    # Wrong types and negatives fail loud (caller bugs, never silent).
    with pytest.raises(TypeError):
        export_ledger(list(records), {"lane": "soft"}, io.StringIO(), reader_invalid_lines="2")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        export_ledger(list(records), {"lane": "soft"}, io.StringIO(), reader_invalid_lines=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        export_ledger(list(records), {"lane": "soft"}, io.StringIO(), reader_invalid_lines=-1)
    with pytest.raises(TypeError):
        export_ledger(
            list(records),
            {"lane": "soft"},
            io.StringIO(),
            reader_invalid_lines=lambda: "x",  # type: ignore[return-value]
        )


def test_export_none_reader_invalid_counts_parsed_malformed_only() -> None:
    """R16: None (the default) means no reader in the loop.

    A 3-arg call over pre-parsed records counts parsed-level malformed only;
    an explicit None is byte-identical. Production callers consuming raw
    streams MUST pass the reader callback instead (see the exporter's
    docstring contract).
    """
    records: list[Any] = [
        _report("tests/a.py::test_one"),
        "not-a-mapping",
        {"$report_type": "TestReport", "when": "call", "outcome": "passed"},
        _report("tests/a.py::test_two", outcome="failed"),
    ]
    default_sink, explicit_sink = io.StringIO(), io.StringIO()
    default_header = export_ledger(list(records), {"lane": "soft"}, default_sink)
    explicit_header = export_ledger(
        list(records), {"lane": "soft"}, explicit_sink, reader_invalid_lines=None
    )
    assert default_header.malformed_lines == 2
    assert explicit_header.malformed_lines == 2
    assert default_sink.getvalue() == explicit_sink.getvalue()


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


def _finalize_stream(*finalizes: dict[str, Any]) -> list[Any]:
    return [
        {"$report_type": "SessionStart"},
        _marker("tests/life.py", 0),
        _report("tests/life.py::test_ok"),
        *finalizes,
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]


def _lifecycle_rows(lines: list[str]) -> list[dict[str, Any]]:
    return [
        row for line in lines[1:] if (row := json.loads(line))["node_id"] == "C_Finalize::teardown"
    ]


@pytest.mark.parametrize(
    ("finalize", "expected_outcome", "expected_reason", "expected_ckr_actual"),
    [
        # Plain error with CKR evidence (the review's rv=5 probe shape).
        (
            {
                "$report_type": "TeardownFinalize",
                "outcome": "error",
                "rv": 5,
                "rv_name": "CKR_DEVICE_ERROR",
            },
            "error",
            "self_contradiction",
            "CKR_DEVICE_ERROR",
        ),
        # Explicit crash outcome.
        (
            {
                "$report_type": "TeardownFinalize",
                "outcome": "crashed",
                "rv": 5,
                "rv_name": "CKR_DEVICE_ERROR",
            },
            "crashed",
            "crash",
            "CKR_DEVICE_ERROR",
        ),
        # Crash detected via windows_status, mirroring the consumer's
        # windows_status/access-violation priority rule.
        (
            {
                "$report_type": "TeardownFinalize",
                "outcome": "error",
                "rv": 5,
                "rv_name": "CKR_DEVICE_ERROR",
                "windows_status": CTYPES_ACCESS_VIOLATION,
            },
            "crashed",
            "crash",
            "CKR_DEVICE_ERROR",
        ),
        # Crash detected via a ctypes access-violation traceback in the error text.
        (
            {
                "$report_type": "TeardownFinalize",
                "outcome": "error",
                "error": "OSError: Exception: Access Violation reading 0x00000000",
            },
            "crashed",
            "crash",
            "",
        ),
        # Timeout passes through as its own outcome (consumer parity).
        (
            {"$report_type": "TeardownFinalize", "outcome": "timeout"},
            "timeout",
            "self_contradiction",
            "",
        ),
        # Missing outcome is an error in the consumer (str("") -> not ok) --
        # evidence, never a silent skip.
        ({"$report_type": "TeardownFinalize"}, "error", "self_contradiction", ""),
    ],
)
def test_export_preserves_failed_teardown_finalize(
    finalize: dict[str, Any],
    expected_outcome: str,
    expected_reason: str,
    expected_ckr_actual: str,
) -> None:
    """Finding 3: failed finalization becomes a lifecycle row, never vanishes.

    Outcome detection mirrors ``core/_report_records.py`` ``finalize_outcome``
    (access-violation -> crashed; ok -> skip; crashed/timeout pass through;
    else error); facets mirror ``report/extract.py``
    ``_classification_from_teardown_finalize`` (reason crash/self_contradiction,
    kind lifecycle, expected CKR_OK, actual rv_name).
    """
    sink = io.StringIO()
    header = export_ledger(_finalize_stream(finalize), {"lane": "soft"}, sink)
    lines = sink.getvalue().splitlines()
    assert header.counters["passed"] == 1
    assert header.counters[expected_outcome] == 1
    assert header.malformed_lines == 0
    life = _lifecycle_rows(lines)
    assert len(life) == 1
    row = life[0]
    assert row["phase"] == "teardown"
    assert row["attempt"] == 1
    assert row["outcome"] == expected_outcome
    assert row["reason"] == expected_reason
    assert row["class_reason"] == "fail"
    assert row["category"] == "lifecycle"
    assert row["ckr_expected"] == "CKR_OK"
    assert row["ckr_actual"] == expected_ckr_actual


def test_export_skips_ok_teardown_finalize_and_orders_finalizers_canonically() -> None:
    """R17: every unsuccessful finalizer keeps its row; effective-outcome
    collapsing is E3's job, not the exporter's. Rank order (error < crashed <
    timeout) and input-order independence are unchanged from the old fold."""
    sink = io.StringIO()
    header = export_ledger(
        _finalize_stream({"$report_type": "TeardownFinalize", "outcome": "ok"}),
        {"lane": "soft"},
        sink,
    )
    assert header.counters["passed"] == 1
    assert _lifecycle_rows(sink.getvalue().splitlines()) == []

    # Different priorities: no occurrence is dropped, and both input orders
    # produce identical bytes in canonical rank order.
    error = {"$report_type": "TeardownFinalize", "outcome": "error", "rv_name": "X"}
    timeout = {"$report_type": "TeardownFinalize", "outcome": "timeout"}
    forward = _export_lines(_finalize_stream(error, timeout), {"lane": "soft"})
    backward = _export_lines(_finalize_stream(timeout, error), {"lane": "soft"})
    assert forward == backward
    life = _lifecycle_rows(forward)
    assert [row["outcome"] for row in life] == ["error", "timeout"]
    assert [row["attempt"] for row in life] == [1, 2]
    assert [row["attempts_total"] for row in life] == [2, 2]
    header = export_ledger(_finalize_stream(error, timeout), {"lane": "soft"}, io.StringIO())
    assert header.counters["error"] == 1
    assert header.counters["timeout"] == 1


def test_export_preserves_same_priority_finalizer_ties() -> None:
    """R17: same-priority finalizers are ALL preserved, byte-identical in both
    input orders. Lifecycle rows are totally ordered by (priority rank,
    outcome, canonical JSON of salient fields); attempt is the 1-based
    position in that canonical order."""
    first: dict[str, Any] = {
        "$report_type": "TeardownFinalize",
        "outcome": "error",
        "rv_name": "CKR_A",
        "shard_id": "shard-a",
    }
    second: dict[str, Any] = {
        "$report_type": "TeardownFinalize",
        "outcome": "error",
        "rv_name": "CKR_B",
        "shard_id": "shard-b",
    }
    forward = _export_lines(_finalize_stream(first, second), {"lane": "soft"})
    backward = _export_lines(_finalize_stream(second, first), {"lane": "soft"})
    assert forward == backward
    life = _lifecycle_rows(forward)
    assert len(life) == 2
    assert {(row["ckr_actual"], row["shard_id"]) for row in life} == {
        ("CKR_A", "shard-a"),
        ("CKR_B", "shard-b"),
    }
    assert [row["attempt"] for row in life] == [1, 2]
    assert [row["attempts_total"] for row in life] == [2, 2]
    header = export_ledger(_finalize_stream(first, second), {"lane": "soft"}, io.StringIO())
    assert header.counters["error"] == 2
    assert header.malformed_lines == 0


def test_export_marks_unfinished_session_incomplete() -> None:
    """Finding 4: observed incompleteness survives export (E2 cannot rebuild it)."""
    finished = [
        {"$report_type": "SessionStart"},
        _marker("tests/s.py", 0),
        _report("tests/s.py::test_t"),
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]
    unfinished = [
        {"$report_type": "SessionStart"},
        _marker("tests/s.py", 0),
        _report("tests/s.py::test_t"),
    ]
    finished_sink, unfinished_sink = io.StringIO(), io.StringIO()
    finished_header = export_ledger(list(finished), {"lane": "soft"}, finished_sink)
    unfinished_header = export_ledger(list(unfinished), {"lane": "soft"}, unfinished_sink)
    assert finished_header.counters["incomplete"] == 0
    assert unfinished_header.counters["incomplete"] == 1
    assert finished_sink.getvalue() != unfinished_sink.getvalue()

    # Unframed legacy streams (no bookends at all) are unverifiable, never clean.
    unframed = export_ledger([_report("tests/s.py::test_t")], {"lane": "soft"}, io.StringIO())
    assert unframed.counters["incomplete"] == 1

    # Collection/harness failure evidence marks the session incomplete, matching
    # the canonical consumer (which sets incomplete on collect/harness errors).
    collect_failed = export_ledger(
        [
            {"$report_type": "SessionStart"},
            {
                "$report_type": "CollectReport",
                "nodeid": "tests/broken.py",
                "when": "collect",
                "outcome": "failed",
            },
            {"$report_type": "SessionFinish", "exitstatus": 2},
        ],
        {"lane": "soft"},
        io.StringIO(),
    )
    assert collect_failed.counters["incomplete"] == 1
    assert collect_failed.counters["error"] == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"$report_type": "TestReport", "nodeid": "t", "when": "call", "outcome": []},
        {"$report_type": "TestReport", "nodeid": "t", "when": "call", "outcome": None},
        {"$report_type": "TestReport", "nodeid": "t", "when": [], "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t", "when": "collect", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": 42, "when": "call", "outcome": "passed"},
        {
            "$report_type": "TestReport",
            "nodeid": "t",
            "when": "call",
            "outcome": "passed",
            "user_properties": 42,
        },
        {
            "$report_type": "TestReport",
            "nodeid": "t",
            "when": "call",
            "outcome": "passed",
            "user_properties": "nope",
        },
        {"$report_type": "CollectReport", "nodeid": "tests/b.py", "when": "collect"},
        {"$report_type": "CollectReport", "nodeid": "t", "when": "collect", "outcome": []},
        {"$report_type": "CollectReport", "when": "collect", "outcome": "failed"},
        {"$report_type": "HarnessError"},
        {"$report_type": None, "nodeid": "t", "when": "call", "outcome": "passed"},
        {"$report_type": 42, "nodeid": "t", "when": "call", "outcome": "passed"},
        42,
        "not-a-mapping",
        ["a-list"],
    ],
)
def test_export_counts_wrong_typed_shapes(bad: Any) -> None:
    """Finding 5: wrong JSON types count as malformed; export never aborts."""
    records: list[Any] = [
        _report("tests/w.py::test_a"),
        bad,
        _report("tests/w.py::test_b"),
    ]
    sink = io.StringIO()
    header = export_ledger(records, {"lane": "soft"}, sink)
    assert header.malformed_lines == 1
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert [row["node_id"] for row in rows] == [
        "tests/w.py::test_a",
        "tests/w.py::test_b",
    ]


def test_export_keeps_row_when_classification_value_mistyped() -> None:
    """A mistyped classification property value drops facets, not the row.

    Matches ``iter_classification_occurrences``: a non-list property value is
    malformed at the property level while the record itself stays processable.
    """
    record = _report("tests/w.py::test_t", outcome="failed")
    record["user_properties"] = [("pkcs11_classification", {"reason": "wrong_result"})]
    sink = io.StringIO()
    header = export_ledger([record], {"lane": "soft"}, sink)
    assert header.malformed_lines == 0
    rows = [json.loads(line) for line in sink.getvalue().splitlines()[1:]]
    assert len(rows) == 1
    assert rows[0]["outcome"] == "failed"
    assert rows[0]["reason"] == ""


def test_export_selects_terminating_classification() -> None:
    """Finding 7: facets come from the terminating classification, not index 0.

    Selection mirrors ``_plugin_report_attach._apply_recorded_outcome``: the
    first ``fail`` entry wins, else the first ``xfail`` entry, else the first
    entry. Additional observations survive as ``extra:<reason>`` flags (no
    silent discard, no schema expansion).
    """
    sanctioned = _classification_fields(
        reason="sanctioned_refusal",
        outcome="pass",
        severity="INFO",
        kind="policy",
        mechanism="CKM_RSA_PKCS",
        expected_ckr=["CKR_OK"],
        actual_ckr="CKR_OK",
    )
    wrong = _classification_fields(
        reason="wrong_result",
        outcome="fail",
        kind="crypto",
        mechanism="CKM_AES_CBC",
        expected_ckr=["CKR_OK"],
        actual_ckr="CKR_DATA_INVALID",
    )
    # The review's probe: earlier non-terminating entry + later terminating one.
    record = _multi_classified(
        _report("tests/k.py::test_t", outcome="failed"), [dict(sanctioned), dict(wrong)]
    )
    rows = [json.loads(line) for line in _export_lines([record], {"lane": "soft"})[1:]]
    assert len(rows) == 1
    assert rows[0]["reason"] == "wrong_result"
    assert rows[0]["class_reason"] == "fail"
    assert rows[0]["category"] == "crypto"
    assert rows[0]["ckr_expected"] == "CKR_OK"
    assert rows[0]["ckr_actual"] == "CKR_DATA_INVALID"
    assert rows[0]["mechanism"] == "CKM_AES_CBC"
    assert rows[0]["flags"] == ["extra:sanctioned_refusal"]

    # Selection is priority-based, not position-based: either order exports
    # identical facets for the same entry multiset.
    flipped = _multi_classified(
        _report("tests/k.py::test_t", outcome="failed"), [dict(wrong), dict(sanctioned)]
    )
    flipped_rows = [json.loads(line) for line in _export_lines([flipped], {"lane": "soft"})[1:]]
    assert flipped_rows[0]["reason"] == "wrong_result"
    assert flipped_rows[0]["flags"] == ["extra:sanctioned_refusal"]

    # xfail beats pass when no fail entry exists.
    deviated = _classification_fields(
        reason="not_operational", outcome="xfail", severity="LOW", kind="policy"
    )
    xfail_record = _multi_classified(
        _report("tests/k.py::test_x"), [dict(sanctioned), dict(deviated)]
    )
    xfail_rows = [json.loads(line) for line in _export_lines([xfail_record], {"lane": "soft"})[1:]]
    assert xfail_rows[0]["reason"] == "not_operational"
    assert xfail_rows[0]["class_reason"] == "xfail"
    assert xfail_rows[0]["flags"] == ["extra:sanctioned_refusal"]

    # A lone classification leaves no extra flags.
    lone = _classified(_report("tests/k.py::test_l", outcome="failed"))
    lone_rows = [json.loads(line) for line in _export_lines([lone], {"lane": "soft"})[1:]]
    assert lone_rows[0]["reason"] == "wrong_result"
    assert lone_rows[0]["flags"] == []


class _CountingSink(io.TextIOBase):
    """A sink that accounts every line and byte without retaining content."""

    def __init__(self) -> None:
        self.lines = 0
        self.bytes_written = 0

    def write(self, text: str) -> int:
        self.lines += text.count("\n")
        self.bytes_written += len(text)
        return len(text)


def test_export_streams_constant_memory() -> None:
    """Finding 8: the 200k streaming bound is proven by accounting, not vibes.

    tracemalloc measures traced Python allocations (not RSS); the assertion
    below bounds exporter-retained allocations while 200k occurrences -- each
    carrying kilobytes of DISTINCT discarded raw payload -- stream through.
    """
    yielded = 0

    def generate() -> Iterator[dict[str, Any]]:
        nonlocal yielded
        yield {"$report_type": "SessionStart"}
        yielded += 1
        for index in range(200_000):
            yielded += 1
            # Distinct per record: retaining raw payloads would pin ~3 GB and
            # explode the bound below; streaming drops each after processing.
            junk = f"junk-{index}-" + "y" * 8000 + "z" * 8000
            yield {
                "$report_type": "TestReport",
                "nodeid": f"tests/gen.py::test_case_{index}",
                "when": "call",
                "outcome": "passed",
                "duration": 0.001,
                "user_properties": [],
                "longrepr": junk,
                "stdout": junk,
            }
        yield {"$report_type": "SessionFinish", "exitstatus": 0}
        yielded += 1

    stream = generate()
    sink = _CountingSink()
    # Isolate the tracer: start our own measurement only when nothing else is
    # tracing, and restore the prior state afterwards (never stop another
    # owner's tracer). When already tracing, peak-since-start belongs to the
    # outer owner, so the bound below uses retained growth instead.
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        header = export_ledger(stream, {"lane": "soft"}, sink)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()
    measured = peak - baseline if not was_tracing else current - baseline

    # Correctness oracle: the generator was exhausted exactly once, all 200k
    # occurrences reached the sink (header + one line each), counters agree.
    assert yielded == 200_002
    assert header.counters["passed"] == 200_000
    assert header.malformed_lines == 0
    assert sink.lines == 200_001
    assert sink.bytes_written > 0
    assert measured < TRACEMALLOC_LIMIT_BYTES

    # Single-pass proof: the exhausted generator traverses no second time.
    sink2 = _CountingSink()
    header2 = export_ledger(stream, {"lane": "soft"}, sink2)
    assert sink2.lines == 1
    assert header2.counters["passed"] == 0
