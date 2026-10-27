"""Tests for the evidence CLI: export / admit / compare (Task E3)."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

from pkcs11_check.cli.app import app
from pkcs11_check.core.evidence.admit import shard_digest
from pkcs11_check.core.evidence.export import export_ledger, load_ledger
from pkcs11_check.core.evidence.schema import LedgerHeader, LedgerRow
from tests._plain_cli_runner import PlainCliRunner

NODE_A = "tests/a.py::test_a"
NODE_B = "tests/b.py::test_b"

runner = PlainCliRunner()

IDENTITY = {
    "lane": "soft",
    "lane_os": "linux",
    "lane_arch": "x86_64",
    "framework_sha": "f" * 40,
    "p11lab_sha": "p" * 40,
    "image_digest": "img",
    "corpus_hash": "c",
    "disabled_hash": "d",
    "shard_id": "s0",
}


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
        "detail": {"termination": "clean"},
        "schema": 1,
    }
    fields.update(overrides)
    return fields


def _classified(record: dict[str, Any], **fields: Any) -> dict[str, Any]:
    record["user_properties"] = [("pkcs11_classification", [_classification_fields(**fields)])]
    return record


def _framed(*records: Any) -> list[Any]:
    return [
        {"$report_type": "SessionStart"},
        *records,
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]


def _write_report(path: Path, records: list[Any], extra_lines: list[str] | None = None) -> Path:
    lines = [json.dumps(record) for record in records]
    lines.extend(extra_lines or [])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_ledger(path: Path, records: list[Any]) -> tuple[LedgerHeader, list[LedgerRow]]:
    sink = io.StringIO()
    export_ledger(records, IDENTITY, sink)
    path.write_text(sink.getvalue(), encoding="utf-8")
    return load_ledger(path)


def _roster_doc(header_rows: tuple[LedgerHeader, list[LedgerRow]]) -> dict[str, Any]:
    _, rows = header_rows
    groups: dict[str, list[LedgerRow]] = {}
    for row in rows:
        groups.setdefault(row.shard_id, []).append(row)
    return {
        "lane": "soft",
        "shards": {
            shard: {"records": len(members), "sha256": shard_digest(members)}
            for shard, members in groups.items()
        },
    }


def _obligations_doc(header_rows: tuple[LedgerHeader, list[LedgerRow]]) -> dict[str, Any]:
    cases = sorted({row.node_id for row in header_rows[1]})
    return {"catalog": {case: {} for case in cases}, "profile": {"cases": cases}}


# --- evidence-export -------------------------------------------------------


def test_export_happy_path_summary(tmp_path: Path) -> None:
    report = _write_report(
        tmp_path / "report.jsonl",
        _framed(_report(NODE_A), _classified(_report(NODE_B, outcome="failed"))),
    )
    ledger = tmp_path / "ledger.jsonl"
    result = runner.invoke(
        app,
        [
            "evidence-export",
            str(report),
            str(ledger),
            "--lane",
            "soft",
            "--lane-os",
            "linux",
            "--lane-arch",
            "x86_64",
            "--framework-sha",
            "f" * 40,
            "--p11lab-sha",
            "p" * 40,
            "--image-digest",
            "img",
            "--corpus-hash",
            "c",
            "--disabled-hash",
            "d",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "soft" in result.output
    header, rows = load_ledger(ledger)
    assert len(rows) == 2
    assert header.malformed_lines == 0
    assert header.counters["incomplete"] == 0


def test_export_json_shape(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "report.jsonl", _framed(_report(NODE_A)))
    ledger = tmp_path / "ledger.jsonl"
    result = runner.invoke(
        app,
        ["evidence-export", str(report), str(ledger), "--lane", "soft", "--output", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["header"]["record"] == "header"
    assert payload["header"]["lane"] == "soft"
    assert payload["rows"] == 1
    assert payload["header"]["counters"]["passed"] == 1


def test_export_measures_raw_stream_identity(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "report.jsonl", _framed(_report(NODE_A)))
    ledger = tmp_path / "ledger.jsonl"
    result = runner.invoke(app, ["evidence-export", str(report), str(ledger), "--lane", "soft"])
    assert result.exit_code == 0, result.output
    raw = report.read_bytes()
    header, _ = load_ledger(ledger)
    assert header.raw_stream_bytes == len(raw)
    assert header.raw_stream_sha256 == hashlib.sha256(raw).hexdigest()
    assert header.planned_count == 0


def test_export_invalid_lines_counted_and_red(tmp_path: Path) -> None:
    """R16 wiring proof: reader-invalid lines land in malformed_lines via the CLI."""
    report = _write_report(
        tmp_path / "report.jsonl",
        _framed(_report(NODE_A)),
        extra_lines=["{not json", "[1, 2]"],
    )
    ledger = tmp_path / "ledger.jsonl"
    result = runner.invoke(
        app,
        ["evidence-export", str(report), str(ledger), "--lane", "soft", "--output", "json"],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["header"]["malformed_lines"] == 2
    header, _ = load_ledger(ledger)
    assert header.malformed_lines == 2


def test_export_missing_report_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["evidence-export", str(tmp_path / "absent.jsonl"), str(tmp_path / "out.jsonl")],
    )
    assert result.exit_code == 2


def test_export_unknown_output_exit_2(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "report.jsonl", _framed(_report(NODE_A)))
    result = runner.invoke(
        app,
        [
            "evidence-export",
            str(report),
            str(tmp_path / "out.jsonl"),
            "--output",
            "yaml",
        ],
    )
    assert result.exit_code == 2


# --- evidence-admit --------------------------------------------------------


def _admit_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    pair = _write_ledger(
        tmp_path / "ledger.jsonl",
        _framed(_report(NODE_A), _classified(_report(NODE_B, outcome="failed"))),
    )
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps(_roster_doc(pair)), encoding="utf-8")
    obligations = tmp_path / "obligations.json"
    obligations.write_text(json.dumps(_obligations_doc(pair)), encoding="utf-8")
    return tmp_path / "ledger.jsonl", roster, obligations


def test_admit_happy_path_summary(tmp_path: Path) -> None:
    ledger, roster, obligations = _admit_files(tmp_path)
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(ledger),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "admitted" in result.output.lower()


def test_admit_json_shape(tmp_path: Path) -> None:
    ledger, roster, obligations = _admit_files(tmp_path)
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(ledger),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload == {"admitted": True, "failures": [], "warnings": []}


def test_admit_roster_mismatch_exit_1(tmp_path: Path) -> None:
    ledger, roster, obligations = _admit_files(tmp_path)
    doc = json.loads(roster.read_text(encoding="utf-8"))
    doc["shards"]["s0"]["sha256"] = "0" * 64
    roster.write_text(json.dumps(doc), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(ledger),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "roster_complete" in result.output


def test_admit_malformed_ledger_exit_1(tmp_path: Path) -> None:
    ledger, roster, obligations = _admit_files(tmp_path)
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write("{not a ledger row}\n")
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(ledger),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
        ],
    )
    assert result.exit_code == 1, result.output


def test_admit_missing_ledger_exit_2(tmp_path: Path) -> None:
    _, roster, obligations = _admit_files(tmp_path)
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(tmp_path / "absent.jsonl"),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
        ],
    )
    assert result.exit_code == 2


def test_admit_bad_roster_json_exit_2(tmp_path: Path) -> None:
    ledger, roster, obligations = _admit_files(tmp_path)
    roster.write_text("{not json", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(ledger),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
        ],
    )
    assert result.exit_code == 2


def test_admit_unknown_obligation_case_exit_2(tmp_path: Path) -> None:
    ledger, roster, obligations = _admit_files(tmp_path)
    doc = json.loads(obligations.read_text(encoding="utf-8"))
    doc["profile"]["cases"].append("tests/ghost.py::test_missing")
    obligations.write_text(json.dumps(doc), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "evidence-admit",
            str(ledger),
            "--roster",
            str(roster),
            "--obligations",
            str(obligations),
        ],
    )
    assert result.exit_code == 2


# --- evidence-compare ------------------------------------------------------


def _compare_ledgers(tmp_path: Path) -> tuple[Path, Path]:
    base = tmp_path / "base.jsonl"
    _write_ledger(
        base,
        _framed(
            _classified(_report(NODE_A, outcome="failed")),
            _report(NODE_B, outcome="passed"),
        ),
    )
    cand = tmp_path / "cand.jsonl"
    _write_ledger(
        cand,
        _framed(
            _report(NODE_A, outcome="passed"),
            _classified(_report(NODE_B, outcome="failed")),
        ),
    )
    return base, cand


def test_compare_green_exit_0(tmp_path: Path) -> None:
    base, _ = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(base)])
    assert result.exit_code == 0, result.output


def test_compare_regression_exit_1(tmp_path: Path) -> None:
    base, cand = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output
    assert NODE_B in result.output
    assert "failed" in result.output and "passed" in result.output
    assert f"soft/s0/{NODE_B}::call@1" in result.output
    assert "raw:" in result.output


def test_compare_json_shape(tmp_path: Path) -> None:
    base, cand = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand), "--output", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["counts"] == {
        "compared": 2,
        "regressions": 1,
        "improvements": 1,
        "unstable": 0,
        "deltas_applied": 0,
        "deltas_stale": 0,
    }
    (regression,) = payload["regressions"]
    assert regression["node_id"] == NODE_B
    assert regression["axis"] == "outcome"
    assert regression["old"][0] == "passed"
    assert regression["new"][0] == "failed"
    assert isinstance(regression["old"], list)
    assert payload["unstable"] == []


def test_compare_invalid_deltas_exit_1(tmp_path: Path) -> None:
    base, _ = _compare_ledgers(tmp_path)
    deltas = tmp_path / "deltas.json"
    deltas.write_text(
        json.dumps(
            {
                "version": "ComparisonAdmissionV1",
                "entries": [
                    {
                        "lane": "soft",
                        "case_id": "tests/*",
                        "phase": "call",
                        "old_fp": ["passed", "", "", "", "", "", ""],
                        "new_fp": ["failed", "", "", "", "", "", ""],
                        "reason": "wildcard",
                        "ttl": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["evidence-compare", str(base), str(base), "--deltas", str(deltas)])
    assert result.exit_code == 1, result.output


def test_compare_deltas_bad_json_exit_2(tmp_path: Path) -> None:
    base, _ = _compare_ledgers(tmp_path)
    deltas = tmp_path / "deltas.json"
    deltas.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["evidence-compare", str(base), str(base), "--deltas", str(deltas)])
    assert result.exit_code == 2


def test_compare_malformed_ledger_exit_1(tmp_path: Path) -> None:
    base, cand = _compare_ledgers(tmp_path)
    with cand.open("a", encoding="utf-8") as handle:
        handle.write("garbage\n")
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output


def test_compare_missing_file_exit_2(tmp_path: Path) -> None:
    base, _ = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(tmp_path / "absent.jsonl")])
    assert result.exit_code == 2


def test_compare_summary_triage_contract(tmp_path: Path) -> None:
    """Red summaries name case/attempt/phase, dispositions, facets, locator."""
    base, cand = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output
    assert "phase=call" in result.output
    assert "passed -> failed" in result.output
    assert "wrong_result" in result.output
    assert "CKR_DATA_INVALID" in result.output
    assert "clean" in result.output  # termination facet
    assert "raw:" in result.output
