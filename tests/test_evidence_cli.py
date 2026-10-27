"""Tests for the evidence CLI: export / admit / compare (Task E3)."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.cli import evidence_cmd
from pkcs11_check.cli.app import app
from pkcs11_check.core.evidence.admit import (
    PredeclaredRoster,
    ShardExpectation,
    admit_lane,
    shard_digest,
)
from pkcs11_check.core.evidence.compare import fingerprint
from pkcs11_check.core.evidence.export import export_ledger, load_ledger
from pkcs11_check.core.evidence.obligations import ObligationInventory
from pkcs11_check.core.evidence.schema import (
    LEDGER_SCHEMA_VERSION,
    LedgerHeader,
    LedgerRow,
    Outcome,
    zero_counters,
)
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


# --- fix round 1 helpers: hand-built ledgers ---------------------------------


def _hb_row(
    node_id: str,
    outcome: Outcome,
    attempt: int = 1,
    attempts_total: int = 1,
    phase: str = "call",
    shard_id: str = "s0",
    reason: str = "",
    ckr_expected: str = "",
    ckr_actual: str = "",
    termination: str = "",
) -> LedgerRow:
    return LedgerRow(
        node_id=node_id,
        phase=phase,
        attempt=attempt,
        attempts_total=attempts_total,
        shard_id=shard_id,
        outcome=outcome,
        duration_ms=1,
        reason=reason,
        class_reason="",
        category="",
        ckr_expected=ckr_expected,
        ckr_actual=ckr_actual,
        mechanism="",
        stimulus_rev="",
        oracle_rev="",
        reach="",
        effect="",
        cleanup="",
        termination=termination,
        flags=[],
    )


def _hb_header(
    rows: list[LedgerRow],
    lane: str = "soft",
    raw_sha: str = "0" * 64,
    incomplete: int = 0,
    malformed_lines: int = 0,
    framework_sha: str = "f" * 40,
) -> LedgerHeader:
    counters = zero_counters()
    for row in rows:
        counters[row.outcome.value] += 1
    counters["incomplete"] = incomplete
    return LedgerHeader(
        schema_v=LEDGER_SCHEMA_VERSION,
        lane=lane,
        lane_os="linux",
        lane_arch="x86_64",
        framework_sha=framework_sha,
        p11lab_sha="p" * 40,
        image_digest="img",
        corpus_hash="c",
        disabled_hash="d",
        planned_collection_hash="p",
        planned_count=len(rows),
        raw_stream_bytes=0,
        raw_stream_sha256=raw_sha,
        malformed_lines=malformed_lines,
        counters=counters,
        created_by="pkcs11-check",
    )


def _write_hb_ledger(path: Path, header: LedgerHeader, rows: list[LedgerRow]) -> None:
    lines = [json.dumps(header.to_record(), sort_keys=True)]
    lines.extend(json.dumps(row.to_record(), sort_keys=True) for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_admit_files(
    tmp_path: Path, header: LedgerHeader, rows: list[LedgerRow]
) -> tuple[Path, Path, Path]:
    ledger = tmp_path / "ledger.jsonl"
    _write_hb_ledger(ledger, header, rows)
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps(_roster_doc((header, rows))), encoding="utf-8")
    obligations = tmp_path / "obligations.json"
    obligations.write_text(json.dumps(_obligations_doc((header, rows))), encoding="utf-8")
    return ledger, roster, obligations


def _invoke_admit(ledger: Path, roster: Path, obligations: Path) -> Any:
    return runner.invoke(
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


def _clean_hb_lane() -> tuple[LedgerHeader, list[LedgerRow]]:
    rows = [
        _hb_row(
            NODE_A,
            Outcome.FAILED,
            reason="wrong_result",
            ckr_expected="CKR_OK",
            ckr_actual="CKR_DATA_INVALID",
            termination="clean",
        ),
        _hb_row(NODE_B, Outcome.PASSED),
    ]
    return _hb_header(rows), rows


def _roster_for(rows: list[LedgerRow]) -> PredeclaredRoster:
    groups: dict[str, list[LedgerRow]] = {}
    for row in rows:
        groups.setdefault(row.shard_id, []).append(row)
    return PredeclaredRoster(
        lane="soft",
        shards={
            shard: ShardExpectation(records=len(members), sha256=shard_digest(members))
            for shard, members in groups.items()
        },
    )


def _inventory_for(rows: list[LedgerRow]) -> ObligationInventory:
    return ObligationInventory(members=frozenset(row.node_id for row in rows))


# --- fix round 1: F1 covered instability via CLI ------------------------------


def test_compare_delta_covered_instability_is_gate_red(tmp_path: Path) -> None:
    """F1 probe (a) via CLI: [fail x3] vs [pass,pass,fail] + delta -> exit 1."""
    base_rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=n, attempts_total=3, reason="wrong_result")
        for n in (1, 2, 3)
    ]
    cand_rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
        _hb_row(NODE_A, Outcome.FAILED, attempt=3, attempts_total=3, reason="bad_signature"),
    ]
    base = tmp_path / "base.jsonl"
    _write_hb_ledger(base, _hb_header(base_rows), base_rows)
    cand = tmp_path / "cand.jsonl"
    _write_hb_ledger(cand, _hb_header(cand_rows), cand_rows)
    deltas = tmp_path / "deltas.json"
    deltas.write_text(
        json.dumps(
            {
                "version": "ComparisonAdmissionV1",
                "entries": [
                    {
                        "lane": "soft",
                        "case_id": NODE_A,
                        "phase": "call",
                        "old_fp": list(fingerprint(base_rows[0])),
                        "new_fp": list(fingerprint(cand_rows[2])),
                        "reason": "oracle fix rotates the failure reason",
                        "ttl": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand), "--deltas", str(deltas)])
    assert result.exit_code == 1, result.output
    assert "unstable" in result.output


# --- fix round 1: F2 exit classification --------------------------------------


def test_compare_malformed_file_named_unreadable_is_gate_red(tmp_path: Path) -> None:
    """F2: a filename containing 'unreadable' must not reclassify malformed evidence."""
    base, _ = _compare_ledgers(tmp_path)
    bad = tmp_path / "unreadable-ledger.jsonl"
    bad.write_text("{not valid json\n", encoding="utf-8")
    result = runner.invoke(app, ["evidence-compare", str(base), str(bad)])
    assert result.exit_code == 1, result.output


def test_compare_row_outcome_unreadable_is_gate_red(tmp_path: Path) -> None:
    """F2: a row outcome literally 'unreadable' is malformed evidence (1), not infra."""
    base, _ = _compare_ledgers(tmp_path)
    lines = base.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    lines[1] = lines[1].replace('"outcome": "failed"', '"outcome": "unreadable"')
    cand = tmp_path / "cand.jsonl"
    cand.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output


def test_compare_invalid_utf8_deltas_sidecar_exit_2(tmp_path: Path) -> None:
    """F2: undecodable JSON sidecar bytes are unparseable-JSON usage error (2)."""
    base, _ = _compare_ledgers(tmp_path)
    deltas = tmp_path / "deltas.json"
    deltas.write_bytes(b'{"version": "\xff\xfe broken"\n')
    result = runner.invoke(app, ["evidence-compare", str(base), str(base), "--deltas", str(deltas)])
    assert result.exit_code == 2, result.output
    assert "UTF-8" in result.output


def test_compare_unreadable_ledger_file_exit_2(tmp_path: Path) -> None:
    """F2: a genuinely unreadable ledger file is infra (2) via the open-probe."""
    base, _ = _compare_ledgers(tmp_path)
    locked = tmp_path / "locked.jsonl"
    locked.write_bytes(base.read_bytes())
    locked.chmod(0o000)
    try:
        try:
            with locked.open("rb"):
                pass
        except OSError:
            pass
        else:
            pytest.skip("file readable despite chmod 000 (running as root?)")
        result = runner.invoke(app, ["evidence-compare", str(base), str(locked)])
        assert result.exit_code == 2, result.output
    finally:
        locked.chmod(0o644)


# --- fix round 1: F3 side-aware locators --------------------------------------


def test_compare_removed_row_locator_uses_baseline_sha(tmp_path: Path) -> None:
    """F3 probe: a removed row exists only in the baseline artifact (aaaa)."""
    base_rows = [
        _hb_row(NODE_A, Outcome.FAILED, reason="wrong_result"),
        _hb_row(NODE_B, Outcome.PASSED),
    ]
    cand_rows = [_hb_row(NODE_B, Outcome.PASSED)]
    base = tmp_path / "base.jsonl"
    _write_hb_ledger(base, _hb_header(base_rows, raw_sha="a" * 64), base_rows)
    cand = tmp_path / "cand.jsonl"
    _write_hb_ledger(cand, _hb_header(cand_rows, raw_sha="b" * 64), cand_rows)
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output
    assert f"{NODE_A}::call@1 raw:{'a' * 12}" in result.output


def test_compare_added_row_locator_uses_candidate_sha(tmp_path: Path) -> None:
    """F3 mirror: an added row exists only in the candidate artifact (bbbb)."""
    base_rows = [_hb_row(NODE_B, Outcome.PASSED)]
    cand_rows = [
        _hb_row(NODE_A, Outcome.FAILED, reason="wrong_result"),
        _hb_row(NODE_B, Outcome.PASSED),
    ]
    base = tmp_path / "base.jsonl"
    _write_hb_ledger(base, _hb_header(base_rows, raw_sha="a" * 64), base_rows)
    cand = tmp_path / "cand.jsonl"
    _write_hb_ledger(cand, _hb_header(cand_rows, raw_sha="b" * 64), cand_rows)
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output
    assert f"{NODE_A}::call@1 raw:{'b' * 12}" in result.output


# --- fix round 1: F4 admit per-row triage (one test per predicate class) ------


def test_admit_roster_mismatch_renders_implicated_rows(tmp_path: Path) -> None:
    """F4/roster_complete: digest mismatch renders the shard's rows + locators."""
    header, rows = _clean_hb_lane()
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    doc = json.loads(roster.read_text(encoding="utf-8"))
    doc["shards"]["s0"]["sha256"] = "0" * 64
    roster.write_text(json.dumps(doc), encoding="utf-8")
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "roster_complete" in result.output
    assert "wrong_result" in result.output
    assert "CKR_OK/CKR_DATA_INVALID" in result.output
    assert f"soft/s0/{NODE_A}::call@1 raw:" in result.output


def test_admit_roster_missing_shard_reports_zero_rows(tmp_path: Path) -> None:
    """F4/roster_complete: a shard missing from rows reports '0 rows present'."""
    header, rows = _clean_hb_lane()
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    doc = json.loads(roster.read_text(encoding="utf-8"))
    doc["shards"]["sx"] = {"records": 1, "sha256": "0" * 64}
    roster.write_text(json.dumps(doc), encoding="utf-8")
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "missing from rows" in result.output
    assert "0 rows present" in result.output
    assert "raw:" in result.output


def test_admit_zero_malformed_renders_header_note_and_facts(tmp_path: Path) -> None:
    """F4/zero_malformed: header-level failure renders a no-rows note + facts."""
    _, rows = _clean_hb_lane()
    header = _hb_header(rows, malformed_lines=3)
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "zero_malformed" in result.output
    assert "no implicated rows" in result.output
    assert "malformed_lines=3" in result.output
    assert "raw:" in result.output


def test_admit_typed_fields_renders_indexed_rows() -> None:
    """F4/typed_fields: genuine E2 'row N' shapes resolve to rows + locators."""
    header, rows = _clean_hb_lane()
    bad = [replace(rows[0], attempt="1"), *rows[1:]]
    verdict = admit_lane(header, bad, _roster_for(rows), _inventory_for(rows))
    assert not verdict.admitted
    (failure,) = [item for item in verdict.failures if item.startswith("typed_fields")]
    lines = evidence_cmd._admit_failure_lines(failure, header, rows)
    joined = "\n".join(lines)
    assert NODE_A in joined
    assert f"soft/s0/{NODE_A}::call@1 raw:" in joined


def test_admit_typed_fields_out_of_range_index_falls_back() -> None:
    """F4/typed_fields: an unresolvable index renders the raw message only."""
    header, rows = _clean_hb_lane()
    failure = "typed_fields: 1 row(s) with missing/mistyped outcome/node_id/phase/attempt: row 99"
    lines = evidence_cmd._admit_failure_lines(failure, header, rows)
    joined = "\n".join(lines)
    assert failure in joined
    assert "out of range" in joined
    assert "raw:" not in joined


def test_admit_session_framing_renders_bucket_rows(tmp_path: Path) -> None:
    """F4/session_framing: a bucket mismatch renders rows with that outcome."""
    rows = [_hb_row(NODE_A, Outcome.PASSED)]
    header = replace(_hb_header(rows), counters={**_hb_header(rows).counters, "passed": 5})
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "session_framing" in result.output
    assert "bucket 'passed'" in result.output
    assert f"soft/s0/{NODE_A}::call@1 raw:" in result.output


def test_admit_occurrence_renders_group_rows(tmp_path: Path) -> None:
    """F4/occurrence_preserved: a broken group renders its member rows + locators."""
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
    ]
    header = _hb_header(rows)
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "occurrence_preserved" in result.output
    assert f"soft/s0/{NODE_A}::call@1 raw:" in result.output
    assert f"soft/s0/{NODE_A}::call@2 raw:" in result.output


def test_admit_observability_renders_header_note(tmp_path: Path) -> None:
    """F4/observability_complete: header-level failure renders a no-rows note."""
    _, rows = _clean_hb_lane()
    clean = _hb_header(rows)
    header = replace(clean, counters={**clean.counters, "incomplete": 1})
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "observability_complete" in result.output
    assert "no implicated rows" in result.output
    assert "incomplete=1" in result.output


def test_admit_provenance_renders_header_note(tmp_path: Path) -> None:
    """F4/provenance_present: header-level failure renders a no-rows note."""
    _, rows = _clean_hb_lane()
    header = replace(_hb_header(rows), framework_sha="")
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "provenance_present" in result.output
    assert "no implicated rows" in result.output
    assert "raw:" in result.output


# --- fix round 1: F5 Rich-markup escaping -------------------------------------


@pytest.mark.parametrize("node_id", ["t.py::test_A[red]", "t.py::test_A[bold]"])
def test_compare_summary_preserves_bracketed_case_id(tmp_path: Path, node_id: str) -> None:
    """F5: Rich markup must not eat brackets in evidence-derived IDs."""
    base = tmp_path / "base.jsonl"
    _write_ledger(base, _framed(_report(node_id, outcome="passed")))
    cand = tmp_path / "cand.jsonl"
    _write_ledger(cand, _framed(_classified(_report(node_id, outcome="failed"))))
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand)])
    assert result.exit_code == 1, result.output
    assert node_id in result.output
    assert f"{node_id}::call@1 raw:" in result.output
    as_json = runner.invoke(app, ["evidence-compare", str(base), str(cand), "--output", "json"])
    assert as_json.exit_code == 1, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["regressions"][0]["node_id"] == node_id


# --- fix round 1: F6 JSON error envelope --------------------------------------


def test_compare_malformed_ledger_json_envelope(tmp_path: Path) -> None:
    """F6: malformed ledger + --output json -> parseable error envelope, exit 1."""
    base, _ = _compare_ledgers(tmp_path)
    bad = tmp_path / "bad.jsonl"
    bad.write_text("garbage\n", encoding="utf-8")
    result = runner.invoke(app, ["evidence-compare", str(base), str(bad), "--output", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert isinstance(payload["errors"], list) and payload["errors"]


def test_compare_invalid_delta_version_json_envelope(tmp_path: Path) -> None:
    """F6: invalid delta version + --output json -> parseable envelope, exit 1."""
    base, _ = _compare_ledgers(tmp_path)
    deltas = tmp_path / "deltas.json"
    deltas.write_text(json.dumps({"version": "Bogus", "entries": []}), encoding="utf-8")
    result = runner.invoke(
        app, ["evidence-compare", str(base), str(base), "--deltas", str(deltas), "--output", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert isinstance(payload["errors"], list) and payload["errors"]


def test_compare_missing_delta_fields_json_envelope(tmp_path: Path) -> None:
    """F6: missing delta fields + --output json -> parseable envelope, exit 1."""
    base, _ = _compare_ledgers(tmp_path)
    deltas = tmp_path / "deltas.json"
    deltas.write_text(
        json.dumps({"version": "ComparisonAdmissionV1", "entries": [{"lane": "soft"}]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["evidence-compare", str(base), str(base), "--deltas", str(deltas), "--output", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert isinstance(payload["errors"], list) and payload["errors"]


# --- fix round 1: strict TTL at the CLI build layer (nit) ---------------------


@pytest.mark.parametrize("ttl", [True, 1.0, 2])
def test_compare_non_unit_ttl_rejected_as_bad_paperwork(tmp_path: Path, ttl: Any) -> None:
    """Nit (build layer): ttl true/1.0/2 in delta JSON all gate-red (exit 1)."""
    base = tmp_path / "base.jsonl"
    _write_ledger(
        base, _framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result"))
    )
    cand = tmp_path / "cand.jsonl"
    _write_ledger(
        cand, _framed(_classified(_report(NODE_A, outcome="failed"), reason="bad_signature"))
    )
    _, base_rows = load_ledger(base)
    _, cand_rows = load_ledger(cand)
    deltas = tmp_path / "deltas.json"
    deltas.write_text(
        json.dumps(
            {
                "version": "ComparisonAdmissionV1",
                "entries": [
                    {
                        "lane": "soft",
                        "case_id": NODE_A,
                        "phase": "call",
                        "old_fp": list(fingerprint(base_rows[0])),
                        "new_fp": list(fingerprint(cand_rows[0])),
                        "reason": "rotation",
                        "ttl": ttl,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["evidence-compare", str(base), str(cand), "--deltas", str(deltas)])
    assert result.exit_code == 1, result.output


# --- fix round 2: repr-quote shard/bucket parsing (F4r) -------------------------


def test_admit_double_quoted_shard_renders_implicated_rows(tmp_path: Path) -> None:
    """F4r: shard ID s'0 (E2 double-quoted repr) still renders rows + locators."""
    rows = [
        _hb_row(
            NODE_A,
            Outcome.FAILED,
            shard_id="s'0",
            reason="wrong_result",
            ckr_expected="CKR_OK",
            ckr_actual="CKR_DATA_INVALID",
            termination="clean",
        ),
        _hb_row(NODE_B, Outcome.PASSED, shard_id="s'0"),
    ]
    header = _hb_header(rows)
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    doc = json.loads(roster.read_text(encoding="utf-8"))
    doc["shards"]["s'0"]["sha256"] = "0" * 64
    roster.write_text(json.dumps(doc), encoding="utf-8")
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert 'shard "s\'0" digest mismatch' in result.output
    assert "unparseable" not in result.output
    assert "wrong_result" in result.output
    assert f"soft/s'0/{NODE_A}::call@1 raw:" in result.output


def test_admit_double_quoted_bucket_parses() -> None:
    """F4r audit: a double-quoted bucket repr parses (no 'unparseable' note).

    Pinned at the parser level: a quoted bucket cannot survive ledger load
    (``from_record`` drops unknown counter keys), so the genuine E2 message
    is produced in-memory and fed to ``_admit_failure_lines`` directly.
    """
    header, rows = _clean_hb_lane()
    quoted = replace(header, counters={**header.counters, "b'x": 1})
    verdict = admit_lane(quoted, rows, _roster_for(rows), _inventory_for(rows))
    assert not verdict.admitted
    (failure,) = [item for item in verdict.failures if item.startswith("session_framing: bucket")]
    assert failure == 'session_framing: bucket "b\'x" header says 1, rows have 0'
    lines = evidence_cmd._admit_failure_lines(failure, header, rows)
    joined = "\n".join(lines)
    assert "unparseable" not in joined
    assert "b'x" in joined


def test_admit_occurrence_group_with_quote_renders_rows(tmp_path: Path) -> None:
    """F4r audit control: occurrence already literal_evals, quoted IDs render."""
    node = "tests/q.py::test_q'n"
    rows = [
        _hb_row(node, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(node, Outcome.PASSED, attempt=2, attempts_total=3),
    ]
    header = _hb_header(rows)
    ledger, roster, obligations = _write_admit_files(tmp_path, header, rows)
    result = _invoke_admit(ledger, roster, obligations)
    assert result.exit_code == 1, result.output
    assert "occurrence_preserved" in result.output
    assert f"soft/s0/{node}::call@1 raw:" in result.output
    assert f"soft/s0/{node}::call@2 raw:" in result.output


# --- fix round 2: path failures reach the JSON-aware preflight (F6r) ------------


def _assert_error_envelope(result: Any) -> None:
    """Assert an R25 error envelope on stdout (parseable, non-empty errors)."""
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert isinstance(payload["errors"], list) and payload["errors"]


def _chmod_locked(path: Path) -> bool:
    """chmod-000 `path`; True unless still readable (e.g. running as root)."""
    path.chmod(0o000)
    try:
        with path.open("rb"):
            pass
    except OSError:
        return True
    return False


def _normalized_text(result: Any) -> str:
    """Captured output with every whitespace run collapsed to one space.

    Rich word-wraps summary lines at the console width (80 under CliRunner):
    a multi-word phrase on an unbounded-length line -- e.g. the preflight
    ``{path} not found or unreadable ...`` line -- may be split across output
    lines depending on width and path length. Assertions on such lines must
    use this form so they hold at any width and any tmp-path length.
    """
    return " ".join(result.output.split())


def test_compare_unreadable_candidate_json_envelope_exit_2(tmp_path: Path) -> None:
    """F6r: chmod-000 candidate + --output json -> R25 envelope, exit 2."""
    base, _ = _compare_ledgers(tmp_path)
    locked = tmp_path / "locked.jsonl"
    locked.write_bytes(base.read_bytes())
    try:
        if not _chmod_locked(locked):
            pytest.skip("file readable despite chmod 000 (running as root?)")
        result = runner.invoke(
            app, ["evidence-compare", str(base), str(locked), "--output", "json"]
        )
        assert result.exit_code == 2, result.output
        _assert_error_envelope(result)
    finally:
        locked.chmod(0o644)


def test_compare_missing_file_json_envelope_exit_2(tmp_path: Path) -> None:
    """F6r control: missing candidate + --output json -> R25 envelope, exit 2."""
    base, _ = _compare_ledgers(tmp_path)
    result = runner.invoke(
        app, ["evidence-compare", str(base), str(tmp_path / "absent.jsonl"), "--output", "json"]
    )
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)


def test_compare_directory_ledger_json_envelope_exit_2(tmp_path: Path) -> None:
    """F6r audit: a directory ledger also reaches the preflight envelope."""
    base, _ = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(tmp_path), "--output", "json"])
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)


def test_compare_unreadable_candidate_summary_prose_exit_2(tmp_path: Path) -> None:
    """F6r: chmod-000 candidate in summary mode -> preflight prose, exit 2."""
    base, _ = _compare_ledgers(tmp_path)
    locked = tmp_path / "locked.jsonl"
    locked.write_bytes(base.read_bytes())
    try:
        if not _chmod_locked(locked):
            pytest.skip("file readable despite chmod 000 (running as root?)")
        result = runner.invoke(app, ["evidence-compare", str(base), str(locked)])
        assert result.exit_code == 2, result.output
        assert "not found or unreadable" in _normalized_text(result)
        assert "Usage:" not in result.output
    finally:
        locked.chmod(0o644)


def test_compare_missing_file_summary_prose_exit_2(tmp_path: Path) -> None:
    """F6r control: missing candidate in summary mode -> preflight prose, exit 2."""
    base, _ = _compare_ledgers(tmp_path)
    result = runner.invoke(app, ["evidence-compare", str(base), str(tmp_path / "absent.jsonl")])
    assert result.exit_code == 2, result.output
    assert "not found or unreadable" in _normalized_text(result)
    assert "Usage:" not in result.output


# Tuned total length of str(missing) in the wrap-forcing test below: raw
# contiguity of "not found or unreadable" fails at width 80 for totals
# 137..156 (swept 1..160); 146 sits mid-band. See the test docstring.
_WRAP_TARGET = 146


def test_compare_missing_file_long_path_wrap_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R28: the preflight phrase asserts green on a Rich-wrapped long-path line.

    The missing path is padded so ``str(missing)`` is exactly
    ``_WRAP_TARGET`` chars; at width 80 that puts the wrap split inside
    ``not found or unreadable`` (tuned: raw contiguity fails for total path
    lengths 137..156, target 146 sits mid-band with -9/+10 margin). Width is
    pinned via ``COLUMNS`` (Rich re-reads it per print even under CliRunner,
    verified empirically), and the padded total makes the wrap point identical
    on every machine -- CliRunner is never a tty, so nothing else moves it.
    The test asserts the NORMALIZED form: it passes at any width, and goes
    red if the assertion ever regresses to raw contiguity. (A tmp_path
    containing spaces or exotic OSError text only costs the wrap bite, never
    the pass: normalization holds regardless.)
    """
    monkeypatch.setenv("COLUMNS", "80")
    base, _ = _compare_ledgers(tmp_path)
    padding = _WRAP_TARGET - len(str(tmp_path)) - 2 - len("absent.jsonl")
    if padding < 1:
        pytest.skip("tmp_path too long to pad to the tuned wrap length")
    missing = tmp_path / ("d" * padding) / "absent.jsonl"
    assert len(str(missing)) == _WRAP_TARGET
    result = runner.invoke(app, ["evidence-compare", str(base), str(missing)])
    assert result.exit_code == 2, result.output
    assert "not found or unreadable" in _normalized_text(result)
    assert "Usage:" not in result.output


# --- final fix round F2: FF1 parser hardening + FF4 CLI export --------------------


def _invoke_admit_json(ledger: Path, roster: Path, obligations: Path) -> Any:
    return runner.invoke(
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


def test_admit_roster_huge_int_json_envelope_exit_2(tmp_path: Path) -> None:
    """FF1: roster with a 5000-digit int -> exit 2 + R25 envelope, no traceback."""
    ledger, roster, obligations = _admit_files(tmp_path)
    roster.write_text(
        '{"lane": "soft", "shards": {"s0": {"records": ' + "9" * 5000 + ', "sha256": "x"}}}',
        encoding="utf-8",
    )
    result = _invoke_admit_json(ledger, roster, obligations)
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)


def test_admit_roster_deep_nesting_json_envelope_exit_2(tmp_path: Path) -> None:
    """FF1: roster with 20000-nested arrays -> exit 2 + R25 envelope, no traceback."""
    ledger, roster, obligations = _admit_files(tmp_path)
    roster.write_text("[" * 20000 + "]" * 20000, encoding="utf-8")
    result = _invoke_admit_json(ledger, roster, obligations)
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)


def test_admit_obligations_non_utf8_json_envelope_exit_2(tmp_path: Path) -> None:
    """FF1 pin: 0xff-bytes obligations sidecar -> exit 2 + R25 envelope."""
    ledger, roster, obligations = _admit_files(tmp_path)
    obligations.write_bytes(b'{"catalog": {}, "profile": {"cases": []}}\xff')
    result = _invoke_admit_json(ledger, roster, obligations)
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)


def test_export_overflow_durations_cli_exit_0_rows_preserved(tmp_path: Path) -> None:
    """FF4/R34: reviewer probes through the full CLI path -- exit 0, rows kept."""
    report = _write_report(
        tmp_path / "report.jsonl",
        _framed(
            _report(NODE_A, duration=1e308),
            _report(NODE_B, duration=10**400),
        ),
    )
    ledger = tmp_path / "ledger.jsonl"
    result = runner.invoke(app, ["evidence-export", str(report), str(ledger), "--lane", "soft"])
    assert result.exit_code == 0, result.output
    _, rows = load_ledger(ledger)
    assert [row.duration_ms for row in rows] == [0, 0]


def test_compare_ledger_deep_nesting_json_envelope_exit_2(tmp_path: Path) -> None:
    """R36: deeply-nested ledger line -> exit 2 + R25 envelope, no traceback."""
    base, _ = _compare_ledgers(tmp_path)
    header_line = base.read_text(encoding="utf-8").splitlines()[0]
    nested = tmp_path / "nested.jsonl"
    nested.write_text(header_line + "\n" + "[" * 20000 + "]" * 20000 + "\n", encoding="utf-8")
    result = runner.invoke(app, ["evidence-compare", str(base), str(nested), "--output", "json"])
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)


def test_compare_ledger_non_utf8_json_envelope_exit_2(tmp_path: Path) -> None:
    """R36: 0xff-bytes ledger file -> exit 2 + R25 envelope, no traceback."""
    base, _ = _compare_ledgers(tmp_path)
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(base.read_bytes() + b"\xff")
    result = runner.invoke(app, ["evidence-compare", str(base), str(bad), "--output", "json"])
    assert result.exit_code == 2, result.output
    _assert_error_envelope(result)
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)


def test_compare_ledger_malformed_content_json_envelope_exit_1(tmp_path: Path) -> None:
    """R36 control: bad-schema valid-JSON ledger stays exit 1 (content, not parse)."""
    base, _ = _compare_ledgers(tmp_path)
    lines = base.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["outcome"] = "bogus-outcome"
    bad = tmp_path / "bad-content.jsonl"
    bad.write_text(lines[0] + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["evidence-compare", str(base), str(bad), "--output", "json"])
    assert result.exit_code == 1, result.output
    _assert_error_envelope(result)
