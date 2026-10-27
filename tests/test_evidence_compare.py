"""Mutation suite for the evidence comparator (Task E3).

Each test crafts a baseline and a candidate ledger with E1's exporter from
synthetic report-log streams and asserts the comparator verdict. Hand-built
``LedgerHeader``/``LedgerRow`` objects are used only where the exporter
cannot emit the shape (inconsistent ``attempts_total``, ``error`` on a
``call`` phase, ``missing``/``crash_limited`` outcomes, counter-key loss).
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from pkcs11_check.core.crash_codes import CTYPES_ACCESS_VIOLATION
from pkcs11_check.core.evidence.compare import (
    ComparisonVerdict,
    Delta,
    QuorumPolicy,
    Regression,
    RotationDeltas,
    combine_attempts,
    compare_lanes,
    fingerprint,
    validate_deltas,
)
from pkcs11_check.core.evidence.export import export_ledger
from pkcs11_check.core.evidence.schema import (
    LEDGER_SCHEMA_VERSION,
    LedgerHeader,
    LedgerRow,
    Outcome,
    zero_counters,
)

NODE_A = "tests/a.py::test_a"
NODE_B = "tests/b.py::test_b"
NODE_C = "tests/c.py::test_c"
NODE_D = "tests/d.py::test_d"

FP_VERSION = "ComparisonAdmissionV1"


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


def _crashed(record: dict[str, Any]) -> dict[str, Any]:
    """Mark a failed TestReport as a caught ctypes access violation (maps to crashed)."""
    return _classified(record, reason="crash", detail={"windows_status": CTYPES_ACCESS_VIOLATION})


def _framed(*records: Any) -> list[Any]:
    """Wrap records in a complete single-session bookend pair."""
    return [
        {"$report_type": "SessionStart"},
        *records,
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]


def _export(records: list[Any], lane: str = "soft") -> tuple[LedgerHeader, list[LedgerRow]]:
    """Export synthetic records and return the loaded (header, rows) pair."""
    sink = io.StringIO()
    header = export_ledger(records, {"lane": lane}, sink)
    rows = [
        LedgerRow.from_record(json.loads(line), line_number=number)
        for number, line in enumerate(sink.getvalue().splitlines()[1:], start=2)
    ]
    return header, rows


def _hb_row(
    node_id: str,
    outcome: Outcome,
    attempt: int = 1,
    attempts_total: int = 1,
    phase: str = "call",
    reason: str = "",
    class_reason: str = "",
    category: str = "",
    ckr_expected: str = "",
    ckr_actual: str = "",
    termination: str = "",
) -> LedgerRow:
    return LedgerRow(
        node_id=node_id,
        phase=phase,
        attempt=attempt,
        attempts_total=attempts_total,
        shard_id="s0",
        outcome=outcome,
        duration_ms=1,
        reason=reason,
        class_reason=class_reason,
        category=category,
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
    incomplete: int = 0,
    drop_incomplete: bool = False,
) -> LedgerHeader:
    counters = zero_counters()
    for row in rows:
        counters[row.outcome.value] += 1
    counters["incomplete"] = incomplete
    if drop_incomplete:
        del counters["incomplete"]
    return LedgerHeader(
        schema_v=LEDGER_SCHEMA_VERSION,
        lane=lane,
        lane_os="linux",
        lane_arch="x86_64",
        framework_sha="f" * 40,
        p11lab_sha="p" * 40,
        image_digest="img",
        corpus_hash="c",
        disabled_hash="d",
        planned_collection_hash="p",
        planned_count=len(rows),
        raw_stream_bytes=0,
        raw_stream_sha256="",
        malformed_lines=0,
        counters=counters,
        created_by="pkcs11-check",
    )


def _fp(
    outcome: str,
    reason: str = "",
    class_reason: str = "",
    category: str = "",
    ckr_expected: str = "",
    ckr_actual: str = "",
    termination: str = "",
) -> tuple[str, ...]:
    return (outcome, reason, class_reason, category, ckr_expected, ckr_actual, termination)


def _no_deltas() -> RotationDeltas:
    return RotationDeltas(version=FP_VERSION, entries=())


def _compare(
    base: tuple[LedgerHeader, list[LedgerRow]],
    cand: tuple[LedgerHeader, list[LedgerRow]],
    deltas: RotationDeltas | None = None,
    quorum: QuorumPolicy | None = None,
) -> ComparisonVerdict:
    return compare_lanes(
        base,
        cand,
        deltas if deltas is not None else _no_deltas(),
        quorum if quorum is not None else QuorumPolicy(),
    )


def _negative(verdict: ComparisonVerdict) -> bool:
    return bool(verdict.regressions or verdict.unstable)


def _valid_change_kwargs() -> dict[str, Any]:
    return {
        "lane": "soft",
        "case_id": NODE_A,
        "phase": "call",
        "old_fp": _fp("failed", "wrong_result"),
        "new_fp": _fp("failed", "bad_signature"),
        "reason": "oracle fix rotates the failure reason",
        "ttl": 1,
    }


# --- fingerprint -----------------------------------------------------------


def test_fingerprint_excludes_permitted_nondeterministic_fields() -> None:
    first = _hb_row(NODE_A, Outcome.FAILED, reason="r")
    second = _hb_row(NODE_A, Outcome.FAILED, reason="r")
    assert fingerprint(first) == fingerprint(second)
    assert fingerprint(first) == ("failed", "r", "", "", "", "", "")
    # duration_ms / shard_id / attempt are permitted-nondeterministic (A-9).
    other = LedgerRow(**{**first.__dict__, "duration_ms": 999, "shard_id": "s9", "attempt": 3})
    assert fingerprint(other) == fingerprint(first)
    changed = LedgerRow(**{**first.__dict__, "reason": "other"})
    assert fingerprint(changed) != fingerprint(first)


# --- combine_attempts ------------------------------------------------------


def test_combine_unanimous_returns_fp_without_findings() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=2),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=2),
    ]
    combined, findings = combine_attempts(rows, QuorumPolicy())
    assert combined == fingerprint(rows[0])
    assert findings == []


def test_combine_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="empty"):
        combine_attempts([], QuorumPolicy())


def test_combine_is_attempt_order_independent() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=2),
        _hb_row(NODE_A, Outcome.FAILED, attempt=2, attempts_total=2, reason="r"),
    ]
    assert combine_attempts(rows, QuorumPolicy()) == combine_attempts(
        list(reversed(rows)), QuorumPolicy()
    )


def test_combine_picks_worst_rank_with_deterministic_tiebreak() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.FAILED, attempt=2, attempts_total=3, reason="zzz"),
        _hb_row(NODE_A, Outcome.FAILED, attempt=3, attempts_total=3, reason="aaa"),
    ]
    combined, _ = combine_attempts(rows, QuorumPolicy())
    assert combined[0] == "failed"
    # Same-rank tie breaks toward the lexicographically smallest canonical JSON.
    assert combined[1] == "aaa"
    swapped = [rows[0], rows[2], rows[1]]
    assert combine_attempts(swapped, QuorumPolicy())[0] == combined


def test_combine_first_attempt_flip_finding() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=1, attempts_total=3, reason="r"),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=3, attempts_total=3),
    ]
    _, findings = combine_attempts(rows, QuorumPolicy())
    assert "first_attempt" in findings


def test_combine_all_attempts_disagree_is_unstable() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.FAILED, attempt=2, attempts_total=3, reason="r"),
        _hb_row(NODE_A, Outcome.SKIPPED, attempt=3, attempts_total=3),
    ]
    _, findings = combine_attempts(rows, QuorumPolicy())
    assert findings == ["unstable"]


def test_combine_quorum_met_without_unstable_policy_is_bare_disagree() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
        _hb_row(NODE_A, Outcome.FAILED, attempt=3, attempts_total=3, reason="r"),
    ]
    policy = QuorumPolicy(min_repeats=3, quorum_frac=2 / 3, disagree_is_unstable=False)
    _, findings = combine_attempts(rows, policy)
    assert findings == ["disagree"]


def test_combine_quorum_min_repeats_unmet_is_unstable() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.FAILED, attempt=2, attempts_total=3, reason="r"),
        _hb_row(NODE_A, Outcome.SKIPPED, attempt=3, attempts_total=3),
    ]
    policy = QuorumPolicy(min_repeats=5, quorum_frac=2 / 3, disagree_is_unstable=False)
    _, findings = combine_attempts(rows, policy)
    assert findings == ["unstable"]


def test_combine_flip_and_unstable_coexist_under_default_policy() -> None:
    rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=1, attempts_total=3, reason="r"),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=3, attempts_total=3),
    ]
    _, findings = combine_attempts(rows, QuorumPolicy())
    assert findings == ["first_attempt", "unstable"]


# --- per-ID mutations ------------------------------------------------------


def test_fail_move_across_ids_flags_regression() -> None:
    base = _export(
        _framed(
            _report(NODE_A, outcome="failed"),
            _report(NODE_B, outcome="passed"),
        )
    )
    cand = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _report(NODE_B, outcome="failed"),
        )
    )
    verdict = _compare(base, cand)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_B, "outcome")]
    assert [r.node_id for r in verdict.improvements] == [NODE_A]
    assert _negative(verdict)


def test_balanced_fail_skip_swap_flags_regression() -> None:
    base = _export(
        _framed(
            _report(NODE_A, outcome="failed"),
            _report(NODE_B, outcome="skipped"),
        )
    )
    cand = _export(
        _framed(
            _report(NODE_A, outcome="skipped"),
            _report(NODE_B, outcome="failed"),
        )
    )
    verdict = _compare(base, cand)
    # Counts are balanced but both IDs changed disposition: the fail moved.
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_B, "outcome")]
    assert [(r.node_id, r.axis) for r in verdict.improvements] == [(NODE_A, "outcome")]
    assert _negative(verdict)


def test_skip_to_pass_is_clean_improvement() -> None:
    base = _export(_framed(_report(NODE_A, outcome="skipped")))
    cand = _export(_framed(_report(NODE_A, outcome="passed")))
    verdict = _compare(base, cand)
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert len(verdict.improvements) == 1
    assert not _negative(verdict)


def test_xfail_move_across_ids_flags_regression() -> None:
    base = _export(
        _framed(
            _report(NODE_A, outcome="skipped", wasxfail="strict"),
            _report(NODE_B, outcome="passed"),
        )
    )
    cand = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _report(NODE_B, outcome="skipped", wasxfail="strict"),
        )
    )
    verdict = _compare(base, cand)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_B, "outcome")]
    assert [r.node_id for r in verdict.improvements] == [NODE_A]
    assert _negative(verdict)


def test_removed_failing_id_flags_regression() -> None:
    base = _export(
        _framed(
            _report(NODE_A, outcome="failed"),
            _report(NODE_B, outcome="passed"),
        )
    )
    cand = _export(_framed(_report(NODE_B, outcome="passed")))
    verdict = _compare(base, cand)
    assert [(r.node_id, r.old, r.new, r.axis) for r in verdict.regressions] == [
        (NODE_A, _fp("failed"), "absent", "removed")
    ]
    assert _negative(verdict)


def test_new_passing_id_is_improvement() -> None:
    base = _export(_framed(_report(NODE_A, outcome="passed")))
    cand = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _report(NODE_B, outcome="passed"),
        )
    )
    verdict = _compare(base, cand)
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert [(r.node_id, r.axis) for r in verdict.improvements] == [(NODE_B, "added")]
    assert not _negative(verdict)


def test_new_failing_id_without_delta_flags_regression() -> None:
    base = _export(_framed(_report(NODE_A, outcome="passed")))
    cand = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _classified(_report(NODE_B, outcome="failed")),
        )
    )
    verdict = _compare(base, cand)
    assert [(r.node_id, r.old, r.axis) for r in verdict.regressions] == [
        (NODE_B, "absent", "added")
    ]
    assert verdict.regressions[0].new[0] == "failed"
    assert _negative(verdict)


def test_new_failing_id_with_added_delta_passes() -> None:
    base = _export(_framed(_report(NODE_A, outcome="passed")))
    cand = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _classified(_report(NODE_B, outcome="failed")),
        )
    )
    new_fp = fingerprint(next(row for row in cand[1] if row.node_id == NODE_B))
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_B,
                phase="call",
                old_fp="absent",
                new_fp=new_fp,
                reason="new coverage lands failing, tracked",
                ttl=1,
            ),
        ),
    )
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert verdict.counts["deltas_applied"] == 1
    assert not _negative(verdict)


def test_xfail_to_xpass_is_loud() -> None:
    base = _export(_framed(_report(NODE_A, outcome="skipped", wasxfail="strict")))
    cand = _export(_framed(_report(NODE_A, outcome="passed", wasxfail="strict")))
    verdict = _compare(base, cand)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "outcome")]
    assert _negative(verdict)


@pytest.mark.parametrize(
    ("base_fields", "cand_fields"),
    [
        ({"reason": "wrong_result"}, {"reason": "bad_signature"}),
        ({"actual_ckr": "CKR_DATA_INVALID"}, {"actual_ckr": "CKR_SIGNATURE_INVALID"}),
    ],
)
def test_same_outcome_different_reason_or_ckr_flags(
    base_fields: dict[str, Any], cand_fields: dict[str, Any]
) -> None:
    """C2 rule: same outcome plus a changed facet must flag."""
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), **base_fields)))
    cand = _export(_framed(_classified(_report(NODE_A, outcome="failed"), **cand_fields)))
    verdict = _compare(base, cand)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "fingerprint")]
    assert _negative(verdict)


@pytest.mark.parametrize(
    ("old_outcome", "new_outcome"),
    [
        (Outcome.FAILED, Outcome.ERROR),  # rank up within the red set
        (Outcome.ERROR, Outcome.FAILED),  # rank down within the red set: still red
        (Outcome.TIMEOUT, Outcome.FAILED),  # rank down within the red set
        (Outcome.CRASHED, Outcome.CRASH_LIMITED),  # same rank, both red
    ],
)
def test_red_set_moves_flag_in_either_direction(old_outcome: Outcome, new_outcome: Outcome) -> None:
    """Harness-attribution churn is never a clean improvement (error<->failure)."""
    base_rows = [_hb_row(NODE_A, old_outcome)]
    cand_rows = [_hb_row(NODE_A, new_outcome)]
    verdict = _compare((_hb_header(base_rows), base_rows), (_hb_header(cand_rows), cand_rows))
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "outcome")]
    assert _negative(verdict)


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_duplicate_normalized_ids_rejected(side: str) -> None:
    """Inconsistent attempts_total within one (node_id, phase) group is loud."""
    clean_rows = [_hb_row(NODE_A, Outcome.PASSED)]
    clean = (_hb_header(clean_rows), clean_rows)
    bad_rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=1),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=2),
    ]
    bad = (_hb_header(bad_rows), bad_rows)
    base, cand = (bad, clean) if side == "baseline" else (clean, bad)
    with pytest.raises(ValueError, match="attempts_total"):
        _compare(base, cand)


# --- attempts, quorum, pre-checks -------------------------------------------


def _attempted(nodeid: str, outcomes: list[tuple[str, Any]]) -> list[Any]:
    """Build marker-separated attempts; each item is (outcome, classifier|None)."""
    records: list[Any] = []
    for raw, (outcome, classify) in enumerate(outcomes):
        records.append(_marker(nodeid, raw))
        record = _report(nodeid, outcome=outcome)
        if classify == "crash":
            record = _crashed(record)
        records.append(record)
    return records


def test_crash_then_ordinary_order_independent() -> None:
    base = _export(
        _framed(
            _marker(NODE_A, 0),
            _report(NODE_A, outcome="passed"),
            _marker(NODE_A, 1),
            _report(NODE_A, outcome="passed"),
        )
    )
    crash_first = _export(
        _framed(
            _marker(NODE_A, 0),
            _crashed(_report(NODE_A, outcome="failed")),
            _marker(NODE_A, 1),
            _report(NODE_A, outcome="passed"),
        )
    )
    pass_first = _export(
        _framed(
            _marker(NODE_A, 1),
            _report(NODE_A, outcome="passed"),
            _marker(NODE_A, 0),
            _crashed(_report(NODE_A, outcome="failed")),
        )
    )
    # Same occurrence keys from either stream order: the crash is counted once.
    assert [row.sort_key for row in crash_first[1]] == [row.sort_key for row in pass_first[1]]
    assert {row.outcome for row in crash_first[1]} == {Outcome.CRASHED, Outcome.PASSED}
    first_verdict = _compare(base, crash_first)
    second_verdict = _compare(base, pass_first)
    assert first_verdict == second_verdict
    assert first_verdict.unstable == [f"{NODE_A}::call:first_attempt"]
    assert _negative(first_verdict)


def test_pass_pass_fail_triplet_is_unstable_and_red() -> None:
    base = _export(_framed(*_attempted(NODE_A, [("passed", None)] * 3)))
    cand = _export(
        _framed(*_attempted(NODE_A, [("passed", None), ("passed", None), ("failed", None)]))
    )
    verdict = _compare(base, cand)
    assert verdict.unstable == [f"{NODE_A}::call:attempts"]
    assert _negative(verdict)


def test_first_attempt_finding_compared_separately() -> None:
    """A-9: a first-attempt flip on exactly one side gates red on its own axis."""
    base = _export(
        _framed(*_attempted(NODE_A, [("failed", None), ("passed", None), ("passed", None)]))
    )
    cand = _export(_framed(*_attempted(NODE_A, [("passed", None)] * 3)))
    verdict = _compare(base, cand)
    assert verdict.unstable == [f"{NODE_A}::call:first_attempt"]
    assert _negative(verdict)


def test_attempt_count_change_is_unstable() -> None:
    base = _export(_framed(*_attempted(NODE_A, [("passed", None)])))
    cand = _export(_framed(*_attempted(NODE_A, [("passed", None)] * 2)))
    verdict = _compare(base, cand)
    assert verdict.unstable == [f"{NODE_A}::call:attempts"]
    assert _negative(verdict)


def test_disagree_bare_marker_still_gates_red() -> None:
    """Disagreement is never silent even when the policy only marks disagree."""
    policy = QuorumPolicy(min_repeats=3, quorum_frac=2 / 3, disagree_is_unstable=False)
    base = _export(_framed(*_attempted(NODE_A, [("passed", None)] * 3)))
    cand = _export(
        _framed(*_attempted(NODE_A, [("passed", None), ("passed", None), ("failed", None)]))
    )
    _, findings = combine_attempts([row for row in cand[1] if row.node_id == NODE_A], policy)
    assert findings == ["disagree"]
    verdict = _compare(base, cand, quorum=policy)
    assert verdict.unstable == [f"{NODE_A}::call:attempts"]
    assert _negative(verdict)


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_incomplete_header_fails_closed(side: str) -> None:
    clean = _export(_framed(_report(NODE_A, outcome="passed")))
    # No session bookends at all: unverifiable, never clean.
    dirty = _export([_report(NODE_A, outcome="passed")])
    assert dirty[0].counters["incomplete"] == 1
    base, cand = (dirty, clean) if side == "baseline" else (clean, dirty)
    verdict = _compare(base, cand)
    assert verdict.regressions == [
        Regression(node_id="", phase="", old="absent", new="absent", axis="incomplete")
    ]
    assert verdict.unstable == []
    assert verdict.counts["compared"] == 0
    assert _negative(verdict)


def test_hand_built_header_missing_incomplete_key_fails_closed() -> None:
    rows = [_hb_row(NODE_A, Outcome.PASSED)]
    clean = (_hb_header(rows), rows)
    broken_rows = [_hb_row(NODE_A, Outcome.PASSED)]
    broken = (_hb_header(broken_rows, drop_incomplete=True), broken_rows)
    verdict = _compare(clean, broken)
    assert [r.axis for r in verdict.regressions] == ["incomplete"]
    assert _negative(verdict)


@pytest.mark.parametrize(
    ("side", "axis"),
    [("candidate", "empty_candidate"), ("baseline", "empty_baseline")],
)
def test_empty_lane_fails_closed(side: str, axis: str) -> None:
    full = _export(_framed(_report(NODE_A, outcome="passed")))
    empty = _export(
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ]
    )
    assert empty[1] == []
    assert empty[0].counters["incomplete"] == 0
    base, cand = (empty, full) if side == "baseline" else (full, empty)
    verdict = _compare(base, cand)
    assert [r.axis for r in verdict.regressions] == [axis]
    assert _negative(verdict)


def test_undeltaed_changed_fail_to_fail_flags() -> None:
    """A-7 gloss: a failure that changed character without paperwork fails."""
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    cand = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="bad_signature")))
    verdict = _compare(base, cand)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "fingerprint")]
    assert _negative(verdict)


def test_identical_fail_to_fail_is_silent() -> None:
    """Rule 5 verbatim: byte-identical fingerprints compare silent, even when red."""
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    cand = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    verdict = _compare(base, cand)
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert not _negative(verdict)


def test_missing_outcome_hand_built_is_ranked_worst() -> None:
    base_rows = [_hb_row(NODE_A, Outcome.PASSED)]
    cand_rows = [_hb_row(NODE_A, Outcome.MISSING)]
    verdict = _compare((_hb_header(base_rows), base_rows), (_hb_header(cand_rows), cand_rows))
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "outcome")]
    assert _negative(verdict)


def test_counts_account_every_key() -> None:
    base = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _report(NODE_B, outcome="failed"),
            _report(NODE_C, outcome="passed"),
        )
    )
    cand = _export(
        _framed(
            _report(NODE_A, outcome="passed"),
            _report(NODE_B, outcome="passed"),
            _report(NODE_D, outcome="failed"),
        )
    )
    verdict = _compare(base, cand)
    assert verdict.counts == {
        "compared": 4,
        "regressions": 2,  # C removed, D added failing
        "improvements": 1,  # B failed -> passed
        "unstable": 0,
        "deltas_applied": 0,
        "deltas_stale": 0,
    }
    assert all(type(value) is int for value in verdict.counts.values())


# --- rotation deltas -------------------------------------------------------


def test_valid_single_axis_delta_passes() -> None:
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    cand = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="bad_signature")))
    old_fp = fingerprint(base[1][0])
    new_fp = fingerprint(cand[1][0])
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_A,
                phase="call",
                old_fp=old_fp,
                new_fp=new_fp,
                reason="oracle fix rotates the failure reason",
                ttl=1,
            ),
        ),
    )
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert verdict.counts["deltas_applied"] == 1
    assert not _negative(verdict)


def test_wildcard_delta_rejected() -> None:
    kwargs = _valid_change_kwargs()
    kwargs["case_id"] = "tests/*"
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert "identity" in "\n".join(errors)


def test_many_to_one_delta_rejected() -> None:
    fp = _fp("failed", "wrong_result")
    entries = (
        Delta(
            lane="soft",
            case_id=NODE_A,
            phase="call",
            old_fp=fp,
            new_fp="absent",
            reason="rename source one",
            ttl=1,
        ),
        Delta(
            lane="soft",
            case_id=NODE_B,
            phase="call",
            old_fp=fp,
            new_fp="absent",
            reason="rename source two",
            ttl=1,
        ),
        Delta(
            lane="soft",
            case_id=NODE_C,
            phase="call",
            old_fp="absent",
            new_fp=fp,
            reason="rename target",
            ttl=1,
        ),
    )
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=entries))
    assert errors
    assert "rename" in "\n".join(errors)


def test_duplicate_case_delta_rejected() -> None:
    kwargs = _valid_change_kwargs()
    errors = validate_deltas(
        RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs), Delta(**kwargs)))
    )
    assert errors
    assert "duplicate" in "\n".join(errors)


def test_ttl_greater_than_one_rejected() -> None:
    kwargs = _valid_change_kwargs()
    kwargs["ttl"] = 2
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert "ttl" in "\n".join(errors)


def test_version_mismatch_rejected() -> None:
    errors = validate_deltas(RotationDeltas(version="ComparisonAdmissionV2", entries=()))
    assert errors
    assert "version" in "\n".join(errors)


def test_bijective_rename_passes() -> None:
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    cand = _export(_framed(_classified(_report(NODE_B, outcome="failed"), reason="wrong_result")))
    moved_fp = fingerprint(base[1][0])
    assert moved_fp == fingerprint(cand[1][0])
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_A,
                phase="call",
                old_fp=moved_fp,
                new_fp="absent",
                reason="case renamed A -> B",
                ttl=1,
            ),
            Delta(
                lane="soft",
                case_id=NODE_B,
                phase="call",
                old_fp="absent",
                new_fp=moved_fp,
                reason="case renamed A -> B",
                ttl=1,
            ),
        ),
    )
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert verdict.counts["deltas_applied"] == 2
    assert not _negative(verdict)


def test_non_bijective_rename_rejected() -> None:
    """One removal fanning out to two additions is not an exclusive rename."""
    fp = _fp("failed", "wrong_result")
    entries = (
        Delta(
            lane="soft",
            case_id=NODE_A,
            phase="call",
            old_fp=fp,
            new_fp="absent",
            reason="rename source",
            ttl=1,
        ),
        Delta(
            lane="soft",
            case_id=NODE_B,
            phase="call",
            old_fp="absent",
            new_fp=fp,
            reason="rename target one",
            ttl=1,
        ),
        Delta(
            lane="soft",
            case_id=NODE_C,
            phase="call",
            old_fp="absent",
            new_fp=fp,
            reason="rename target two",
            ttl=1,
        ),
    )
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=entries))
    assert errors
    assert "rename" in "\n".join(errors)


def test_stale_delta_claiming_unobserved_change() -> None:
    """Paperwork claims a change the candidate never made: stale only, still red."""
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    cand = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    old_fp = fingerprint(base[1][0])
    new_fp = _fp("failed", "bad_signature", "fail", "crypto", "CKR_OK", "CKR_DATA_INVALID", "")
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_A,
                phase="call",
                old_fp=old_fp,
                new_fp=new_fp,
                reason="claimed rotation that never landed",
                ttl=1,
            ),
        ),
    )
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "stale_delta")]
    assert verdict.counts["deltas_stale"] == 1
    assert _negative(verdict)


def test_stale_delta_with_unclaimed_change_compares_on_top() -> None:
    """Candidate matching neither old nor new: stale paperwork plus a real diff."""
    base = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="wrong_result")))
    cand = _export(_framed(_classified(_report(NODE_A, outcome="failed"), reason="bad_padding")))
    old_fp = fingerprint(base[1][0])
    new_fp = _fp("failed", "bad_signature", "fail", "crypto", "CKR_OK", "CKR_DATA_INVALID", "")
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_A,
                phase="call",
                old_fp=old_fp,
                new_fp=new_fp,
                reason="paperwork names the wrong target",
                ttl=1,
            ),
        ),
    )
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert sorted(r.axis for r in verdict.regressions) == ["fingerprint", "stale_delta"]
    assert verdict.counts["deltas_stale"] == 1
    assert _negative(verdict)


def test_invalid_deltas_fail_loud() -> None:
    base = _export(_framed(_report(NODE_A, outcome="passed")))
    cand = _export(_framed(_report(NODE_A, outcome="passed")))
    kwargs = _valid_change_kwargs()
    kwargs["ttl"] = 9
    with pytest.raises(ValueError, match="deltas"):
        _compare(base, cand, RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))


def test_cross_lane_compare_rejected() -> None:
    base = _export(_framed(_report(NODE_A, outcome="passed")), lane="soft")
    cand = _export(_framed(_report(NODE_A, outcome="passed")), lane="hard")
    with pytest.raises(ValueError, match="lane"):
        _compare(base, cand)


def test_delta_lane_mismatch_is_stale() -> None:
    """A delta filed for another lane never covers this comparison."""
    base = _export(_framed(_report(NODE_A, outcome="passed")))
    cand = _export(_framed(_report(NODE_A, outcome="passed")))
    seen_fp = fingerprint(base[1][0])
    other_fp = _fp("failed")  # single-axis move: outcome only
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="hard",
                case_id=NODE_A,
                phase="call",
                old_fp=seen_fp,
                new_fp=other_fp,
                reason="filed against the wrong lane",
                ttl=1,
            ),
        ),
    )
    # Paperwork shape is valid; it just belongs to another lane.
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert [(r.node_id, r.axis) for r in verdict.regressions] == [(NODE_A, "stale_delta")]
    assert verdict.counts["deltas_stale"] == 1
    assert _negative(verdict)


def test_validate_deltas_accepts_empty_and_valid_entries() -> None:
    assert validate_deltas(_no_deltas()) == []
    change = Delta(**_valid_change_kwargs())
    fp = _fp("failed", "wrong_result")
    removal = Delta(
        lane="soft",
        case_id=NODE_B,
        phase="call",
        old_fp=fp,
        new_fp="absent",
        reason="covered removal",
        ttl=1,
    )
    addition = Delta(
        lane="soft",
        case_id=NODE_C,
        phase="call",
        old_fp="absent",
        new_fp=_fp("passed"),
        reason="covered addition",
        ttl=1,
    )
    assert (
        validate_deltas(RotationDeltas(version=FP_VERSION, entries=(change, removal, addition)))
        == []
    )


def test_validate_deltas_rejects_both_absent() -> None:
    kwargs = _valid_change_kwargs()
    kwargs["old_fp"] = "absent"
    kwargs["new_fp"] = "absent"
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert "shape" in "\n".join(errors)


def test_validate_deltas_rejects_noop_change() -> None:
    kwargs = _valid_change_kwargs()
    kwargs["new_fp"] = kwargs["old_fp"]
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert "single-axis" in "\n".join(errors)


def test_validate_deltas_rejects_multi_axis_change() -> None:
    kwargs = _valid_change_kwargs()
    kwargs["new_fp"] = _fp("failed", "bad_signature", "fail", "crypto", "CKR_OK", "CKR_OTHER", "")
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert "single-axis" in "\n".join(errors)


@pytest.mark.parametrize(
    ("field", "bad", "tag"),
    [
        ("ttl", 0, "ttl"),
        ("reason", "", "reason"),
        ("case_id", "tests/*", "identity"),
        ("phase", "{when}", "identity"),
        ("lane", "", "identity"),
        ("old_fp", ("failed",) * 6, "shape"),
        ("old_fp", ("bogus", "", "", "", "", "", ""), "shape"),
        ("old_fp", ["failed", "", "", "", "", "", ""], "shape"),
        ("new_fp", "absent ", "shape"),
    ],
)
def test_validate_deltas_rejects_malformed(field: str, bad: Any, tag: str) -> None:
    kwargs = _valid_change_kwargs()
    kwargs[field] = bad
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert tag in "\n".join(errors)


# --- fix round 1: coverage excuses disposition, never instability (F1) --------


def _reason_only_delta(old_fp: tuple[str, ...], new_fp: tuple[str, ...]) -> RotationDeltas:
    """Build the matching single-axis (reason-only) change-delta for NODE_A."""
    assert sum(1 for old, new in zip(old_fp, new_fp) if old != new) == 1
    return RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_A,
                phase="call",
                old_fp=old_fp,
                new_fp=new_fp,
                reason="oracle fix rotates the failure reason",
                ttl=1,
            ),
        ),
    )


def test_delta_covered_key_still_flags_attempt_instability() -> None:
    """F1 probe (a): [fail x3] vs [pass,pass,fail] + matching delta -> unstable."""
    base_rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=n, attempts_total=3, reason="wrong_result")
        for n in (1, 2, 3)
    ]
    cand_rows = [
        _hb_row(NODE_A, Outcome.PASSED, attempt=1, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
        _hb_row(NODE_A, Outcome.FAILED, attempt=3, attempts_total=3, reason="bad_signature"),
    ]
    base = (_hb_header(base_rows), base_rows)
    cand = (_hb_header(cand_rows), cand_rows)
    deltas = _reason_only_delta(fingerprint(base_rows[0]), fingerprint(cand_rows[2]))
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert verdict.counts["deltas_applied"] == 1
    assert verdict.unstable == [f"{NODE_A}::call:attempts"]
    assert _negative(verdict)


def test_delta_covered_first_attempt_flip_still_unstable() -> None:
    """F1 probe (b): a first-attempt flip under a matching delta still gates red."""
    base_rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=n, attempts_total=3, reason="wrong_result")
        for n in (1, 2, 3)
    ]
    cand_rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=1, attempts_total=3, reason="bad_signature"),
        _hb_row(NODE_A, Outcome.PASSED, attempt=2, attempts_total=3),
        _hb_row(NODE_A, Outcome.PASSED, attempt=3, attempts_total=3),
    ]
    base = (_hb_header(base_rows), base_rows)
    cand = (_hb_header(cand_rows), cand_rows)
    deltas = _reason_only_delta(fingerprint(base_rows[0]), fingerprint(cand_rows[0]))
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert verdict.counts["deltas_applied"] == 1
    assert verdict.unstable == [f"{NODE_A}::call:first_attempt"]
    assert _negative(verdict)


def test_delta_covered_attempt_count_change_still_unstable() -> None:
    """F1 probe (c): a 1->3 attempt-count change under a matching delta is unstable."""
    base_rows = [_hb_row(NODE_A, Outcome.FAILED, reason="wrong_result")]
    cand_rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=n, attempts_total=3, reason="bad_signature")
        for n in (1, 2, 3)
    ]
    base = (_hb_header(base_rows), base_rows)
    cand = (_hb_header(cand_rows), cand_rows)
    deltas = _reason_only_delta(fingerprint(base_rows[0]), fingerprint(cand_rows[0]))
    assert validate_deltas(deltas) == []
    verdict = _compare(base, cand, deltas)
    assert verdict.counts["deltas_applied"] == 1
    assert verdict.unstable == [f"{NODE_A}::call:attempts"]
    assert _negative(verdict)


# --- fix round 1: R22 rename boundary + quorum-boundary + TTL pins ------------


def test_split_delete_add_pair_is_independent_not_rename() -> None:
    """R22 pin: delete+add with DIFFERING fps are independent covered ops (green)."""
    base_rows = [_hb_row(NODE_A, Outcome.FAILED, reason="wrong_result")]
    cand_rows = [_hb_row(NODE_B, Outcome.FAILED, reason="bad_signature")]
    old_fp = fingerprint(base_rows[0])
    new_fp = fingerprint(cand_rows[0])
    assert old_fp != new_fp
    deltas = RotationDeltas(
        version=FP_VERSION,
        entries=(
            Delta(
                lane="soft",
                case_id=NODE_A,
                phase="call",
                old_fp=old_fp,
                new_fp="absent",
                reason="old case deleted",
                ttl=1,
            ),
            Delta(
                lane="soft",
                case_id=NODE_B,
                phase="call",
                old_fp="absent",
                new_fp=new_fp,
                reason="new case added",
                ttl=1,
            ),
        ),
    )
    assert validate_deltas(deltas) == []
    verdict = _compare(
        (_hb_header(base_rows), base_rows), (_hb_header(cand_rows), cand_rows), deltas
    )
    assert verdict.regressions == []
    assert verdict.unstable == []
    assert verdict.counts["deltas_applied"] == 2
    assert not _negative(verdict)


def test_quorum_exact_two_thirds_boundary_satisfied() -> None:
    """Quorum pin: top fraction exactly 2/3 meets a 2/3 quorum (bare disagree)."""
    rows = [
        _hb_row(NODE_A, Outcome.FAILED, attempt=1, attempts_total=3, reason="r"),
        _hb_row(NODE_A, Outcome.FAILED, attempt=2, attempts_total=3, reason="r"),
        _hb_row(NODE_A, Outcome.PASSED, attempt=3, attempts_total=3),
    ]
    policy = QuorumPolicy(min_repeats=3, quorum_frac=2 / 3, disagree_is_unstable=False)
    _, findings = combine_attempts(rows, policy)
    assert findings == ["disagree"]
    # The same split just below the boundary is unstable, not merely disagreeing.
    strict = QuorumPolicy(min_repeats=3, quorum_frac=0.67, disagree_is_unstable=False)
    _, strict_findings = combine_attempts(rows, strict)
    assert strict_findings == ["unstable"]


@pytest.mark.parametrize("ttl", [True, 1.0, 2])
def test_validate_deltas_rejects_non_unit_ttl_strictly(ttl: Any) -> None:
    """Nit pin (validate layer): ttl must be the int 1 -- bool/float/2 rejected."""
    kwargs = _valid_change_kwargs()
    kwargs["ttl"] = ttl
    errors = validate_deltas(RotationDeltas(version=FP_VERSION, entries=(Delta(**kwargs),)))
    assert errors
    assert "ttl" in "\n".join(errors)
