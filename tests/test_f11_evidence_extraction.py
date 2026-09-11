"""F11 slice A: raw classification-occurrence evidence extraction.

Covers ``core.report_log.iter_classification_occurrences`` /
``user_property_values`` and ``core._report_records.extract_quality_report_evidence_from_jsonl``
against the binding contract in
``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md``.

These tests exercise BEHAVIOUR (raw occurrence counting/attribution/status), not just
that the functions exist -- each asserts a length/value that can only hold if the
production code actually implements the contract's counting semantics.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core._report_records import (
    extract_quality_report_evidence_from_jsonl,
    extract_quality_report_records_from_jsonl,
)
from pkcs11_check.core.report_log import (
    ClassificationOccurrence,
    QualityReportEvidence,
    iter_classification_occurrences,
    user_property,
    user_property_values,
)


def _hard_fail_on_xfail(callable_: Any, *args: Any, **kwargs: Any) -> Any:
    """Run ``callable_`` and turn an escaping XFailed into a hard failure.

    pytest exits 0 on an uncaught xfail, so a helper that can raise ``pytest.xfail()``
    before this test's real assertions run would make a red run look green. None of the
    helpers below call ``pytest.xfail``/``pytest.skip``, but this wrapper is kept as the
    documented guard the task brief requires and is cheap insurance if that ever changes.
    """
    try:
        return callable_(*args, **kwargs)
    except pytest.xfail.Exception as exc:  # pragma: no cover - defensive
        pytest.fail(f"escaping XFailed treated as a hard failure: {exc}")


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _unclassified(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"reason": "unclassified", "outcome": "fail", "severity": "HIGH"}
    base.update(overrides)
    return base


def _test_report(
    nodeid: str,
    when: str,
    *,
    outcome: str = "failed",
    classifications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": outcome,
    }
    if classifications is not None:
        record["user_properties"] = [["pkcs11_classification", classifications]]
    return record


# ---------------------------------------------------------------------------
# user_property_values: the all-values accessor
# ---------------------------------------------------------------------------


def test_user_property_values_returns_every_matching_pair() -> None:
    record = {
        "user_properties": [
            ["pkcs11_classification", ["a"]],
            ["other", ["x"]],
            ["pkcs11_classification", ["b"]],
        ]
    }
    assert user_property_values(record, "pkcs11_classification") == [["a"], ["b"]]
    # user_property() (first match only) must stay undercount-prone by contrast --
    # documents why the new accessor exists rather than reusing it.
    assert user_property(record, "pkcs11_classification") == ["a"]


def test_user_property_values_empty_when_absent() -> None:
    assert user_property_values({}, "pkcs11_classification") == []
    assert user_property_values({"user_properties": None}, "pkcs11_classification") == []


# ---------------------------------------------------------------------------
# iter_classification_occurrences: the shared phase/attempt iterator
# ---------------------------------------------------------------------------


def test_deliberate_unclassified_occurrence_is_counted() -> None:
    records = [
        _marker("t.py::test_a", 0),
        _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
    ]
    occurrences = list(iter_classification_occurrences(records))
    assert len(occurrences) == 1
    occ = occurrences[0]
    assert occ.reason == "unclassified"
    assert occ.nodeid == "t.py::test_a"
    assert occ.canonical_nodeid == "t.py::test_a"
    assert occ.phase == "call"
    assert occ.target == "t.py::test_a"
    assert occ.attempt == 0


def test_setup_call_teardown_preserved_separately() -> None:
    records = [
        _marker("t.py::test_a", 0),
        _test_report("t.py::test_a", "setup", classifications=[_unclassified()]),
        _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
        _test_report("t.py::test_a", "teardown", classifications=[_unclassified()]),
    ]
    occurrences = list(iter_classification_occurrences(records))
    assert len(occurrences) == 3
    phases = sorted(occ.phase for occ in occurrences)
    assert phases == ["call", "setup", "teardown"]


def test_retry_pass_does_not_erase_earlier_occurrence() -> None:
    records = [
        _marker("t.py::test_a", 0),
        _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
        _marker("t.py::test_a", 1),
        _test_report("t.py::test_a", "call", outcome="passed", classifications=None),
    ]
    occurrences = list(iter_classification_occurrences(records))
    assert len(occurrences) == 1
    assert occurrences[0].attempt == 0
    assert occurrences[0].target == "t.py::test_a"


def test_file_level_and_per_test_target_are_one_testcase_two_occurrences() -> None:
    records = [
        _marker("t.py", 0),
        _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
        _marker("t.py::test_a", 0),
        _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
    ]
    occurrences = list(iter_classification_occurrences(records))
    assert len(occurrences) == 2
    canonical_nodeids = {occ.canonical_nodeid for occ in occurrences}
    assert canonical_nodeids == {"t.py::test_a"}
    targets = sorted(occ.target for occ in occurrences if occ.target is not None)
    assert targets == ["t.py", "t.py::test_a"]


def test_unmarked_shard_does_not_inherit_prior_target() -> None:
    records = [
        {"$report_type": "SessionStart"},
        _marker("a.py", 0),
        _test_report("a.py::test_a", "call", classifications=[_unclassified()]),
        {"$report_type": "SessionStart"},
        _test_report("a.py::test_a", "call", classifications=[_unclassified()]),
    ]
    occurrences = list(iter_classification_occurrences(records))
    assert len(occurrences) == 2
    assert occurrences[0].target == "a.py"
    assert occurrences[0].attempt == 0
    assert occurrences[1].target is None
    assert occurrences[1].attempt is None


def test_same_nodeid_in_different_iterator_calls_is_distinct_scope() -> None:
    """A separate call (separate provider/report scope) never shares state."""
    records = [
        _marker("t.py::test_a", 0),
        _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
    ]
    first = list(iter_classification_occurrences(records))
    second = list(iter_classification_occurrences(records))
    assert len(first) == 1
    assert len(second) == 1


def test_multiple_classification_properties_on_one_record_all_inspected() -> None:
    record = {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "failed",
        "user_properties": [
            ["pkcs11_classification", [_unclassified(label="first")]],
            ["pkcs11_classification", [_unclassified(label="second")]],
        ],
    }
    records = [_marker("t.py::test_a", 0), record]
    occurrences = list(iter_classification_occurrences(records))
    assert len(occurrences) == 2
    assert {occ.property_index for occ in occurrences} == {0, 1}
    assert sorted(occ.classification["label"] for occ in occurrences) == ["first", "second"]


def test_malformed_classification_entry_is_skipped_but_readable_ones_kept() -> None:
    record = {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "failed",
        "user_properties": [
            ["pkcs11_classification", ["not-a-dict", _unclassified(), {"kind": "no_reason_field"}]],
        ],
    }
    records = [_marker("t.py::test_a", 0), record]
    malformed = 0

    def _on_malformed_entry() -> None:
        nonlocal malformed
        malformed += 1

    occurrences = list(
        iter_classification_occurrences(records, on_malformed_entry=_on_malformed_entry)
    )
    assert len(occurrences) == 1
    assert occurrences[0].reason == "unclassified"
    assert malformed == 2


def test_malformed_classification_property_value_is_skipped() -> None:
    record = {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "failed",
        "user_properties": [["pkcs11_classification", "not-a-list"]],
    }
    calls = []
    occurrences = list(
        iter_classification_occurrences([record], on_malformed_property=lambda: calls.append(1))
    )
    assert occurrences == []
    assert calls == [1]


def test_malformed_marker_resets_and_signals() -> None:
    records = [
        _marker("a.py", 0),
        {"$report_type": "IsolatedUnitReport", "target": None, "attempt": 0},
        _test_report("a.py::test_a", "call", classifications=[_unclassified()]),
    ]
    calls = []
    occurrences = list(
        iter_classification_occurrences(records, on_malformed_marker=lambda: calls.append(1))
    )
    assert calls == [1]
    assert len(occurrences) == 1
    assert occurrences[0].target is None
    assert occurrences[0].attempt is None


def test_reason_filter_selects_only_matching_reason() -> None:
    records = [
        _marker("t.py::test_a", 0),
        _test_report(
            "t.py::test_a",
            "call",
            classifications=[_unclassified(), {"reason": "wrong_result", "outcome": "fail"}],
        ),
    ]
    occurrences = list(iter_classification_occurrences(records, reason_filter="unclassified"))
    assert len(occurrences) == 1
    assert occurrences[0].reason == "unclassified"


def test_bounded_occurrence_retains_no_rv_trace_or_timing_fields() -> None:
    record = {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "failed",
        "duration": 12.34,
        "user_properties": [
            ["pkcs11_rv_trace", [{"fn": "C_Decrypt", "rv": "CKR_OK"}] * 500],
            ["pkcs11_classification", [_unclassified()]],
        ],
    }
    occurrences = list(iter_classification_occurrences([_marker("t.py::test_a", 0), record]))
    assert len(occurrences) == 1
    assert occurrences[0].classification == _unclassified()
    assert "duration" not in occurrences[0].classification
    payload = dataclasses.asdict(occurrences[0])
    assert "rv_trace" not in json.dumps(payload)


# ---------------------------------------------------------------------------
# extract_quality_report_evidence_from_jsonl: source status + aggregate evidence
# ---------------------------------------------------------------------------


def test_evidence_complete_status_for_one_clean_source(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    _write_jsonl(
        path,
        [
            _marker("t.py::test_a", 0),
            _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
        ],
    )
    evidence = _hard_fail_on_xfail(extract_quality_report_evidence_from_jsonl, [path])
    assert isinstance(evidence, QualityReportEvidence)
    assert evidence.status == "complete"
    assert evidence.status_reasons == ()
    assert evidence.expected_sources == 1
    assert evidence.readable_sources == 1
    assert evidence.missing_sources == 0
    unclassified = evidence.unclassified
    assert unclassified is not None
    assert unclassified.occurrences == 1
    assert unclassified.lower_bound is False
    assert unclassified.unique_testcases == 1
    assert unclassified.phase_counts == {"call": 1}


def test_evidence_malformed_json_line_retains_prefix_and_is_partial(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    path.write_text(
        json.dumps(_marker("t.py::test_a", 0))
        + "\n"
        + json.dumps(_test_report("t.py::test_a", "call", classifications=[_unclassified()]))
        + "\n"
        + "{not valid json\n"
        + json.dumps(_test_report("t.py::test_b", "call", classifications=[_unclassified()]))
        + "\n",
        encoding="utf-8",
    )
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.status == "partial"
    assert evidence.malformed_records == 1
    assert evidence.unclassified is not None
    # both readable occurrences survive the malformed line between them
    assert evidence.unclassified.occurrences == 2
    assert evidence.unclassified.lower_bound is True


def test_evidence_malformed_classification_object_is_partial(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    record = {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "failed",
        "user_properties": [["pkcs11_classification", ["garbage", _unclassified()]]],
    }
    _write_jsonl(path, [_marker("t.py::test_a", 0), record])
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.status == "partial"
    assert evidence.malformed_entries == 1
    assert evidence.unclassified is not None
    assert evidence.unclassified.occurrences == 1
    assert evidence.unclassified.lower_bound is True


def test_evidence_invalid_utf8_retains_readable_prefix_and_is_partial(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    good_line = (
        json.dumps(_marker("t.py::test_a", 0))
        + "\n"
        + json.dumps(_test_report("t.py::test_a", "call", classifications=[_unclassified()]))
        + "\n"
    ).encode("utf-8")
    path.write_bytes(good_line + b"\xff\xfe not valid utf-8 at all\n")
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.status == "partial"
    assert evidence.malformed_records == 1
    assert evidence.unclassified is not None
    assert evidence.unclassified.occurrences == 1
    assert evidence.unclassified.lower_bound is True


def test_evidence_truncated_readable_prefix_is_partial(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    good = json.dumps(_marker("t.py::test_a", 0)) + "\n"
    good += (
        json.dumps(_test_report("t.py::test_a", "call", classifications=[_unclassified()])) + "\n"
    )
    truncated_tail = '{"$report_type": "TestReport", "nodeid": "t.py::test_b", "when": "call"'
    path.write_text(good + truncated_tail, encoding="utf-8")
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.status == "partial"
    assert evidence.malformed_records == 1
    assert evidence.unclassified is not None
    assert evidence.unclassified.occurrences == 1


def test_evidence_missing_shard_is_partial_with_lower_bound(tmp_path: Path) -> None:
    good_path = tmp_path / "report.jsonl"
    _write_jsonl(
        good_path,
        [
            _marker("t.py::test_a", 0),
            _test_report("t.py::test_a", "call", classifications=[_unclassified()]),
        ],
    )
    missing_path = tmp_path / "shard-2-report.jsonl"
    evidence = extract_quality_report_evidence_from_jsonl([good_path, missing_path])
    assert evidence.status == "partial"
    assert evidence.expected_sources == 2
    assert evidence.readable_sources == 1
    assert evidence.missing_sources == 1
    assert evidence.unclassified is not None
    assert evidence.unclassified.lower_bound is True
    assert evidence.unclassified.occurrences == 1


def test_evidence_no_inspectable_input_is_unavailable_with_null_block(tmp_path: Path) -> None:
    missing_path = tmp_path / "does-not-exist.jsonl"
    evidence = extract_quality_report_evidence_from_jsonl([missing_path])
    assert evidence.status == "unavailable"
    assert evidence.unclassified is None
    assert evidence.readable_sources == 0
    assert evidence.missing_sources == 1


def test_evidence_empty_declared_sources_is_unavailable(tmp_path: Path) -> None:
    evidence = extract_quality_report_evidence_from_jsonl([])
    assert evidence.status == "unavailable"
    assert evidence.unclassified is None
    assert evidence.expected_sources == 0


def test_unavailable_never_serializes_as_zero(tmp_path: Path) -> None:
    """The single worst failure mode: unavailable must be null, never a fabricated zero."""
    missing_path = tmp_path / "does-not-exist.jsonl"
    evidence = extract_quality_report_evidence_from_jsonl([missing_path])
    payload = dataclasses.asdict(evidence)
    assert payload["unclassified"] is None
    # A block that WAS inspectable, by contrast, is a real object (even if its own count
    # happens to be zero for a different reason) -- proving the two are structurally
    # distinguishable and this suite would fail if unavailable ever produced counts.
    good_path = tmp_path / "report.jsonl"
    _write_jsonl(good_path, [_marker("t.py::test_a", 0)])  # no classification at all
    zero_but_available = extract_quality_report_evidence_from_jsonl([good_path])
    assert zero_but_available.status == "complete"
    assert zero_but_available.unclassified is not None
    assert zero_but_available.unclassified.occurrences == 0


def test_evidence_exact_duplicate_flagged_but_still_counted(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    dup_record = _test_report("t.py::test_a", "call", classifications=[_unclassified()])
    _write_jsonl(path, [_marker("t.py::test_a", 0), dup_record, dup_record])
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.unclassified is not None
    assert evidence.unclassified.occurrences == 2
    assert evidence.unclassified.exact_duplicate_occurrences == 1


def test_evidence_unknown_provenance_never_flagged_as_duplicate(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    dup_record = _test_report("t.py::test_a", "call", classifications=[_unclassified()])
    # no preceding marker at all -> target/attempt unknown for both
    _write_jsonl(path, [dup_record, dup_record])
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.unclassified is not None
    assert evidence.unclassified.occurrences == 2
    assert evidence.unclassified.exact_duplicate_occurrences == 0
    assert evidence.unclassified.unattributed_occurrences == 2


def test_evidence_per_file_and_target_counts(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    _write_jsonl(
        path,
        [
            _marker("a.py::test_a", 0),
            _test_report("a.py::test_a", "call", classifications=[_unclassified()]),
            _marker("b.py::test_b", 0),
            _test_report("b.py::test_b", "call", classifications=[_unclassified()]),
        ],
    )
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.unclassified is not None
    assert evidence.unclassified.per_file_counts == {"a.py": 1, "b.py": 1}
    assert evidence.unclassified.target_counts == {"a.py::test_a": 1, "b.py::test_b": 1}
    assert evidence.unclassified.attempt_counts == {0: 2}


def test_evidence_unreadable_existing_source_does_not_inflate_readable_count(
    tmp_path: Path,
) -> None:
    """Minor 1: an existing-but-unreadable source must not count as readable.

    ``path.is_file()`` is true (the file exists) but the permission bits deny
    ``open()`` -- distinct from the missing-file case. The status/malformed
    handling this exercises (unavailable + malformed_records bump) was already
    correct; only ``readable_sources`` was wrong (it counted every is_file()
    path, even ones that then failed to open).
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root bypasses permission bits; cannot exercise an unreadable-but-existing")
    path = tmp_path / "unreadable.jsonl"
    _write_jsonl(path, [_marker("t.py::test_a", 0)])
    path.chmod(0o000)
    try:
        evidence = extract_quality_report_evidence_from_jsonl([path])
    finally:
        path.chmod(0o644)
    assert evidence.readable_sources == 0
    assert evidence.missing_sources == 0
    assert evidence.malformed_records == 1
    assert evidence.status == "unavailable"
    assert evidence.unclassified is None


def test_evidence_samples_are_bounded_but_totals_are_not(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    records: list[dict[str, Any]] = [_marker("t.py", 0)]
    for i in range(50):
        records.append(_test_report(f"t.py::test_{i}", "call", classifications=[_unclassified()]))
    _write_jsonl(path, records)
    evidence = extract_quality_report_evidence_from_jsonl([path])
    assert evidence.unclassified is not None
    assert evidence.unclassified.occurrences == 50
    assert len(evidence.unclassified.samples) < 50


# ---------------------------------------------------------------------------
# Compatibility wrapper: unchanged behaviour for extract_quality_report_records_from_jsonl
# ---------------------------------------------------------------------------

_COMPAT_FIXTURE: list[dict[str, Any]] = [
    {"$report_type": "SessionStart"},
    {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "passed",
        "duration": 0.01,
        "user_properties": [["pkcs11_classification", [_unclassified()]]],
    },
    {"$report_type": "SelectionReport", "deselected": []},
    {"$report_type": "SessionFinish", "exitstatus": 0},
]


def test_compat_wrapper_still_projects_and_drops_user_properties(tmp_path: Path) -> None:
    """The existing extractor must keep discarding user_properties (byte-identity guard).

    This is a slice-A-local sanity check; the authoritative byte-identity guard is
    tests/test_jsonl_streaming.py, which must keep passing unchanged (gate #2).
    """
    path = tmp_path / "report.jsonl"
    _write_jsonl(path, _COMPAT_FIXTURE)
    records = extract_quality_report_records_from_jsonl(path)
    assert len(records) == 2
    test_report = next(r for r in records if r["$report_type"] == "TestReport")
    assert test_report == {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "passed",
    }
    assert "user_properties" not in test_report
    assert "duration" not in test_report


def test_compat_wrapper_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert extract_quality_report_records_from_jsonl(tmp_path / "nope.jsonl") == []


def test_classification_occurrence_is_a_dataclass_with_documented_fields() -> None:
    field_names = {f.name for f in dataclasses.fields(ClassificationOccurrence)}
    assert field_names == {
        "source_index",
        "nodeid",
        "canonical_nodeid",
        "phase",
        "target",
        "attempt",
        "property_index",
        "occurrence_index",
        "reason",
        "classification",
    }
