"""F11 slice B: classification-observability wiring through `core.merge`.

Covers the merge-specific behaviour the shared contract calls out explicitly:
pooled quality regenerated from the merged raw stream (never summed per-shard
quality.json counts), missing-shard partial state, and the plan's specific
merge-ordering regression -- proving repair (RV-trace promotion) never replaces the
authoritative stream classification observability is read from.

See ``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.core.file_runner import extract_quality_report_evidence_from_jsonl
from pkcs11_check.core.merge import _promote_rv_traces_to_outcome_reports, merge_shard_dirs

_RV_TRACE = [
    {"i": 0, "fn": "C_GetSessionInfo", "mech": None, "rv": 48, "rv_name": "CKR_DEVICE_ERROR"}
]


def _write_shard(d: Path, units: list[dict[str, Any]], summary: dict[str, int], lines: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "results.json").write_text(
        json.dumps(
            {"tool": "pkcs11-check", "kind": "test-run", "summary": summary, "units": units}
        ),
        encoding="utf-8",
    )
    (d / "report.jsonl").write_text(lines, encoding="utf-8")


def _unclassified_report(nodeid: str) -> str:
    return json.dumps(
        {
            "$report_type": "TestReport",
            "nodeid": nodeid,
            "when": "call",
            "outcome": "failed",
            "user_properties": [
                ["pkcs11_classification", [{"reason": "unclassified", "outcome": "fail"}]]
            ],
        }
    )


def _needs_promotion_reports(nodeid: str) -> list[str]:
    """A call+teardown pair that `_promote_rv_traces_to_outcome_reports` rewrites in place."""
    return [
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": nodeid,
                "when": "call",
                "outcome": "failed",
                "user_properties": [],
            }
        ),
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": nodeid,
                "when": "teardown",
                "outcome": "passed",
                "user_properties": [["pkcs11_rv_trace", _RV_TRACE]],
            }
        ),
    ]


# --------------------------------------------------------------------------- #
# Pooled regeneration from the merged raw stream (never summed shard counts)
# --------------------------------------------------------------------------- #


def test_pooled_observability_regenerates_from_raw_sources_not_summed_shard_quality(
    tmp_path: Path,
) -> None:
    """No shard ever writes its own quality.json here -- pooled counts can only come from
    re-reading the raw per-shard report.jsonl streams, never from summing nonexistent
    per-shard quality.json artifacts."""
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "failed"}],
        summary={"passed": 0, "failed": 1},
        lines=_unclassified_report("a.py::t1") + "\n",
    )
    _write_shard(
        s1,
        units=[{"target": "b.py", "status": "failed"}],
        summary={"passed": 0, "failed": 2},
        lines=_unclassified_report("b.py::t1") + "\n" + _unclassified_report("b.py::t2") + "\n",
    )
    assert not (s0 / "quality.json").exists()
    assert not (s1 / "quality.json").exists()

    out = tmp_path / "merged"
    merge_shard_dirs([s0, s1], out)

    quality = json.loads((out / "quality.json").read_text(encoding="utf-8"))
    block = quality["classification_observability"]
    assert block["status"] == "complete"
    assert block["expected_sources"] == 2
    assert block["readable_sources"] == 2
    unclassified = block["unclassified"]
    assert unclassified is not None
    assert unclassified["occurrences"] == 3
    assert unclassified["unique_testcases"] == 3


# --------------------------------------------------------------------------- #
# Missing-shard partial state
# --------------------------------------------------------------------------- #


def test_missing_shard_report_jsonl_marks_status_partial(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "failed"}],
        summary={"passed": 0, "failed": 1},
        lines=_unclassified_report("a.py::t1") + "\n",
    )
    # shard1 has a results.json but its report.jsonl is deleted post-write, simulating a
    # genuinely missing raw source for that declared shard.
    _write_shard(
        s1,
        units=[{"target": "b.py", "status": "failed"}],
        summary={"passed": 0, "failed": 1},
        lines=_unclassified_report("b.py::t1") + "\n",
    )
    (s1 / "report.jsonl").unlink()

    out = tmp_path / "merged"
    merge_shard_dirs([s0, s1], out)

    block = json.loads((out / "quality.json").read_text(encoding="utf-8"))[
        "classification_observability"
    ]
    assert block["status"] == "partial"
    assert block["missing_sources"] == 1
    assert block["expected_sources"] == 2
    # The one readable shard's occurrence still counts -- a missing shard is a lower
    # bound, never a reason to drop what IS readable.
    unclassified = block["unclassified"]
    assert unclassified is not None
    assert unclassified["lower_bound"] is True
    assert unclassified["occurrences"] == 1


# --------------------------------------------------------------------------- #
# The merge-ordering regression: repair must never replace the authoritative stream
# --------------------------------------------------------------------------- #


def test_malformed_json_plus_occurrence_plus_promotable_trace_stays_partial_and_keeps_occurrence(
    tmp_path: Path,
) -> None:
    """The scenario the whole slice exists to get right: a shard's raw report.jsonl mixes a
    malformed JSON line, a valid `unclassified` classification occurrence, AND a
    teardown-only RV trace that IS promotable onto its sibling failed call report. Merging
    must still report `partial` (the malformed line is real evidence, not silently
    repaired away) while STILL surfacing the readable occurrence -- proving classification
    observability was read from the untouched raw shard file, not from whatever
    `_promote_rv_traces_to_outcome_reports` rewrote."""
    s0 = tmp_path / "shard0"
    lines = [
        "{this is not valid json",
        _unclassified_report("a.py::test_unclassified"),
        *_needs_promotion_reports("a.py::test_needs_trace"),
    ]
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "failed"}],
        summary={"passed": 0, "failed": 2},
        lines="\n".join(lines) + "\n",
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    quality = json.loads((out / "quality.json").read_text(encoding="utf-8"))
    block = quality["classification_observability"]
    assert block["status"] == "partial"
    assert block["malformed_records"] >= 1
    unclassified = block["unclassified"]
    assert unclassified is not None
    assert unclassified["lower_bound"] is True
    assert unclassified["occurrences"] == 1
    assert len(unclassified["samples"]) == 1
    assert unclassified["samples"][0]["nodeid"] == "a.py::test_unclassified"

    # Confirm the scenario really did trigger a repair rewrite of the merged output (so the
    # "partial" status above is not merely because promotion never touched anything).
    merged_records = [
        json.loads(line) for line in (out / "report.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    call_report = next(
        r
        for r in merged_records
        if r.get("nodeid") == "a.py::test_needs_trace" and r.get("when") == "call"
    )
    assert dict(call_report["user_properties"])["pkcs11_rv_trace"] == _RV_TRACE
    # And the malformed line is indeed gone from the rewritten merged output -- the very
    # loss that would make reading observability from `merged_report` wrong.
    assert len(merged_records) == 3


def test_reading_observability_from_the_repaired_merged_file_would_be_wrong(
    tmp_path: Path,
) -> None:
    """Direct demonstration of why merge.py reads observability from the untouched
    per-shard files rather than the post-repair concatenated `report.jsonl`:
    `_promote_rv_traces_to_outcome_reports`'s rewrite pass silently drops any line it
    cannot JSON-decode, so evidence captured AFTER it would misreport `complete`."""
    path = tmp_path / "report.jsonl"
    lines = [
        "{this is not valid json",
        *_needs_promotion_reports("a.py::test_needs_trace"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    before = extract_quality_report_evidence_from_jsonl([path])
    assert before.status == "partial"
    assert before.malformed_records == 1

    _promote_rv_traces_to_outcome_reports(path)

    after = extract_quality_report_evidence_from_jsonl([path])
    assert after.status == "complete"
    assert after.malformed_records == 0
