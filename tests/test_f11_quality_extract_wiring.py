"""F11 slice B: additive phase/attempt/duplicate metadata on `report.extract.extract_groups`,
and the single-source CLI wiring in `cli.test_cmd._assemble_json_artifacts_from_jsonl`.

``extract_groups`` now reads occurrences via the shared
``core.report_log.iter_classification_occurrences`` iterator instead of re-deriving the parse;
these tests pin that the existing group keys/counts stay exactly as before while the new
metadata fields are populated correctly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.cli.test_cmd import _assemble_json_artifacts_from_jsonl
from pkcs11_check.report.extract import extract_groups


def _classification(**over: object) -> dict[str, object]:
    rec: dict[str, object] = {
        "reason": "accepted_invalid",
        "outcome": "fail",
        "severity": "CRITICAL",
        "kind": "crypto",
        "label": "RSA:decrypt",
        "summary": "RSA:decrypt: expected reject, got CKR_OK",
        "operation": "C_Decrypt",
        "mechanism": "CKM_RSA_PKCS",
        "expected_ckr": ["CKR_ENCRYPTED_DATA_INVALID"],
        "actual_ckr": "CKR_OK",
        "spec_ref": "PKCS#11 v3.2 §6.13",
        "source": "wycheproof",
        "vector_id": None,
        "detail": None,
        "schema": 1,
    }
    rec.update(over)
    return rec


def _test_report(
    nodeid: str, records: list[dict[str, object]], *, when: str = "call"
) -> dict[str, object]:
    return {
        "$report_type": "TestReport",
        "when": when,
        "nodeid": nodeid,
        "outcome": "failed",
        "user_properties": [["pkcs11_classification", records]],
    }


def _marker(target: str, attempt: int) -> dict[str, object]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


# --------------------------------------------------------------------------- #
# extract_groups: existing keys/counts unchanged, new metadata additive
# --------------------------------------------------------------------------- #


def test_existing_group_keys_and_count_are_unchanged(tmp_path: Path) -> None:
    """Pins the pre-existing contract: same GroupKey grouping, same `count`, same `nodeids`."""
    path = tmp_path / "report.jsonl"
    r1 = _classification(vector_id="tc101")
    r2 = _classification(vector_id="tc202")
    lines = [
        _test_report("tests/test_rsa.py::test_a", [r1]),
        _test_report("tests/test_rsa.py::test_b", [r2]),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])

    assert len(groups) == 1
    grp = groups[0]
    assert grp["count"] == 2
    assert grp["reason"] == "accepted_invalid"
    assert "tc101" in grp["vector_ids"]
    assert "tc202" in grp["vector_ids"]


def test_phase_attempt_and_duplicate_metadata_are_populated(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    classification = _classification(vector_id="tc1")
    nodeid = "tests/test_rsa.py::test_case"
    lines: list[dict[str, object]] = [
        _marker(nodeid, 0),
        _test_report(nodeid, [classification], when="call"),
        _test_report(nodeid, [classification], when="call"),  # exact duplicate at same marker
        _marker(nodeid, 1),
        _test_report(nodeid, [classification], when="teardown"),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])

    assert len(groups) == 1
    grp = groups[0]
    # Existing count contract: unaffected by duplicate tracking (never deduplicated).
    assert grp["count"] == 3
    assert grp["phase_counts"] == {"call": 2, "teardown": 1}
    assert grp["target_counts"] == {nodeid: 3}
    # N14: attempt_counts keys are ints in memory (unified with the Counter[int]
    # convention in core/_report_records.py / report_log.py); JSON serialization at
    # render time (report.__main__._write_group_lines -> json.dumps) is what turns
    # them into string keys, not this accumulation step.
    assert grp["attempt_counts"] == {0: 2, 1: 1}
    assert grp["exact_duplicate_count"] == 1
    assert grp["unattributed_count"] == 0


def test_attempt_counts_keys_are_int_not_str(tmp_path: Path) -> None:
    """N14: unify attempt_counts key type across layers.

    ``report.extract`` used to stringify keys at accumulation time
    (``group["attempt_counts"][str(attempt)]``) while
    ``core._report_records.extract_quality_report_evidence_from_jsonl`` /
    ``report_log.QualityReportEvidence.attempt_counts`` keep ``Counter[int]`` /
    ``Mapping[int, int]`` until the quality_audit.py render step. Both were
    JSON-equal after ``json.dumps`` (JSON object keys are always strings), but
    an in-memory comparison between the two layers would mismatch on key type.
    This pins the side that changed: report.extract now keeps int keys too,
    stringifying only implicitly at the final json.dumps render boundary
    (report/__main__.py's `json.dumps(group, ...)`), matching the
    core._report_records/report_log convention instead of inventing a second one.
    """
    path = tmp_path / "report.jsonl"
    classification = _classification(vector_id="tc1")
    nodeid = "tests/test_rsa.py::test_case"
    lines: list[dict[str, object]] = [
        _marker(nodeid, 0),
        _test_report(nodeid, [classification], when="call"),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])

    attempt_counts = groups[0]["attempt_counts"]
    assert attempt_counts == {0: 1}
    assert all(isinstance(k, int) for k in attempt_counts)
    # Still JSON-equal to the old stringified shape after serialization -- the render
    # boundary, not this accumulation step, is where keys become strings.
    assert json.loads(json.dumps(attempt_counts)) == {"0": 1}


def test_unmarked_occurrence_is_unattributed_not_reconstructed(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    path.write_text(
        json.dumps(_test_report("t.py::a", [_classification()])) + "\n", encoding="utf-8"
    )
    groups = extract_groups(path, crashes=[])
    assert groups[0]["unattributed_count"] == 1
    assert groups[0]["target_counts"] == {}
    assert groups[0]["attempt_counts"] == {}


def test_crash_and_teardown_finalize_findings_still_group_as_before(tmp_path: Path) -> None:
    """Non-classification findings (crashes, C_Finalize) still ingest fine and count as
    unattributed -- they never carried marker provenance to begin with."""
    path = tmp_path / "report.jsonl"
    path.write_text(
        json.dumps({"$report_type": "TeardownFinalize", "outcome": "timeout"}) + "\n",
        encoding="utf-8",
    )
    groups = extract_groups(path, crashes=[])
    assert len(groups) == 1
    assert groups[0]["reason"] == "self_contradiction"
    assert groups[0]["unattributed_count"] == 1


# --------------------------------------------------------------------------- #
# CLI wiring: the single raw report.jsonl is the declared authoritative source
# --------------------------------------------------------------------------- #


def test_assemble_json_artifacts_wires_evidence_from_the_single_raw_source(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw.jsonl"
    lines: list[dict[str, Any]] = [
        {"$report_type": "SessionStart"},
        _marker("t.py", 0),
        _test_report(
            "t.py::test_a",
            [{"reason": "unclassified", "outcome": "fail", "severity": "HIGH"}],
        ),
        {"$report_type": "SessionFinish", "exitstatus": 1},
    ]
    raw.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    _assemble_json_artifacts_from_jsonl(raw, str(tmp_path / "results.json"), {})

    quality = json.loads((tmp_path / "quality.json").read_text(encoding="utf-8"))
    block = quality["classification_observability"]
    assert block["status"] == "complete"
    assert block["expected_sources"] == 1
    unclassified = block["unclassified"]
    assert unclassified is not None
    assert unclassified["occurrences"] == 1
    assert unclassified["target_counts"] == {"t.py": 1}
