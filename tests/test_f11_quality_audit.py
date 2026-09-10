"""F11 slice B: the `classification_observability` block in `build_quality_audit()`.

Covers ``core.quality_audit.build_quality_audit``/``_build_classification_observability``
against the binding contract in
``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md``.

These construct :class:`QualityReportEvidence`/:class:`UnclassifiedEvidence` directly (the
serializer's whole job is turning one of those into the artifact shape) rather than going
through JSONL fixtures -- that raw-extraction behaviour is slice A's, already covered by
``tests/test_f11_evidence_extraction.py``; this file is about the serialization contract only.
"""

from __future__ import annotations

from pkcs11_check.core.quality_audit import SCHEMA_VERSION, build_quality_audit
from pkcs11_check.core.report_log import (
    ClassificationOccurrence,
    QualityReportEvidence,
    UnclassifiedEvidence,
)

_RESULTS = {"summary": {"passed": 1, "failed": 1}, "units": []}


def _occurrence(**overrides: object) -> ClassificationOccurrence:
    base: dict[str, object] = {
        "source_index": 0,
        "nodeid": "tests/test_x.py::test_a",
        "canonical_nodeid": "tests/test_x.py::test_a",
        "phase": "call",
        "target": "tests/test_x.py",
        "attempt": 0,
        "property_index": 0,
        "occurrence_index": 0,
        "reason": "unclassified",
        "classification": {"reason": "unclassified", "outcome": "fail"},
    }
    base.update(overrides)
    return ClassificationOccurrence(**base)  # type: ignore[arg-type]


def _evidence(
    *,
    status: str = "complete",
    status_reasons: tuple[str, ...] = (),
    expected_sources: int = 1,
    readable_sources: int = 1,
    missing_sources: int = 0,
    malformed_records: int = 0,
    malformed_markers: int = 0,
    malformed_properties: int = 0,
    malformed_entries: int = 0,
    unclassified: UnclassifiedEvidence | None,
) -> QualityReportEvidence:
    return QualityReportEvidence(
        contract_version="1",
        status=status,  # type: ignore[arg-type]
        status_reasons=status_reasons,
        expected_sources=expected_sources,
        readable_sources=readable_sources,
        missing_sources=missing_sources,
        malformed_records=malformed_records,
        malformed_markers=malformed_markers,
        malformed_properties=malformed_properties,
        malformed_entries=malformed_entries,
        count_semantics="serialized_classification_occurrences",
        unclassified=unclassified,
    )


def _unclassified(**overrides: object) -> UnclassifiedEvidence:
    base: dict[str, object] = {
        "occurrences": 0,
        "lower_bound": False,
        "unique_testcases": 0,
        "exact_duplicate_occurrences": 0,
        "phase_counts": {},
        "target_counts": {},
        "attempt_counts": {},
        "unattributed_occurrences": 0,
        "per_file_counts": {},
        "samples": (),
    }
    base.update(overrides)
    return UnclassifiedEvidence(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Schema/versioning basics
# --------------------------------------------------------------------------- #


def test_quality_schema_version_unchanged_by_the_new_block() -> None:
    """Quality keeps schema_version "1"; the new block is separately versioned."""
    audit = build_quality_audit(results=_RESULTS)
    assert audit["schema_version"] == SCHEMA_VERSION == "1"
    assert audit["classification_observability"]["contract_version"] == "1"


def test_summary_never_gains_an_unclassified_key() -> None:
    """The overlapping serialized-occurrence measure must never land in `summary`."""
    evidence = _evidence(unclassified=_unclassified(occurrences=7))
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    assert "unclassified" not in audit["summary"]
    assert audit["classification_observability"]["unclassified"]["occurrences"] == 7


# --------------------------------------------------------------------------- #
# complete-zero vs unavailable/null vs partial/lower-bound
# --------------------------------------------------------------------------- #


def test_no_evidence_renders_unavailable_never_a_fabricated_zero() -> None:
    audit = build_quality_audit(results=_RESULTS)
    block = audit["classification_observability"]
    assert block["status"] == "unavailable"
    assert block["unclassified"] is None


def test_complete_zero_is_a_real_zero_not_unavailable() -> None:
    """A readable, empty raw stream is a genuine "0 occurrences", distinct from unavailable."""
    evidence = _evidence(status="complete", unclassified=_unclassified(occurrences=0))
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    block = audit["classification_observability"]
    assert block["status"] == "complete"
    assert block["unclassified"] is not None
    assert block["unclassified"]["occurrences"] == 0
    assert block["unclassified"]["lower_bound"] is False


def test_partial_status_marks_every_unclassified_count_as_a_lower_bound() -> None:
    evidence = _evidence(
        status="partial",
        status_reasons=("missing raw source(s): 1",),
        missing_sources=1,
        expected_sources=2,
        readable_sources=1,
        unclassified=_unclassified(occurrences=3, lower_bound=True, unique_testcases=2),
    )
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    block = audit["classification_observability"]
    assert block["status"] == "partial"
    assert block["status_reasons"] == ["missing raw source(s): 1"]
    assert block["missing_sources"] == 1
    assert block["unclassified"]["lower_bound"] is True
    assert block["unclassified"]["occurrences"] == 3


# --------------------------------------------------------------------------- #
# raw-vs-quality equality when complete
# --------------------------------------------------------------------------- #


def test_complete_evidence_counts_pass_through_unchanged() -> None:
    """When status is complete, the artifact's counts equal the raw evidence exactly."""
    occurrence = _occurrence()
    evidence = _evidence(
        status="complete",
        unclassified=_unclassified(
            occurrences=1,
            unique_testcases=1,
            exact_duplicate_occurrences=0,
            phase_counts={"call": 1},
            target_counts={"tests/test_x.py": 1},
            attempt_counts={0: 1},
            unattributed_occurrences=0,
            per_file_counts={"tests/test_x.py": 1},
            samples=(occurrence,),
        ),
    )
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    unclassified = audit["classification_observability"]["unclassified"]
    assert unclassified["occurrences"] == evidence.unclassified.occurrences  # type: ignore[union-attr]
    assert unclassified["unique_testcases"] == 1
    assert unclassified["phase_counts"] == {"call": 1}
    assert unclassified["target_counts"] == {"tests/test_x.py": 1}
    # int attempt keys become string keys (JSON has no integer keys).
    assert unclassified["attempt_counts"] == {"0": 1}
    assert unclassified["per_file_counts"] == {"tests/test_x.py": 1}
    assert len(unclassified["samples"]) == 1
    assert unclassified["samples"][0]["nodeid"] == "tests/test_x.py::test_a"
    assert unclassified["samples"][0]["classification"] == {
        "reason": "unclassified",
        "outcome": "fail",
    }


def test_samples_serialize_every_occurrence_field() -> None:
    occurrence = _occurrence(
        source_index=2,
        phase="teardown",
        target="tests/test_y.py",
        attempt=3,
        property_index=1,
        occurrence_index=4,
    )
    evidence = _evidence(status="complete", unclassified=_unclassified(samples=(occurrence,)))
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    sample = audit["classification_observability"]["unclassified"]["samples"][0]
    assert sample["source_index"] == 2
    assert sample["phase"] == "teardown"
    assert sample["target"] == "tests/test_y.py"
    assert sample["attempt"] == 3
    assert sample["property_index"] == 1
    assert sample["occurrence_index"] == 4


# --------------------------------------------------------------------------- #
# unavailable: unclassified is null, never a zero-valued block
# --------------------------------------------------------------------------- #


def test_unavailable_status_keeps_unclassified_null() -> None:
    evidence = _evidence(
        status="unavailable",
        status_reasons=("no raw source declared",),
        expected_sources=0,
        readable_sources=0,
        unclassified=None,
    )
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    block = audit["classification_observability"]
    assert block["status"] == "unavailable"
    assert block["unclassified"] is None
    assert "unclassified" not in audit["summary"]


# --------------------------------------------------------------------------- #
# A nonzero unclassified count must never fail or gate anything here --
# build_quality_audit has no pass/fail concept at all; the guard is that it
# never raises and never mutates the (already-computed) summary counts.
# --------------------------------------------------------------------------- #


def test_large_unclassified_count_does_not_affect_summary_or_raise() -> None:
    evidence = _evidence(status="complete", unclassified=_unclassified(occurrences=100_000))
    audit = build_quality_audit(results=_RESULTS, quality_report_evidence=evidence)
    assert audit["summary"]["failed"] == 1  # unchanged by the huge observability count
    assert audit["classification_observability"]["unclassified"]["occurrences"] == 100_000
