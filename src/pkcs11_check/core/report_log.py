"""Shared reader for pytest-reportlog JSONL report logs.

A run produces ``report.jsonl`` (the raw pytest-reportlog stream). The run, report, and
merge layers all need to walk it: iterate the JSON-object records, map a pytest outcome to
the unified outcome vocabulary, and pull values out of a record's ``user_properties`` list.
These are defined once here so the parsing rules cannot drift between consumers.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core.crash_codes import CTYPES_ACCESS_VIOLATION
from pkcs11_check.core.nodeids import normalize_nodeid


@dataclass
class SessionCompletionTracker:
    """Validate pytest report-log session bookends as records are streamed."""

    starts: int = 0
    finishes: int = 0
    _active: bool = False
    _invalid: bool = False
    _exitstatuses: list[int] | None = None

    def observe(self, record: Mapping[str, Any]) -> None:
        report_type = record.get("$report_type")
        if not isinstance(report_type, str) or not report_type:
            self._invalid = True
            return
        if report_type == "SessionStart":
            self.starts += 1
            if self._active:
                self._invalid = True
            self._active = True
            return
        if report_type == "TestReport":
            if (
                not self._active
                or not isinstance(record.get("nodeid"), str)
                or not record["nodeid"]
                or record.get("when") not in {"setup", "call", "teardown"}
                or record.get("outcome") not in {"passed", "failed", "skipped"}
            ):
                self._invalid = True
            return
        if report_type == "CollectReport":
            if (
                not self._active
                or not isinstance(record.get("nodeid"), str)
                or record.get("outcome") not in {"passed", "failed", "skipped"}
            ):
                self._invalid = True
            return
        if report_type != "SessionFinish":
            return

        self.finishes += 1
        if not self._active:
            self._invalid = True
        self._active = False
        exitstatus = record.get("exitstatus")
        if type(exitstatus) is not int:
            self._invalid = True
            return
        if self._exitstatuses is None:
            self._exitstatuses = []
        self._exitstatuses.append(exitstatus)

    def invalidate(self) -> None:
        """Mark the streamed session incomplete after malformed report input."""
        self._invalid = True

    @property
    def complete(self) -> bool:
        """Whether all observed sessions have exactly one valid finish."""
        return self.starts > 0 and not self._active and not self._invalid

    @property
    def single_exitstatus(self) -> int | None:
        """Return one session's exit status only for one valid session pair."""
        if not self.complete or self.starts != 1 or self.finishes != 1:
            return None
        return self._exitstatuses[0] if self._exitstatuses else None


def iter_report_log_records(
    path: Path, *, on_invalid: Callable[[], None] | None = None
) -> Iterator[dict[str, Any]]:
    """Yield parseable JSON-object records from a JSONL report log, line by line.

    Blank/whitespace-only lines, lines that are not valid JSON, and JSON values that are not
    objects are skipped. A missing/unreadable file yields nothing (never raises) so callers
    can treat an absent log as "no records".
    """
    # Opened in binary mode and decoded per line (rather than text mode) so a
    # concatenated raw report input with invalid UTF-8 on one line (e.g. a corrupted
    # write, or a shard truncated mid multi-byte sequence) never poisons neighboring
    # lines: text-mode decoding happens on whatever chunk the buffering layer reads,
    # which need not align with line boundaries, so a single bad byte can raise
    # UnicodeDecodeError before any line in that chunk -- including otherwise-good
    # lines before and after it -- is ever seen. Binary iteration splits on b"\n"
    # first, independent of decoding, so exactly one line is lost to a decode failure
    # and every other line (earlier or later) is still yielded.
    try:
        fh = path.open("rb")
    except OSError:
        if on_invalid is not None:
            on_invalid()
        return
    with fh:
        for raw_bytes in fh:
            try:
                raw_line = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                if on_invalid is not None:
                    on_invalid()
                continue
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                if on_invalid is not None:
                    on_invalid()
                continue
            if isinstance(obj, dict):
                yield obj
            elif on_invalid is not None:
                on_invalid()


def map_report_outcome(raw_outcome: str, wasxfail: object) -> str:
    """Map a raw pytest-reportlog outcome to the unified outcome value.

    ``passed`` + wasxfail -> ``xpassed``; ``skipped`` + wasxfail -> ``xfailed``; a strict-xfail
    ``failed`` stays ``failed`` regardless of wasxfail. Everything else passes through.
    """
    if raw_outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if raw_outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    return raw_outcome


def map_report_record_outcome(record: Mapping[str, Any]) -> str:
    """Map one report record, including a direct caught ctypes SEH failure."""
    raw_outcome = str(record.get("outcome", "passed"))
    if record.get("$report_type", "TestReport") == "TestReport" and raw_outcome == "failed":
        classifications = user_property(dict(record), "pkcs11_classification")
        if isinstance(classifications, list) and any(
            isinstance(classification, Mapping)
            and classification.get("reason") == "crash"
            and isinstance(detail := classification.get("detail"), Mapping)
            and detail.get("windows_status") == CTYPES_ACCESS_VIOLATION
            for classification in classifications
        ):
            return "crashed"
    return map_report_outcome(raw_outcome, record.get("wasxfail"))


def user_property(record: dict[str, Any], key: str) -> Any:
    """Return the value of the first ``(key, value)`` pair in ``record.user_properties``."""
    for pair in record.get("user_properties", []) or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == key:
            return pair[1]
    return None


def user_property_names(record: dict[str, Any]) -> set[str]:
    """Return the set of property names present in ``record.user_properties``."""
    names: set[str] = set()
    for prop in record.get("user_properties") or []:
        if isinstance(prop, (list, tuple)) and prop:
            names.add(str(prop[0]))
    return names


# Kept as a private literal (not imported from core/_report_records.py, which imports
# FROM this module) so the marker type name cannot drift; core/_report_records.py's
# `_ISOLATED_UNIT_REPORT_TYPE` must keep the same value.
_ISOLATED_UNIT_REPORT_TYPE = "IsolatedUnitReport"
_TEST_REPORT_PHASES = ("setup", "call", "teardown")
_CLASSIFICATION_PROPERTY = "pkcs11_classification"

# F11 classification-observability schema/count-semantics identifiers (shared contract,
# `.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md`).
F11_CONTRACT_VERSION = "1"
F11_COUNT_SEMANTICS = "serialized_classification_occurrences"

SourceStatus = Literal["complete", "partial", "unavailable"]


def user_property_values(record: dict[str, Any], key: str) -> list[Any]:
    """Return every value paired with ``key`` in ``record.user_properties``, in order.

    Unlike :func:`user_property` (first match only), this inspects every ``(key, value)``
    pair on the record. A well-formed record carries at most one ``pkcs11_classification``
    property, but duplicated/malformed input can carry more than one, and F11 counting must
    inspect all of them -- reusing ``user_property`` would silently undercount.
    """
    values: list[Any] = []
    for pair in record.get("user_properties", []) or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == key:
            values.append(pair[1])
    return values


@dataclass(frozen=True)
class ClassificationOccurrence:
    """One serialized ``pkcs11_classification`` dict read from a raw report-log record.

    Produced by :func:`iter_classification_occurrences`, which is the single shared
    parser for this shape -- do not re-derive occurrence parsing elsewhere.

    Fields:
      source_index: which declared raw source (e.g. index into a caller's list of
        shard/report JSONL paths) this occurrence was read from. The iterator itself is
        source-agnostic; the caller supplies this tag (default ``0``) per call.
      nodeid: the raw ``TestReport.nodeid``, byte-identical to the source record.
      canonical_nodeid: ``normalize_nodeid(nodeid)`` -- the key for grouping one logical
        testcase. Two occurrences with the same ``canonical_nodeid`` but different
        ``target`` (e.g. a file-level isolation target vs. a later per-test escalation
        target for the same test) are the SAME logical testcase and TWO occurrences; do
        not fold on ``target``.
      phase: ``"setup"``, ``"call"``, or ``"teardown"`` -- preserved separately, never
        merged. A retry pass (a later ``IsolatedUnitReport`` marker with a higher
        ``attempt``) never erases or overwrites an earlier phase's occurrence; occurrences
        already yielded are immutable and the caller is expected to keep all of them.
      target / attempt: the runner execution/isolation unit and attempt number most
        recently established by a well-formed ``IsolatedUnitReport`` marker seen earlier
        in this call's record stream, or ``None``/``None`` when no such marker has been
        seen since the last shard/session boundary (a `SessionStart` record, or simply the
        start of a new call -- marker provenance is never carried across calls). Attempts
        are attributed ONLY from a preceding marker; an unmarked record is left
        unattributed rather than having an id reconstructed for it.
      property_index: 0-based index of the ``pkcs11_classification`` user-property PAIR
        on the record (>0 only when a record carries more than one such pair -- itself an
        unusual-but-not-necessarily-invalid shape; every pair is still inspected).
      occurrence_index: 0-based index of this dict within that property's list value.
      reason: the occurrence's ``classification["reason"]`` (already validated to be a
        non-empty string; entries missing a usable ``reason`` are not yielded as
        occurrences -- see ``on_malformed_entry`` on the iterator).
      classification: the occurrence's own serialized classification dict, copied
        verbatim. This is bounded by construction: only the ``pkcs11_classification``
        property's own list entries are ever inspected, so no RV-trace user property
        (``pkcs11_rv_trace``/``pkcs11_rv_trace_dropped``, tracked separately in
        core/merge.py) and no per-record timing field (e.g. ``duration``) can ever reach
        this dict -- callers must not need to additionally strip either.
    """

    source_index: int
    nodeid: str
    canonical_nodeid: str
    phase: str
    target: str | None
    attempt: int | None
    property_index: int
    occurrence_index: int
    reason: str
    classification: Mapping[str, Any]


def iter_classification_occurrences(
    records: Iterable[Mapping[str, Any]],
    *,
    source_index: int = 0,
    reason_filter: str | None = None,
    on_malformed_marker: Callable[[], None] | None = None,
    on_malformed_property: Callable[[], None] | None = None,
    on_malformed_entry: Callable[[], None] | None = None,
) -> Iterator[ClassificationOccurrence]:
    """Yield one :class:`ClassificationOccurrence` per serialized classification dict.

    This is the ONE shared phase/attempt parser for ``pkcs11_classification`` evidence --
    both ``core/_report_records.py`` (F11 slice A) and the F11 slice B schema/report layer
    consume it directly; do not re-derive this parsing.

    ``records`` must be raw report-log dict records (e.g. from
    :func:`iter_report_log_records`) in file order, for exactly ONE shard/session scope.
    Marker provenance (the ``target``/``attempt`` most recently set by an
    ``IsolatedUnitReport`` record) is local to one call and starts unattributed: to honor
    "reset marker provenance at shard/session boundaries", start a NEW call per declared
    raw source rather than concatenating multiple sources' records into one call, or an
    unmarked shard will incorrectly inherit the previous shard's marker. A ``SessionStart``
    record encountered mid-stream (concatenated sessions within one source) also resets
    the marker to unattributed, since a new pytest session begins there too.

    Only ``setup``/``call``/``teardown`` ``TestReport`` records are inspected. Every
    ``pkcs11_classification`` user-property PAIR on a record is inspected via
    :func:`user_property_values` (not just the first), and every dict in each such
    property's list value is inspected -- so a record with several classification pairs,
    or a pair whose list holds several dicts, yields several occurrences, all counted (no
    deduplication of this total; the shared contract's counting semantics forbid it here).

    Malformed input is never dropped silently: a malformed ``IsolatedUnitReport`` marker
    (missing/wrong-typed ``target``/``attempt``) resets provenance to unattributed and
    invokes ``on_malformed_marker``; a ``pkcs11_classification`` property value that is not
    a list invokes ``on_malformed_property`` and contributes no occurrences; a list entry
    that is not a mapping, or lacks a non-empty string ``reason``, invokes
    ``on_malformed_entry`` and is skipped -- every other readable entry is still yielded.
    Pass ``reason_filter`` to see only occurrences whose ``reason`` equals it (e.g.
    ``"unclassified"``); leave it ``None`` to see every reason. Never raises; never caps
    or bounds its output -- any sample-size bounding is the caller's responsibility.
    """
    current_target: str | None = None
    current_attempt: int | None = None
    for record in records:
        report_type = record.get("$report_type", "TestReport")
        if report_type == "SessionStart":
            current_target = None
            current_attempt = None
            continue
        if report_type == _ISOLATED_UNIT_REPORT_TYPE:
            target = record.get("target")
            attempt = record.get("attempt")
            if (
                isinstance(target, str)
                and target
                and isinstance(attempt, int)
                and not isinstance(attempt, bool)
            ):
                current_target = target
                current_attempt = attempt
            else:
                current_target = None
                current_attempt = None
                if on_malformed_marker is not None:
                    on_malformed_marker()
            continue
        if report_type != "TestReport":
            continue
        when = record.get("when")
        if when not in _TEST_REPORT_PHASES:
            continue
        nodeid = str(record.get("nodeid", ""))
        canonical_nodeid = normalize_nodeid(nodeid)
        for property_index, value in enumerate(
            user_property_values(dict(record), _CLASSIFICATION_PROPERTY)
        ):
            if not isinstance(value, list):
                if on_malformed_property is not None:
                    on_malformed_property()
                continue
            for occurrence_index, entry in enumerate(value):
                if not isinstance(entry, Mapping):
                    if on_malformed_entry is not None:
                        on_malformed_entry()
                    continue
                reason = entry.get("reason")
                if not isinstance(reason, str) or not reason:
                    if on_malformed_entry is not None:
                        on_malformed_entry()
                    continue
                if reason_filter is not None and reason != reason_filter:
                    continue
                yield ClassificationOccurrence(
                    source_index=source_index,
                    nodeid=nodeid,
                    canonical_nodeid=canonical_nodeid,
                    phase=str(when),
                    target=current_target,
                    attempt=current_attempt,
                    property_index=property_index,
                    occurrence_index=occurrence_index,
                    reason=reason,
                    classification=dict(entry),
                )


@dataclass(frozen=True)
class UnclassifiedEvidence:
    """Aggregate raw evidence for the ``reason == "unclassified"`` classification occurrences.

    ``occurrences`` is the authoritative total (``count_semantics =
    "serialized_classification_occurrences"``): every matching dict counted, never
    deduplicated. ``lower_bound`` is ``True`` whenever the owning
    :class:`QualityReportEvidence`'s ``status`` is ``"partial"`` -- every count on this
    object is then a LOWER BOUND, never an exact total. ``samples`` is bounded (see
    ``core/_report_records.py``'s ``extract_quality_report_evidence_from_jsonl``) and must
    never be used as a substitute for ``occurrences`` or the other counts here, which are
    computed from the full stream regardless of how many samples are retained.
    """

    occurrences: int
    lower_bound: bool
    unique_testcases: int
    exact_duplicate_occurrences: int
    phase_counts: Mapping[str, int]
    target_counts: Mapping[str, int]
    attempt_counts: Mapping[int, int]
    unattributed_occurrences: int
    per_file_counts: Mapping[str, int]
    samples: tuple[ClassificationOccurrence, ...]


@dataclass(frozen=True)
class QualityReportEvidence:
    """Raw classification-observability evidence extracted from declared JSONL sources.

    See ``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md``
    for the binding status vocabulary and counting semantics this encodes.

    ``status`` follows the exact contract vocabulary:
      * ``"complete"``: every declared raw source was readable and reconciled with no
        missing or malformed artifact evidence.
      * ``"partial"``: readable evidence survives, but a missing source and/or malformed
        records/markers/properties/entries make every count in ``unclassified`` a LOWER
        BOUND.
      * ``"unavailable"``: no declared raw source could be inspected at all; ``unclassified``
        is ``None`` -- NEVER a zero-valued block. A fabricated zero here would silently
        claim "clean", which the shared contract calls out as the single worst failure mode.

    ``status_reasons`` is a human-readable, non-exhaustive-order-independent explanation of
    why the status is what it is (empty for ``"complete"``).
    """

    contract_version: str
    status: SourceStatus
    status_reasons: tuple[str, ...]
    expected_sources: int
    readable_sources: int
    missing_sources: int
    malformed_records: int
    malformed_markers: int
    malformed_properties: int
    malformed_entries: int
    count_semantics: str
    unclassified: UnclassifiedEvidence | None
