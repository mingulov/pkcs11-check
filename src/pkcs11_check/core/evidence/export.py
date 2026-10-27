"""Streaming semantic-ledger exporter (schema v1).

Consumes parsed report-log records (e.g. from
:func:`pkcs11_check.core.report_log.iter_report_log_records`) in a single
pass and writes a stable ledger: header first, rows sorted by (node_id,
phase, attempt). One row per occurrence (case x phase x attempt), never
collapsed.

Mapping table (report-record key -> row field, ``""`` default). All source
shapes below were inspected in ``core/report_log.py``,
``core/_report_records.py``, ``core/file_runner.py``,
``classification.py``, ``_plugin_report_attach.py`` and
``report/extract.py``:

- ``TestReport`` records (``nodeid``/``when``/``outcome``/``duration``/
  ``user_properties``) are the main row source. Only ``when`` in
  ``{"setup", "call", "teardown"}`` with ``outcome`` in
  ``{"passed", "failed", "skipped"}`` yields a row.
- ``node_id``: ``normalize_nodeid(record["nodeid"])`` (forward slashes).
- ``phase``: ``record["when"]``; ``"collect"`` for failed ``CollectReport``
  records; ``"harness"`` for ``HarnessError`` markers; ``"teardown"`` for
  ``TeardownFinalize`` lifecycle rows.
- ``attempt``: ledger attempts are 1-based while source markers are
  0-based, so a row's attempt is the source marker + 1. This matches the
  merge layer's ``raw_attempt + 1`` (``core/_report_records.py``). A
  well-formed marker (``IsolatedUnitReport`` with a non-empty str
  ``target`` and a non-bool int ``attempt`` >= 0 -- every emission site
  starts at 0 and increments, and static-skip markers use 0) establishes
  provenance for subsequent records; a later well-formed marker supersedes
  earlier provenance (escalation, e.g. a file-level target refined to a
  per-test target); ``SessionStart`` resets provenance to unattributed. A
  malformed marker (bad ``target``, non-int or negative ``attempt``)
  counts one malformed line and resets provenance to unattributed
  (recovery); unattributed rows export attempt 1. Attribution follows
  marker order, so byte-stability holds for reorderings within a marker
  scope -- moving records across markers is a different stream.
- ``attempts_total``: the count of exported rows sharing (node_id, phase).
- ``shard_id``: ``record["shard_id"]`` (orchestrator-injected per-record
  shard tag), else ``identity["shard_id"]``, else ``""``.
- ``outcome``: ``map_report_record_outcome(record)`` for ``TestReport``
  (passed/failed/skipped/xfailed/xpassed/crashed); ``"error"`` for failed
  ``CollectReport`` and ``HarnessError`` records; ``"error"``/``"crashed``/
  ``"timeout"`` for each ``TeardownFinalize`` lifecycle row (see below).
  ``crash_limited`` and ``missing`` have no report-record producer and only
  ever appear as zero counters / accepted load vocabulary.
- ``duration_ms``: ``record["duration"]`` seconds x 1000, else ``0``.
- Facets from the TERMINATING ``pkcs11_classification`` user-property
  entry (``classification.serialize`` shape: reason/outcome/severity/kind/
  label/summary/operation/mechanism/expected_ckr/actual_ckr/spec_ref/
  source/vector_id/params/detail/schema): the first entry whose
  ``outcome`` is ``"fail"``, else the first ``"xfail"`` entry, else the
  first entry. This mirrors ``_apply_recorded_outcome`` in
  ``_plugin_report_attach.py``, which drives the report outcome from the
  same priority (the exception-linked terminating record does not survive
  serialization, so list order + outcome priority is the reproducible
  approximation). ``reason`` <- ``reason``, ``class_reason`` <-
  ``outcome`` (the classification's declared outcome), ``category`` <-
  ``kind``, ``ckr_expected`` <- ``","``-joined ``expected_ckr``,
  ``ckr_actual`` <- ``actual_ckr``, ``mechanism`` <- ``mechanism``.
  ``reason`` is ``"harness_error"``/``"collect_error"`` for those derived
  rows. Each ADDITIONAL entry contributes an ``extra:<reason>`` flag (in
  stream order), so no semantic observation is silently discarded and the
  locked schema is untouched. A non-list property value carries no facets
  (the row survives), matching ``iter_classification_occurrences``.
- ``stimulus_rev/oracle_rev/reach/effect/cleanup/termination`` and
  ``flags``: forward-compat facets read from the selected classification's
  ``detail`` mapping's same-named sub-keys (declared detail flags come
  first, then any ``extra:<reason>`` markers); always ``""``/``[]`` on
  current producers, which never emit them.
- Every UNSUCCESSFUL ``TeardownFinalize`` record keeps its OWN lifecycle
  row (node_id ``"C_Finalize::teardown"``, phase ``"teardown"``,
  stream-position shard): outcome detection mirrors ``finalize_outcome``
  in ``core/_report_records.py`` (a Windows access-violation -- via
  ``windows_status`` or a ctypes traceback in ``error`` -- forces
  ``"crashed"``; ``"ok"`` (case-insensitive, and only ``"ok"``) is
  skipped; ``"crashed"``/``"timeout"`` pass through; anything else,
  including a missing outcome, is ``"error"``). Rows are totally ordered
  by (priority rank, outcome, canonical JSON of salient fields) -- rank
  error < crashed < timeout uses the same values as the consumer's
  ``max()`` rule, while ties order by emitted content, so every input
  order yields byte-identical output and no occurrence is dropped.
  ``attempt`` is the 1-based position in that canonical order (lifecycle
  rows carry no case identity, so marker provenance does not apply), hence
  rows never collide with each other. Facets mirror
  ``_classification_from_teardown_finalize`` in ``report/extract.py``:
  ``reason`` ``"crash"``/``"self_contradiction"``, ``class_reason``
  ``"fail"``, ``category`` ``"lifecycle"``, ``ckr_expected`` ``"CKR_OK"``,
  ``ckr_actual`` <- ``rv_name``. Deciding the EFFECTIVE outcome of several
  finalizers (which one governs the lane) is E3's job, NOT the exporter's:
  the exporter preserves every unsuccessful finalizer; E3 collapses.
- Session completion: every mapping record is observed by
  ``SessionCompletionTracker`` (``core/report_log.py``).
  ``counters["incomplete"]`` is 0 only for a fully verified complete
  session, else 1: unbalanced/missing bookends, malformed input, or
  collection/harness failure evidence (the canonical consumer also marks
  the session incomplete on collect/harness errors). Unframed legacy
  streams (no ``SessionStart`` at all) always export ``incomplete=1``:
  absent bookends are unverifiable, never clean. Reader-invalid lines (see
  below) and non-mapping items invalidate completion, mirroring the
  ``on_invalid=completion.invalidate`` wiring in ``core/_jsonl_extract.py``.
- Skipped silently (framing): ``SessionStart``/``SessionFinish``,
  passed/skipped ``CollectReport``, ``ProcessReport``, ``"ok"``
  ``TeardownFinalize``, unknown ``$report_type`` values.
- Counted into ``header.malformed_lines`` (never silently dropped):
  non-mapping items; records with a missing/empty/non-str ``$report_type``;
  ``TestReport`` records with a missing/invalid ``nodeid``/``when``/
  ``outcome`` (a missing ``outcome`` is malformed -- the shared mapper's
  ``"passed"`` default is NOT inherited) or a mistyped
  ``user_properties`` container; ``HarnessError``/failed-``CollectReport``
  records with a non-str ``nodeid``; ``CollectReport`` records with a
  missing/invalid ``outcome``; ``IsolatedUnitReport`` markers with a
  missing/empty ``target`` or a non-int/negative ``attempt`` (provenance
  resets); plus the ``reader_invalid_lines`` count (lines the reader
  skipped before parsing, e.g. invalid JSON/UTF-8 or non-object JSON).
  Every row-producing shape flows through ONE disposition function
  (row/skip/malformed), so row and malformed accounting cannot drift.
- Duplicate occurrence keys: ``export_ledger`` raises ``ValueError``
  (before writing anything) when two rows share (node_id, phase, attempt)
  -- e.g. equal keys with conflicting outcomes, or overlapping shards.
  The loader rejects such ledgers, and occurrence preservation forbids
  silently dropping or merging either row, so failing explicitly is the
  only loader-consistent behavior. The first duplicate in sort order is
  named, making the failure deterministic under any input order.

``reader_invalid_lines`` is CONTRACT, not an opt-in extension: the reader
skips invalid lines (invalid JSON/UTF-8, non-object JSON) before they ever
become records, so the count can only arrive through this channel.
``None`` (the default) declares NO reader in the loop -- the correct 0 for
pre-parsed or otherwise reader-less inputs, which then count parsed-level
malformed only. Production callers consuming raw report-log streams MUST
pass the reader's invalid count: a zero-argument thunk returning the count
(evaluated once, after ``records`` is consumed; the E3 CLI wires
``report_log.on_invalid``), or an int when the caller materialized the
stream and counted already::

    invalid = 0
    def count() -> None: ...
    records = iter_report_log_records(path, on_invalid=count)
    export_ledger(records, identity, sink, reader_invalid_lines=lambda: invalid)

Header identity (``lane``, ``lane_os``, ``lane_arch``, ``framework_sha``,
``p11lab_sha``, ``image_digest``, ``corpus_hash``, ``disabled_hash``,
``planned_collection_hash``, ``raw_stream_sha256``, ``created_by``) echoes
``identity`` verbatim, ``""`` when absent (``created_by`` defaults to
``"pkcs11-check"``); ``planned_count``/``raw_stream_bytes`` parse as int
(``0`` when absent/unparseable). The exporter consumes parsed records, so
the orchestrator -- which sees the raw JSONL bytes -- measures
``raw_stream_bytes``/``raw_stream_sha256`` and passes them via
``identity``. ``missing``/``child_crash``/``child_timeout`` counters are
always ``0`` from this exporter: child crash/timeout needs merge-layer
unit association, missing is an admission/comparison concept (E2/E3);
``incomplete`` is observed here (see above) since E2 cannot reconstruct
discarded session bookends.

Memory: row lines spill to an on-disk temp file while only (key, file-offset)
pairs sort in memory, so peak heap is O(rows) keys -- an in-memory line
buffer provably exceeds the 64 MB @ 200k-rows budget (~370 bytes/row).
``attempts_total`` is fixed at output time from sorted (node_id, phase)
runs (single-row groups stream through untouched), and duplicate keys are
detected by an adjacent scan after sorting (no extra memory).
"""

from __future__ import annotations

import json
import math
import tempfile
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import IO, Any, Literal, TextIO

from pkcs11_check.core.crash_codes import (
    CTYPES_ACCESS_VIOLATION,
    ctypes_access_violation_from_stderr,
)
from pkcs11_check.core.evidence.schema import (
    LEDGER_SCHEMA_VERSION,
    LedgerHeader,
    LedgerRow,
    zero_counters,
)
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.report_log import (
    SessionCompletionTracker,
    map_report_record_outcome,
    user_property,
)

_TEST_PHASES = ("setup", "call", "teardown")
_TEST_OUTCOMES = ("passed", "failed", "skipped")

#: Node id of each TeardownFinalize lifecycle row (the same
#: ``"C_Finalize::teardown"`` nodeid the canonical consumer attributes).
_LIFECYCLE_NODE_ID = "C_Finalize::teardown"

#: Canonical rank for lifecycle-row ordering (same values as the
#: consumer's ``max()`` rule in ``core/_report_records.py``; the exporter
#: keeps every row in rank order while the consumer folds to one).
_FINALIZE_PRIORITY: dict[str, int] = {"error": 1, "crashed": 2, "timeout": 3}

#: Emitted row fields that distinguish finalizer occurrences. The canonical
#: JSON of these fields is the tie-break element of the lifecycle total
#: order (after priority rank and outcome).
_FINALIZE_SALIENT_FIELDS: tuple[str, ...] = (
    "shard_id",
    "reason",
    "class_reason",
    "category",
    "ckr_expected",
    "ckr_actual",
    "mechanism",
    "stimulus_rev",
    "oracle_rev",
    "reach",
    "effect",
    "cleanup",
    "termination",
    "flags",
)

_DUMPS_KWARGS: dict[str, Any] = {"sort_keys": True}

_CREATED_BY_DEFAULT = "pkcs11-check"

_Disposition = Literal["row", "skip", "malformed"]


def _facet_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return str(value)
    return ""


def _ckr_expected(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return ""


def _flags(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


def _duration_ms(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
        return int(round(value * 1000))
    return 0


def _identity_str(identity: Mapping[str, str], key: str) -> str:
    value = identity.get(key)
    return value if isinstance(value, str) else ""


def _identity_int(identity: Mapping[str, str], key: str) -> int:
    value = identity.get(key)
    if not isinstance(value, str):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _classification_facets(record: Mapping[str, Any]) -> dict[str, Any]:
    facets: dict[str, Any] = {
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
    classifications = user_property(dict(record), "pkcs11_classification")
    entries = (
        [entry for entry in classifications if isinstance(entry, Mapping)]
        if isinstance(classifications, list)
        else []
    )
    selected = next((entry for entry in entries if entry.get("outcome") == "fail"), None)
    if selected is None:
        selected = next((entry for entry in entries if entry.get("outcome") == "xfail"), None)
    if selected is None:
        if not entries:
            return facets
        selected = entries[0]
    detail = selected.get("detail")
    detail_map = detail if isinstance(detail, Mapping) else {}
    flags = _flags(detail_map.get("flags"))
    for entry in entries:
        if entry is selected:
            continue
        reason = entry.get("reason")
        if isinstance(reason, str) and reason:
            flags.append(f"extra:{reason}")
    facets.update(
        reason=_facet_str(selected.get("reason")),
        class_reason=_facet_str(selected.get("outcome")),
        category=_facet_str(selected.get("kind")),
        ckr_expected=_ckr_expected(selected.get("expected_ckr")),
        ckr_actual=_facet_str(selected.get("actual_ckr")),
        mechanism=_facet_str(selected.get("mechanism")),
        stimulus_rev=_facet_str(detail_map.get("stimulus_rev")),
        oracle_rev=_facet_str(detail_map.get("oracle_rev")),
        reach=_facet_str(detail_map.get("reach")),
        effect=_facet_str(detail_map.get("effect")),
        cleanup=_facet_str(detail_map.get("cleanup")),
        termination=_facet_str(detail_map.get("termination")),
        flags=flags,
    )
    return facets


def _user_properties_usable(value: Any) -> bool:
    """Whether a ``user_properties`` container is safe to traverse."""
    return value is None or isinstance(value, (list, tuple))


def _marker_raw_attempt(item: Mapping[str, Any]) -> int | None:
    """Return a marker's source 0-based attempt, or None when malformed."""
    target = item.get("target")
    attempt = item.get("attempt")
    if isinstance(target, str) and target and type(attempt) is int and attempt >= 0:
        return attempt
    return None


def _finalize_outcome(record: Mapping[str, Any]) -> str | None:
    """Mirror ``core/_report_records.py`` ``finalize_outcome`` exactly."""
    error = record.get("error")
    if record.get("windows_status") == CTYPES_ACCESS_VIOLATION or (
        ctypes_access_violation_from_stderr(str(error)) is not None
    ):
        return "crashed"
    outcome = str(record.get("outcome", "")).casefold()
    if outcome == "ok":
        return None
    if outcome in {"crashed", "timeout"}:
        return outcome
    return "error"


def _finalize_row(
    record: Mapping[str, Any], ledger_attempt: int, shard_id: str, outcome: str
) -> dict[str, Any]:
    """Build one lifecycle row (facets per ``report/extract.py``)."""
    return {
        "node_id": _LIFECYCLE_NODE_ID,
        "phase": "teardown",
        "attempt": ledger_attempt,
        "shard_id": shard_id,
        "outcome": outcome,
        "duration_ms": 0,
        "reason": "crash" if outcome == "crashed" else "self_contradiction",
        "class_reason": "fail",
        "category": "lifecycle",
        "ckr_expected": "CKR_OK",
        "ckr_actual": _facet_str(record.get("rv_name")),
        "mechanism": "",
        "stimulus_rev": "",
        "oracle_rev": "",
        "reach": "",
        "effect": "",
        "cleanup": "",
        "termination": "",
        "flags": [],
    }


def _finalize_sort_key(row: Mapping[str, Any]) -> tuple[int, str, str]:
    """Total-order key for one lifecycle row: rank, outcome, salient JSON."""
    outcome = str(row["outcome"])
    salient = {field: row[field] for field in _FINALIZE_SALIENT_FIELDS}
    return (
        _FINALIZE_PRIORITY[outcome],
        outcome,
        json.dumps(salient, **_DUMPS_KWARGS),
    )


def _resolve_reader_invalid_lines(value: int | Callable[[], int] | None) -> int:
    """Evaluate and validate the threaded reader-invalid count.

    ``None`` declares no reader in the loop (correct 0 for pre-parsed
    inputs); anything else must be an int or a thunk returning one.
    """
    if value is None:
        return 0
    candidate: Any = value() if callable(value) else value
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        raise TypeError(
            "export_ledger: reader_invalid_lines must be None, an int, "
            f"or a thunk returning one, got {candidate!r}"
        )
    if candidate < 0:
        raise ValueError(f"export_ledger: reader_invalid_lines must be >= 0, got {candidate}")
    return candidate


def _disposition(
    item: Mapping[str, Any],
    report_type: str,
    ledger_attempt: int,
    fallback_shard: str,
) -> tuple[_Disposition, dict[str, Any] | None]:
    """Return the single row/skip/malformed disposition for one record.

    This is the ONLY row-vs-malformed decision path: callers must not
    re-derive validity elsewhere.
    """
    shard_id = _facet_str(item.get("shard_id")) or fallback_shard
    if report_type == "TestReport":
        nodeid = item.get("nodeid")
        when = item.get("when")
        outcome = item.get("outcome")
        if (
            not isinstance(nodeid, str)
            or not nodeid
            or not isinstance(when, str)
            or when not in _TEST_PHASES
            or not isinstance(outcome, str)
            or outcome not in _TEST_OUTCOMES
            or not _user_properties_usable(item.get("user_properties"))
        ):
            return "malformed", None
        row = _classification_facets(item)
        row.update(
            node_id=normalize_nodeid(nodeid),
            phase=when,
            attempt=ledger_attempt,
            shard_id=shard_id,
            outcome=map_report_record_outcome(item),
            duration_ms=_duration_ms(item.get("duration")),
        )
        return "row", row
    if report_type == "HarnessError":
        nodeid = item.get("nodeid")
        if (
            not isinstance(nodeid, str)
            or not nodeid
            or not _user_properties_usable(item.get("user_properties"))
        ):
            return "malformed", None
        row = _classification_facets(item)
        row.update(
            node_id=normalize_nodeid(nodeid),
            phase="harness",
            attempt=ledger_attempt,
            shard_id=shard_id,
            outcome="error",
            duration_ms=0,
            reason="harness_error",
        )
        return "row", row
    if report_type == "CollectReport":
        outcome = item.get("outcome")
        if outcome == "failed":
            nodeid = item.get("nodeid")
            if (
                not isinstance(nodeid, str)
                or not nodeid
                or not _user_properties_usable(item.get("user_properties"))
            ):
                return "malformed", None
            row = _classification_facets(item)
            row.update(
                node_id=normalize_nodeid(nodeid),
                phase="collect",
                attempt=ledger_attempt,
                shard_id=shard_id,
                outcome="error",
                duration_ms=0,
                reason="collect_error",
            )
            return "row", row
        if isinstance(outcome, str) and outcome in {"passed", "skipped"}:
            return "skip", None
        return "malformed", None
    return "skip", None


def _spill_row(
    spilled: IO[bytes],
    entries: list[tuple[tuple[str, str, int], int]],
    counters: dict[str, int],
    row: dict[str, Any],
) -> None:
    key = (row["node_id"], row["phase"], row["attempt"])
    counters[row["outcome"]] += 1
    offset = spilled.tell()
    # attempts_total ships as 1 and is fixed at output time from the
    # sorted (node_id, phase) runs; single-row groups stream through.
    line = json.dumps({"record": "case", **row, "attempts_total": 1}, **_DUMPS_KWARGS)
    spilled.write(line.encode("ascii") + b"\n")
    entries.append((key, offset))


def export_ledger(
    records: Iterable[Mapping[str, Any]],
    identity: Mapping[str, str],
    sink: TextIO,
    *,
    reader_invalid_lines: int | Callable[[], int] | None = None,
) -> LedgerHeader:
    """Export report-log records to a stable ledger written to ``sink``.

    ``reader_invalid_lines`` is CONTRACT: ``None`` (the default) declares
    no reader in the loop -- the correct 0 for pre-parsed inputs, which
    then count parsed-level malformed only. Production callers consuming
    raw streams MUST pass the reader's invalid count: a zero-argument
    thunk returning the count (evaluated once, after ``records`` is
    consumed; wire ``iter_report_log_records(..., on_invalid=...)``), or
    an int when the caller materialized the stream and counted already.
    The count lands in ``header.malformed_lines`` and invalidates session
    completion.

    Raises ``ValueError`` (before writing anything) when two rows share
    one (node_id, phase, attempt) occurrence key.
    """
    counters = zero_counters()
    malformed = 0
    raw_attempt: int | None = None  # source 0-based marker provenance
    # (sort key, byte offset of the spilled line); the only O(rows) memory.
    entries: list[tuple[tuple[str, str, int], int]] = []
    fallback_shard = _identity_str(identity, "shard_id")
    completion = SessionCompletionTracker()
    saw_diagnostic = False
    finalize_events: list[tuple[Mapping[str, Any], str]] = []

    with tempfile.TemporaryFile("w+b") as spilled:
        for item in records:
            if not isinstance(item, Mapping):
                malformed += 1
                completion.invalidate()
                continue
            completion.observe(item)
            report_type = item.get("$report_type", "TestReport")
            if not isinstance(report_type, str) or not report_type:
                malformed += 1
                continue
            if report_type == "SessionStart":
                raw_attempt = None
                continue
            if report_type == "IsolatedUnitReport":
                marker = _marker_raw_attempt(item)
                if marker is None:
                    malformed += 1
                    raw_attempt = None
                else:
                    raw_attempt = marker
                continue
            ledger_attempt = raw_attempt + 1 if raw_attempt is not None else 1
            if report_type == "TeardownFinalize":
                shard_id = _facet_str(item.get("shard_id")) or fallback_shard
                finalize_events.append((item, shard_id))
                continue
            disposition, row = _disposition(item, report_type, ledger_attempt, fallback_shard)
            if disposition == "malformed":
                malformed += 1
                continue
            if row is None:
                continue
            if report_type in {"CollectReport", "HarnessError"}:
                saw_diagnostic = True
            _spill_row(spilled, entries, counters, row)

        reader_invalid = _resolve_reader_invalid_lines(reader_invalid_lines)
        malformed += reader_invalid
        if reader_invalid:
            completion.invalidate()
        if finalize_events:
            # ONE lifecycle row per unsuccessful finalizer, totally ordered
            # so every input order yields byte-identical output; attempt is
            # the 1-based canonical position (no case identity, no marker
            # provenance). Effective-outcome collapsing is E3's job.
            pending: list[dict[str, Any]] = []
            for event_record, event_shard in finalize_events:
                event_outcome = _finalize_outcome(event_record)
                if event_outcome is None:
                    continue
                pending.append(_finalize_row(event_record, 0, event_shard, event_outcome))
            pending.sort(key=_finalize_sort_key)
            for position, pending_row in enumerate(pending, start=1):
                pending_row["attempt"] = position
                _spill_row(spilled, entries, counters, pending_row)
        counters["incomplete"] = 0 if (completion.complete and not saw_diagnostic) else 1
        header = LedgerHeader(
            schema_v=LEDGER_SCHEMA_VERSION,
            lane=_identity_str(identity, "lane"),
            lane_os=_identity_str(identity, "lane_os"),
            lane_arch=_identity_str(identity, "lane_arch"),
            framework_sha=_identity_str(identity, "framework_sha"),
            p11lab_sha=_identity_str(identity, "p11lab_sha"),
            image_digest=_identity_str(identity, "image_digest"),
            corpus_hash=_identity_str(identity, "corpus_hash"),
            disabled_hash=_identity_str(identity, "disabled_hash"),
            planned_collection_hash=_identity_str(identity, "planned_collection_hash"),
            planned_count=_identity_int(identity, "planned_count"),
            raw_stream_bytes=_identity_int(identity, "raw_stream_bytes"),
            raw_stream_sha256=_identity_str(identity, "raw_stream_sha256"),
            malformed_lines=malformed,
            counters=counters,
            created_by=_identity_str(identity, "created_by") or _CREATED_BY_DEFAULT,
        )

        entries.sort(key=lambda entry: entry[0])
        for previous, current in zip(entries, entries[1:]):
            if current[0] == previous[0]:
                raise ValueError(
                    "export_ledger: duplicate occurrence key "
                    f"(node_id, phase, attempt) {current[0]!r}: two rows claim one "
                    "occurrence (equal keys or overlapping shards)"
                )
        sink.write(json.dumps(header.to_record(), **_DUMPS_KWARGS) + "\n")

        index = 0
        while index < len(entries):
            group = (entries[index][0][0], entries[index][0][1])
            end = index + 1
            while end < len(entries) and (entries[end][0][0], entries[end][0][1]) == group:
                end += 1
            total = end - index
            for _, offset in entries[index:end]:
                spilled.seek(offset)
                raw = spilled.readline().decode("ascii")
                if total == 1:
                    sink.write(raw)
                else:
                    fixed = json.loads(raw)
                    fixed["attempts_total"] = total
                    sink.write(json.dumps(fixed, **_DUMPS_KWARGS) + "\n")
            index = end
    return header


def load_ledger(path: Path) -> tuple[LedgerHeader, list[LedgerRow]]:
    """Load and validate a ledger file, failing loud on any defect.

    Whitespace-only lines are skipped; everything else must be a JSON
    object, the first a ``header`` record and the rest ``case`` rows.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"ledger {path}: unreadable ({exc})") from None
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"ledger {path}: missing header (empty file)")
    try:
        first = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError(f"ledger {path} line 1: header is not valid JSON") from exc
    if not isinstance(first, dict) or first.get("record") != "header":
        raise ValueError(f"ledger {path} line 1: missing/non-first header")
    if first.get("schema_v") != LEDGER_SCHEMA_VERSION:
        raise ValueError(f"ledger {path} line 1: wrong/missing schema_v {first.get('schema_v')!r}")
    header = LedgerHeader.from_record(first, line_number=1)
    rows: list[LedgerRow] = []
    seen: set[tuple[str, str, int]] = set()
    previous: tuple[str, str, int] | None = None
    for number, line in enumerate(lines[1:], start=2):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ledger {path} line {number}: row is not valid JSON") from exc
        if not isinstance(parsed, dict) or parsed.get("record") != "case":
            raise ValueError(f"ledger {path} line {number}: not a case row")
        row = LedgerRow.from_record(parsed, line_number=number)
        key = row.sort_key
        if key in seen:
            raise ValueError(
                f"ledger {path} line {number}: duplicate (node_id, phase, attempt) {key!r}"
            )
        seen.add(key)
        if previous is not None and key < previous:
            raise ValueError(f"ledger {path} line {number}: unsorted rows")
        previous = key
        rows.append(row)
    return header, rows
