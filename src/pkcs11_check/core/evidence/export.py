"""Streaming semantic-ledger exporter (schema v1).

Consumes parsed report-log records (e.g. from
:func:`pkcs11_check.core.report_log.iter_report_log_records`) in a single
pass and writes a stable ledger: header first, rows sorted by (node_id,
phase, attempt). One row per occurrence (case x phase x attempt), never
collapsed.

Mapping table (report-record key -> row field, ``""`` default). All source
shapes below were inspected in ``core/report_log.py``,
``core/_report_records.py``, ``core/file_runner.py`` and
``classification.py``:

- ``TestReport`` records (``nodeid``/``when``/``outcome``/``duration``/
  ``user_properties``) are the main row source. Only ``when`` in
  ``{"setup", "call", "teardown"}`` yields a row.
- ``node_id``: ``normalize_nodeid(record["nodeid"])`` (forward slashes).
- ``phase``: ``record["when"]``; ``"collect"`` for failed ``CollectReport``
  records; ``"harness"`` for ``HarnessError`` markers.
- ``attempt``: the ``attempt`` of the most recent well-formed
  ``IsolatedUnitReport`` marker (``target`` non-empty str, ``attempt`` int
  >= 1), reset by ``SessionStart``; ``1`` when unattributed. Attribution
  follows marker order, so byte-stability holds for reorderings within a
  marker scope -- moving records across markers is a different stream.
- ``attempts_total``: the count of exported rows sharing (node_id, phase).
- ``shard_id``: ``record["shard_id"]`` (orchestrator-injected per-record
  shard tag), else ``identity["shard_id"]``, else ``""``.
- ``outcome``: ``map_report_record_outcome(record)`` for ``TestReport``
  (passed/failed/skipped/xfailed/xpassed/crashed); ``"error"`` for failed
  ``CollectReport`` and ``HarnessError`` records. ``timeout``,
  ``crash_limited`` and ``missing`` have no report-record producer and only
  ever appear as zero counters / accepted load vocabulary.
- ``duration_ms``: ``record["duration"]`` seconds x 1000, else ``0``.
- Facets from the FIRST ``pkcs11_classification`` user-property entry
  (``classification.serialize`` shape: reason/outcome/severity/kind/label/
  summary/operation/mechanism/expected_ckr/actual_ckr/spec_ref/source/
  vector_id/params/detail/schema): ``reason`` <- ``reason``,
  ``class_reason`` <- ``outcome`` (the classification's declared outcome),
  ``category`` <- ``kind``, ``ckr_expected`` <- ``","``-joined
  ``expected_ckr``, ``ckr_actual`` <- ``actual_ckr``, ``mechanism`` <-
  ``mechanism``. ``reason`` is ``"harness_error"``/``"collect_error"`` for
  those derived rows.
- ``stimulus_rev/oracle_rev/reach/effect/cleanup/termination`` and
  ``flags``: forward-compat facets read from the classification ``detail``
  mapping's same-named sub-keys; always ``""``/``[]`` on current
  producers, which never emit them.
- Skipped silently (framing, matching the canonical consumer in
  ``core/_report_records.py``): ``SessionStart``/``SessionFinish``,
  passed/skipped ``CollectReport``, ``ProcessReport``,
  ``TeardownFinalize``, unknown ``$report_type`` values.
- Counted into ``header.malformed_lines`` (never silently dropped):
  non-mapping items; ``TestReport`` records with a missing/invalid
  ``nodeid``/``when``/``outcome`` (a missing ``outcome`` is malformed --
  the shared mapper's ``"passed"`` default is NOT inherited);
  ``HarnessError``/failed-``CollectReport`` records with a non-str
  ``nodeid``; ``IsolatedUnitReport`` markers with a missing/empty
  ``target`` or a non-int/``< 1`` ``attempt`` (provenance resets).

Header identity (``lane``, ``lane_os``, ``lane_arch``, ``framework_sha``,
``p11lab_sha``, ``image_digest``, ``corpus_hash``, ``disabled_hash``,
``planned_collection_hash``, ``raw_stream_sha256``, ``created_by``) echoes
``identity`` verbatim, ``""`` when absent (``created_by`` defaults to
``"pkcs11-check"``); ``planned_count``/``raw_stream_bytes`` parse as int
(``0`` when absent/unparseable). The exporter consumes parsed records, so
the orchestrator -- which sees the raw JSONL bytes -- measures
``raw_stream_bytes``/``raw_stream_sha256`` and passes them via
``identity``. ``missing``/``child_crash``/``child_timeout``/``incomplete``
counters are always ``0`` from this exporter: child crash/timeout needs
merge-layer unit association, missing/incomplete are admission/comparison
concepts (E2/E3).

Memory: row lines spill to an on-disk temp file while only (key, file-offset)
pairs sort in memory, so peak heap is O(rows) keys -- an in-memory line
buffer provably exceeds the 64 MB @ 200k-rows budget (~370 bytes/row).
``attempts_total`` is fixed at output time from sorted (node_id, phase)
runs (single-row groups stream through untouched).
"""

from __future__ import annotations

import json
import math
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, TextIO

from pkcs11_check.core.evidence.schema import (
    LEDGER_SCHEMA_VERSION,
    LedgerHeader,
    LedgerRow,
    zero_counters,
)
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.report_log import map_report_record_outcome, user_property

_TEST_PHASES = ("setup", "call", "teardown")

_DUMPS_KWARGS: dict[str, Any] = {"sort_keys": True}

_CREATED_BY_DEFAULT = "pkcs11-check"


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
    entry: Any = None
    if isinstance(classifications, list) and classifications:
        entry = classifications[0]
    if not isinstance(entry, Mapping):
        return facets
    detail = entry.get("detail")
    detail_map = detail if isinstance(detail, Mapping) else {}
    facets.update(
        reason=_facet_str(entry.get("reason")),
        class_reason=_facet_str(entry.get("outcome")),
        category=_facet_str(entry.get("kind")),
        ckr_expected=_ckr_expected(entry.get("expected_ckr")),
        ckr_actual=_facet_str(entry.get("actual_ckr")),
        mechanism=_facet_str(entry.get("mechanism")),
        stimulus_rev=_facet_str(detail_map.get("stimulus_rev")),
        oracle_rev=_facet_str(detail_map.get("oracle_rev")),
        reach=_facet_str(detail_map.get("reach")),
        effect=_facet_str(detail_map.get("effect")),
        cleanup=_facet_str(detail_map.get("cleanup")),
        termination=_facet_str(detail_map.get("termination")),
        flags=_flags(detail_map.get("flags")),
    )
    return facets


def export_ledger(
    records: Iterable[Mapping[str, Any]],
    identity: Mapping[str, str],
    sink: TextIO,
) -> LedgerHeader:
    """Export report-log records to a stable ledger written to ``sink``."""
    counters = zero_counters()
    malformed = 0
    current_attempt: int | None = None
    # (sort key, byte offset of the spilled line); the only O(rows) memory.
    entries: list[tuple[tuple[str, str, int], int]] = []
    fallback_shard = _identity_str(identity, "shard_id")

    with tempfile.TemporaryFile("w+b") as spilled:
        for item in records:
            row = _row_for_record(item, current_attempt, fallback_shard)
            if row is None:
                if _is_malformed(item):
                    malformed += 1
                current_attempt = _next_attempt(item, current_attempt)
                continue
            current_attempt = _next_attempt(item, current_attempt)
            key = (row["node_id"], row["phase"], row["attempt"])
            counters[row["outcome"]] += 1
            offset = spilled.tell()
            # attempts_total ships as 1 and is fixed at output time from the
            # sorted (node_id, phase) runs; single-row groups stream through.
            line = json.dumps({"record": "case", **row, "attempts_total": 1}, **_DUMPS_KWARGS)
            spilled.write(line.encode("ascii") + b"\n")
            entries.append((key, offset))

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
        sink.write(json.dumps(header.to_record(), **_DUMPS_KWARGS) + "\n")

        entries.sort(key=lambda entry: entry[0])
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


def _next_attempt(item: Any, current: int | None) -> int | None:
    if not isinstance(item, Mapping):
        return current
    report_type = item.get("$report_type", "TestReport")
    if report_type == "SessionStart":
        return None
    if report_type == "IsolatedUnitReport":
        target = item.get("target")
        attempt = item.get("attempt")
        if isinstance(target, str) and target and type(attempt) is int and attempt >= 1:
            return attempt
        return None
    return current


def _is_malformed(item: Any) -> bool:
    if not isinstance(item, Mapping):
        return True
    report_type = item.get("$report_type", "TestReport")
    if not isinstance(report_type, str) or not report_type:
        return True
    if report_type == "IsolatedUnitReport":
        target = item.get("target")
        attempt = item.get("attempt")
        return not (isinstance(target, str) and target and type(attempt) is int and attempt >= 1)
    if report_type == "TestReport":
        return not (
            isinstance(item.get("nodeid"), str)
            and item.get("nodeid")
            and item.get("when") in _TEST_PHASES
            and item.get("outcome") in {"passed", "failed", "skipped"}
        )
    if report_type in {"HarnessError", "CollectReport"}:
        if report_type == "CollectReport" and item.get("outcome") != "failed":
            return False
        nodeid = item.get("nodeid")
        return not (isinstance(nodeid, str) and nodeid)
    return False


def _row_for_record(
    item: Any, current_attempt: int | None, fallback_shard: str
) -> dict[str, Any] | None:
    if not isinstance(item, Mapping):
        return None
    report_type = item.get("$report_type", "TestReport")
    attempt = current_attempt if current_attempt is not None else 1
    shard_id = _facet_str(item.get("shard_id")) or fallback_shard
    if report_type == "TestReport":
        nodeid = item.get("nodeid")
        when = item.get("when")
        outcome = item.get("outcome")
        if (
            not isinstance(nodeid, str)
            or not nodeid
            or when not in _TEST_PHASES
            or outcome not in {"passed", "failed", "skipped"}
        ):
            return None
        row = _classification_facets(item)
        row.update(
            node_id=normalize_nodeid(nodeid),
            phase=str(when),
            attempt=attempt,
            shard_id=shard_id,
            outcome=map_report_record_outcome(item),
            duration_ms=_duration_ms(item.get("duration")),
        )
        return row
    if report_type == "HarnessError":
        nodeid = item.get("nodeid")
        if not isinstance(nodeid, str) or not nodeid:
            return None
        row = _classification_facets(item)
        row.update(
            node_id=normalize_nodeid(nodeid),
            phase="harness",
            attempt=attempt,
            shard_id=shard_id,
            outcome="error",
            duration_ms=0,
            reason="harness_error",
        )
        return row
    if report_type == "CollectReport":
        if item.get("outcome") != "failed":
            return None
        nodeid = item.get("nodeid")
        if not isinstance(nodeid, str) or not nodeid:
            return None
        row = _classification_facets(item)
        row.update(
            node_id=normalize_nodeid(nodeid),
            phase="collect",
            attempt=attempt,
            shard_id=shard_id,
            outcome="error",
            duration_ms=0,
            reason="collect_error",
        )
        return row
    return None


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
