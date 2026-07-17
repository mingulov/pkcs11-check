"""Per-unit report-record cache and report.jsonl assembly for the isolated runner.

Moved verbatim from file_runner.py (god-module split, 2026-07-17): streaming record
cache (one file per unit), report.jsonl writers built from record sources, and the
per-unit detail builders derived from report records.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from pkcs11_check.core._run_units import (
    _DETAIL_COUNT_KEYS as _DETAIL_COUNT_KEYS,
)
from pkcs11_check.core._run_units import (
    _DISABLE_COLLECTION_PROBES_ENV as _DISABLE_COLLECTION_PROBES_ENV,
)
from pkcs11_check.core._run_units import (
    _RESUME_COMPLETE_STATUSES as _RESUME_COMPLETE_STATUSES,
)
from pkcs11_check.core._run_units import (
    _SPECIAL_DETAIL_OUTCOMES as _SPECIAL_DETAIL_OUTCOMES,
)
from pkcs11_check.core._run_units import (
    _TIMEOUT_RETURN_CODE as _TIMEOUT_RETURN_CODE,
)
from pkcs11_check.core._run_units import (
    UNIT_STATUS_PRIORITY as UNIT_STATUS_PRIORITY,
)
from pkcs11_check.core._run_units import (
    BackendIsolationPolicy as BackendIsolationPolicy,
)
from pkcs11_check.core._run_units import (
    CrashStatus as CrashStatus,
)
from pkcs11_check.core._run_units import (
    FileRunResult as FileRunResult,
)
from pkcs11_check.core._run_units import (
    FileRunState as FileRunState,
)
from pkcs11_check.core._run_units import (
    IsolatedReportConfig as IsolatedReportConfig,
)
from pkcs11_check.core._run_units import (
    IsolationGranularity as IsolationGranularity,
)
from pkcs11_check.core._run_units import (
    RunnerGranularity as RunnerGranularity,
)
from pkcs11_check.core._run_units import (
    _absolute_nodeid as _absolute_nodeid,
)
from pkcs11_check.core._run_units import (
    _empty_counts as _empty_counts,
)
from pkcs11_check.core._run_units import (
    _extract_option_value as _extract_option_value,
)
from pkcs11_check.core._run_units import (
    _flatten_longrepr as _flatten_longrepr,
)
from pkcs11_check.core._run_units import (
    _state_summary as _state_summary,
)
from pkcs11_check.core._run_units import (
    _unit_file_key as _unit_file_key,
)
from pkcs11_check.core._run_units import (
    normalize_policy_file_key as normalize_policy_file_key,
)
from pkcs11_check.core.quality_audit import build_quality_audit
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import (
    map_report_outcome as _map_outcome,
)


def _load_report_log_records(jsonl_path: Path) -> list[dict[str, Any]]:
    """Load parseable JSONL report-log records from disk (streamed line-by-line)."""
    return list(_iter_report_log_records(jsonl_path))


def _report_record_cache_dir(state_file: Path) -> Path:
    return state_file.parent / f".{state_file.name}.report-records"


def _report_record_cache_path(state_file: Path, unit: str) -> Path:
    digest = hashlib.sha256(unit.encode("utf-8")).hexdigest()
    return _report_record_cache_dir(state_file) / f"{digest}.jsonl"


def _write_unit_report_record_cache(
    state_file: Path,
    unit: str,
    records: Sequence[Mapping[str, Any]],
) -> None:
    cache_path = _report_record_cache_path(state_file, unit)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )


def _write_unit_report_record_cache_from_jsonl_paths(
    state_file: Path,
    unit: str,
    jsonl_paths: Sequence[Path],
) -> None:
    """Persist one unit's report-record cache by streaming source JSONL files."""
    cache_path = _report_record_cache_path(state_file, unit)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_suffix(".jsonl.tmp")
    wrote = False
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            for jsonl_path in jsonl_paths:
                for record in _iter_report_log_records(jsonl_path):
                    out_fh.write(json.dumps(record) + "\n")
                    wrote = True
        if wrote:
            tmp_path.replace(cache_path)
        else:
            tmp_path.unlink(missing_ok=True)
            cache_path.unlink(missing_ok=True)
    finally:
        tmp_path.unlink(missing_ok=True)


def _delete_unit_report_record_cache(state_file: Path, unit: str) -> None:
    _report_record_cache_path(state_file, unit).unlink(missing_ok=True)


def _load_cached_report_records_by_unit(
    state_file: Path,
    units: list[str],
) -> dict[str, list[dict[str, Any]]]:
    cached: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        records = _load_report_log_records(_report_record_cache_path(state_file, unit))
        if records:
            cached[unit] = records
    return cached


def _ordered_report_record_units(
    units: Sequence[str],
    inline_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
) -> Iterable[str]:
    seen: set[str] = set()
    for unit in units:
        seen.add(unit)
        yield unit
    for unit in sorted(inline_records_by_unit):
        if unit not in seen:
            yield unit


def _iter_unit_report_record_source(
    state_file: Path,
    unit: str,
    inline_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
) -> Iterable[Mapping[str, Any]]:
    """Yield one unit's report records from its cache shard or inline fallback."""
    cache_path = _report_record_cache_path(state_file, unit)
    yielded_cache_record = False
    if cache_path.exists():
        for record in _iter_report_log_records(cache_path):
            yielded_cache_record = True
            yield record
        if yielded_cache_record:
            return

    for inline_record in inline_records_by_unit.get(unit, []):
        if isinstance(inline_record, Mapping):
            yield inline_record


def _write_report_jsonl_from_record_sources(
    state_file: Path,
    *,
    units: Sequence[str],
    inline_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
    output_path: Path,
) -> bool:
    """Write merged report.jsonl from per-unit cache shards without loading all records."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(".jsonl.tmp")
    wrote = False
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            for unit in _ordered_report_record_units(units, inline_records_by_unit):
                for record in _iter_unit_report_record_source(
                    state_file, unit, inline_records_by_unit
                ):
                    out_fh.write(json.dumps(record) + "\n")
                    wrote = True
        if wrote:
            tmp_path.replace(output_path)
        else:
            tmp_path.unlink(missing_ok=True)
    finally:
        tmp_path.unlink(missing_ok=True)
    return wrote


def _build_per_unit_details_from_record_sources(
    state_file: Path,
    *,
    units: Sequence[str],
    inline_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for unit in _ordered_report_record_units(units, inline_records_by_unit):
        detail = _build_detail_from_report_records(
            _iter_unit_report_record_source(state_file, unit, inline_records_by_unit)
        )
        if detail is not None:
            details[unit] = detail
    return details


# The only consumer of these records is build_quality_audit(); it reads just
# these top-level fields. Projecting to them drops the heavy unused fields
# (rv-trace user_properties, captured sections, keywords, location, timings) so
# the in-container quality pass holds ~3x less than the full records. Verified
# byte-identical against real artifacts (tests/test_jsonl_streaming.py). If the
# quality audit starts reading a new record field, add it here (the golden test
# on quality.json will catch the omission).
_QUALITY_AUDIT_RECORD_FIELDS = frozenset(
    {
        "$report_type",
        "nodeid",
        "when",
        "outcome",
        "wasxfail",
        "longrepr",
        "reason",
        "count",
        "nodeids",
        "sources",
        "selection_coverage",
        "selected_mechanisms",
        "rejected_reason_counts",
        "rejected_mechanisms",
    }
)


def extract_quality_report_records_from_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
    """Extract the quality-audit-relevant report-log records from JSONL.

    Streams + filters to TestReport/SelectionReport in one pass and projects each
    record to the fields build_quality_audit reads, so the full record set is
    never materialized.
    """
    records: list[dict[str, Any]] = []
    try:
        fh = jsonl_path.open(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("$report_type", "TestReport") in {"TestReport", "SelectionReport"}:
                records.append({k: v for k, v in rec.items() if k in _QUALITY_AUDIT_RECORD_FIELDS})
    return records


def write_quality_json_report(
    path: Path,
    results: Mapping[str, Any],
    *,
    coverage: Mapping[str, Any] | None = None,
    report_log_records: Iterable[Mapping[str, Any]] | None = None,
) -> None:
    """Write the quality audit artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_quality_audit(
        results=results,
        coverage=coverage,
        report_log_records=report_log_records,
    )
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_report_jsonl(jsonl_paths: list[Path], output_path: Path) -> None:
    """Stream-concatenate per-unit JSONL temp files into a single artifact.

    Writes to a sibling .tmp file first, then atomically renames to
    output_path.  Deletes all source JSONL temp files in a finally block
    regardless of success or failure.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(".jsonl.tmp")
    try:
        with tmp_path.open("wb") as out_fh:
            for src in jsonl_paths:
                try:
                    with src.open("rb") as in_fh:
                        shutil.copyfileobj(in_fh, out_fh)
                except (FileNotFoundError, OSError):
                    pass  # missing temp file - skip silently
        tmp_path.rename(output_path)
    finally:
        tmp_path.unlink(missing_ok=True)
        for src in jsonl_paths:
            src.unlink(missing_ok=True)


def _infer_unit_target_from_records(
    records: Sequence[Mapping[str, Any]],
    candidate_targets: set[str],
) -> str | None:
    nodeids = [
        str(record.get("nodeid", "")).strip()
        for record in records
        if record.get("$report_type", "TestReport") in {"TestReport", "CollectReport"}
        and str(record.get("nodeid", "")).strip()
    ]
    if not nodeids:
        return None

    unique_nodeids = sorted(set(nodeids))
    file_targets = sorted({nodeid.split("::", 1)[0] for nodeid in unique_nodeids})

    if len(unique_nodeids) == 1 and unique_nodeids[0] in candidate_targets:
        return unique_nodeids[0]
    if len(file_targets) == 1 and file_targets[0] in candidate_targets:
        return file_targets[0]
    if len(unique_nodeids) == 1:
        return unique_nodeids[0]
    if len(file_targets) == 1:
        return file_targets[0]
    return None


def _unit_candidate_from_record(
    record: Mapping[str, Any],
    candidate_targets: set[str],
) -> str | None:
    report_type = record.get("$report_type", "TestReport")
    if report_type not in {"TestReport", "CollectReport"}:
        return None
    nodeid = str(record.get("nodeid", "")).strip()
    if not nodeid:
        return None
    file_target = nodeid.split("::", 1)[0]
    if file_target in candidate_targets and nodeid not in candidate_targets:
        return file_target
    if nodeid in candidate_targets:
        return nodeid
    if file_target in candidate_targets:
        return file_target
    return nodeid


def _extract_unit_report_records_from_jsonl(
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
) -> dict[str, list[dict[str, Any]]]:
    """Split a merged report.jsonl back into per-unit record chunks."""
    records_by_unit: dict[str, list[dict[str, Any]]] = {}
    for unit_target, records in _iter_unit_report_record_chunks_from_jsonl(
        jsonl_path,
        candidate_targets=candidate_targets,
    ):
        records_by_unit.setdefault(unit_target, []).extend(records)
    return records_by_unit


def _iter_unit_report_record_chunks_from_jsonl(
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
) -> Iterable[tuple[str, list[dict[str, Any]]]]:
    """Yield per-unit record chunks from a merged report.jsonl without a full map."""
    current_chunk: list[dict[str, Any]] = []
    current_target: str | None = None

    def pop_current_chunk() -> tuple[str, list[dict[str, Any]]] | None:
        nonlocal current_chunk, current_target
        if not current_chunk:
            return None
        unit_target = _infer_unit_target_from_records(current_chunk, candidate_targets)
        chunk = current_chunk
        current_chunk = []
        current_target = None
        if unit_target is not None:
            return unit_target, chunk
        return None

    for record in _iter_report_log_records(jsonl_path):
        record_target = _unit_candidate_from_record(record, candidate_targets)
        if (
            current_chunk
            and current_target is not None
            and record_target is not None
            and record_target != current_target
        ):
            chunk = pop_current_chunk()
            if chunk is not None:
                yield chunk
        current_chunk.append(record)
        if current_target is None and record_target is not None:
            current_target = record_target
        if record.get("$report_type") == "CoverageReport":
            chunk = pop_current_chunk()
            if chunk is not None:
                yield chunk

    chunk = pop_current_chunk()
    if chunk is not None:
        yield chunk


def _report_record_cache_has_records(state_file: Path, unit: str) -> bool:
    for _record in _iter_report_log_records(_report_record_cache_path(state_file, unit)):
        return True
    return False


def _seed_missing_report_record_caches_from_jsonl(
    state_file: Path,
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
    skip_units: Iterable[str] = (),
) -> None:
    """Populate absent per-unit cache shards by streaming an existing merged report."""
    skip_unit_set = set(skip_units)
    existing_cache_units: set[str] = set()
    tmp_paths: dict[str, Path] = {}
    try:
        for unit, records in _iter_unit_report_record_chunks_from_jsonl(
            jsonl_path,
            candidate_targets=candidate_targets,
        ):
            if unit in skip_unit_set or unit in existing_cache_units:
                continue
            if unit not in tmp_paths and _report_record_cache_has_records(state_file, unit):
                existing_cache_units.add(unit)
                continue
            cache_path = _report_record_cache_path(state_file, unit)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = tmp_paths.get(unit)
            if tmp_path is None:
                tmp_path = cache_path.with_suffix(".jsonl.resume.tmp")
                tmp_path.unlink(missing_ok=True)
                tmp_paths[unit] = tmp_path
            with tmp_path.open("a", encoding="utf-8") as out_fh:
                for record in records:
                    out_fh.write(json.dumps(record) + "\n")
        for unit, tmp_path in tmp_paths.items():
            tmp_path.replace(_report_record_cache_path(state_file, unit))
    finally:
        for tmp_path in tmp_paths.values():
            tmp_path.unlink(missing_ok=True)


def _write_report_jsonl_from_record_map(
    report_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    units: list[str],
    output_path: Path,
) -> None:
    """Write a merged report.jsonl from in-memory per-unit record groups."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(".jsonl.tmp")
    written_units: set[str] = set()
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            for unit in units:
                for record in report_records_by_unit.get(unit, []):
                    out_fh.write(json.dumps(record) + "\n")
                written_units.add(unit)
            for unit in sorted(report_records_by_unit):
                if unit in written_units:
                    continue
                for record in report_records_by_unit[unit]:
                    out_fh.write(json.dumps(record) + "\n")
        tmp_path.rename(output_path)
    finally:
        tmp_path.unlink(missing_ok=True)


_COMPLIANCE_NOTE_FIELDS = ("description", "level", "reference", "test_id", "nodeid")


def _compliance_notes_from_user_properties(
    user_properties: Any,
    *,
    nodeid: str,
) -> list[dict[str, str]]:
    if not isinstance(user_properties, list):
        return []

    notes: list[dict[str, str]] = []
    for prop in user_properties:
        if not isinstance(prop, (list, tuple)) or len(prop) != 2:
            continue
        name, value = prop
        if name != "pkcs11_compliance_notes" or not isinstance(value, list):
            continue
        for raw_note in value:
            if not isinstance(raw_note, Mapping):
                continue
            note = {
                field: str(raw_note.get(field, ""))
                for field in _COMPLIANCE_NOTE_FIELDS
                if raw_note.get(field, "") not in (None, "")
            }
            if "nodeid" not in note and nodeid:
                note["nodeid"] = nodeid
            if note.get("description") and note.get("level"):
                notes.append(note)
    return notes


def _build_detail_from_report_records(
    records: Iterable[Mapping[str, Any]],
    *,
    call_record_hook: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any] | None:
    """Build per-unit detail payload from parsed report-log records."""
    counts: dict[str, int] = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
    }
    non_passing: list[dict[str, Any]] = []
    compliance_notes: list[dict[str, str]] = []
    seen_compliance_notes: set[tuple[tuple[str, str], ...]] = set()
    skip_reasons: dict[str, int] = {}
    seen_call: set[str] = set()
    setup_events: list[Mapping[str, Any]] = []
    call_events: list[Mapping[str, Any]] = []
    collect_errors: list[Mapping[str, Any]] = []

    for rec in records:
        if not isinstance(rec, Mapping):
            continue

        report_type = rec.get("$report_type", "TestReport")
        when = rec.get("when", "")
        outcome = rec.get("outcome", "")
        nodeid = rec.get("nodeid", "")

        if report_type == "CollectReport":
            if outcome == "passed":
                continue
            collect_errors.append(rec)
            continue

        if report_type != "TestReport":
            continue

        if when == "call":
            seen_call.add(str(nodeid))
            call_events.append(rec)
            if call_record_hook is not None:
                call_record_hook(rec)
        elif when == "setup" and outcome in ("skipped", "failed", "error"):
            setup_events.append(rec)

    for rec in call_events:
        nodeid = rec.get("nodeid", "")
        raw_outcome = rec.get("outcome", "passed")
        wasxfail = rec.get("wasxfail")
        mapped = _map_outcome(raw_outcome, wasxfail)
        counts[mapped] = counts.get(mapped, 0) + 1
        for note in _compliance_notes_from_user_properties(
            rec.get("user_properties"), nodeid=str(nodeid)
        ):
            key = tuple((field, note.get(field, "")) for field in _COMPLIANCE_NOTE_FIELDS)
            if key in seen_compliance_notes:
                continue
            seen_compliance_notes.add(key)
            compliance_notes.append(note)

        if mapped == "skipped":
            reason = _flatten_longrepr(rec.get("longrepr")) or "skipped"
            if reason.startswith("(") and "Skipped:" in reason:
                parts = reason.split("Skipped:", 1)
                if len(parts) > 1:
                    reason = parts[1].strip().rstrip("')")
            elif reason.startswith("Skipped:"):
                reason = reason[8:].strip()
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue
        if mapped == "passed":
            continue

        entry: dict[str, Any] = {
            "nodeid": nodeid,
            "outcome": mapped,
            "duration": rec.get("duration", 0.0),
        }
        if rec.get("start") is not None:
            entry["start"] = rec["start"]
        if wasxfail is not None:
            entry["wasxfail"] = wasxfail
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            entry["longrepr"] = flat
        if rec.get("location"):
            entry["location"] = rec["location"]
        for section in rec.get("sections", []):
            if isinstance(section, list) and len(section) >= 2:
                name, content = section[0], section[1]
                if "stdout" in name.lower():
                    entry["stdout"] = content
                elif "stderr" in name.lower():
                    entry["stderr"] = content
        non_passing.append(entry)

    seen_error_reprs: set[str] = set()
    for rec in setup_events:
        nodeid = rec.get("nodeid", "")
        if nodeid in seen_call:
            continue
        raw_outcome = rec.get("outcome", "")
        if raw_outcome == "skipped":
            counts["skipped"] = counts.get("skipped", 0) + 1
            reason = _flatten_longrepr(rec.get("longrepr")) or "skipped"
            if "Skipped:" in reason:
                parts = reason.split("Skipped:", 1)
                reason = parts[1].strip().rstrip("')")
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue

        counts["error"] = counts.get("error", 0) + 1
        flat = _flatten_longrepr(rec.get("longrepr"))
        dedup_key = flat or str(nodeid)
        if dedup_key in seen_error_reprs:
            continue
        seen_error_reprs.add(dedup_key)
        entry = {
            "nodeid": nodeid,
            "outcome": "error",
            "duration": rec.get("duration", 0.0),
        }
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    for rec in collect_errors:
        counts["error"] = counts.get("error", 0) + 1
        entry = {
            "nodeid": rec.get("nodeid", ""),
            "outcome": "error",
            "duration": rec.get("duration", 0.0),
        }
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    if not any(counts.values()) and not compliance_notes:
        return None
    result: dict[str, Any] = {"counts": counts, "tests": non_passing}
    if compliance_notes:
        result["compliance_notes"] = compliance_notes
    if skip_reasons:
        result["skip_reasons"] = skip_reasons
    return result


def _build_per_unit_details_from_record_map(
    report_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for unit, records in report_records_by_unit.items():
        detail = _build_detail_from_report_records(records)
        if detail is not None:
            details[unit] = detail
    return details
