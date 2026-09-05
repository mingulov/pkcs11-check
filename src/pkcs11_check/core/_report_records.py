"""Per-unit report-record cache and report.jsonl assembly for the isolated runner.

Moved verbatim from file_runner.py (god-module split, 2026-07-17): streaming record
cache (one file per unit), report.jsonl writers built from record sources, and the
per-unit detail builders derived from report records.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
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
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.crash_codes import (
    CTYPES_ACCESS_VIOLATION,
    ctypes_access_violation_from_stderr,
)
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.quality_audit import build_quality_audit
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import (
    map_report_record_outcome as _map_record_outcome,
)

_ISOLATED_UNIT_REPORT_TYPE = "IsolatedUnitReport"


def _resolved_report_file(path: str, cwd: Path) -> str:
    normalized = normalize_nodeid(path)
    candidate = Path(normalized)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    return normalize_nodeid(str(candidate.resolve()))


@dataclass(frozen=True)
class _ReportOwnerAliases:
    """Authoritative report aliases derived from scheduling and collection metadata."""

    file_identities_by_alias: Mapping[str, str]
    file_identities_by_candidate: Mapping[str, str]
    candidates_by_alias: Mapping[str, str]
    candidates_by_canonical_nodeid: Mapping[str, str]
    file_owners: Mapping[str, str]
    report_targets: Mapping[str, str]

    def file_identity(self, target: str) -> str | None:
        normalized = normalize_nodeid(target.strip())
        candidate_identity = self.file_identities_by_candidate.get(normalized)
        if candidate_identity is not None:
            return candidate_identity
        return self.file_identities_by_alias.get(normalized.split("::", 1)[0])

    def canonical_nodeid(self, nodeid: str) -> str | None:
        normalized = normalize_nodeid(nodeid.strip())
        file_identity = self.file_identity(normalized)
        if file_identity is None:
            return None
        return normalize_nodeid(_absolute_nodeid(file_identity, normalized))

    def owner_for_nodeid(self, nodeid: str) -> str | None:
        normalized = normalize_nodeid(nodeid.strip())
        direct = self.candidates_by_alias.get(normalized)
        if direct is not None:
            file_identity = self.file_identity(direct)
            if file_identity is not None and file_identity in self.file_owners:
                return self.file_owners[file_identity]
            return direct
        file_identity = self.file_identity(normalized)
        if file_identity is None:
            return None
        file_owner = self.file_owners.get(file_identity)
        if file_owner is not None:
            return file_owner
        canonical = self.canonical_nodeid(normalized)
        return self.candidates_by_canonical_nodeid.get(canonical or "")

    def candidate_for_target(self, target: str) -> str | None:
        normalized = normalize_nodeid(target.strip())
        direct = self.candidates_by_alias.get(normalized)
        if direct is not None:
            return direct
        canonical = self.canonical_nodeid(normalized)
        return self.candidates_by_canonical_nodeid.get(canonical or "")

    def possible_legacy_owners(self, nodeid: str) -> frozenset[str]:
        file_identity = self.file_identity(nodeid)
        if file_identity is None:
            return frozenset()
        owners = {self.file_owners[file_identity]} if file_identity in self.file_owners else set()
        canonical = self.canonical_nodeid(nodeid)
        exact = self.candidates_by_canonical_nodeid.get(canonical or "")
        if exact is not None:
            owners.add(exact)
        return frozenset(owners)

    def report_target(self, file_identity: str) -> str | None:
        return self.report_targets.get(file_identity)


def _build_report_owner_aliases(
    candidate_targets: Sequence[str],
    collected_items: Sequence[CollectedPytestItem] = (),
    *,
    cwd: Path | None = None,
) -> _ReportOwnerAliases:
    """Build the one report-owner index used by resume extraction and reporting."""
    base = (cwd or Path.cwd()).resolve()
    file_identities_by_alias: dict[str, str] = {}
    file_identities_by_candidate: dict[str, str] = {}
    candidates_by_alias: dict[str, str] = {}
    candidates_by_canonical_nodeid: dict[str, str] = {}
    candidates_by_file: dict[str, list[str]] = {}

    def register_file_alias(alias: str, file_identity: str) -> None:
        normalized_alias = normalize_nodeid(alias.strip()).split("::", 1)[0]
        prior = file_identities_by_alias.get(normalized_alias)
        if prior is not None and prior != file_identity:
            raise ValueError(
                "ambiguous report owner alias "
                f"{normalized_alias!r}: collected as both {prior!r} and {file_identity!r}"
            )
        file_identities_by_alias[normalized_alias] = file_identity

    ordered_candidates = list(dict.fromkeys(str(target) for target in candidate_targets))
    for target in ordered_candidates:
        normalized = normalize_nodeid(target.strip())
        if not normalized:
            continue
        file_part = normalized.split("::", 1)[0]
        file_identity = _resolved_report_file(file_part, base)
        register_file_alias(file_part, file_identity)
        register_file_alias(file_identity, file_identity)
        file_identities_by_candidate[normalized] = file_identity
        candidates_by_alias.setdefault(normalized, target)
        candidates_by_file.setdefault(file_identity, []).append(target)
        canonical = normalize_nodeid(_absolute_nodeid(file_identity, normalized))
        candidates_by_canonical_nodeid.setdefault(canonical, target)

    for item in collected_items:
        raw_nodeid = normalize_nodeid(item.nodeid.strip())
        if not raw_nodeid:
            continue
        file_identity = _resolved_report_file(item.file_path, base)
        register_file_alias(raw_nodeid, file_identity)
        register_file_alias(item.file_path, file_identity)
        register_file_alias(file_identity, file_identity)

    file_owners: dict[str, str] = {}
    report_targets: dict[str, str] = {}
    for file_identity, candidates in candidates_by_file.items():
        bare_candidates = [candidate for candidate in candidates if "::" not in candidate]
        if bare_candidates:
            file_owners[file_identity] = bare_candidates[0]
            report_targets[file_identity] = bare_candidates[0]
        else:
            report_targets[file_identity] = candidates[0].split("::", 1)[0]

    return _ReportOwnerAliases(
        file_identities_by_alias=file_identities_by_alias,
        file_identities_by_candidate=file_identities_by_candidate,
        candidates_by_alias=candidates_by_alias,
        candidates_by_canonical_nodeid=candidates_by_canonical_nodeid,
        file_owners=file_owners,
        report_targets=report_targets,
    )


def _isolated_unit_report(unit: str, attempt: int) -> dict[str, Any]:
    return {
        "$report_type": _ISOLATED_UNIT_REPORT_TYPE,
        "target": unit,
        "attempt": attempt,
    }


def _load_report_log_records(jsonl_path: Path) -> list[dict[str, Any]]:
    """Load parseable JSONL report-log records from disk (streamed line-by-line)."""
    return list(_iter_report_log_records(jsonl_path))


def _canonical_executions(
    *groups: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Canonicalize executions in their supplied order."""
    executions: list[dict[str, Any]] = []
    attempts: dict[tuple[str, str, str], int] = {}
    for group in groups:
        for raw in group:
            if not isinstance(raw, Mapping):
                continue
            execution = dict(raw)
            key = (
                str(execution.get("parent_nodeid") or ""),
                str(execution.get("role") or ""),
                str(execution.get("target") or ""),
            )
            execution["attempt"] = attempts.get(key, 0)
            attempts[key] = execution["attempt"] + 1
            executions.append(execution)
    return executions


def _process_observations_from_user_properties(user_properties: Any) -> list[dict[str, Any]]:
    if not isinstance(user_properties, list):
        return []
    observations: list[dict[str, Any]] = []
    for prop in user_properties:
        if not isinstance(prop, (list, tuple)) or len(prop) != 2:
            continue
        name, value = prop
        if name != "pkcs11_process_observations" or not isinstance(value, list):
            continue
        observations.extend(dict(item) for item in value if isinstance(item, Mapping))
    return observations


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
    next_attempt = 0
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            for jsonl_path in jsonl_paths:
                source_started = False
                for record in _iter_report_log_records(jsonl_path):
                    if record.get("$report_type") == _ISOLATED_UNIT_REPORT_TYPE:
                        source_started = True
                        raw_attempt = record.get("attempt")
                        if isinstance(raw_attempt, int):
                            next_attempt = max(next_attempt, raw_attempt + 1)
                    elif not source_started:
                        out_fh.write(json.dumps(_isolated_unit_report(unit, next_attempt)) + "\n")
                        next_attempt += 1
                        source_started = True
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


def _saved_process_observations(state_file: Path) -> list[dict[str, Any]]:
    """Read saved outer observations without making run-state a module dependency."""
    try:
        raw = json.loads(state_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    observations = raw.get("process_observations", []) if isinstance(raw, dict) else []
    if not isinstance(observations, list):
        return []
    return [dict(item) for item in observations if isinstance(item, Mapping)]


def _saved_process_observations_complete(state_file: Path) -> bool:
    try:
        raw = json.loads(state_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return False
    observations = raw.get("process_observations") if isinstance(raw, dict) else None
    return (
        raw.get("process_observations_complete") is True
        and isinstance(observations, list)
        and all(isinstance(observation, Mapping) for observation in observations)
    )


def _process_observation_key(observation: Mapping[str, Any]) -> str:
    return json.dumps(observation, sort_keys=True, separators=(",", ":"))


def _execution_owner_file(execution: Mapping[str, Any]) -> str | None:
    """Return the owning file, rejecting malformed nested ownership."""
    target = normalize_nodeid(str(execution.get("target", "")).strip())
    parent_value = execution.get("parent_nodeid")
    if parent_value is None:
        if execution.get("role") == "probe":
            return None
        return target.split("::", 1)[0] or None
    if not isinstance(parent_value, str):
        return None
    parent_nodeid = normalize_nodeid(parent_value.strip())
    if not parent_nodeid:
        return None
    return parent_nodeid.split("::", 1)[0] or None


def _reconcile_process_observations(
    prior_observations: Sequence[Mapping[str, Any]],
    saved_observations: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge saved occurrences not already present in prior source history."""
    reconciled = [dict(observation) for observation in prior_observations]
    prior_counts = Counter(_process_observation_key(observation) for observation in reconciled)
    for observation in saved_observations:
        key = _process_observation_key(observation)
        if prior_counts[key] > 0:
            prior_counts[key] -= 1
            continue
        reconciled.append(dict(observation))
    return reconciled


def _hydrate_process_observations(
    saved_observations: Sequence[Mapping[str, Any]],
    jsonl_path: Path | None,
) -> list[dict[str, Any]]:
    """Recover outer observations from a legacy state and its global JSONL log."""
    recovered: list[dict[str, Any]] = []
    seen_records: set[str] = set()
    if jsonl_path is not None:
        for record in _iter_report_log_records(jsonl_path):
            if record.get("$report_type") != "ProcessReport":
                continue
            source_key = json.dumps(record, sort_keys=True, separators=(",", ":"))
            if source_key in seen_records:
                continue
            seen_records.add(source_key)
            observation = record.get("observation")
            if isinstance(observation, Mapping) and observation.get("parent_nodeid") is None:
                recovered.append(dict(observation))

    return _canonical_executions(_reconcile_process_observations(recovered, saved_observations))


def _write_report_jsonl_from_record_sources(
    state_file: Path,
    *,
    units: Sequence[str],
    inline_records_by_unit: Mapping[str, Sequence[Mapping[str, Any]]],
    output_path: Path,
    attempt_history: Sequence[Mapping[str, Any]] = (),
    recovery_events: Sequence[Mapping[str, Any]] = (),
    collection_failure_path: Path | None = None,
) -> bool:
    """Write merged report.jsonl from per-unit cache shards without loading all records."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(".jsonl.tmp")
    wrote = False
    durable_events = [event for event in recovery_events if isinstance(event, Mapping)]
    if not durable_events:
        seen_events: set[str] = set()
        for attempt in attempt_history:
            event = attempt.get("recovery_event") if isinstance(attempt, Mapping) else None
            if not isinstance(event, Mapping):
                continue
            event_key = json.dumps(event, sort_keys=True, separators=(",", ":"))
            if event_key not in seen_events:
                seen_events.add(event_key)
                durable_events.append(dict(event))
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            collection_records = (
                _load_report_log_records(collection_failure_path)
                if collection_failure_path is not None
                else []
            )
            collection_keys = {
                json.dumps(record, sort_keys=True, separators=(",", ":"))
                for record in collection_records
            }
            saved_observations = [
                observation
                for observation in _saved_process_observations(state_file)
                if observation.get("parent_nodeid") is None
            ]
            if _saved_process_observations_complete(state_file):
                for observation in saved_observations:
                    out_fh.write(
                        json.dumps(
                            {
                                "$report_type": "ProcessReport",
                                "target": observation.get("target", ""),
                                "observation": observation,
                            }
                        )
                        + "\n"
                    )
                    wrote = True
            else:
                cached_observations: list[dict[str, Any]] = []
                seen_process_records: set[str] = set()

                # Legacy state has no global sequence; recover source process history first.
                for unit in _ordered_report_record_units(units, inline_records_by_unit):
                    for record in _iter_unit_report_record_source(
                        state_file, unit, inline_records_by_unit
                    ):
                        if record.get("$report_type") != "ProcessReport":
                            continue
                        source_key = json.dumps(record, sort_keys=True, separators=(",", ":"))
                        if source_key in seen_process_records:
                            continue
                        seen_process_records.add(source_key)
                        source_observation = record.get("observation")
                        if isinstance(source_observation, Mapping) and (
                            source_observation.get("parent_nodeid") is None
                        ):
                            cached_observations.append(dict(source_observation))

                # Reconcile source history and saved occurrences, then canonicalize once.
                for observation in _canonical_executions(
                    _reconcile_process_observations(cached_observations, saved_observations)
                ):
                    out_fh.write(
                        json.dumps(
                            {
                                "$report_type": "ProcessReport",
                                "target": observation.get("target", ""),
                                "observation": observation,
                            }
                        )
                        + "\n"
                    )
                    wrote = True

            # Ordinary records are always sourced from report-record shards.
            for event in durable_events:
                if not isinstance(event, Mapping):
                    continue
                out_fh.write(
                    json.dumps(
                        {
                            "$report_type": "RecoveryEvent",
                            "event_id": event.get("event_id", ""),
                            "target": event.get("trigger_unit", ""),
                            "event": dict(event),
                        }
                    )
                    + "\n"
                )
                wrote = True
            for attempt in attempt_history:
                if not isinstance(attempt, Mapping):
                    continue
                out_fh.write(
                    json.dumps(
                        {
                            "$report_type": "RecoveryAttempt",
                            "target": attempt.get("target", ""),
                            "attempt": dict(attempt),
                        }
                    )
                    + "\n"
                )
                wrote = True
            for unit in _ordered_report_record_units(units, inline_records_by_unit):
                source_started = False
                for record in _iter_unit_report_record_source(
                    state_file, unit, inline_records_by_unit
                ):
                    if record.get("$report_type") in {"ProcessReport", "RecoveryEvent"}:
                        continue
                    if (
                        collection_keys
                        and json.dumps(record, sort_keys=True, separators=(",", ":"))
                        in collection_keys
                    ):
                        continue
                    if not source_started:
                        if record.get("$report_type") != _ISOLATED_UNIT_REPORT_TYPE:
                            out_fh.write(json.dumps(_isolated_unit_report(unit, 0)) + "\n")
                            wrote = True
                        source_started = True
                    out_fh.write(json.dumps(record) + "\n")
                    wrote = True
            for record in collection_records:
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
    *,
    owner_aliases: _ReportOwnerAliases | None = None,
) -> str | None:
    aliases = owner_aliases or _build_report_owner_aliases(sorted(candidate_targets))
    owners: list[str] = []
    explicit_owner: str | None = None
    for record in records:
        report_type = record.get("$report_type", "TestReport")
        if report_type not in {
            "TestReport",
            "CollectReport",
            "HarnessError",
            "ProcessReport",
            _ISOLATED_UNIT_REPORT_TYPE,
        }:
            continue
        field = (
            "target"
            if report_type in {"ProcessReport", _ISOLATED_UNIT_REPORT_TYPE}
            else "nodeid"
        )
        value = str(record.get(field, "")).strip()
        if report_type == "CollectReport" and not value and record.get("outcome") == "passed":
            continue
        if report_type == _ISOLATED_UNIT_REPORT_TYPE:
            owner = aliases.candidate_for_target(value) if value else None
            if owner is None:
                raise ValueError(
                    "cannot safely reconstruct report ownership; "
                    f"unknown owner marker {value!r}"
                )
            if explicit_owner is not None and owner != explicit_owner:
                raise ValueError(
                    "ambiguous explicit report ownership within one record chunk: "
                    f"{explicit_owner}, {owner}"
                )
            explicit_owner = owner
            continue

        if report_type == "ProcessReport":
            owner = aliases.candidate_for_target(value) if value else None
            possible_owners = frozenset({owner}) if owner is not None else frozenset()
        else:
            possible_owners = aliases.possible_legacy_owners(value) if value else frozenset()
        if explicit_owner is not None:
            if possible_owners and explicit_owner not in possible_owners:
                raise ValueError(
                    "conflicting report ownership: "
                    f"marker owns {explicit_owner!r}, record belongs to "
                    f"{', '.join(sorted(possible_owners))}"
                )
            continue
        if not possible_owners:
            raise ValueError(
                "cannot safely reconstruct report ownership; "
                f"unmarked record owner {value!r} is unknown"
            )
        if len(possible_owners) > 1:
            raise ValueError(
                "ambiguous legacy report ownership for "
                f"{value!r}: {', '.join(sorted(possible_owners))}"
            )
        owners.extend(possible_owners)

    if explicit_owner is not None:
        return explicit_owner
    if not owners:
        return None
    unique_owners = list(dict.fromkeys(owners))
    if len(unique_owners) != 1:
        raise ValueError(
            "ambiguous report ownership within one legacy record chunk: "
            + ", ".join(unique_owners)
        )
    return unique_owners[0]


def _unit_candidate_from_record(
    record: Mapping[str, Any],
    candidate_targets: set[str],
    *,
    owner_aliases: _ReportOwnerAliases | None = None,
) -> str | None:
    aliases = owner_aliases or _build_report_owner_aliases(sorted(candidate_targets))
    report_type = record.get("$report_type", "TestReport")
    if report_type not in {
        "TestReport",
        "CollectReport",
        "HarnessError",
        "ProcessReport",
        _ISOLATED_UNIT_REPORT_TYPE,
    }:
        return None
    field = (
        "target" if report_type in {"ProcessReport", _ISOLATED_UNIT_REPORT_TYPE} else "nodeid"
    )
    nodeid = str(record.get(field, "")).strip()
    if not nodeid:
        return None
    if report_type in {"ProcessReport", _ISOLATED_UNIT_REPORT_TYPE}:
        return aliases.candidate_for_target(nodeid)
    return aliases.owner_for_nodeid(nodeid)


def _extract_unit_report_records_from_jsonl(
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
    owner_aliases: _ReportOwnerAliases | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Split a merged report.jsonl back into per-unit record chunks."""
    records_by_unit: dict[str, list[dict[str, Any]]] = {}
    for unit_target, records in _iter_unit_report_record_chunks_from_jsonl(
        jsonl_path,
        candidate_targets=candidate_targets,
        owner_aliases=owner_aliases,
    ):
        records_by_unit.setdefault(unit_target, []).extend(records)
    return records_by_unit


def _iter_unit_report_record_chunks_from_jsonl(
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
    owner_aliases: _ReportOwnerAliases | None = None,
) -> Iterable[tuple[str, list[dict[str, Any]]]]:
    """Yield per-unit record chunks from a merged report.jsonl without a full map."""
    aliases = owner_aliases or _build_report_owner_aliases(sorted(candidate_targets))
    current_chunk: list[dict[str, Any]] = []
    current_target: str | None = None

    def pop_current_chunk() -> tuple[str, list[dict[str, Any]]] | None:
        nonlocal current_chunk, current_target
        if not current_chunk:
            return None
        unit_target = _infer_unit_target_from_records(
            current_chunk,
            candidate_targets,
            owner_aliases=aliases,
        )
        chunk = current_chunk
        current_chunk = []
        current_target = None
        if unit_target is not None:
            return unit_target, chunk
        raise ValueError(
            "cannot safely reconstruct report ownership; original report was not replaced"
        )

    for record in _iter_report_log_records(jsonl_path):
        # RecoveryAttempt is a global archival record, not part of the preceding unit's
        # TestReport chunk. The final merge writes the authoritative state history once.
        if record.get("$report_type") in {"RecoveryAttempt", _ISOLATED_UNIT_REPORT_TYPE}:
            chunk = pop_current_chunk()
            if chunk is not None:
                yield chunk
            if record.get("$report_type") == "RecoveryAttempt":
                continue
        record_target = _unit_candidate_from_record(
            record,
            candidate_targets,
            owner_aliases=aliases,
        )
        if (
            current_chunk
            and current_chunk[0].get("$report_type") == _ISOLATED_UNIT_REPORT_TYPE
        ):
            record_target = current_target
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

    chunk = pop_current_chunk()
    if chunk is not None:
        yield chunk


def _report_record_cache_has_records(state_file: Path, unit: str) -> bool:
    for _record in _iter_report_log_records(_report_record_cache_path(state_file, unit)):
        return True
    return False


def _validate_legacy_report_ownership(
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
    owner_aliases: _ReportOwnerAliases,
) -> None:
    """Validate every source chunk before replacing any report-record cache."""
    for _unit, _records in _iter_unit_report_record_chunks_from_jsonl(
        jsonl_path,
        candidate_targets=candidate_targets,
        owner_aliases=owner_aliases,
    ):
        pass


def _seed_missing_report_record_caches_from_jsonl(
    state_file: Path,
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
    skip_units: Iterable[str] = (),
    owner_aliases: _ReportOwnerAliases | None = None,
) -> None:
    """Populate absent per-unit cache shards by streaming an existing merged report."""
    skip_unit_set = set(skip_units)
    if all(
        unit in skip_unit_set or _report_record_cache_has_records(state_file, unit)
        for unit in candidate_targets
    ):
        return
    aliases = owner_aliases or _build_report_owner_aliases(sorted(candidate_targets))
    _validate_legacy_report_ownership(
        jsonl_path,
        candidate_targets=candidate_targets,
        owner_aliases=aliases,
    )
    existing_cache_units: set[str] = set()
    tmp_paths: dict[str, Path] = {}
    attempts_by_unit: dict[str, int] = {}
    try:
        for unit, records in _iter_unit_report_record_chunks_from_jsonl(
            jsonl_path,
            candidate_targets=candidate_targets,
            owner_aliases=aliases,
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
                if not any(
                    record.get("$report_type") == _ISOLATED_UNIT_REPORT_TYPE
                    for record in records
                ):
                    attempt = attempts_by_unit.get(unit, 0)
                    out_fh.write(json.dumps(_isolated_unit_report(unit, attempt)) + "\n")
                    attempts_by_unit[unit] = attempt + 1
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
    result_record_hook: Callable[[Mapping[str, Any]], None] | None = None,
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
    teardown_events: list[Mapping[str, Any]] = []
    collect_errors: list[Mapping[str, Any]] = []
    harness_errors: list[Mapping[str, Any]] = []
    collect_error_files: set[str] = set()
    finalize_events: list[Mapping[str, Any]] = []
    execution_records_seen: set[str] = set()
    execution_observations: list[dict[str, Any]] = []

    for rec in records:
        if not isinstance(rec, Mapping):
            continue

        report_type = rec.get("$report_type", "TestReport")
        when = rec.get("when", "")
        outcome = rec.get("outcome", "")
        nodeid = rec.get("nodeid", "")

        if report_type == "ProcessReport":
            observation = rec.get("observation")
            if isinstance(observation, Mapping):
                source_key = json.dumps(rec, sort_keys=True, separators=(",", ":"))
                if source_key not in execution_records_seen:
                    execution_records_seen.add(source_key)
                    execution_observations.append(dict(observation))
            continue

        if report_type == "TeardownFinalize":
            finalize_events.append(rec)
            continue

        if report_type == "CollectReport":
            if outcome != "failed":
                continue
            collect_errors.append(rec)
            continue

        if report_type == "HarnessError":
            harness_errors.append(rec)
            continue

        if report_type != "TestReport":
            continue

        if when == "call":
            seen_call.add(str(nodeid))
            call_events.append(rec)
            observations = _process_observations_from_user_properties(rec.get("user_properties"))
            if observations:
                source_key = json.dumps(rec, sort_keys=True, separators=(",", ":"))
                if source_key not in execution_records_seen:
                    execution_records_seen.add(source_key)
                    execution_observations.extend(observations)
        elif when == "setup" and outcome in ("skipped", "failed", "error"):
            setup_events.append(rec)
        elif when == "teardown" and outcome in ("failed", "error"):
            teardown_events.append(rec)

    teardown_nodeids = {str(rec.get("nodeid", "")) for rec in teardown_events}

    for rec in call_events:
        nodeid = rec.get("nodeid", "")
        raw_outcome = rec.get("outcome", "passed")
        wasxfail = rec.get("wasxfail")
        for note in _compliance_notes_from_user_properties(
            rec.get("user_properties"), nodeid=str(nodeid)
        ):
            key = tuple((field, note.get(field, "")) for field in _COMPLIANCE_NOTE_FIELDS)
            if key in seen_compliance_notes:
                continue
            seen_compliance_notes.add(key)
            compliance_notes.append(note)

        overridden_by_teardown = str(nodeid) in teardown_nodeids
        if result_record_hook is not None and not overridden_by_teardown:
            result_record_hook(rec)
        mapped = _map_record_outcome(rec)
        if not overridden_by_teardown:
            counts[mapped] = counts.get(mapped, 0) + 1

        if mapped == "skipped":
            if overridden_by_teardown:
                continue
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
            if result_record_hook is not None:
                result_record_hook(rec)
            counts["skipped"] = counts.get("skipped", 0) + 1
            reason = _flatten_longrepr(rec.get("longrepr")) or "skipped"
            if "Skipped:" in reason:
                parts = reason.split("Skipped:", 1)
                reason = parts[1].strip().rstrip("')")
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue

        mapped = _map_record_outcome(rec)
        effective_outcome = "crashed" if mapped == "crashed" else "error"
        if result_record_hook is not None:
            result_record_hook({**rec, "outcome": effective_outcome})
        counts[effective_outcome] = counts.get(effective_outcome, 0) + 1
        flat = _flatten_longrepr(rec.get("longrepr"))
        dedup_key = flat or str(nodeid)
        if dedup_key in seen_error_reprs:
            continue
        seen_error_reprs.add(dedup_key)
        entry = {
            "nodeid": nodeid,
            "outcome": effective_outcome,
            "duration": rec.get("duration", 0.0),
        }
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    for rec in teardown_events:
        nodeid = rec.get("nodeid", "")
        mapped = _map_record_outcome(rec)
        effective_outcome = "crashed" if mapped == "crashed" else "error"
        if result_record_hook is not None:
            result_record_hook({**rec, "outcome": effective_outcome})
        counts[effective_outcome] = counts.get(effective_outcome, 0) + 1
        flat = _flatten_longrepr(rec.get("longrepr"))
        entry = {
            "nodeid": nodeid,
            "outcome": effective_outcome,
            "duration": rec.get("duration", 0.0),
        }
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    for rec in collect_errors:
        counts["error"] = counts.get("error", 0) + 1
        nodeid = str(rec.get("nodeid", ""))
        file_part = nodeid.split("::", 1)[0] or "<collection>"
        collect_error_files.add(file_part)
        if result_record_hook is not None:
            result_record_hook({**rec, "nodeid": file_part, "outcome": "error"})
        entry = {
            "nodeid": nodeid or file_part,
            "outcome": "error",
            "evidence_type": "collection",
            "duration": rec.get("duration", 0.0),
        }
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    for rec in harness_errors:
        counts["error"] = counts.get("error", 0) + 1
        nodeid = str(rec.get("nodeid") or rec.get("target") or "<harness>")
        harness_entry: dict[str, Any] = {
            "nodeid": nodeid,
            "outcome": "error",
            "evidence_type": "harness",
            "duration": rec.get("duration", 0.0),
        }
        for field in ("returncode", "completion_verified", "stdout", "stderr"):
            if field in rec:
                harness_entry[field] = rec[field]
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            harness_entry["longrepr"] = flat
        non_passing.append(harness_entry)
        if result_record_hook is not None:
            result_record_hook({**rec, "nodeid": nodeid, "outcome": "error"})

    if finalize_events:

        def finalize_outcome(rec: Mapping[str, Any]) -> str | None:
            error = rec.get("error")
            if rec.get("windows_status") == CTYPES_ACCESS_VIOLATION or (
                ctypes_access_violation_from_stderr(str(error)) is not None
            ):
                return "crashed"
            outcome = str(rec.get("outcome", "")).casefold()
            if outcome == "ok":
                return None
            if outcome in {"crashed", "timeout"}:
                return outcome
            return "error"

        priority = {None: 0, "error": 1, "crashed": 2, "timeout": 3}
        finalize = max(finalize_events, key=lambda rec: priority[finalize_outcome(rec)])
        finalize_effective_outcome = finalize_outcome(finalize)
        if finalize_effective_outcome is not None:
            error = str(finalize.get("error") or "").strip()
            if not error:
                rv = finalize.get("rv")
                rv_name = finalize.get("rv_name") or "unknown CK_RV"
                if rv is None:
                    rv_text = "unknown"
                else:
                    try:
                        rv_text = f"0x{int(rv):08x}"
                    except (TypeError, ValueError):
                        rv_text = str(rv)
                error = f"C_Finalize returned {rv_name} ({rv_text})"
            entry = {
                "nodeid": "C_Finalize::teardown",
                "outcome": finalize_effective_outcome,
                "duration": 0.0,
                "longrepr": error,
            }
            counts[finalize_effective_outcome] = counts.get(finalize_effective_outcome, 0) + 1
            non_passing.append(entry)
            if result_record_hook is not None:
                result_record_hook(
                    {
                        "$report_type": "TestReport",
                        "when": "teardown",
                        **entry,
                    }
                )

    executions = execution_observations
    if not any(counts.values()) and not compliance_notes and not executions:
        return None
    result: dict[str, Any] = {"counts": counts, "tests": non_passing}
    if collect_errors:
        result["incomplete"] = True
        if collect_error_files:
            result["incomplete_files"] = sorted(collect_error_files)
    if harness_errors:
        result["incomplete"] = True
        result["harness_error"] = True
    if compliance_notes:
        result["compliance_notes"] = compliance_notes
    if skip_reasons:
        result["skip_reasons"] = skip_reasons
    if executions:
        result["executions"] = executions
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
