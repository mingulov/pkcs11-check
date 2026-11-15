"""Coverage / provisioning extraction from report.jsonl and unified postprocessing.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from pkcs11_check.core._report_records import (
    _COMPLIANCE_NOTE_FIELDS as _COMPLIANCE_NOTE_FIELDS,
)
from pkcs11_check.core._report_records import (
    _QUALITY_AUDIT_RECORD_FIELDS as _QUALITY_AUDIT_RECORD_FIELDS,
)
from pkcs11_check.core._report_records import (
    _build_detail_from_report_records as _build_detail_from_report_records,
)
from pkcs11_check.core._report_records import (
    _build_per_unit_details_from_record_map as _build_per_unit_details_from_record_map,
)
from pkcs11_check.core._report_records import (
    _build_per_unit_details_from_record_sources as _build_per_unit_details_from_record_sources,
)
from pkcs11_check.core._report_records import (
    _canonical_executions as _canonical_executions,
)
from pkcs11_check.core._report_records import (
    _compliance_notes_from_user_properties as _compliance_notes_from_user_properties,
)
from pkcs11_check.core._report_records import (
    _delete_unit_report_record_cache as _delete_unit_report_record_cache,
)
from pkcs11_check.core._report_records import (
    _execution_owner_file as _execution_owner_file,
)
from pkcs11_check.core._report_records import (
    _extract_unit_report_records_from_jsonl as _extract_unit_report_records_from_jsonl,
)
from pkcs11_check.core._report_records import (
    _infer_unit_target_from_records as _infer_unit_target_from_records,
)
from pkcs11_check.core._report_records import (
    _iter_unit_report_record_chunks_from_jsonl as _iter_unit_report_record_chunks_from_jsonl,
)
from pkcs11_check.core._report_records import (
    _iter_unit_report_record_source as _iter_unit_report_record_source,
)
from pkcs11_check.core._report_records import (
    _load_cached_report_records_by_unit as _load_cached_report_records_by_unit,
)
from pkcs11_check.core._report_records import (
    _load_report_log_records as _load_report_log_records,
)
from pkcs11_check.core._report_records import (
    _ordered_report_record_units as _ordered_report_record_units,
)
from pkcs11_check.core._report_records import (
    _report_record_cache_dir as _report_record_cache_dir,
)
from pkcs11_check.core._report_records import (
    _report_record_cache_has_records as _report_record_cache_has_records,
)
from pkcs11_check.core._report_records import (
    _report_record_cache_path as _report_record_cache_path,
)
from pkcs11_check.core._report_records import (
    _seed_missing_report_record_caches_from_jsonl as _seed_missing_report_record_caches_from_jsonl,
)
from pkcs11_check.core._report_records import (
    _unit_candidate_from_record as _unit_candidate_from_record,
)
from pkcs11_check.core._report_records import (
    _write_report_jsonl_from_record_map as _write_report_jsonl_from_record_map,
)
from pkcs11_check.core._report_records import (
    _write_report_jsonl_from_record_sources as _write_report_jsonl_from_record_sources,
)
from pkcs11_check.core._report_records import (
    _write_unit_report_record_cache as _write_unit_report_record_cache,
)
from pkcs11_check.core._report_records import (
    _write_unit_report_record_cache_from_jsonl_paths as _write_unit_report_record_cache_from_jsonl_paths,  # noqa: E501
)
from pkcs11_check.core._report_records import (
    extract_quality_report_records_from_jsonl as extract_quality_report_records_from_jsonl,
)
from pkcs11_check.core._report_records import (
    write_quality_json_report as write_quality_json_report,
)
from pkcs11_check.core._report_records import (
    write_report_jsonl as write_report_jsonl,
)
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
from pkcs11_check.core.call_counters import (
    CALL_COUNTERS_PROPERTY,
    CALL_COUNTERS_REPORT_TYPE,
    merge_serialized,
)
from pkcs11_check.core.report_log import (
    _ISOLATED_UNIT_REPORT_TYPE as _ISOLATED_UNIT_REPORT_TYPE,
)
from pkcs11_check.core.report_log import (
    SessionCompletionTracker as _SessionCompletionTracker,
)
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import (
    map_report_record_outcome as _map_record_outcome,
)
from pkcs11_check.core.report_log import (
    user_property as _user_property,
)
from pkcs11_check.core.run_metrics import (
    RESULT_OUTCOME_KEYS,
    compute_child_subprocess_counts,
    run_is_incomplete,
)


def extract_coverage_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Extract and merge CoverageReport entries from a JSONL artifact.

    Returns a merged coverage dict with function_coverage and mechanism_coverage,
    or None if no CoverageReport entries are found.
    """
    from collections import Counter

    all_called: set[str] = set()
    all_uncalled: set[str] = set()
    func_available = 0
    all_invoked: set[str] = set()
    all_not_invoked: set[str] = set()
    all_available_mechs: set[str] = set()
    all_advertised_mechs: set[str] = set()
    all_selected_mechs: set[str] = set()
    all_selection_rejected_mechs: set[str] = set()
    all_attempted_mechs: set[str] = set()
    all_accepted_mechs: set[str] = set()
    all_rejected_cleanly_mechs: set[str] = set()
    all_skipped_by_capability_mechs: set[str] = set()
    all_crashed_mechs: set[str] = set()
    all_timeout_mechs: set[str] = set()
    all_detail: set[str] = set()
    all_func_counts: Counter[str] = Counter()
    all_ok_counts: Counter[str] = Counter()
    all_bootstrap_counts: Counter[str] = Counter()
    all_module_session_health_checks = 0
    all_module_session_health_duration_s = 0.0
    all_mech_counts: Counter[str] = Counter()
    all_detail_counts: Counter[str] = Counter()
    found = False

    # Streamed via the shared binary-decode iterator (report_log.iter_report_log_records)
    # rather than a text-mode `for line in fh` loop, so a single undecodable byte anywhere
    # in the file only drops that one line instead of raising UnicodeDecodeError and losing
    # every remaining record.
    for rec in _iter_report_log_records(jsonl_path):
        if rec.get("$report_type") != "CoverageReport":
            continue
        found = True
        fc = rec.get("function_coverage", {})
        func_available = max(func_available, fc.get("available", 0))
        all_called.update(fc.get("called_names", []))
        all_uncalled.update(fc.get("uncalled_names", []))
        all_func_counts.update(fc.get("called_counts", {}))
        # ok_counts (per-function CKR_OK counts) feed the hollow-pass oracle's productive
        # numerator; without carrying it here productive_ok is always empty (every claimed
        # operation would look hollow).
        all_ok_counts.update(fc.get("ok_counts", {}))
        all_bootstrap_counts.update(fc.get("bootstrap_counts", {}))
        module_session_health = fc.get("module_session_health", {})
        if isinstance(module_session_health, dict):
            all_module_session_health_checks += int(module_session_health.get("checks", 0) or 0)
            all_module_session_health_duration_s += float(
                module_session_health.get("duration_s", 0.0) or 0.0
            )
        mc = rec.get("mechanism_coverage", {})
        all_available_mechs.update(mc.get("available_names", []))
        all_invoked.update(mc.get("invoked_names", []))
        all_not_invoked.update(mc.get("not_invoked_names", []))
        all_advertised_mechs.update(mc.get("advertised_names", mc.get("available_names", [])))
        all_selected_mechs.update(mc.get("selected_names", []))
        all_selection_rejected_mechs.update(mc.get("selection_rejected_names", []))
        all_attempted_mechs.update(mc.get("attempted_names", mc.get("invoked_names", [])))
        all_accepted_mechs.update(mc.get("accepted_names", []))
        all_rejected_cleanly_mechs.update(mc.get("rejected_cleanly_names", []))
        all_skipped_by_capability_mechs.update(mc.get("skipped_by_capability_names", []))
        all_crashed_mechs.update(mc.get("crashed_names", []))
        all_timeout_mechs.update(mc.get("timeout_names", []))
        all_detail.update(mc.get("invoked_detail", []))
        all_mech_counts.update(mc.get("invoked_counts", {}))
        all_detail_counts.update(mc.get("invoked_detail_counts", {}))

    if not found:
        return None

    merged_not_invoked = sorted(all_available_mechs - all_invoked)
    merged_uncalled = sorted(all_uncalled - all_called)
    return {
        "function_coverage": {
            "available": func_available,
            "called": len(all_called),
            "called_names": sorted(all_called),
            "called_counts": dict(all_func_counts),
            "ok_counts": dict(all_ok_counts),
            "bootstrap_counts": dict(all_bootstrap_counts),
            "module_session_health": {
                "checks": all_module_session_health_checks,
                "duration_s": all_module_session_health_duration_s,
            },
            "uncalled_names": merged_uncalled,
        },
        "mechanism_coverage": {
            "available": len(all_available_mechs),
            "available_names": sorted(all_available_mechs),
            "advertised_names": sorted(all_advertised_mechs),
            "selected_names": sorted(all_selected_mechs),
            "selection_rejected_names": sorted(all_selection_rejected_mechs),
            "attempted_names": sorted(all_attempted_mechs),
            "invoked": len(all_invoked),
            "invoked_names": sorted(all_invoked),
            "invoked_counts": dict(all_mech_counts),
            "not_invoked": len(merged_not_invoked),
            "not_invoked_names": merged_not_invoked,
            "invoked_detail": sorted(all_detail),
            "invoked_detail_counts": dict(all_detail_counts),
            "accepted_names": sorted(all_accepted_mechs),
            "rejected_cleanly_names": sorted(all_rejected_cleanly_mechs),
            "skipped_by_capability_names": sorted(all_skipped_by_capability_mechs),
            "crashed_names": sorted(all_crashed_mechs),
            "timeout_names": sorted(all_timeout_mechs),
        },
    }


def extract_provisioning_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Extract and merge ProvisioningReport entries from a JSONL artifact.

    Returns a merged dict with ``by_class`` and ``totals``, or None if no
    ProvisioningReport entries are found.
    """
    _methods = ("ran_via_create", "ran_via_unwrap", "ran_via_external", "skipped_no_path")
    by_class: dict[str, dict[str, int]] = {}
    found = False

    # Streamed via the shared binary-decode iterator (report_log.iter_report_log_records)
    # rather than a text-mode `for line in fh` loop, so a single undecodable byte anywhere
    # in the file only drops that one line instead of raising UnicodeDecodeError and losing
    # every remaining record.
    for rec in _iter_report_log_records(jsonl_path):
        if rec.get("$report_type") != "ProvisioningReport":
            continue
        found = True
        for cls, counts in rec.get("by_class", {}).items():
            if cls not in by_class:
                by_class[cls] = {}
            for method, val in counts.items():
                by_class[cls][method] = by_class[cls].get(method, 0) + int(val)

    if not found:
        return None

    totals: dict[str, int] = {m: 0 for m in _methods}
    for counts in by_class.values():
        for method in _methods:
            totals[method] += counts.get(method, 0)

    return {"by_class": by_class, "totals": totals}


def extract_provenance_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Return the framework block of the first ProvenanceReport record."""
    # Streamed via the shared binary-decode iterator (report_log.iter_report_log_records)
    # rather than a text-mode `for line in fh` loop, so a single undecodable byte anywhere
    # in the file only drops that one line instead of raising UnicodeDecodeError and losing
    # every remaining record.
    for rec in _iter_report_log_records(jsonl_path):
        if rec.get("$report_type") != "ProvenanceReport":
            continue
        framework = rec.get("framework")
        return dict(framework) if isinstance(framework, dict) else None
    return None


def _as_nonneg_int(value: Any) -> int | None:
    """Return ``value`` as a non-negative int, else None (bools rejected)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _counters_buckets_valid(buckets: Any) -> bool:
    """Whether ``buckets`` has the serialized-schema buckets shape (T1).

    Every ``calls``/``count`` scalar must be a non-negative int (bools
    rejected), every function/RV key a string, every RV leaf a
    ``{"name": str, "count": int}`` dict. Cross-total consistency is NOT
    enforced: crash windows make ``sum(by_rv) <= calls`` by design, so only
    the shape and scalar types are validated.
    """
    if not isinstance(buckets, dict):
        return False
    for bucket_name, block in buckets.items():
        if not isinstance(bucket_name, str) or not isinstance(block, dict):
            return False
        if _as_nonneg_int(block.get("calls")) is None:
            return False
        by_fn = block.get("by_fn")
        if not isinstance(by_fn, dict):
            return False
        for fn, fn_block in by_fn.items():
            if not isinstance(fn, str) or not fn or not isinstance(fn_block, dict):
                return False
            if _as_nonneg_int(fn_block.get("calls")) is None:
                return False
            by_rv = fn_block.get("by_rv")
            if not isinstance(by_rv, dict):
                return False
            for rv_key, rv_block in by_rv.items():
                if not isinstance(rv_key, str) or not isinstance(rv_block, dict):
                    return False
                if not isinstance(rv_block.get("name"), str):
                    return False
                if _as_nonneg_int(rv_block.get("count")) is None:
                    return False
    return True


def _parse_session_counters(
    record: dict[str, Any],
) -> tuple[int, int, dict[str, Any], int, str] | None:
    """Validate a CallCountersReport record into (pid, total, buckets, lost, isolation).

    Returns None for any malformed shape. ``probes_lost`` is load-bearing for
    the ``complete`` flag, so a record without a usable value is garbage;
    ``isolation`` is informational and defaults to ``"unknown"`` (the T3
    read-default) when absent or mistyped.
    """
    pid = _as_nonneg_int(record.get("pid"))
    total = _as_nonneg_int(record.get("total_calls"))
    probes_lost = _as_nonneg_int(record.get("probes_lost"))
    buckets: Any = record.get("buckets")
    if pid is None or total is None or probes_lost is None:
        return None
    if not _counters_buckets_valid(buckets):
        return None
    isolation = record.get("isolation")
    if not isinstance(isolation, str):
        isolation = "unknown"
    return (pid, total, buckets, probes_lost, isolation)


def _parse_test_counters(entry: Any) -> tuple[int, int, dict[str, Any]] | None:
    """Validate a per-test counter entry into (pid, total, buckets) or None."""
    if not isinstance(entry, dict):
        return None
    pid = _as_nonneg_int(entry.get("pid"))
    total = _as_nonneg_int(entry.get("total_calls"))
    buckets: Any = entry.get("buckets")
    if pid is None or total is None or not _counters_buckets_valid(buckets):
        return None
    return (pid, total, buckets)


@dataclass
class _CountersGroup:
    """One (target, attempt) group's reconciliation state (built, then reconciled).

    Per-test entries are buffered during the stream pass because a session
    record (emitted at sessionfinish) sorts AFTER the test reports it
    supersedes; the fallback fold runs once the stream is fully read.
    """

    session_pids: set[int] = field(default_factory=set)
    session_probes_lost: int = 0
    has_session: bool = False
    fallback_used: bool = False
    pending: list[tuple[int, int, dict[str, Any]]] = field(default_factory=list)


@dataclass
class _CountersPid:
    """One pid's folded contribution across all groups."""

    sessions_total: int = 0
    sessions_probes_lost: int = 0
    has_session: bool = False
    fallback_total: int = 0
    fallback_used: bool = False
    isolation: str = "unknown"


def extract_call_counters_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Aggregate call-counter records from a JSONL artifact into one payload.

    Folds ``CallCountersReport`` session records and per-test
    ``pkcs11_call_counters`` user properties (phase-agnostic: production rides
    teardown reports, but no phase is assumed), segmented by
    ``IsolatedUnitReport`` (target, attempt) marker provenance exactly like
    :func:`report_log.iter_classification_occurrences` (reset at SessionStart;
    a malformed marker resets to unattributed; never raises).

    Reconciliation per group: every session record is summed (retries count
    twice — both runs made real calls); a buffered per-test entry folds only
    when its pid has NO session record in that group (the crashed/timed-out
    fallback). A group is complete iff a session record exists, no fallback
    was used, and session ``probes_lost`` is 0; the run is complete iff every
    group is. Returns None when the JSONL carries no counters data, so old
    artifacts stay clean. Malformed records are ignored, never raised.
    """
    groups: dict[tuple[str | None, int | None], _CountersGroup] = {}
    pids: dict[int, _CountersPid] = {}
    merged: dict[str, Any] = {"total_calls": 0, "buckets": {}}
    current: tuple[str | None, int | None] = (None, None)
    found = False

    def _group(key: tuple[str | None, int | None]) -> _CountersGroup:
        return groups.setdefault(key, _CountersGroup())

    def _pid_state(pid: int) -> _CountersPid:
        return pids.setdefault(pid, _CountersPid())

    # Streamed via the shared binary-decode iterator (report_log.iter_report_log_records)
    # like the coverage/provisioning extractors above: one bad byte drops one line.
    for rec in _iter_report_log_records(jsonl_path):
        report_type = rec.get("$report_type", "TestReport")
        if report_type == "SessionStart":
            current = (None, None)
            continue
        if report_type == _ISOLATED_UNIT_REPORT_TYPE:
            target = rec.get("target")
            attempt = rec.get("attempt")
            if (
                isinstance(target, str)
                and target
                and isinstance(attempt, int)
                and not isinstance(attempt, bool)
            ):
                current = (target, attempt)
            else:
                current = (None, None)
            continue
        if report_type == CALL_COUNTERS_REPORT_TYPE:
            parsed = _parse_session_counters(rec)
            if parsed is None:
                continue
            pid, total, buckets, probes_lost, isolation = parsed
            merge_serialized(merged, {"total_calls": total, "buckets": buckets})
            group = _group(current)
            group.has_session = True
            group.session_pids.add(pid)
            group.session_probes_lost += probes_lost
            pid_state = _pid_state(pid)
            if not pid_state.has_session:
                pid_state.isolation = isolation
            pid_state.has_session = True
            pid_state.sessions_total += total
            pid_state.sessions_probes_lost += probes_lost
            found = True
            continue
        if report_type != "TestReport":
            continue
        entry = _parse_test_counters(_user_property(rec, CALL_COUNTERS_PROPERTY))
        if entry is None:
            continue
        _group(current).pending.append(entry)

    # Session records sort after the test reports they supersede, so fallback
    # folds only now that every group's session-pid set is final.
    for group in groups.values():
        for pid, total, buckets in group.pending:
            if pid in group.session_pids:
                continue
            merge_serialized(merged, {"total_calls": total, "buckets": buckets})
            group.fallback_used = True
            pid_state = _pid_state(pid)
            pid_state.fallback_total += total
            pid_state.fallback_used = True
            found = True

    if not found:
        return None
    complete = all(
        group.has_session and not group.fallback_used and group.session_probes_lost == 0
        for group in groups.values()
    )
    by_process = [
        {
            "pid": pid,
            "isolation": state.isolation,
            "total_calls": state.sessions_total + state.fallback_total,
            "complete": (
                state.has_session and not state.fallback_used and state.sessions_probes_lost == 0
            ),
        }
        for pid, state in sorted(pids.items())
        if state.has_session or state.fallback_used
    ]
    return {
        "complete": complete,
        "total_calls": merged["total_calls"],
        "by_bucket": merged,
        "probes_lost": sum(group.session_probes_lost for group in groups.values()),
        "by_process": by_process,
    }


def _emit_external_provision_banner(n: int) -> None:
    """Print a prominent warning when external key provisioning was active."""
    from rich.panel import Panel

    console = Console(stderr=True)
    console.print(
        Panel(
            f"⚠ EXTERNAL KEY PROVISIONING WAS ACTIVE ({n} keys)"
            " — results are NOT a pure in-API run",
            style="bold yellow",
        )
    )


# Pseudo-unit owning session-global lifecycle records (C_Finalize teardown),
# which belong to no file. Same tradition as the <collection> pseudo-unit.
_LIFECYCLE_UNIT = "<lifecycle>"


def postprocess_jsonl_to_unified(
    jsonl_path: Path, output_path: Path, provenance: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Convert a pytest-reportlog JSONL file to pkcs11-check unified format.

    Groups tests by file and writes the unified JSON report.
    Used for ``--isolation none`` to produce consistent output.
    If ``provenance`` is provided, it is included in the output payload.
    """
    file_counts: dict[str, dict[str, int]] = {}
    completion = _SessionCompletionTracker()

    def _accumulate_file_count(rec: Mapping[str, Any]) -> None:
        if rec.get("lifecycle") == "session-teardown":
            file_part = _LIFECYCLE_UNIT
        else:
            nodeid = str(rec.get("nodeid", ""))
            file_part = nodeid.split("::")[0] or "<collection>"
        if file_part not in file_counts:
            file_counts[file_part] = _empty_counts()
        outcome = _map_record_outcome(rec)
        file_counts[file_part][outcome] = file_counts[file_part].get(outcome, 0) + 1

    def _records_with_completion() -> Iterator[dict[str, Any]]:
        for record in _iter_report_log_records(jsonl_path, on_invalid=completion.invalidate):
            completion.observe(record)
            yield record

    # Parse the JSONL once: build the aggregate detail and the per-file counts
    # from the same streaming record pass.
    detail = _build_detail_from_report_records(
        _records_with_completion(),
        result_record_hook=_accumulate_file_count,
    )
    # An empty / vacuous JSONL (no records at all) returns None from the builder;
    # treat it as a zero-count run so we still produce a results.json payload.
    if detail is None:
        detail = {"counts": _empty_counts(), "tests": []}

    # Group tests by file; session-teardown lifecycle records group under the
    # <lifecycle> pseudo-unit (same tradition as <collection>), never a phantom file.
    by_file: dict[str, list[dict[str, Any]]] = {}
    for test in detail["tests"]:
        if isinstance(test, Mapping) and test.get("lifecycle") == "session-teardown":
            file_part = _LIFECYCLE_UNIT
        else:
            file_part = test.get("nodeid", "").split("::")[0]
        by_file.setdefault(file_part, []).append(test)

    compliance_notes_by_file: dict[str, list[dict[str, Any]]] = {}
    for note in detail.get("compliance_notes", []):
        if not isinstance(note, Mapping):
            continue
        file_part = str(note.get("nodeid", "")).split("::")[0]
        if not file_part:
            continue
        compliance_notes_by_file.setdefault(file_part, []).append(dict(note))

    raw_executions = [
        execution
        for execution in detail.get("executions", [])
        if isinstance(execution, Mapping) and _execution_owner_file(execution) is not None
    ]
    executions_by_file: dict[str, list[dict[str, Any]]] = {}
    for execution in _canonical_executions(raw_executions):
        owner_file = _execution_owner_file(execution)
        if owner_file is not None:
            executions_by_file.setdefault(owner_file, []).append(execution)

    summary: dict[str, int] = _empty_counts()
    units: list[dict[str, Any]] = []

    for target in sorted(
        set(
            list(by_file.keys())
            + list(file_counts.keys())
            + list(compliance_notes_by_file.keys())
            + list(executions_by_file.keys())
        )
    ):
        counts = file_counts.get(target, _empty_counts())
        for key in summary:
            summary[key] += counts.get(key, 0)
        has_failure = any(
            counts.get(key, 0) > 0 for key in ("failed", "error", "crashed", "timeout")
        )
        status = (
            "timeout"
            if counts.get("timeout", 0)
            else ("crashed" if counts.get("crashed", 0) else "failed")
        )
        unit: dict[str, Any] = {
            "target": target,
            "status": status if has_failure else "passed",
            "returncode": 1 if has_failure else 0,
            "duration_s": 0.0,
            "counts": counts,
        }
        incomplete_files = detail.get("incomplete_files")
        if detail.get("incomplete") is True and (
            not isinstance(incomplete_files, list) or target in incomplete_files
        ):
            unit["incomplete"] = True
        if not completion.complete:
            unit["completion_verified"] = False
        tests = by_file.get(target, [])
        if tests:
            unit["tests"] = tests
        compliance_notes = compliance_notes_by_file.get(target, [])
        if compliance_notes:
            unit["compliance_notes"] = compliance_notes
        executions = executions_by_file.get(target, [])
        if executions:
            unit["executions"] = executions
        units.append(unit)

    summary["total"] = sum(summary[key] for key in RESULT_OUTCOME_KEYS)
    child_crash, child_timeout = compute_child_subprocess_counts(units)
    summary["child_crash"] = child_crash
    summary["child_timeout"] = child_timeout
    summary["incomplete"] = not completion.complete
    summary["incomplete"] = run_is_incomplete(summary, units)
    if not completion.complete:
        for unit in units:
            unit["incomplete"] = True
    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    # The none path embeds counters here (not via a caller pass like coverage):
    # the internal call keeps every existing caller, including merge salvage,
    # working with zero signature change. None when the JSONL predates fw#73.
    call_counters = extract_call_counters_from_jsonl(jsonl_path)
    if call_counters:
        payload["call_counters"] = call_counters
    if provenance:
        payload["provenance"] = provenance
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return payload
