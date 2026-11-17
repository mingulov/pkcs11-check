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
)
from pkcs11_check.core.counters_schema import (
    LOST_REPORT_TYPE,
    PARTIAL_REPORT_TYPE,
    canonicalize_module_first,
    is_end_state,
    is_legacy_buckets_block,
    is_lost_key,
    is_module_first_block,
    is_receipt,
    is_role,
    is_worker_uuid,
    merge_module_first,
    normalize_legacy_to_module_first,
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


def _parse_counters_block(record: dict[str, Any], total: int) -> dict[str, Any] | None:
    """Validate a record's counters into a module-first block, else None (fail-closed).

    Exactly one of ``buckets`` (rc1 legacy) or ``by_module`` (module-first)
    must be present; both or neither is malformed. Shapes validate through
    the frozen Task-1 predicates (known buckets only, decimal RV keys, exact
    totals at every level, ``sum(by_rv) <= calls``); legacy blocks normalize
    to the ``""`` unknown module, never inferred to a real module id.
    """
    has_buckets = "buckets" in record
    has_modules = "by_module" in record
    if has_buckets == has_modules:
        return None
    if has_buckets:
        legacy = {"total_calls": total, "buckets": record["buckets"]}
        if not is_legacy_buckets_block(legacy):
            return None
        normalized = normalize_legacy_to_module_first(legacy)
        assert normalized is not None  # validated above; never None here
        return normalized
    module_first = {"total_calls": total, "by_module": record["by_module"]}
    if not is_module_first_block(module_first):
        return None
    return module_first


def _parse_round(record: dict[str, Any]) -> str | None:
    """Return the record's round key: implicit ``""`` when absent, None when malformed.

    Fail-closed (mirror I2): a ``run_id`` that is present but not a non-empty
    string (wrong type, empty string, explicit null) skips the whole record.
    An absent key is the pre-round / direct-pytest shape and folds into the
    implicit ``""`` round.
    """
    if "run_id" not in record:
        return ""
    run_id = record["run_id"]
    if not isinstance(run_id, str) or not run_id:
        return None
    return run_id


def _parse_receipts_list(value: Any) -> frozenset[tuple[str, int]]:
    """Return the well-formed receipt keys from a record's receipts list.

    Item-tolerant like the live ingest path: a non-list container yields
    nothing and malformed items are skipped, so one hostile receipt never
    discards the record's counts.
    """
    if not isinstance(value, list):
        return frozenset()
    return frozenset(
        (entry["worker_uuid"], entry["probe_seq"]) for entry in value if is_receipt(entry)
    )


def _parse_lost_keys_list(value: Any) -> frozenset[tuple[str, int]]:
    """Return the well-formed lost keys from a record's key list.

    Item-tolerant like receipts: malformed pairs are skipped, so one
    hostile pair never discards the record. The scalar anchors the total
    (unkeyed = scalar − keyed length), so skipping a pair conserves the
    total instead of dropping it.
    """
    if not isinstance(value, list):
        return frozenset()
    return frozenset(
        (entry["parent_uuid"], entry["probe_seq"]) for entry in value if is_lost_key(entry)
    )


def _parse_session_counters(
    record: dict[str, Any],
) -> (
    tuple[
        int,
        int,
        dict[str, Any],
        int,
        str,
        str,
        str | None,
        frozenset[tuple[str, int]],
        str | None,
        bool,
        frozenset[tuple[str, int]],
    ]
    | None
):
    """Validate a CallCountersReport into its folded tuple (now with role).

    Returns None for any malformed shape. ``probes_lost`` is load-bearing for
    the ``complete`` flag, so a record without a usable value is garbage;
    ``isolation`` is informational and defaults to ``"unknown"`` (the T3
    read-default) when absent or mistyped. ``block`` is the module-first
    counters block (legacy buckets-first normalized to ``""``); a present but
    malformed ``worker_uuid`` or ``role`` fails the whole record closed (a
    forged attribution tag must not fold). ``run`` is the round key from
    :func:`_parse_round` (implicit ``""`` when the key is absent). Receipts
    fold item-tolerantly (see :func:`_parse_receipts_list`). A present
    non-None ``persistence_pending`` marker (any shape: its contents are
    forensic, not validity-gating) reads as pending — fail closed, since an
    unreadable marker cannot prove clean persistence; absent/None reads clean.
    Keyed losses parse item-tolerantly; the scalar minus their length is the
    unkeyed remainder (clamped at zero: identities win over an inconsistent
    scalar, fail closed toward incomplete).
    """
    pid = _as_nonneg_int(record.get("pid"))
    total = _as_nonneg_int(record.get("total_calls"))
    probes_lost = _as_nonneg_int(record.get("probes_lost"))
    run = _parse_round(record)
    if pid is None or total is None or probes_lost is None or run is None:
        return None
    block = _parse_counters_block(record, total)
    if block is None:
        return None
    uuid = record.get("worker_uuid")
    if uuid is not None and not is_worker_uuid(uuid):
        return None
    role = record.get("role")
    if role is not None and not is_role(role):
        return None
    isolation = record.get("isolation")
    if not isinstance(isolation, str):
        isolation = "unknown"
    receipts = _parse_receipts_list(record.get("receipts"))
    pending = record.get("persistence_pending") is not None
    keys = _parse_lost_keys_list(record.get("lost_keys"))
    assert role is None or isinstance(role, str)
    return (pid, total, block, probes_lost, isolation, run, uuid, receipts, role, pending, keys)


def _parse_partial_counters(
    record: dict[str, Any],
) -> (
    tuple[
        int | None,
        int,
        dict[str, Any],
        str,
        str,
        frozenset[tuple[str, int]],
        str | None,
        str,
        int,
        frozenset[tuple[str, int]],
        frozenset[tuple[str, int]],
        frozenset[tuple[str, int]],
    ]
    | None
):
    """Validate a CallCountersPartial into its staged tuple.

    Carries role + isolation + probes_lost + the three key lists.

    The producer uuid is required (a partial without one is unattributable
    garbage); the pid is optional (counts fold globally, but no by_process
    row can name a pid-less producer). ``truncated`` must be exactly True
    and the counters shape follows the same fail-closed contract as
    sessions; anything malformed skips the whole record. A present role
    fails closed like sessions (a forged tag must not fold); isolation is
    informational like sessions (``"unknown"`` when absent or mistyped). A
    present ``probes_lost`` must be a usable non-negative int (absent reads
    0); anything else skips the whole record. Key lists
    (``lost_keys``/``orphan_keys``/``recovered_keys``) parse item-tolerantly
    like receipts.
    """
    if record.get("truncated") is not True:
        return None
    uuid = record.get("worker_uuid")
    if not is_worker_uuid(uuid):
        return None
    total = _as_nonneg_int(record.get("total_calls"))
    run = _parse_round(record)
    if total is None or run is None:
        return None
    block = _parse_counters_block(record, total)
    if block is None:
        return None
    pid: int | None
    if "pid" not in record:
        pid = None
    else:
        pid = _as_nonneg_int(record.get("pid"))
        if pid is None:
            return None
    role = record.get("role")
    if role is not None and not is_role(role):
        return None
    isolation = record.get("isolation")
    if not isinstance(isolation, str):
        isolation = "unknown"
    part_lost = _as_nonneg_int(record.get("probes_lost", 0))
    if part_lost is None:
        return None
    assert isinstance(uuid, str)
    assert role is None or isinstance(role, str)
    return (
        pid,
        total,
        block,
        uuid,
        run,
        _parse_receipts_list(record.get("receipts")),
        role,
        isolation,
        part_lost,
        _parse_lost_keys_list(record.get("lost_keys")),
        _parse_lost_keys_list(record.get("orphan_keys")),
        _parse_lost_keys_list(record.get("recovered_keys")),
    )


def _parse_lost_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """Validate a CallCountersLost record into a normalized entry, else None.

    Requires a known end state, a valid (but assembly-rebased) scope index,
    a well-formed round key, and at least one of a valid worker uuid / pid;
    unit/attempt/origin_shard are carried when well-formed. A present role
    fails closed like sessions (a forged tag must not fold); isolation is
    informational like sessions (carried when a string, dropped otherwise).
    Anything else malformed fails the whole record closed (a hostile loss
    claim never flips completeness by itself).
    """
    if not is_end_state(record.get("end_state")):
        return None
    if _as_nonneg_int(record.get("scope_index")) is None:
        return None
    run = _parse_round(record)
    if run is None:
        return None
    uuid = record.get("worker_uuid")
    if uuid is not None and not is_worker_uuid(uuid):
        return None
    pid: int | None
    if "pid" not in record:
        pid = None
    else:
        pid = _as_nonneg_int(record.get("pid"))
        if pid is None:
            return None
    if uuid is None and pid is None:
        return None
    unit = record.get("unit")
    if unit is not None and (not isinstance(unit, str) or not unit):
        return None
    attempt = record.get("attempt")
    if attempt is not None and _as_nonneg_int(attempt) is None:
        return None
    origin = record.get("origin_shard")
    if origin is not None and not isinstance(origin, str):
        return None
    role = record.get("role")
    if role is not None and not is_role(role):
        return None
    isolation = record.get("isolation")
    if isolation is not None and not isinstance(isolation, str):
        isolation = None
    entry: dict[str, Any] = {"end_state": record["end_state"], "run": run}
    if uuid is not None:
        entry["worker_uuid"] = uuid
    if pid is not None:
        entry["pid"] = pid
    if unit is not None:
        entry["unit"] = unit
    if attempt is not None:
        entry["attempt"] = attempt
    if origin:
        entry["origin_shard"] = origin
    if role is not None:
        entry["role"] = role
    if isolation is not None:
        entry["isolation"] = isolation
    return entry


def _marker_is_static_skip(rec: dict[str, Any]) -> bool:
    """Whether a marker carries explicit static-skip provenance.

    The writer (``_report_records._isolated_unit_report``) emits ``reason`` +
    ``skipped`` together for a unit skipped before pytest execution, and
    neither for plain attempt markers (stream framing). Only the full
    writer shape reads as "never executed"; a partial shape fails visible
    (startup loss), never silent.
    """
    return (
        isinstance(rec.get("reason"), str)
        and isinstance(rec.get("skipped"), int)
        and not isinstance(rec.get("skipped"), bool)
    )


def _is_framing_marker(rec: dict[str, Any], following: dict[str, Any] | None) -> bool:
    """Whether ``rec`` is merged-writer framing re-stated after the bookend.

    The merged writer (``_report_records._write_report_jsonl_from_record_sources``)
    emits ``_isolated_unit_report(unit, 0)`` BEFORE a unit's records when they do
    not start with a marker; every production cache starting with SessionStart
    continues with that unit's OWN ``(unit, 0)`` marker (the cache writer's
    ``next_attempt`` is still 0 before its first emission), so a framing marker
    is always immediately re-stated after the bookend with the identical
    (target, attempt). A genuine attempt marker that merely precedes the next
    scope's SessionStart (a truncated attempt 0 before attempt 1's bookend)
    names a DIFFERENT (target, attempt) than the following scope's marker.

    Only an exact well-formed (target, attempt) re-statement positively
    establishes framing; anything else (different/absent/malformed following
    marker, EOF) keeps current-scope attribution, so an unfinished marked
    scope degrades to a visible C2b empty group instead of vanishing.
    Static-skip markers carry explicit never-executed provenance and never
    move: moving one would mark the new scope's segment static-skipped and
    suppress its own unfinished-segment accounting.
    """
    if following is None or following.get("$report_type") != _ISOLATED_UNIT_REPORT_TYPE:
        return False
    if _marker_is_static_skip(rec):
        return False
    target = rec.get("target")
    attempt = rec.get("attempt")
    following_target = following.get("target")
    following_attempt = following.get("attempt")
    # Both identities are validated with the same non-bool-int checks as
    # _apply_marker BEFORE comparison: `0 == False` and `0 == 0.0` in
    # Python, so comparing the following attempt by equality alone would let
    # a malformed marker establish framing and erase an unfinished attempt.
    return (
        isinstance(target, str)
        and bool(target)
        and isinstance(attempt, int)
        and not isinstance(attempt, bool)
        and isinstance(following_target, str)
        and bool(following_target)
        and isinstance(following_attempt, int)
        and not isinstance(following_attempt, bool)
        and target == following_target
        and attempt == following_attempt
    )


def _parse_test_counters(
    entry: Any,
) -> tuple[int, int, dict[str, Any], str, str | None, frozenset[tuple[str, int]], str] | None:
    """Validate a per-test counter entry into (pid, total, block, run, uuid, receipts, isolation).

    Same fail-closed contract as session records (I2): shape, bucket
    membership, exact totals, the RV upper bound, a well-formed
    ``worker_uuid`` when present, and a well-formed round key, or the entry
    is skipped. Counters normalize to a module-first block like sessions.
    Receipts fold item-tolerantly (a superseded entry still unions its
    receipts into the group). ``isolation`` is informational like on
    sessions: the stamped value when it is a string, else ``"unknown"``
    (bare-pytest entries carry no stamp).
    """
    if not isinstance(entry, dict):
        return None
    pid = _as_nonneg_int(entry.get("pid"))
    total = _as_nonneg_int(entry.get("total_calls"))
    run = _parse_round(entry)
    if pid is None or total is None or run is None:
        return None
    block = _parse_counters_block(entry, total)
    if block is None:
        return None
    uuid = entry.get("worker_uuid")
    if uuid is not None and not is_worker_uuid(uuid):
        return None
    isolation = entry.get("isolation")
    if not isinstance(isolation, str):
        isolation = "unknown"
    return (
        pid,
        total,
        block,
        run,
        uuid,
        _parse_receipts_list(entry.get("receipts")),
        isolation,
    )


@dataclass
class _LossEntry:
    """One loss source's books: keyed identities plus an unkeyed remainder."""

    keyed: set[tuple[str, int]] = field(default_factory=set)
    unkeyed: int = 0


@dataclass
class _LossLedger:
    """Per-scope loss books: keyed sets plus unkeyed counts (R3-1 operator).

    Entries are keyed by source: ``("uuid", run, uuid)`` for attributed
    producers, ``("record", run, pid, scope, target, attempt)`` for uuid-less
    records (the canonical fallback: same scope twice is a torn-append
    retry, distinct scopes are distinct producers). Newer cumulative state
    for one source REPLACES its entry; independent orphan keys UNION;
    exact recovery discards one keyed identity. The derived total (keyed
    plus unkeyed) can never go negative and never double-counts.
    """

    entries: dict[tuple[Any, ...], _LossEntry] = field(default_factory=dict)

    def replace(
        self, source: tuple[Any, ...], keys: frozenset[tuple[str, int]], unkeyed: int
    ) -> None:
        """Replace one source's cumulative entry (newer state supersedes)."""
        self.entries[source] = _LossEntry(set(keys), unkeyed)

    def union_orphans(self, run: str, keys: frozenset[tuple[str, int]]) -> None:
        """Union adopted-orphan keys (fresh info no session could hold)."""
        for parent, seq in keys:
            self.entries.setdefault(("uuid", run, parent), _LossEntry()).keyed.add((parent, seq))

    def discard(self, key: tuple[str, int]) -> None:
        """Discard one recovered keyed identity everywhere (idempotent)."""
        for entry in self.entries.values():
            entry.keyed.discard(key)

    def total(self) -> int:
        """Derived loss total: keyed identities plus unkeyed counts."""
        return sum(len(entry.keyed) + entry.unkeyed for entry in self.entries.values())

    def net_keys(self) -> set[tuple[str, int]]:
        """Union of surviving keyed identities (for lost detail rows)."""
        result: set[tuple[str, int]] = set()
        for entry in self.entries.values():
            result |= entry.keyed
        return result


def _loss_source(
    run: str, uuid: str | None, pid: int, coords: tuple[int, str | None, int | None]
) -> tuple[Any, ...]:
    """Return the canonical loss-ledger source for one record.

    Attributed producers key by identity; uuid-less records fall back to
    ``("record", run, pid, scope, target, attempt)`` so the same scope
    twice (a torn-append retry) replaces while distinct scopes add.
    """
    if uuid is not None:
        return ("uuid", run, uuid)
    scope, target, attempt = coords
    return ("record", run, pid, scope, target, attempt)


@dataclass
class _CountersGroup:
    """One (target, attempt) group's reconciliation state (built, then reconciled).

    Per-test entries are buffered during the stream pass because a session
    record (emitted at sessionfinish) sorts AFTER the test reports it
    supersedes; the fallback fold runs once the stream is fully read.
    (Partials stage globally, not per group: a superseded partial must
    leave no vacuous group behind to poison completeness.)
    """

    session_pids: set[int] = field(default_factory=set)
    loss: _LossLedger = field(default_factory=_LossLedger)
    session_persistence_pending: bool = False
    has_session: bool = False
    fallback_used: bool = False
    has_partial: bool = False
    has_lost: bool = False
    pending: list[tuple[int, int, dict[str, Any], str | None, frozenset[tuple[str, int]], str]] = (
        field(default_factory=list)
    )


@dataclass
class _CountersPid:
    """One pid's folded contribution across all groups (split per module at render)."""

    sessions_total: int = 0
    loss: _LossLedger = field(default_factory=_LossLedger)
    sessions_persistence_pending: bool = False
    has_session: bool = False
    fallback_total: int = 0
    fallback_used: bool = False
    isolation: str = "unknown"
    worker_uuid: str | None = None
    role: str | None = None
    session_modules: dict[str, int] = field(default_factory=dict)
    fallback_modules: dict[str, int] = field(default_factory=dict)
    partial_modules: dict[str, int] = field(default_factory=dict)
    end_states: set[str] = field(default_factory=set)


def _counters_group_complete(group: _CountersGroup) -> bool:
    """Whether a group reconciles clean: session, no fallback/partial/loss, empty ledger."""
    return (
        group.has_session
        and not group.fallback_used
        and not group.has_partial
        and not group.has_lost
        and group.loss.total() == 0
        and not group.session_persistence_pending
    )


def _fold_module_calls(state: dict[str, int], block: dict[str, Any]) -> None:
    """Add one module-first block's per-module calls into a pid split map (in place)."""
    for module, module_block in block["by_module"].items():
        state[module] = state.get(module, 0) + module_block["calls"]


def _decorate_process_row(row: dict[str, Any], state: _CountersPid, *, module: str | None) -> None:
    """Attach attribution keys to one by_process row (in place)."""
    if state.worker_uuid is not None:
        row["worker_uuid"] = state.worker_uuid
    if state.role is not None and state.role != "unit":
        row["role"] = state.role
    if module is not None and module in state.partial_modules:
        row["truncated"] = True
    if state.sessions_persistence_pending:
        row["persistence_pending"] = True
    if state.end_states:
        row["end_state"] = (
            next(iter(state.end_states)) if len(state.end_states) == 1 else "conflict"
        )
    if module is not None:
        row["module"] = module


def _counters_process_rows(pid: int, state: _CountersPid) -> list[dict[str, Any]]:
    """Render one by_process row per (pid, module), each carrying its ``module`` key.

    A row is complete iff its module reconciles clean for this pid (session
    evidence, no fallback or partial evidence, an empty loss ledger, no loss
    disposition, no surviving persistence marker); ledger losses, loss
    dispositions, and the marker are process-level, so they flip every row
    of the pid. Partial modules render ``truncated`` rows; a surviving
    marker renders ``persistence_pending``; a reconciled loss disposition
    renders ``end_state``; a non-unit
    role (session or partial evidence; retry, confirmation, preflight)
    renders ``role``. A pid with incomplete-visible evidence but no modules
    (fallback evidence, a loss disposition, outstanding ledger losses, or a
    degraded marker) renders one module-less row so the evidence is never
    invisible; a clean zero-call session stays silent. No round/shard keys;
    the caller tags those, and strips ``module`` when the block holds a
    single distinct module (see :func:`_strip_single_module_tag`).
    """
    rows: list[dict[str, Any]] = []
    modules = sorted(
        set(state.session_modules) | set(state.fallback_modules) | set(state.partial_modules)
    )
    for module in modules:
        row: dict[str, Any] = {
            "pid": pid,
            "isolation": state.isolation,
            "total_calls": state.session_modules.get(module, 0)
            + state.fallback_modules.get(module, 0)
            + state.partial_modules.get(module, 0),
            "complete": (
                module in state.session_modules
                and module not in state.fallback_modules
                and module not in state.partial_modules
                and state.loss.total() == 0
                and not state.end_states
                and not state.sessions_persistence_pending
            ),
        }
        _decorate_process_row(row, state, module=module)
        rows.append(row)
    if not modules and (
        state.fallback_used
        or state.end_states
        or state.loss.total() > 0
        or state.sessions_persistence_pending
    ):
        row = {
            "pid": pid,
            "isolation": state.isolation,
            "total_calls": 0,
            "complete": False,
        }
        _decorate_process_row(row, state, module=None)
        rows.append(row)
    return rows


def _strip_single_module_tag(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop ``module`` from every row unless >1 distinct module occurs (in place).

    The same conditional rule as ``round``/``shard``: single-module output
    reads exactly like rc1 on every row key. Imported by ``core.merge`` for
    the same decision over the merged row set. Module-less rows (zero-call
    evidence) pass through untouched and never vote: only present tags count.
    """
    if len({row["module"] for row in rows if "module" in row}) > 1:
        return rows
    for row in rows:
        row.pop("module", None)
    return rows


def _anchor_lost_record(
    normalized: dict[str, Any],
    staged: tuple[int, str | None, int | None],
    marked: set[tuple[int, str | None, int | None]],
) -> tuple[int, str | None, int | None] | None:
    """Return the assembly anchor segment for one staged lost record.

    A lost record covers a marked segment ONLY on a source-association
    match ``(origin_shard, unit, attempt)``: the origin must be local
    (absent or empty) and the unit/attempt must name a marked segment.
    The staged stream position wins among matches (the collector appends
    into its own segment, so agreement means zero behavior change);
    otherwise the earliest matching marked scope anchors, so prepended
    and reordered records still dispose their execution. Static-skipped
    segments match too: an explicit loss claim against a never-executed
    unit is contradictory evidence and stays fail-visible incomplete.
    The worker identity rides along as the disposition identity (dedup
    and row end states) but never gates the match -- a C2b segment has
    no counter evidence to compare it against.

    A foreign ``origin_shard`` anchors to nothing (None): no producer
    writes it, so the claim names no local execution; the caller keeps
    the loss groupless (its run rides the lost entry, visibly
    incomplete) rather than covering a local segment by positional
    coincidence. Records without an association (no unit/attempt:
    legacy sources) keep their staged position (existing C2b behavior,
    retained never guessed); decoys whose association matches no marked
    segment key their own group from the staged scope plus their own
    ``(unit, attempt)``. The caller assigns the entry ``scope_index``
    from the anchor scope (the staged scope for groupless records):
    assembly-assigned, rebased together with the group key.
    """
    if normalized.get("origin_shard"):
        return None
    unit = normalized.get("unit")
    attempt = normalized.get("attempt")
    if unit is None or attempt is None:
        return staged
    staged_scope, staged_target, staged_attempt = staged
    if staged_target == unit and staged_attempt == attempt:
        return staged
    for scope_id in sorted({scope for scope, _, _ in marked}):
        if (scope_id, unit, attempt) in marked:
            return (scope_id, unit, attempt)
    return (staged_scope, unit, attempt)


def extract_call_counters_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Aggregate call-counter records from a JSONL artifact into one payload.

    Folds ``CallCountersReport`` session records and per-test
    ``pkcs11_call_counters`` user properties (phase-agnostic: production rides
    teardown reports, but no phase is assumed), segmented by
    ``IsolatedUnitReport`` (target, attempt) marker provenance exactly like
    :func:`report_log.iter_classification_occurrences` (reset at SessionStart;
    a malformed marker resets to unattributed; never raises), plus a
    two-record marker lookahead: a marker immediately followed by SessionStart
    AND re-stated identically after the bookend (merged-writer framing)
    belongs to the NEW scope, otherwise to the current scope. Groups are
    additionally namespaced by SessionStart scope (C3a), so a repeated marker
    or pid in a later session never reconciles against an earlier one, and by
    round (the record's ``run_id``) ABOVE the session scope, so each CLI
    invocation's calls stay attributable after resume appends new rounds.

    Reconciliation per group: every session record is summed (retries count
    twice — both runs made real calls — except a uuid-bearing repeat of an
    already-folded ``(run, worker_uuid)``, which is a torn-append retry and
    folds first-wins; uuid-less legacy repeats keep summing); a buffered
    per-test entry folds only when its pid has NO session record in that
    group (the crashed/timed-out fallback). A staged sidecar partial folds
    only when its producer has NO
    authoritative session in the same run (authoritative supersedes partial,
    both input orders); a partial without a pid folds its counts globally
    but names no by_process row. A group is complete iff a session record
    exists, no fallback or partial was used, no loss disposition names it,
    session ``probes_lost`` is 0, and no surviving persistence marker names
    it; the run is complete iff every group is. Folded-probe receipts union
    across sessions, entries, and partials
    (superseded sources still contribute their receipts) into
    ``probes_detail``; lost records reconcile globally by producer identity
    (repeats dedup, conflicting end states surface ``conflict``) into
    ``lost_processes``, with the scope index assembly-assigned from the
    anchor segment (the record's provisional value is ignored, never
    fatal). Both keys render only when non-empty, top-level and per-round.
    A segment with at least one TestReport but zero counters data in an
    opened, unfinished session scope is an executed-but-counterless unit
    (typically a first-test crash): it emits an EMPTY group, which flips the
    run to ``complete: false`` instead of vanishing (C2). A crash in
    load_module/C_Initialize during FIRST fixture setup leaves no TestReport
    at all, so a segment with only a plain marker (no ``reason``/``skipped``
    static-skip provenance) and zero reports/counters in an opened,
    unfinished scope emits the same EMPTY group (C2b) -- unless a lost
    record covers the segment on a source-association match (local origin
    plus the segment's own unit/attempt; the staged position wins among
    matches, otherwise the earliest marked scope anchors, so prepended and
    reordered records still dispose their execution). Cross-source decoys
    never cover a segment: the backstop is retained and the loss keys
    its own group from its staged scope plus its own unit/attempt.
    Foreign-origin records anchor to nothing (no producer writes that
    field): they stay groupless, their run rides the lost entry, and
    they never disposition local rows. Legacy records without an
    association keep positional grouping (their staged position still
    covers the segment they were collected into). A finished scope with
    zero counters predates the feature (old artifact): no group, as with a
    static-skip marker with zero reports; None is returned when no group
    exists anywhere. Malformed records are
    ignored, never raised. A surviving lost record is a terminal
    disposition: it keeps its group incomplete (fail-visible). A loss
    naming a producer with validated authoritative evidence in the same
    run is stale (healed by a rerun or a re-collected sidecar) and
    reconciles away before anchoring; pid-only losses never reconcile.

    Rounds: records without ``run_id`` (pre-round artifacts, direct-pytest
    runs) fold into the implicit ``""`` round, which keeps its block whenever
    it holds data. C2/C2b empty groups (executed-but-counterless segments)
    name no round, so they leave the round assembly for the top-level
    ``unattributed_segments`` list (``{scope_index, unit, attempt}``,
    canonically sorted) instead of a degenerate ``""`` block; no ``""``
    block renders for them at all. Segments keep only the GLOBAL
    ``complete`` false (ANDed); per-round flags never see them. A
    segments-only input yields a zero-call payload with ``complete:
    false``, never None. Each round gets its own block under ``by_round``
    with the exact top-level shape; the top level stays the GLOBAL roll-up.
    Top-level ``by_process`` rows carry ``"round"`` iff more than one
    distinct round appears among them (single-round output is identical to
    before on every existing key); per-round rows never carry it. One row
    renders per (round, pid, module) that contributed, and rows carry
    ``"module"`` iff more than one distinct module appears among the
    block's rows, with the same per-block conditional rule top-level and
    per-round. Keys and rows are sorted for determinism.
    """
    groups: dict[tuple[str, int, str | None, int | None], _CountersGroup] = {}
    pids: dict[tuple[str, int], _CountersPid] = {}
    merged: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merged_by_round: dict[str, dict[str, Any]] = {}
    authoritative: set[tuple[str, str]] = set()
    receipts_all: set[tuple[str, int]] = set()
    receipts_by_round: dict[str, set[tuple[str, int]]] = {}
    recovered_by_run: dict[str, set[tuple[str, int]]] = {}
    staged_lost: list[tuple[str, int, str | None, int | None, int, dict[str, Any]]] = []
    staged_partials: list[
        tuple[
            str,
            int,
            str | None,
            int | None,
            str,
            int | None,
            dict[str, Any],
            str | None,
            str,
            int,
            frozenset[tuple[str, int]],
            frozenset[tuple[str, int]],
        ]
    ] = []
    scope = 0
    current: tuple[int, str | None, int | None] = (0, None, None)
    opened: set[int] = set()
    finished: set[int] = set()
    reported: set[tuple[int, str | None, int | None]] = set()
    marked: set[tuple[int, str | None, int | None]] = set()
    static_skipped: set[tuple[int, str | None, int | None]] = set()

    def _group(key: tuple[str, int, str | None, int | None]) -> _CountersGroup:
        return groups.setdefault(key, _CountersGroup())

    def _pid_state(key: tuple[str, int]) -> _CountersPid:
        return pids.setdefault(key, _CountersPid())

    def _fold(run: str, block: dict[str, Any]) -> None:
        merge_module_first(merged, block)
        round_merged = merged_by_round.setdefault(run, {"total_calls": 0, "by_module": {}})
        merge_module_first(round_merged, block)

    def _union_receipts(run: str, keys: frozenset[tuple[str, int]]) -> None:
        receipts_all.update(keys)
        receipts_by_round.setdefault(run, set()).update(keys)

    # Streamed via the shared binary-decode iterator (report_log.iter_report_log_records)
    # like the coverage/provisioning extractors above: one bad byte drops one line.
    # Two-record marker lookahead: the merged writer emits a unit's framing
    # marker BEFORE that unit's SessionStart, so a marker immediately followed
    # by SessionStart AND re-stated identically after the bookend belongs to
    # the NEW scope (applied after the bookend); a marker naming a different
    # (target, attempt) than the following scope's marker is a genuine attempt
    # marker (a truncated attempt before the next attempt's bookend) and stays
    # in the current scope, as do marker+EOF and marker+TestReport.
    def _apply_marker(rec: dict[str, Any], scope_id: int) -> None:
        nonlocal current
        target = rec.get("target")
        attempt = rec.get("attempt")
        if (
            isinstance(target, str)
            and target
            and isinstance(attempt, int)
            and not isinstance(attempt, bool)
        ):
            current = (scope_id, target, attempt)
            marked.add(current)
            if _marker_is_static_skip(rec):
                static_skipped.add(current)
        else:
            current = (scope_id, None, None)

    records = _iter_report_log_records(jsonl_path)
    pending: dict[str, Any] | None = next(records, None)
    nxt: dict[str, Any] | None = next(records, None)
    while pending is not None:
        rec = pending
        pending = nxt
        nxt = next(records, None)
        report_type = rec.get("$report_type", "TestReport")
        if (
            report_type == _ISOLATED_UNIT_REPORT_TYPE
            and pending is not None
            and pending.get("$report_type") == "SessionStart"
        ):
            if _is_framing_marker(rec, nxt):
                scope += 1
                opened.add(scope)
                current = (scope, None, None)
                _apply_marker(rec, scope)
                pending = nxt
                nxt = next(records, None)
                continue
            _apply_marker(rec, scope)
            continue
        if report_type == "SessionStart":
            scope += 1
            opened.add(scope)
            current = (scope, None, None)
            continue
        if report_type == _ISOLATED_UNIT_REPORT_TYPE:
            _apply_marker(rec, scope)
            continue
        if report_type == "SessionFinish":
            finished.add(scope)
            continue
        if report_type == CALL_COUNTERS_REPORT_TYPE:
            parsed = _parse_session_counters(rec)
            if parsed is None:
                continue
            (
                pid,
                total,
                block,
                probes_lost,
                isolation,
                run,
                uuid,
                receipts,
                role,
                marker_pending,
                keys,
            ) = parsed
            if uuid is not None and (run, uuid) in authoritative:
                # Torn-append retry: one producer emits one session per
                # run, so a repeat is the same scope appended twice and
                # folds first-wins (uuid-less legacy keeps fold-every:
                # no attribution is possible without an identity).
                continue
            _fold(run, block)
            _union_receipts(run, receipts)
            if uuid is not None:
                authoritative.add((run, uuid))
            group = _group((run, *current))
            group.has_session = True
            group.session_pids.add(pid)
            source = _loss_source(run, uuid, pid, current)
            group.loss.replace(source, keys, max(0, probes_lost - len(keys)))
            if marker_pending:
                group.session_persistence_pending = True
            pid_state = _pid_state((run, pid))
            if not pid_state.has_session:
                pid_state.isolation = isolation
            if uuid is not None and pid_state.worker_uuid is None:
                pid_state.worker_uuid = uuid
            if role is not None and pid_state.role is None:
                pid_state.role = role
            pid_state.has_session = True
            pid_state.sessions_total += total
            pid_state.loss.replace(source, keys, max(0, probes_lost - len(keys)))
            if marker_pending:
                pid_state.sessions_persistence_pending = True
            _fold_module_calls(pid_state.session_modules, block)
            continue
        if report_type == PARTIAL_REPORT_TYPE:
            parsed_partial = _parse_partial_counters(rec)
            if parsed_partial is None:
                continue
            (
                part_pid,
                _part_total,
                part_block,
                part_uuid,
                part_run,
                part_receipts,
                part_role,
                part_isolation,
                part_lost,
                part_keys,
                part_orphan_keys,
                part_recovered,
            ) = parsed_partial
            _union_receipts(part_run, part_receipts)
            # Recoveries harvest at stage time (like receipts): exact healing
            # must pierce session-supersede, which would otherwise skip this
            # partial's whole contribution at fold time. Keys naming another
            # producer are forged (adoption only ever heals its own uuid),
            # so they drop here instead of erasing a real loss (robustness M2).
            own_recovered = {key for key in part_recovered if key[0] == part_uuid}
            recovered_by_run.setdefault(part_run, set()).update(own_recovered)
            staged_partials.append(
                (
                    part_run,
                    *current,
                    part_uuid,
                    part_pid,
                    part_block,
                    part_role,
                    part_isolation,
                    part_lost,
                    part_keys,
                    part_orphan_keys,
                )
            )
            continue
        if report_type == LOST_REPORT_TYPE:
            parsed_lost = _parse_lost_record(rec)
            if parsed_lost is None:
                continue
            lost_run = parsed_lost["run"]
            # Buffered only: the anchor resolves post-pass (association
            # match, never stream position), once every marker is known.
            staged_lost.append((lost_run, *current, scope, parsed_lost))
            continue
        if report_type != "TestReport":
            continue
        reported.add(current)
        # I1: the shared _user_property iterates the container blindly, so a
        # non-list container (e.g. user_properties: 1) would raise TypeError
        # and abort the whole extraction; validate locally and skip instead
        # (the report still counts as execution evidence above).
        if not isinstance(rec.get("user_properties"), (list, tuple)):
            continue
        parsed_entry = _parse_test_counters(_user_property(rec, CALL_COUNTERS_PROPERTY))
        if parsed_entry is None:
            continue
        (
            entry_pid,
            entry_total,
            entry_block,
            entry_run,
            entry_uuid,
            entry_receipts,
            entry_isolation,
        ) = parsed_entry
        _union_receipts(entry_run, entry_receipts)
        _group((entry_run, *current)).pending.append(
            (entry_pid, entry_total, entry_block, entry_uuid, entry_receipts, entry_isolation)
        )

    # Session records sort after the test reports they supersede, so fallback
    # folds only now that every group's session-pid set is final. Receipts
    # union regardless (a superseded entry still contributes its receipts).
    # Fallback rows inherit the entry's stamped isolation (first source
    # wins, like sessions); pids with session evidence keep the session
    # stamp, and unstamped bare-pytest entries leave "unknown".
    for group_key, group in groups.items():
        for pid, total, block, uuid, _entry_receipts, isolation in group.pending:
            if pid in group.session_pids:
                continue
            _fold(group_key[0], block)
            group.fallback_used = True
            pid_state = _pid_state((group_key[0], pid))
            if not pid_state.has_session and not pid_state.fallback_used:
                pid_state.isolation = isolation
            pid_state.fallback_total += total
            pid_state.fallback_used = True
            if uuid is not None and pid_state.worker_uuid is None:
                pid_state.worker_uuid = uuid
            _fold_module_calls(pid_state.fallback_modules, block)

    # Keyed staging: an authoritative session anywhere in the run supersedes
    # same-producer partials (both input orders); repeats of one partial
    # fold first-wins (re-collection after a crash between append and
    # consume still counts exactly once). Groups are created only for
    # folded partials, so a superseded partial leaves no vacuous group —
    # except when it carries adopted-orphan keys (fresh info no session
    # could hold), which union regardless of supersede.
    folded_partials: set[tuple[str, str]] = set()
    for staged in staged_partials:
        (
            part_run,
            part_scope,
            part_target,
            part_attempt,
            uuid,
            part_pid,
            block,
            part_role,
            part_isolation,
            part_lost,
            part_keys,
            part_orphan_keys,
        ) = staged
        if part_orphan_keys:
            _group((part_run, part_scope, part_target, part_attempt)).loss.union_orphans(
                part_run, part_orphan_keys
            )
            if part_pid is not None:
                _pid_state((part_run, part_pid)).loss.union_orphans(part_run, part_orphan_keys)
        if (part_run, uuid) in authoritative:
            continue
        if (part_run, uuid) in folded_partials:
            continue
        folded_partials.add((part_run, uuid))
        _fold(part_run, block)
        fold_group = _group((part_run, part_scope, part_target, part_attempt))
        fold_group.has_partial = True
        fold_group.loss.replace(
            ("uuid", part_run, uuid), part_keys, max(0, part_lost - len(part_keys))
        )
        if part_pid is None:
            continue
        pid_state = _pid_state((part_run, part_pid))
        pid_state.loss.replace(
            ("uuid", part_run, uuid), part_keys, max(0, part_lost - len(part_keys))
        )
        if pid_state.worker_uuid is None:
            pid_state.worker_uuid = uuid
        # Deliberate asymmetry (rc3-D residual): session values win over
        # partial values — sessions fold during the stream pass while
        # partials stage globally and fill only unset fields afterwards.
        # Same-producer pairs agree (one producer, one identity anyway).
        if part_role is not None and pid_state.role is None:
            pid_state.role = part_role
        if (
            not pid_state.has_session
            and not pid_state.fallback_used
            and not pid_state.partial_modules
        ):
            pid_state.isolation = part_isolation
        _fold_module_calls(pid_state.partial_modules, block)

    # Healed producers: a staged loss carrying a worker uuid whose
    # (run, uuid) has validated authoritative evidence is stale (a resumed
    # rerun, or a crash between collection append and consume, healed it)
    # and drops before anchoring, so it neither dispositions rows nor
    # poisons completeness. Receipts need no union here: lost records carry
    # none, and the authoritative evidence already unioned its own. Pid-only
    # losses never drop (pids are shard-local: no authority key matches
    # them), and losses in other runs never heal this producer's claim.
    staged_lost = [
        staged
        for staged in staged_lost
        if staged[5].get("worker_uuid") is None
        or (staged[0], staged[5]["worker_uuid"]) not in authoritative
    ]
    # Association-anchored lost disposition: every staged lost record
    # resolves to its anchor segment (source-association match, staged
    # position preferred, decoys own-grouped, legacy positional, foreign
    # groupless) and the staged tuple is rewritten with the anchor
    # coordinates, so the entry merge below reuses the anchor scope as the
    # assembly-assigned scope_index (the staged scope for groupless
    # records). Groups form here, before the C2/C2b backstop consults
    # them: only a matched loss covers its segment.
    anchored_lost: list[tuple[str, int, str | None, int | None, int, dict[str, Any]]] = []
    for lost_staged in staged_lost:
        lost_run, staged_scope, staged_target, staged_attempt, _provisional, normalized = (
            lost_staged
        )
        anchor = _anchor_lost_record(
            normalized, (staged_scope, staged_target, staged_attempt), marked
        )
        if anchor is None:
            anchor_scope, anchor_target, anchor_attempt = (
                staged_scope,
                staged_target,
                staged_attempt,
            )
        else:
            anchor_scope, anchor_target, anchor_attempt = anchor
            _group((lost_run, anchor_scope, anchor_target, anchor_attempt)).has_lost = True
        anchored_lost.append(
            (lost_run, anchor_scope, anchor_target, anchor_attempt, anchor_scope, normalized)
        )
    staged_lost = anchored_lost

    # Lost records reconcile globally by producer identity: repeats dedup,
    # conflicting end states surface an explicit conflict (never a silent
    # pick), and the scope index rebases to the assembly scope.
    lost_by_identity: dict[tuple[str, str, Any], dict[str, Any]] = {}
    lost_end_states: dict[tuple[str, str, Any], set[str]] = {}
    for lost_run, _scope_id, _target, _attempt, rebased, normalized in staged_lost:
        if normalized.get("worker_uuid") is not None:
            identity = (lost_run, "uuid", normalized["worker_uuid"])
        else:
            identity = (lost_run, "pid", normalized["pid"])
        known = lost_by_identity.get(identity)
        if known is None:
            merged_entry = dict(normalized)
            merged_entry["scope_index"] = rebased
            lost_by_identity[identity] = merged_entry
            lost_end_states[identity] = {normalized["end_state"]}
            continue
        for name in ("worker_uuid", "pid", "unit", "attempt", "origin_shard", "role", "isolation"):
            if name not in known and normalized.get(name) is not None:
                known[name] = normalized[name]
        lost_end_states[identity].add(normalized["end_state"])
    lost_processes: list[dict[str, Any]] = []
    for identity in sorted(lost_by_identity):
        merged_entry = lost_by_identity[identity]
        states = lost_end_states[identity]
        entry: dict[str, Any] = {}
        if merged_entry.get("worker_uuid") is not None:
            entry["worker_uuid"] = merged_entry["worker_uuid"]
        if merged_entry.get("pid") is not None:
            entry["pid"] = merged_entry["pid"]
        entry["end_state"] = next(iter(states)) if len(states) == 1 else "conflict"
        entry["scope_index"] = merged_entry["scope_index"]
        if merged_entry["run"]:
            entry["run_id"] = merged_entry["run"]
        if merged_entry.get("unit") is not None:
            entry["unit"] = merged_entry["unit"]
        if merged_entry.get("attempt") is not None:
            entry["attempt"] = merged_entry["attempt"]
        if merged_entry.get("origin_shard"):
            entry["origin_shard"] = merged_entry["origin_shard"]
        if merged_entry.get("role") is not None:
            entry["role"] = merged_entry["role"]
        if merged_entry.get("isolation") is not None:
            entry["isolation"] = merged_entry["isolation"]
        lost_processes.append(entry)
    lost_processes.sort(key=lambda item: json.dumps(item, sort_keys=True))
    for entry in lost_processes:
        if entry.get("origin_shard"):
            # Foreign loss claims stay visible but never disposition local
            # rows: pids are shard-local namespaces, and an unverifiable
            # cross-shard claim must not rewrite local attribution.
            continue
        run = entry.get("run_id", "")
        if entry.get("pid") is not None:
            pid_state = _pid_state((run, entry["pid"]))
            pid_state.end_states.add(entry["end_state"])
            if (
                not pid_state.has_session
                and not pid_state.fallback_used
                and not pid_state.partial_modules
            ):
                # Otherwise-evidenceless pid: attribute the zero row from
                # the loss record (real evidence always wins elsewhere).
                if pid_state.worker_uuid is None and entry.get("worker_uuid") is not None:
                    pid_state.worker_uuid = entry["worker_uuid"]
                if pid_state.role is None and entry.get("role") is not None:
                    pid_state.role = entry["role"]
                if pid_state.isolation == "unknown" and entry.get("isolation") is not None:
                    pid_state.isolation = entry["isolation"]
        if entry.get("worker_uuid") is not None:
            for (state_run, _state_pid), pid_state in pids.items():
                if state_run == run and pid_state.worker_uuid == entry["worker_uuid"]:
                    pid_state.end_states.add(entry["end_state"])

    # C2: executed-but-counterless segments (reports, zero counters, opened
    # scope, no finish) emit an empty group so the run reads incomplete. A
    # finished scope with zero counters is an old artifact (no group); a
    # static-skip marker (explicit reason/skipped provenance) with zero
    # reports never executed (no group). The empty group lands in "" — a
    # counterless report names no round, so "" doubles as "round unknown"
    # next to its old-artifact meaning.
    grouped_segments = {key[1:] for key in groups}
    for key in reported:
        if key not in grouped_segments and key[0] in opened and key[0] not in finished:
            groups[("", *key)] = _CountersGroup()
    # C2b: a first-setup crash (Start + plain marker + truncation, zero
    # reports) is a started-but-unfinished execution independent of any
    # TestReport; TestReports elsewhere already won above, so only
    # marked-but-unreported, non-static segments in an opened, unfinished
    # scope emit here.
    for key in marked:
        if key in reported or key in grouped_segments or key in static_skipped:
            continue
        if key[0] in opened and key[0] not in finished:
            groups[("", *key)] = _CountersGroup()

    # Exact recovery: adopted-orphan identities harvested at stage time
    # discard their live-claimed keys everywhere in their run (idempotent;
    # unclaimed keys are no-ops). Applied once all folds are final so the
    # result is independent of record order.
    for run, recovered in recovered_by_run.items():
        for group_key, group in groups.items():
            if group_key[0] == run:
                for healed in recovered:
                    group.loss.discard(healed)
        for (pid_run, _), state in pids.items():
            if pid_run == run:
                for healed in recovered:
                    state.loss.discard(healed)

    # C2/C2b backstop, rc3 Area C: empty "" groups (executed-but-
    # counterless segments: no session, fallback, partial, or loss) are
    # unattributed by definition -- they name no round -- so they leave
    # the round assembly for the top-level segment list instead of a
    # degenerate "" round block. Non-empty "" groups (legacy run-less
    # sessions, loss-anchored decoys) keep their block exactly as before.
    # Group keys are unique, so the segment list is inherently deduped;
    # the canonical sort keeps the wire shape deterministic (C2b stages
    # through set iteration).
    unattributed_segments: list[dict[str, Any]] = []
    for group_key in [group_key for group_key in groups if group_key[0] == ""]:
        group = groups[group_key]
        if (
            group.has_session
            or group.fallback_used
            or group.has_partial
            or group.has_lost
            or group.loss.total() != 0
        ):
            continue
        del groups[group_key]
        _run, scope_index, unit, attempt = group_key
        unattributed_segments.append({"scope_index": scope_index, "unit": unit, "attempt": attempt})
    unattributed_segments.sort(
        key=lambda entry: (
            entry["scope_index"],
            entry["unit"] or "",
            entry["attempt"] if entry["attempt"] is not None else -1,
        )
    )
    if not groups and not lost_processes and not unattributed_segments:
        return None
    # A surviving lost record is a terminal disposition: any named loss
    # keeps its level incomplete, including groupless foreign losses
    # (whose runs ride the lost entries, never segment groups). Losses
    # reconciled against same-run authority dropped before anchoring, so
    # they reach neither this conjunct nor the rows below. For grouped
    # losses these conjuncts are redundant -- their has_lost group already
    # reads incomplete -- and change nothing. Unattributed segments keep
    # the GLOBAL flag incomplete; per-round flags never see them (they
    # belong to no round, not even "").
    complete = all(_counters_group_complete(group) for group in groups.values())
    complete = complete and not lost_processes and not unattributed_segments
    rounds = sorted(
        {key[0] for key in groups} | {entry.get("run_id", "") for entry in lost_processes}
    )
    round_rows: dict[str, list[dict[str, Any]]] = {run: [] for run in rounds}
    for (run, pid), state in sorted(pids.items()):
        if (
            state.has_session
            or state.fallback_used
            or state.partial_modules
            or state.end_states
            or state.loss.total() > 0
        ):
            round_rows[run].extend(_counters_process_rows(pid, state))
    show_round = len({run for run, rows in round_rows.items() if rows}) > 1
    by_process: list[dict[str, Any]] = []
    by_round: dict[str, Any] = {}
    lost_by_round: dict[str, list[dict[str, Any]]] = {run: [] for run in rounds}
    for entry in lost_processes:
        lost_by_round.setdefault(entry.get("run_id", ""), []).append(entry)
    for run in rounds:
        round_merged = merged_by_round.get(run, {"total_calls": 0, "by_module": {}})
        round_groups = [group for key, group in groups.items() if key[0] == run]
        round_complete = all(_counters_group_complete(group) for group in round_groups)
        round_complete = round_complete and not lost_by_round.get(run, [])
        round_block: dict[str, Any] = {
            "complete": round_complete,
            "total_calls": round_merged["total_calls"],
            "by_module": canonicalize_module_first(round_merged),
            "probes_lost": sum(group.loss.total() for group in round_groups),
            "by_process": _strip_single_module_tag([dict(row) for row in round_rows[run]]),
        }
        if lost_by_round.get(run):
            round_block["lost_processes"] = lost_by_round[run]
        round_receipts = sorted(receipts_by_round.get(run, set()))
        round_lost: set[tuple[str, int]] = set()
        for group in round_groups:
            round_lost |= group.loss.net_keys()
        round_lost_rows = [
            {"worker_uuid": parent, "probe_seq": seq, "status": "lost"}
            for parent, seq in sorted(round_lost)
        ]
        if round_receipts or round_lost_rows:
            # Folded rows first (legacy prefix-stable), then net lost rows.
            # A lost row's worker_uuid names the accounting parent (status
            # qualifies the identity); a folded row's names the child.
            round_block["probes_detail"] = [
                {"worker_uuid": uuid, "probe_seq": seq, "status": "folded"}
                for uuid, seq in round_receipts
            ] + round_lost_rows
        by_round[run] = round_block
        for row in round_rows[run]:
            tagged = dict(row)
            if show_round:
                tagged["round"] = run
            by_process.append(tagged)
    _strip_single_module_tag(by_process)
    merged = canonicalize_module_first(merged)
    payload: dict[str, Any] = {
        "complete": complete,
        "total_calls": merged["total_calls"],
        "by_module": merged,
        "probes_lost": sum(group.loss.total() for group in groups.values()),
        "by_process": by_process,
        "by_round": by_round,
    }
    if unattributed_segments:
        payload["unattributed_segments"] = unattributed_segments
    if lost_processes:
        payload["lost_processes"] = lost_processes
    ordered_receipts = sorted(receipts_all)
    net_lost: set[tuple[str, int]] = set()
    for group in groups.values():
        net_lost |= group.loss.net_keys()
    lost_rows = [
        {"worker_uuid": parent, "probe_seq": seq, "status": "lost"}
        for parent, seq in sorted(net_lost)
    ]
    if ordered_receipts or lost_rows:
        payload["probes_detail"] = [
            {"worker_uuid": uuid, "probe_seq": seq, "status": "folded"}
            for uuid, seq in ordered_receipts
        ] + lost_rows
    return payload


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
