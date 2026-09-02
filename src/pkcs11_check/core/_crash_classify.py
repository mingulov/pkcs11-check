"""Crash / timeout classification and crash-culprit identification from report.jsonl.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from pkcs11_check.core._jsonl_extract import (
    _emit_external_provision_banner as _emit_external_provision_banner,
)
from pkcs11_check.core._jsonl_extract import (
    extract_coverage_from_jsonl as extract_coverage_from_jsonl,
)
from pkcs11_check.core._jsonl_extract import (
    extract_provisioning_from_jsonl as extract_provisioning_from_jsonl,
)
from pkcs11_check.core._jsonl_extract import (
    postprocess_jsonl_to_unified as postprocess_jsonl_to_unified,
)
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
    _compliance_notes_from_user_properties as _compliance_notes_from_user_properties,
)
from pkcs11_check.core._report_records import (
    _delete_unit_report_record_cache as _delete_unit_report_record_cache,
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
from pkcs11_check.core._report_writers import (
    _build_isolated_json_payload as _build_isolated_json_payload,
)
from pkcs11_check.core._report_writers import (
    _junit_case_identity as _junit_case_identity,
)
from pkcs11_check.core._report_writers import (
    write_isolated_json_report as write_isolated_json_report,
)
from pkcs11_check.core._report_writers import (
    write_isolated_junit_report as write_isolated_junit_report,
)
from pkcs11_check.core._report_writers import (
    write_isolated_report as write_isolated_report,
)
from pkcs11_check.core._run_state import (
    _DEFAULT_FINGERPRINT_ENV_KEYS as _DEFAULT_FINGERPRINT_ENV_KEYS,
)
from pkcs11_check.core._run_state import (
    _DEFAULT_FINGERPRINT_ENV_PREFIXES as _DEFAULT_FINGERPRINT_ENV_PREFIXES,
)
from pkcs11_check.core._run_state import (
    _FINGERPRINT_ENV_KEYS_ENV as _FINGERPRINT_ENV_KEYS_ENV,
)
from pkcs11_check.core._run_state import (
    _FINGERPRINT_ENV_PREFIXES_ENV as _FINGERPRINT_ENV_PREFIXES_ENV,
)
from pkcs11_check.core._run_state import (
    _POLICY_IGNORED_ENV_KEYS as _POLICY_IGNORED_ENV_KEYS,
)
from pkcs11_check.core._run_state import (
    _REDACTED_ENV_KEYS as _REDACTED_ENV_KEYS,
)
from pkcs11_check.core._run_state import (
    _backend_args_snapshot as _backend_args_snapshot,
)
from pkcs11_check.core._run_state import (
    _fingerprint_env as _fingerprint_env,
)
from pkcs11_check.core._run_state import (
    _fingerprint_env_selectors as _fingerprint_env_selectors,
)
from pkcs11_check.core._run_state import (
    _fingerprint_units as _fingerprint_units,
)
from pkcs11_check.core._run_state import (
    _load_available_mechanisms as _load_available_mechanisms,
)
from pkcs11_check.core._run_state import (
    _manifest_digest as _manifest_digest,
)
from pkcs11_check.core._run_state import (
    _path_snapshot as _path_snapshot,
)
from pkcs11_check.core._run_state import (
    _split_env_list as _split_env_list,
)
from pkcs11_check.core._run_state import (
    build_policy_fingerprint as build_policy_fingerprint,
)
from pkcs11_check.core._run_state import (
    build_state_fingerprint as build_state_fingerprint,
)
from pkcs11_check.core._run_state import (
    load_run_state as load_run_state,
)
from pkcs11_check.core._run_state import (
    save_run_state as save_run_state,
)
from pkcs11_check.core._run_state import (
    units_remaining_for_resume as units_remaining_for_resume,
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
from pkcs11_check.core._unit_details import (
    _augment_mechanism_coverage_from_unit_outcomes as _augment_mechanism_coverage_from_unit_outcomes,  # noqa: E501
)
from pkcs11_check.core._unit_details import (
    _copy_detail as _copy_detail,
)
from pkcs11_check.core._unit_details import (
    _ensure_timeout_recorded as _ensure_timeout_recorded,
)
from pkcs11_check.core._unit_details import (
    _group_results_by_file as _group_results_by_file,
)
from pkcs11_check.core._unit_details import (
    _mechanism_name_set as _mechanism_name_set,
)
from pkcs11_check.core._unit_details import (
    _merge_special_entries_into_detail as _merge_special_entries_into_detail,
)
from pkcs11_check.core._unit_details import (
    _merge_supplemental_special_details as _merge_supplemental_special_details,
)
from pkcs11_check.core._unit_details import (
    _overall_unit_status as _overall_unit_status,
)
from pkcs11_check.core._unit_details import (
    _required_ckm_names_for_unit as _required_ckm_names_for_unit,
)
from pkcs11_check.core._unit_details import (
    _special_test_entry_from_result as _special_test_entry_from_result,
)
from pkcs11_check.core._unit_details import (
    _status_with_detail_counts as _status_with_detail_counts,
)
from pkcs11_check.core._unit_details import (
    _synthetic_file_skip_detail as _synthetic_file_skip_detail,
)
from pkcs11_check.core._unit_discovery import (
    _collection_args as _collection_args,
)
from pkcs11_check.core._unit_discovery import (
    _markers_by_file as _markers_by_file,
)
from pkcs11_check.core._unit_discovery import (
    _validate_pytest_target_exists as _validate_pytest_target_exists,
)
from pkcs11_check.core._unit_discovery import (
    collect_pytest_nodeids as collect_pytest_nodeids,
)
from pkcs11_check.core._unit_discovery import (
    discover_auto_isolation_units as discover_auto_isolation_units,
)
from pkcs11_check.core._unit_discovery import (
    discover_pytest_units as discover_pytest_units,
)
from pkcs11_check.core._unit_discovery import (
    file_forces_file_isolation as file_forces_file_isolation,
)
from pkcs11_check.core._unit_discovery import (
    file_isolation_mode as file_isolation_mode,
)
from pkcs11_check.core._unit_discovery import (
    load_isolation_policy as load_isolation_policy,
)
from pkcs11_check.core._unit_discovery import (
    load_promoted_files as load_promoted_files,
)
from pkcs11_check.core._unit_discovery import (
    save_isolation_policy as save_isolation_policy,
)
from pkcs11_check.core._unit_discovery import (
    validate_subprocess_per_test_expansion as validate_subprocess_per_test_expansion,
)
from pkcs11_check.core.crash_codes import (
    crash_detail_name as _crash_detail_name,
)
from pkcs11_check.core.crash_codes import (
    is_windows_crash_code as _is_windows_crash_code,
)
from pkcs11_check.core.report_log import (
    SessionCompletionTracker as _SessionCompletionTracker,
)
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)


def _status_from_returncode(returncode: int) -> str:
    if returncode == 0:
        return "passed"
    if returncode == 5:
        return "empty"
    if returncode == _TIMEOUT_RETURN_CODE:
        return "timeout"
    if returncode < 0:
        return "crashed"
    if sys.platform == "win32" and _is_windows_crash_code(returncode):
        return "crashed"
    return "failed"


def crash_classification(
    *,
    returncode: int | None,
    target: str,
    timed_out: bool = False,
    observation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a Classification-shaped dict for a crashed/hung test unit (process is dead, so
    this is produced runner/report-side, not via classify())."""
    if observation is not None:
        detail: dict[str, object] = {"observation": dict(observation)}
    elif timed_out:
        detail = {"mode": "timeout"}
    else:
        detail = {"signal": _crash_detail_name(returncode), "returncode": returncode}
    return {
        "schema": 1,
        "reason": "crash",
        "outcome": "fail",
        "severity": "HIGH",
        "kind": None,
        "label": target,
        "summary": f"{target}: process crashed",
        "operation": None,
        "mechanism": None,
        "expected_ckr": None,
        "actual_ckr": None,
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "detail": detail,
    }


def _maybe_set_crash_journal(run_env: dict[str, str], unit: str) -> None:
    """Opt-in: give the unit's subprocess a per-unit CK_RV crash journal.

    Off unless ``PKCS11_CHECK_RV_TRACE_JOURNAL_DIR`` is set (per-call flush has a
    cost, so it is not on by default). When set, a crash leaves the dying C_*
    call on disk under that dir; ``pkcs11-check crash-calls <dir>`` summarizes it.
    The ``{pid}`` placeholder is expanded by the child (``raw.api._journal_path``)
    so concurrent subprocesses don't collide.
    """
    journal_dir = run_env.get("PKCS11_CHECK_RV_TRACE_JOURNAL_DIR")
    if not journal_dir:
        return
    from pkcs11_check.core.crash_journal import unit_journal_slug

    Path(journal_dir).mkdir(parents=True, exist_ok=True)
    run_env["PKCS11_CHECK_RV_TRACE_JOURNAL"] = str(
        Path(journal_dir) / f"{unit_journal_slug(unit)}-{{pid}}.jsonl"
    )


def _identify_crash_culprit_from_records(
    records: Iterable[Mapping[str, Any]],
) -> tuple[str | None, list[str]]:
    """Identify crash culprit and completed tests from already-loaded records.

    Returns ``(culprit_nodeid, list_of_completed_nodeids)``.
    *culprit* is the nodeid that has ``setup`` started but no ``teardown``
    completed - i.e. the test that was running when the process crashed.
    Returns ``(None, completed_list)`` if every test finished cleanly.

    Takes records (already filtered to dicts by ``_load_report_log_records``)
    so a caller that also needs the per-test detail can parse the JSONL once
    and feed both this and ``_build_detail_from_report_records``.
    """
    phases: dict[str, set[str]] = {}
    for rec in records:
        _record_crash_phase(phases, rec)

    return _crash_culprit_from_phases(phases)


def _record_crash_phase(
    phases: dict[str, set[str]],
    rec: Mapping[str, Any],
) -> None:
    """Track pytest phase progress for crash culprit identification."""
    if rec.get("$report_type", "TestReport") != "TestReport":
        return
    nodeid: str = rec.get("nodeid", "")
    when: str = rec.get("when", "")
    if not nodeid or not when:
        return
    phases.setdefault(nodeid, set()).add(when)


def _crash_culprit_from_phases(phases: Mapping[str, set[str]]) -> tuple[str | None, list[str]]:
    """Return the unfinished setup node and completed tests from phase state."""
    completed: list[str] = []
    culprit: str | None = None
    for nid, ph in phases.items():
        if "teardown" in ph:
            completed.append(nid)
        elif "setup" in ph and culprit is None:
            culprit = nid

    return culprit, completed


def _identify_crash_culprit(jsonl_path: Path) -> tuple[str | None, list[str]]:
    """Identify crash culprit and completed tests from a partial JSONL file.

    Thin path wrapper over :func:`_identify_crash_culprit_from_records`.
    """
    return _identify_crash_culprit_from_records(_iter_report_log_records(jsonl_path))


def _read_jsonl_results(jsonl_path: Path) -> dict[str, Any] | None:
    """Read a pytest-reportlog JSONL file and return per-test outcomes.

    Returns ``{"counts": {...}, "tests": [...]}`` where ``tests`` contains
    only non-passing entries (failed, xfailed, xpassed, error).
    Returns ``None`` if the file is missing or empty.
    """
    return _build_detail_from_report_records(_iter_report_log_records(jsonl_path))


def _analyze_report_jsonl(
    jsonl_path: Path,
    *,
    state_file: Path | None = None,
    unit: str | None = None,
) -> tuple[dict[str, Any] | None, str | None, list[str], int | None]:
    """Stream a report JSONL once to build detail, crash progress, and optional cache."""
    if (state_file is None) != (unit is None):
        raise ValueError("state_file and unit must be provided together")

    phases: dict[str, set[str]] = {}
    completion = _SessionCompletionTracker()
    cache_path = _report_record_cache_path(state_file, unit) if state_file and unit else None
    tmp_path = cache_path.with_suffix(".jsonl.tmp") if cache_path is not None else None
    wrote_cache = False

    def iter_records(cache_fh: Any | None = None) -> Iterable[dict[str, Any]]:
        nonlocal wrote_cache
        for record in _iter_report_log_records(jsonl_path, on_invalid=completion.invalidate):
            _record_crash_phase(phases, record)
            completion.observe(record)
            if cache_fh is not None:
                cache_fh.write(json.dumps(record) + "\n")
                wrote_cache = True
            yield record

    if cache_path is None or tmp_path is None:
        detail = _build_detail_from_report_records(iter_records())
        culprit, completed = _crash_culprit_from_phases(phases)
        return detail, culprit, completed, completion.single_exitstatus

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            detail = _build_detail_from_report_records(iter_records(out_fh))
        if wrote_cache:
            tmp_path.replace(cache_path)
        else:
            tmp_path.unlink(missing_ok=True)
            cache_path.unlink(missing_ok=True)
        culprit, completed = _crash_culprit_from_phases(phases)
        return detail, culprit, completed, completion.single_exitstatus
    finally:
        tmp_path.unlink(missing_ok=True)
