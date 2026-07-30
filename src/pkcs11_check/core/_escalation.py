"""Crash escalation: promoting crashing units to test granularity and re-planning.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from rich.console import Console

from pkcs11_check.core._crash_classify import (
    _analyze_report_jsonl as _analyze_report_jsonl,
)
from pkcs11_check.core._crash_classify import (
    _crash_culprit_from_phases as _crash_culprit_from_phases,
)
from pkcs11_check.core._crash_classify import (
    _identify_crash_culprit as _identify_crash_culprit,
)
from pkcs11_check.core._crash_classify import (
    _identify_crash_culprit_from_records as _identify_crash_culprit_from_records,
)
from pkcs11_check.core._crash_classify import (
    _maybe_set_crash_journal as _maybe_set_crash_journal,
)
from pkcs11_check.core._crash_classify import (
    _read_jsonl_results as _read_jsonl_results,
)
from pkcs11_check.core._crash_classify import (
    _record_crash_phase as _record_crash_phase,
)
from pkcs11_check.core._crash_classify import (
    _status_from_returncode as _status_from_returncode,
)
from pkcs11_check.core._crash_classify import (
    crash_classification as crash_classification,
)
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


def _effective_granularity(unit: str, granularity: RunnerGranularity) -> IsolationGranularity:
    if granularity == "mixed":
        return "test" if "::" in unit else "file"
    return granularity


def _promote_crashing_unit(
    policy_file: Path | None,
    pytest_args: list[str],
    env: Mapping[str, str],
    unit: str,
    unit_granularity: IsolationGranularity,
    status: CrashStatus,
    console: Console,
) -> None:
    if policy_file is None:
        return

    policies = load_isolation_policy(policy_file)
    fingerprint = build_policy_fingerprint(pytest_args, env)
    policy = policies.get(
        fingerprint,
        BackendIsolationPolicy(fingerprint=fingerprint, promoted_files=[], crashed_tests=[]),
    )

    file_key = _unit_file_key(unit)
    changed = False

    if file_key not in policy.promoted_files:
        policy.promoted_files.append(file_key)
        policy.promoted_files.sort()
        changed = True

    if unit_granularity == "test" and unit not in policy.crashed_tests:
        policy.crashed_tests.append(unit)
        policy.crashed_tests.sort()
        changed = True

    if not changed:
        return

    policies[fingerprint] = policy
    save_isolation_policy(policy_file, policies)

    if unit_granularity == "file":
        console.print(
            f"[yellow]Adaptive isolation:[/yellow] {unit} {status}; "
            "future auto runs will promote this file to per-test isolation."
        )
    else:
        console.print(
            f"[yellow]Adaptive isolation:[/yellow] recorded crashing test {unit} after {status}."
        )


def _record_result(state: FileRunState, result: FileRunResult) -> None:
    for index, existing in enumerate(state.results):
        if existing.target == result.target:
            state.results[index] = result
            return
    state.results.append(result)


def _refresh_state_plan(
    state: FileRunState,
    units: list[str],
    pytest_args: list[str],
    env: Mapping[str, str],
    *,
    baseline_fingerprint: str | None = None,
) -> None:
    state.units = list(units)
    state.fingerprint = build_state_fingerprint(
        units,
        pytest_args,
        env,
        baseline_fingerprint=baseline_fingerprint,
    )


def _count_test_level_crashes_for_file(state: FileRunState, file_key: str) -> int:
    return sum(
        1
        for result in state.results
        if "::" in result.target
        and _unit_file_key(result.target) == file_key
        and result.status in {"crashed", "timeout"}
    )


def _limit_remaining_units_for_file(
    *,
    unit: str,
    units: list[str],
    index: int,
    pending_units: list[str],
    state: FileRunState,
    pytest_args: list[str],
    env: Mapping[str, str],
    console: Console,
    max_crashes_per_file: int,
    baseline_fingerprint: str | None = None,
) -> list[str]:
    if max_crashes_per_file <= 0 or "::" not in unit:
        return []

    file_key = _unit_file_key(unit)
    crash_count = _count_test_level_crashes_for_file(state, file_key)
    if crash_count < max_crashes_per_file:
        return []

    limited_units: list[str] = []
    for candidate in units[index + 1 :]:
        if "::" not in candidate or _unit_file_key(candidate) != file_key:
            continue
        if candidate not in pending_units:
            continue

        limited_units.append(candidate)
        _record_result(
            state,
            FileRunResult(
                target=candidate,
                status="crash_limited",
                returncode=0,
                duration_s=0.0,
            ),
        )

    if not limited_units:
        return []

    limited_set = set(limited_units)
    pending_units[:] = [candidate for candidate in pending_units if candidate not in limited_set]
    _refresh_state_plan(
        state,
        units,
        pytest_args,
        env,
        baseline_fingerprint=baseline_fingerprint,
    )
    console.print(
        "[yellow]Adaptive isolation:[/yellow] "
        f"reached the per-file crash limit for {Path(unit.split('::', 1)[0]).name} "
        f"({crash_count}/{max_crashes_per_file}); "
        f"skipping {len(limited_units)} remaining test units from that file."
    )
    return limited_units


def _insert_escalated_units(
    state: FileRunState,
    units: list[str],
    index: int,
    new_units: list[str],
    pytest_args: list[str],
    env: Mapping[str, str],
    *,
    baseline_fingerprint: str | None = None,
) -> list[str]:
    existing = set(units)
    additions = [unit for unit in new_units if unit not in existing]
    if not additions:
        return []

    insert_at = index + 1
    units[insert_at:insert_at] = additions
    _refresh_state_plan(
        state,
        units,
        pytest_args,
        env,
        baseline_fingerprint=baseline_fingerprint,
    )
    return additions


def _escalate_current_file(
    *,
    unit: str,
    units: list[str],
    index: int,
    state: FileRunState,
    pytest_args: list[str],
    env: Mapping[str, str],
    console: Console,
    disabled_nodeids: set[str] | None = None,
    exclude_nodeids: set[str] | None = None,
    baseline_fingerprint: str | None = None,
) -> list[str]:
    try:
        nodeids = discover_pytest_units(
            [unit],
            Path(unit).parent,
            granularity="test",
            pytest_args=pytest_args,
            env=env,
        )
    except ValueError as exc:
        console.print(
            f"[yellow]Adaptive isolation:[/yellow] failed to collect tests for {unit}: {exc}"
        )
        return []

    filtered_nodeids = (
        [nodeid for nodeid in nodeids if nodeid not in disabled_nodeids]
        if disabled_nodeids
        else nodeids
    )
    if exclude_nodeids:
        filtered_nodeids = [n for n in filtered_nodeids if n not in exclude_nodeids]

    additions = _insert_escalated_units(
        state,
        units,
        index,
        filtered_nodeids,
        pytest_args,
        env,
        baseline_fingerprint=baseline_fingerprint,
    )
    if additions:
        console.print(
            f"[yellow]Adaptive isolation:[/yellow] escalating {unit} to per-test isolation "
            f"for the rest of this run ({len(additions)} units)."
        )
    return additions
