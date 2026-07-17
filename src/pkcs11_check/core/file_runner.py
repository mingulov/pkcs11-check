"""Per-unit pytest runner with subprocess isolation and resume support."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import IO, Any

from rich.console import Console

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
from pkcs11_check.core.recovery import (
    RecoveryConfig,
    RecoveryController,
    RecoveryOutcome,
    probe_provider_liveness,
    run_recover_cmd,
)
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.test_selection import extract_required_mechanisms, write_deselect_file

_MAX_TIMEOUT_RETRIES = 3
# Exit code when the selection (module/marker/match/path) collected ZERO tests:
# a run that executed nothing must not report success. Maps to the contract's
# "couldn't run" code 2 (docs/integration-contract.md), so CI gates on rc>=2.
_NO_TESTS_COLLECTED_EXIT = 2
# After a child exits on its own, any un-read pipe data is at most the OS pipe
# buffer and drains in milliseconds. Cap the post-exit reader-thread join so a
# grandchild that inherited the pipe write-end cannot stall the runner for the
# full per-test timeout (issue #3: Windows "hangs, single CTRL-C unblocks", where
# a provider DLL more readily leaves a handle-inheriting helper process). Daemon
# readers are abandoned after the grace and die at process exit.
_POST_EXIT_DRAIN_GRACE_S = 3.0


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
) -> dict[str, object]:
    """Build a Classification-shaped dict for a crashed/hung test unit (process is dead, so
    this is produced runner/report-side, not via classify())."""
    if timed_out:
        detail: dict[str, object] = {"mode": "timeout"}
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
) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    """Stream a report JSONL once to build detail, crash progress, and optional cache."""
    if (state_file is None) != (unit is None):
        raise ValueError("state_file and unit must be provided together")

    phases: dict[str, set[str]] = {}
    cache_path = _report_record_cache_path(state_file, unit) if state_file and unit else None
    tmp_path = cache_path.with_suffix(".jsonl.tmp") if cache_path is not None else None
    wrote_cache = False

    def iter_records(cache_fh: Any | None = None) -> Iterable[dict[str, Any]]:
        nonlocal wrote_cache
        for record in _iter_report_log_records(jsonl_path):
            _record_crash_phase(phases, record)
            if cache_fh is not None:
                cache_fh.write(json.dumps(record) + "\n")
                wrote_cache = True
            yield record

    if cache_path is None or tmp_path is None:
        detail = _build_detail_from_report_records(iter_records())
        culprit, completed = _crash_culprit_from_phases(phases)
        return detail, culprit, completed

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
        return detail, culprit, completed
    finally:
        tmp_path.unlink(missing_ok=True)


def _unit_timeout_seconds(
    test_timeout: int,
    granularity: IsolationGranularity,
    *,
    num_tests: int = 0,
) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    if num_tests > 0:
        # 5s per test + 60s startup overhead, floor 300s, cap 14400s (4h)
        return min(max(num_tests * 5 + 60, 300), 14400)
    return max(test_timeout * 30, 900)


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


# Plugins the per-unit pytest subprocess actually needs. Disabling autoload of
# everything else (hypothesis, pytest-benchmark, pytest-cov, xdist) trims ~0.15s
# of fixed startup off every isolated unit. hypothesis/benchmark are re-enabled
# only for the files that use them (detected from source) so test behavior is
# unchanged.
_BASE_SUBPROCESS_PLUGINS: tuple[str, ...] = ("pkcs11-check", "pytest_reportlog", "timeout")
_HYPOTHESIS_IMPORT_RE = re.compile(r"(?m)^\s*(?:from|import)\s+hypothesis\b")
_BENCHMARK_FIXTURE_RE = re.compile(r"def\s+\w+\s*\([^)]*\bbenchmark\b")


@cache
def _unit_plugin_addopts(file_path: str) -> str | None:
    """Return the ``-p ...`` addopts for a unit's subprocess, or None to leave
    plugin autoload enabled (used when the source cannot be read)."""
    try:
        text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    plugins = list(_BASE_SUBPROCESS_PLUGINS)
    if _HYPOTHESIS_IMPORT_RE.search(text):
        plugins.append("hypothesispytest")
    if _BENCHMARK_FIXTURE_RE.search(text):
        plugins.append("benchmark")
    return " ".join(f"-p {name}" for name in plugins)


def _subprocess_plugin_env(base_env: Mapping[str, str], unit: str) -> dict[str, str]:
    """Per-unit env that disables pytest plugin autoload and enables only the
    plugins the unit needs. Behavior-preserving; only trims startup cost."""
    env = dict(base_env)
    # UTF-8 so a unit's pytest subprocess output (rich marks etc.) does not crash on a
    # Windows cp1252 console; no-op off Windows. setdefault respects an explicit value.
    if sys.platform == "win32":
        env.setdefault("PYTHONUTF8", "1")
    addopts = _unit_plugin_addopts(unit.split("::", 1)[0])
    if addopts is None:
        return env
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    existing = env.get("PYTEST_ADDOPTS", "").strip()
    env["PYTEST_ADDOPTS"] = f"{addopts} {existing}".strip()
    return env


def _join_readers_bounded(threads: list[threading.Thread], *, grace: float) -> None:
    """Join each reader thread, but never wait longer than ``grace`` seconds total
    after the child has already exited. A still-running daemon reader is abandoned
    (it dies at process exit); its un-drained tail is acceptable to lose."""
    deadline = time.monotonic() + grace
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))


def _run_subprocess_tee(
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: int,
) -> tuple[int, str, str]:
    """Run a subprocess with tee-style output: live display AND capture.

    Returns (returncode, captured_stdout, captured_stderr).
    If the process is killed by a signal, returncode is negative.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    stdout_buf = io.BytesIO()
    stderr_buf = io.BytesIO()

    # Drain each pipe in its own thread rather than selecting over the pipe fds:
    # selectors.select() on an OS pipe is POSIX-only (Windows select() accepts
    # only sockets -> WSAENOTSOCK, issue #3). Threads read+tee identically on both
    # platforms and drain concurrently with the child, so output larger than the
    # pipe buffer cannot deadlock the child.
    console_lock = threading.Lock()

    def _pump(stream: IO[bytes], buf: io.BytesIO, is_stdout: bool) -> None:
        try:
            while True:
                chunk = stream.read1(8192) if hasattr(stream, "read1") else stream.read(8192)
                if not chunk:
                    break
                buf.write(chunk)
                target = sys.stdout.buffer if is_stdout else sys.stderr.buffer
                with console_lock:
                    target.write(chunk)
                    target.flush()
        except (OSError, ValueError):
            # stream closed underneath us (e.g. proc.kill on the timeout path).
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads: list[threading.Thread] = []
    for stream, buf, is_stdout in (
        (proc.stdout, stdout_buf, True),
        (proc.stderr, stderr_buf, False),
    ):
        if stream is None:
            continue
        thread = threading.Thread(target=_pump, args=(stream, buf, is_stdout), daemon=True)
        thread.start()
        threads.append(thread)

    deadline = time.monotonic() + timeout
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The child is still running at the deadline -- a genuine timeout. Kill,
        # reap (never leave a zombie behind, R5), and re-raise.
        proc.kill()
        proc.wait()
        for thread in threads:
            thread.join(timeout=max(0.0, deadline + 0.5 - time.monotonic()))
        raise subprocess.TimeoutExpired(cmd, timeout)

    # The child exited on its own -- cleanly OR via a crash signal (negative
    # returncode). Drain the readers, but only for a short grace: the child is
    # gone, so any un-read data is at most the OS pipe buffer. A surviving
    # grandchild that inherited the pipe (R2) must NOT hold the runner for the
    # full residual timeout (issue #3 Windows hang); abandon a stuck reader after
    # the grace and report the child's real returncode.
    _join_readers_bounded(threads, grace=_POST_EXIT_DRAIN_GRACE_S)

    proc.wait()
    return (
        proc.returncode,
        stdout_buf.getvalue().decode("utf-8", errors="replace"),
        stderr_buf.getvalue().decode("utf-8", errors="replace"),
    )


def _build_recovery_controller(
    recovery_config: RecoveryConfig | None, pytest_args: list[str]
) -> RecoveryController | None:
    """Bind a RecoveryController to this run's provider, or None when recovery is off.

    The probe/recover callables close over the run's module/interface/slot (extracted from
    pytest_args). ``recover`` performs one cycle: in ``cmd`` mode it invokes the no-shell command,
    then (both modes) waits ``wait_s`` for the external supervisor; the injected probe decides
    whether the daemon actually came back. Returns None when disabled so the run loop stays inert.
    """
    if recovery_config is None or recovery_config.mode == "off":
        return None
    module_path = _extract_option_value(pytest_args, "--p11-module")
    interface = _extract_option_value(pytest_args, "--p11-interface") or "auto"
    slot_raw = _extract_option_value(pytest_args, "--p11-slot")
    try:
        slot = int(slot_raw) if slot_raw else 0
    except ValueError:
        slot = 0

    def _probe() -> bool:
        if not module_path:
            return True  # cannot probe without a module -> treat as alive (never recover)
        live = probe_provider_liveness(
            Path(module_path),
            interface=interface,
            slot=slot,
            timeout=int(recovery_config.probe_timeout_s),
        )
        if live:
            return True
        # A single failing probe can be a slow/timeout blip on a live-but-busy provider; a real
        # daemon death is persistent. Re-confirm once before declaring it dead, so we never
        # recover (in cmd mode, restart) a provider that is merely slow.
        return probe_provider_liveness(
            Path(module_path),
            interface=interface,
            slot=slot,
            timeout=int(recovery_config.probe_timeout_s),
        )

    def _recover() -> bool:
        if recovery_config.mode == "cmd" and recovery_config.recover_cmd:
            run_recover_cmd(recovery_config.recover_cmd, timeout=recovery_config.cmd_timeout_s)
        time.sleep(recovery_config.wait_s)
        return True

    return RecoveryController(recovery_config, probe=_probe, recover=_recover)


def _apply_recovery_between_units(
    controller: RecoveryController,
    new_results: Sequence[FileRunResult],
    *,
    console: Console,
) -> bool:
    """Feed newly-completed unit results to the recovery controller, in order.

    Prints a never-silent banner on each confirmed daemon-death event (the crash finding is never
    hidden) and on abort. Returns True iff the run must abort (provider unrecoverable or the global
    recovery budget exhausted). NOTE (Level A): hint-RVs are not yet scanned from report records, so
    detection uses the consecutive-failure and crash triggers (the spec's primary path); the hint
    fast-path, streak re-queue, and structured report.jsonl finding are scoped refinements.
    """
    for result in new_results:
        assessment = controller.assess(result.target, result.status, frozenset())
        if not assessment.records:
            continue
        for record in assessment.records:
            trigger = record.get("trigger_unit", result.target)
            console.print(f"[red]DAEMON UNREACHABLE[/red] after {trigger} (liveness probe failed)")
        if assessment.outcome is RecoveryOutcome.ABORT:
            console.print(
                "[red]Provider unrecoverable[/red] - stopping this run (recovery attempts or "
                "global budget exhausted). Remaining units not run."
            )
            return True
        if assessment.outcome is RecoveryOutcome.RECOVERED_RETRY:
            console.print("[green]Daemon recovered[/green] - resuming the run.")
        elif assessment.outcome is RecoveryOutcome.QUARANTINE:
            console.print(
                f"[yellow]Quarantining[/yellow] {result.target} - repeatedly crashed the daemon."
            )
    return False


def run_isolated_pytest_units(
    units: list[str],
    pytest_args: list[str],
    *,
    deselect_by_file: Mapping[str, set[str]] | None = None,
    baseline_fingerprint: str | None = None,
    timeout: int,
    state_file: Path,
    policy_file: Path | None,
    report_config: IsolatedReportConfig | None,
    resume: bool,
    stop_on_failure: bool,
    console: Console,
    granularity: RunnerGranularity = "file",
    max_crashes_per_file: int = 10,
    provenance: dict[str, Any] | None = None,
    recovery_config: RecoveryConfig | None = None,
) -> int:
    """Run pytest units in fresh subprocesses and persist progress.

    ``recovery_config`` (default None / mode "off") enables crashing-daemon recovery: the run
    detects a dead daemon between units, pauses for it to return, supersedes the false-failure
    cascade, and resumes or aborts honestly. The wiring is inert unless mode != "off", so a
    default run is byte-identical. See core/recovery.py.
    """
    if not units:
        # No tests were collected — the module / marker / match / path selection
        # matched nothing. A run that executed zero tests must NOT report success
        # (that lets a scoping mistake pass green in CI). This is a "couldn't run"
        # condition, not a clean pass. See docs/integration-contract.md.
        console.print(
            "[red]ERROR: no tests were collected[/red] — the module / marker / "
            "match / path selection matched nothing. Refusing to report success "
            "for a run that executed zero tests."
        )
        if report_config is not None:
            empty_state = FileRunState(units=[], fingerprint="", results=[])
            if report_config.output_format == "json":
                payload = write_isolated_json_report(
                    report_config.output_path, empty_state, provenance=provenance
                )
                write_quality_json_report(
                    report_config.output_path.parent / "quality.json", payload
                )
            else:
                write_isolated_report(report_config, empty_state)
        return _NO_TESTS_COLLECTED_EXIT
    env = os.environ.copy()
    deselect_by_file = {unit: set(nodeids) for unit, nodeids in (deselect_by_file or {}).items()}
    fingerprint = build_state_fingerprint(
        units,
        pytest_args,
        env,
        baseline_fingerprint=baseline_fingerprint,
    )
    previous_state = load_run_state(state_file) if resume else None
    if previous_state is not None and previous_state.fingerprint != fingerprint:
        msg = (
            f"state file {state_file} belongs to a different isolated run; "
            "use a different --state-file or remove the old one"
        )
        raise ValueError(msg)

    state = previous_state or FileRunState(units=units, fingerprint=fingerprint, results=[])
    pending_units = units_remaining_for_resume(units, previous_state)

    if resume:
        if previous_state is None:
            console.print(
                f"[yellow]No prior state[/yellow] at [bold]{state_file}[/bold]; starting fresh."
            )
            save_run_state(state_file, state)
        else:
            console.print(
                f"[cyan]Resuming[/cyan] isolated run from "
                f"[bold]{state_file}[/bold] ({len(pending_units)}/{len(units)} units pending)"
            )
    else:
        state = FileRunState(units=units, fingerprint=fingerprint, results=[])
        save_run_state(state_file, state)
        if granularity == "test":
            unit_noun = "tests"
        elif granularity == "file":
            unit_noun = "files"
        else:
            unit_noun = "units"
        console.print(
            f"[cyan]Running[/cyan] {len(units)} pytest {unit_noun} "
            f"with {granularity} isolation "
            f"(state: [bold]{state_file}[/bold])"
        )

    per_unit_details: dict[str, dict[str, Any]] = {}
    executed_units: set[str] = set()
    available_mechanisms = _load_available_mechanisms(pytest_args)
    recovery_controller = _build_recovery_controller(recovery_config, pytest_args)
    # Number of results already fed to the recovery controller. Seed from any results already in
    # state (a --resume run) so the look-back only ever covers deaths in THIS session, not stale
    # historical failures (which are already recorded).
    recovery_assessed = len(state.results)

    if not pending_units:
        console.print("[green]Nothing to do[/green] - all isolated units already completed.")
        if report_config is not None:
            coverage_data: dict[str, Any] | None = None
            quality_records: list[dict[str, Any]] = []
            inline_report_records_by_unit: dict[str, Sequence[Mapping[str, Any]]] = {}
            for unit, records in state.report_records_by_unit.items():
                inline_report_records_by_unit.setdefault(unit, records)
            if (
                resume
                and report_config.jsonl_path is not None
                and report_config.jsonl_path.exists()
            ):
                candidate_targets = set(state.units) | {result.target for result in state.results}
                _seed_missing_report_record_caches_from_jsonl(
                    state_file,
                    report_config.jsonl_path,
                    candidate_targets=candidate_targets,
                    skip_units=inline_report_records_by_unit,
                )
            merged_details = _build_per_unit_details_from_record_sources(
                state_file,
                units=state.units,
                inline_records_by_unit=inline_report_records_by_unit,
            )
            if report_config.jsonl_path is not None:
                wrote_report_jsonl = _write_report_jsonl_from_record_sources(
                    state_file,
                    units=state.units,
                    inline_records_by_unit=inline_report_records_by_unit,
                    output_path=report_config.jsonl_path,
                )
                if wrote_report_jsonl or report_config.jsonl_path.exists():
                    coverage_data = extract_coverage_from_jsonl(report_config.jsonl_path)
                    quality_records = extract_quality_report_records_from_jsonl(
                        report_config.jsonl_path
                    )
                    coverage_data = _augment_mechanism_coverage_from_unit_outcomes(
                        coverage_data,
                        state,
                        per_unit_details=merged_details,
                    )
                    if coverage_data:
                        coverage_path = report_config.jsonl_path.parent / "coverage.json"
                        coverage_path.write_text(
                            json.dumps(coverage_data, indent=2) + "\n", encoding="utf-8"
                        )
                    provisioning_data = extract_provisioning_from_jsonl(report_config.jsonl_path)
                    if provisioning_data is not None:
                        provisioning_path = report_config.jsonl_path.parent / "provisioning.json"
                        provisioning_path.write_text(
                            json.dumps(provisioning_data, indent=2) + "\n", encoding="utf-8"
                        )
                        if provisioning_data["totals"].get("ran_via_external", 0) > 0:
                            _emit_external_provision_banner(
                                provisioning_data["totals"]["ran_via_external"]
                            )
            if report_config.output_format == "json":
                results_payload = write_isolated_json_report(
                    report_config.output_path,
                    state,
                    per_unit_details=merged_details,
                    coverage=coverage_data,
                    provenance=provenance,
                )
                quality_path = report_config.output_path.parent / "quality.json"
                write_quality_json_report(
                    quality_path,
                    results_payload,
                    coverage=coverage_data,
                    report_log_records=quality_records,
                )
            else:
                write_isolated_report(
                    report_config,
                    state,
                    per_unit_details=merged_details,
                )
        return 0

    exit_code = 0
    index = 0
    try:
        while index < len(units):
            unit = units[index]
            if unit not in pending_units:
                index += 1
                continue

            # -- Crashing-daemon recovery (between-unit look-back) --
            # Feed every result completed since the last check to the controller, in order, BEFORE
            # running the next unit. A confirmed daemon death triggers wait/restart + re-probe here,
            # so the upcoming unit runs against a recovered daemon (or the run aborts honestly).
            # Inert unless recovery is enabled, so default runs are byte-identical.
            if recovery_controller is not None and recovery_assessed < len(state.results):
                abort = _apply_recovery_between_units(
                    recovery_controller,
                    state.results[recovery_assessed:],
                    console=console,
                )
                recovery_assessed = len(state.results)
                if abort:
                    exit_code = 1
                    break

            executed_units.add(unit)
            if report_config is not None and report_config.jsonl_path is not None:
                _delete_unit_report_record_cache(state_file, unit)
                state.report_records_by_unit.pop(unit, None)
            console.print(f"[cyan][{index + 1}/{len(units)}][/cyan] {unit}")

            # -- Static mechanism skip --
            if available_mechanisms is not None:
                required = extract_required_mechanisms(unit.split("::", 1)[0])
                if required is not None:
                    missing = [m for m in required if m not in available_mechanisms]
                    if missing:
                        reason = f"{', '.join(missing)} not supported by module"
                        console.print(f"  [dim]file-skip: {reason}[/dim]")
                        result = FileRunResult(
                            target=unit,
                            status="passed",
                            returncode=0,
                            duration_s=0.0,
                        )
                        _record_result(state, result)
                        per_unit_details[unit] = _synthetic_file_skip_detail(
                            unit,
                            reason,
                            pytest_args,
                            env,
                        )
                        save_run_state(state_file, state)
                        index += 1
                        continue

            start = time.monotonic()
            unit_granularity = _effective_granularity(unit, granularity)
            unit_disabled_nodeids = (
                set(deselect_by_file.get(unit, set())) if unit_granularity == "file" else set()
            )

            # File-level runs always benefit from JSONL detail. Test-level runs
            # only need it when we are building merged JSON artifacts.
            unit_jsonl_path: Path | None = None
            initial_deselect_path: Path | None = None
            run_env = _subprocess_plugin_env(env, unit)
            _maybe_set_crash_journal(run_env, unit)
            collect_report_log = unit_granularity == "file" or (
                report_config is not None and report_config.jsonl_path is not None
            )
            if unit_disabled_nodeids:
                initial_deselect_path = write_deselect_file(unit_disabled_nodeids)
                run_env["PKCS11_CHECK_DESELECT_FILE"] = str(initial_deselect_path)
            if collect_report_log:
                unit_jsonl_fd, unit_jsonl_raw = tempfile.mkstemp(
                    prefix="pkcs11-check-jsonl-", suffix=".jsonl"
                )
                os.close(unit_jsonl_fd)
                unit_jsonl_path = Path(unit_jsonl_raw)
                cmd = [
                    sys.executable,
                    "-m",
                    "pytest",
                    unit,
                    *pytest_args,
                    "--report-log",
                    str(unit_jsonl_path),
                ]
            else:
                cmd = [sys.executable, "-m", "pytest", unit, *pytest_args]

            try:
                try:
                    returncode, captured_stdout, captured_stderr = _run_subprocess_tee(
                        cmd,
                        env=run_env,
                        timeout=_unit_timeout_seconds(timeout, unit_granularity),
                    )
                    status = _status_from_returncode(returncode)
                except subprocess.TimeoutExpired:
                    duration_s = time.monotonic() - start
                    if unit_jsonl_path is not None:
                        if report_config is not None and report_config.jsonl_path is not None:
                            _write_unit_report_record_cache_from_jsonl_paths(
                                state_file,
                                unit,
                                [unit_jsonl_path],
                            )
                    result = FileRunResult(
                        target=unit,
                        status="timeout",
                        returncode=_TIMEOUT_RETURN_CODE,
                        duration_s=duration_s,
                    )
                    _record_result(state, result)
                    save_run_state(state_file, state)

                    # -- Timeouts do NOT promote to policy (unlike crashes) --

                    # -- Progressive timeout retry for file-level mixed mode --
                    if (
                        granularity == "mixed"
                        and unit_granularity == "file"
                        and not stop_on_failure
                    ):
                        to_deselect: set[str] = set(unit_disabled_nodeids)
                        to_accum_detail: dict[str, Any] | None = None
                        total_retry_dur = 0.0
                        to_iter_jsonl: Path | None = unit_jsonl_path
                        to_retry_temps: list[Path] = []
                        escalate = False
                        retry_count = 0

                        try:
                            while retry_count < _MAX_TIMEOUT_RETRIES:
                                # Stream JSONL once for completed + culprit + detail.
                                if to_iter_jsonl is not None:
                                    iter_detail, culprit, completed = _analyze_report_jsonl(
                                        to_iter_jsonl
                                    )
                                else:
                                    culprit, completed = None, []
                                    iter_detail = None

                                to_deselect.update(completed)

                                # Merge partial results
                                if iter_detail is not None:
                                    if to_accum_detail is None:
                                        to_accum_detail = iter_detail
                                    else:
                                        for k in to_accum_detail["counts"]:
                                            to_accum_detail["counts"][k] += iter_detail[
                                                "counts"
                                            ].get(k, 0)
                                        to_accum_detail["tests"].extend(
                                            iter_detail["tests"],
                                        )
                                        for reason, cnt in iter_detail.get(
                                            "skip_reasons", {}
                                        ).items():
                                            to_accum_detail.setdefault("skip_reasons", {})[
                                                reason
                                            ] = (
                                                to_accum_detail.get("skip_reasons", {}).get(
                                                    reason, 0
                                                )
                                                + cnt
                                            )

                                if culprit:
                                    # Confirm timeout culprit individually
                                    console.print(
                                        f"[yellow]Confirming timeout culprit:[/yellow] {culprit}"
                                    )
                                    try:
                                        confirm_rc, confirm_out, confirm_err = _run_subprocess_tee(
                                            [
                                                sys.executable,
                                                "-m",
                                                "pytest",
                                                culprit,
                                                *pytest_args,
                                            ],
                                            env=env,
                                            timeout=_unit_timeout_seconds(timeout, "test"),
                                        )
                                    except subprocess.TimeoutExpired:
                                        confirm_rc = _TIMEOUT_RETURN_CODE
                                        confirm_out = confirm_err = ""
                                    confirm_status = _status_from_returncode(confirm_rc)
                                    culprit_outcome = (
                                        "timeout"
                                        if confirm_status == "timeout"
                                        else "passed-in-isolation"
                                    )
                                    to_culprit_entry: dict[str, Any] = {
                                        "nodeid": culprit,
                                        "outcome": culprit_outcome,
                                    }
                                    if confirm_status == "timeout":
                                        to_culprit_entry["longrepr"] = (
                                            confirm_err.strip() or confirm_out.strip()
                                        )
                                    if confirm_out.strip():
                                        to_culprit_entry["stdout"] = confirm_out
                                    if confirm_err.strip():
                                        to_culprit_entry["stderr"] = confirm_err
                                    if to_accum_detail is None:
                                        to_accum_detail = {
                                            "counts": _empty_counts(),
                                            "tests": [],
                                        }
                                    to_accum_detail["tests"].append(to_culprit_entry)
                                    if culprit_outcome == "timeout":
                                        to_accum_detail["counts"]["timeout"] = (
                                            to_accum_detail["counts"].get("timeout", 0) + 1
                                        )
                                    to_deselect.add(culprit)

                                # -- check exit conditions --
                                if not culprit and not completed:
                                    escalate = True
                                    break
                                if not to_deselect:
                                    escalate = True
                                    break

                                # -- retry file with deselect --
                                deselect_path = write_deselect_file(to_deselect)
                                to_retry_temps.append(deselect_path)

                                retry_jsonl_fd, retry_jsonl_raw = tempfile.mkstemp(
                                    prefix="pkcs11-check-timeout-retry-",
                                    suffix=".jsonl",
                                )
                                os.close(retry_jsonl_fd)
                                retry_jsonl_path = Path(retry_jsonl_raw)
                                to_retry_temps.append(retry_jsonl_path)

                                retry_env = dict(env)
                                retry_env["PKCS11_CHECK_DESELECT_FILE"] = str(deselect_path)
                                retry_cmd = [
                                    sys.executable,
                                    "-m",
                                    "pytest",
                                    unit,
                                    *pytest_args,
                                    "--report-log",
                                    str(retry_jsonl_path),
                                ]
                                console.print(
                                    f"[yellow]Adaptive isolation:[/yellow] "
                                    f"retrying {unit} with "
                                    f"{len(to_deselect)} tests deselected "
                                    f"(timeout retry {retry_count + 1}/"
                                    f"{_MAX_TIMEOUT_RETRIES})"
                                )
                                retry_start = time.monotonic()
                                try:
                                    retry_rc, retry_out, retry_err = _run_subprocess_tee(
                                        retry_cmd,
                                        env=retry_env,
                                        timeout=_unit_timeout_seconds(timeout, unit_granularity),
                                    )
                                    retry_status = _status_from_returncode(retry_rc)
                                except subprocess.TimeoutExpired:
                                    retry_status = "timeout"
                                    retry_rc = _TIMEOUT_RETURN_CODE
                                    retry_out = retry_err = ""
                                retry_dur = time.monotonic() - retry_start
                                total_retry_dur += retry_dur

                                if retry_status != "timeout":
                                    # Retry completed (pass or fail) - merge
                                    final_detail = _read_jsonl_results(retry_jsonl_path)
                                    if final_detail is not None:
                                        if to_accum_detail is None:
                                            to_accum_detail = final_detail
                                        else:
                                            for k in to_accum_detail["counts"]:
                                                to_accum_detail["counts"][k] += final_detail[
                                                    "counts"
                                                ].get(k, 0)
                                            to_accum_detail["tests"].extend(final_detail["tests"])

                                    # The file timed out at least once. When a
                                    # specific test was confirmed as the culprit
                                    # its timeout is already counted above; when
                                    # it could not be attributed (no culprit, or
                                    # the culprit passed in isolation) and the
                                    # rest then pass, preserve an unattributed
                                    # file-level timeout so the green retry does
                                    # not hide a real hang (review finding R3).
                                    to_accum_detail = _ensure_timeout_recorded(
                                        to_accum_detail, unit
                                    )

                                    keep = retry_status != "passed" or (
                                        to_accum_detail is not None
                                        and any(
                                            to_accum_detail["counts"].get(k, 0) > 0
                                            for k in (
                                                "failed",
                                                "xfailed",
                                                "xpassed",
                                                "error",
                                            )
                                        )
                                    )
                                    result = FileRunResult(
                                        target=unit,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        duration_s=(duration_s + total_retry_dur),
                                        stdout=(retry_out if keep else ""),
                                        stderr=(retry_err if keep else ""),
                                    )
                                    _record_result(state, result)
                                    save_run_state(state_file, state)
                                    if to_accum_detail is not None:
                                        per_unit_details[unit] = to_accum_detail
                                    console.print(
                                        f"[green]RETRY OK[/green] {unit} "
                                        f"({total_retry_dur:.1f}s, "
                                        f"{len(to_deselect)} deselected)"
                                    )
                                    if retry_status == "failed":
                                        exit_code = 1
                                    index += 1
                                    break  # exit retry loop

                                # Retry also timed out - loop
                                retry_count += 1
                                console.print(
                                    f"[red]RETRY TIMEOUT[/red] {unit} "
                                    f"(attempt {retry_count}/{_MAX_TIMEOUT_RETRIES})"
                                )
                                to_iter_jsonl = retry_jsonl_path
                                # Continue the while loop

                            else:
                                # while loop exhausted retries without break
                                escalate = True

                        finally:
                            all_iter_jsonls = (
                                [unit_jsonl_path] if unit_jsonl_path else []
                            ) + to_retry_temps
                            if report_config is not None and report_config.jsonl_path is not None:
                                _write_unit_report_record_cache_from_jsonl_paths(
                                    state_file,
                                    unit,
                                    all_iter_jsonls,
                                )
                                save_run_state(state_file, state)
                            for tmp in all_iter_jsonls:
                                tmp.unlink(missing_ok=True)

                        if not escalate:
                            # Retry loop succeeded
                            continue

                        # Fall back: escalate remaining tests
                        if to_accum_detail is not None:
                            per_unit_details[unit] = to_accum_detail

                        escalated_units = _escalate_current_file(
                            unit=unit,
                            units=units,
                            index=index,
                            state=state,
                            pytest_args=pytest_args,
                            env=env,
                            console=console,
                            disabled_nodeids=unit_disabled_nodeids,
                            exclude_nodeids=to_deselect,
                            baseline_fingerprint=baseline_fingerprint,
                        )
                        if escalated_units:
                            _record_result(
                                state,
                                FileRunResult(
                                    target=unit,
                                    status="escalated",
                                    returncode=_TIMEOUT_RETURN_CODE,
                                    duration_s=duration_s,
                                ),
                            )
                            save_run_state(state_file, state)
                            pending_units.extend(escalated_units)
                            exit_code = 1
                            console.print(f"[red]TIMEOUT[/red] {unit} ({duration_s:.1f}s)")
                            index += 1
                            continue

                    if granularity in {"mixed", "test"} and unit_granularity == "test":
                        limited_units = _limit_remaining_units_for_file(
                            unit=unit,
                            units=units,
                            index=index,
                            pending_units=pending_units,
                            state=state,
                            pytest_args=pytest_args,
                            env=env,
                            console=console,
                            max_crashes_per_file=max_crashes_per_file,
                            baseline_fingerprint=baseline_fingerprint,
                        )
                        if limited_units:
                            save_run_state(state_file, state)

                    console.print(f"[red]TIMEOUT[/red] {unit} ({duration_s:.1f}s)")
                    exit_code = 1
                    if stop_on_failure:
                        console.print(
                            f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                            f"[bold]--resume --state-file {state_file}[/bold]."
                        )
                        return exit_code
                    index += 1
                    continue

                duration_s = time.monotonic() - start

                # Extract per-test detail before building the result so we
                # can decide whether to keep stdout/stderr.
                # Keep the JSONL path for the crash handler (iterative deselect
                # needs to re-read it for culprit identification).
                crash_jsonl_path: Path | None = unit_jsonl_path
                detail: dict[str, Any] | None = None
                if unit_jsonl_path is not None:
                    if report_config is not None and report_config.jsonl_path is not None:
                        detail, _culprit, _completed = _analyze_report_jsonl(
                            unit_jsonl_path,
                            state_file=state_file,
                            unit=unit,
                        )
                    else:
                        detail, _culprit, _completed = _analyze_report_jsonl(unit_jsonl_path)
                    if status not in ("crashed", "timeout"):
                        unit_jsonl_path.unlink(missing_ok=True)
                        crash_jsonl_path = None
                    unit_jsonl_path = None

                # Keep output for non-passing units AND for units that
                # contain xfailed/xpassed/error tests (useful for debugging
                # even when the overall unit status is "passed").
                has_notable_tests = detail is not None and any(
                    detail["counts"].get(k, 0) > 0
                    for k in ("failed", "xfailed", "xpassed", "error")
                )
                keep_output = status not in ("passed",) or has_notable_tests
                result = FileRunResult(
                    target=unit,
                    status=status,
                    returncode=returncode,
                    duration_s=duration_s,
                    stdout=captured_stdout if keep_output else "",
                    stderr=captured_stderr if keep_output else "",
                )
                _record_result(state, result)
                save_run_state(state_file, state)
                if detail is not None:
                    per_unit_details[unit] = detail

                if status in {"passed", "empty"}:
                    console.print(f"[green]{status.upper()}[/green] {unit} ({duration_s:.1f}s)")
                    index += 1
                    continue

                if status == "crashed":
                    _promote_crashing_unit(
                        policy_file,
                        pytest_args,
                        env,
                        unit,
                        unit_granularity,
                        "crashed",
                        console,
                    )
                    if (
                        granularity == "mixed"
                        and unit_granularity == "file"
                        and not stop_on_failure
                    ):
                        # Iterative deselect: re-run the file repeatedly,
                        # each time deselecting completed tests + confirmed
                        # crash culprits, until the file passes or exit
                        # conditions are met.
                        deselect_set: set[str] = set(unit_disabled_nodeids)
                        crash_count = 0
                        accumulated_detail: dict[str, Any] | None = None
                        total_retry_dur = 0.0
                        iter_jsonl_path: Path | None = crash_jsonl_path
                        retry_temp_files: list[Path] = []
                        escalate = False

                        try:
                            while True:
                                # Stream JSONL once for completed + culprit + detail.
                                if iter_jsonl_path is not None:
                                    iter_detail, culprit, completed = _analyze_report_jsonl(
                                        iter_jsonl_path
                                    )
                                else:
                                    culprit, completed = None, []
                                    iter_detail = None

                                deselect_set.update(completed)

                                # Merge partial results
                                if iter_detail is not None:
                                    if accumulated_detail is None:
                                        accumulated_detail = iter_detail
                                    else:
                                        for k in accumulated_detail["counts"]:
                                            accumulated_detail["counts"][k] += iter_detail[
                                                "counts"
                                            ].get(k, 0)
                                        accumulated_detail["tests"].extend(iter_detail["tests"])
                                        # Merge skip_reasons
                                        for reason, cnt in iter_detail.get(
                                            "skip_reasons", {}
                                        ).items():
                                            accumulated_detail.setdefault("skip_reasons", {})[
                                                reason
                                            ] = (
                                                accumulated_detail.get("skip_reasons", {}).get(
                                                    reason, 0
                                                )
                                                + cnt
                                            )

                                if culprit:
                                    # Confirm crash by running culprit alone
                                    console.print(
                                        f"[yellow]Confirming crash culprit:[/yellow] {culprit}"
                                    )
                                    try:
                                        confirm_rc, confirm_out, confirm_err = _run_subprocess_tee(
                                            [
                                                sys.executable,
                                                "-m",
                                                "pytest",
                                                culprit,
                                                *pytest_args,
                                            ],
                                            env=env,
                                            timeout=_unit_timeout_seconds(timeout, "test"),
                                        )
                                        confirm_status = _status_from_returncode(confirm_rc)
                                    except subprocess.TimeoutExpired:
                                        confirm_rc = _TIMEOUT_RETURN_CODE
                                        confirm_out = ""
                                        confirm_err = (
                                            "crash culprit confirmation timed out after "
                                            f"{_unit_timeout_seconds(timeout, 'test')} seconds"
                                        )
                                        confirm_status = "timeout"
                                    # Record culprit as a standalone result
                                    if confirm_status in {"crashed", "timeout"}:
                                        culprit_outcome = confirm_status
                                    else:
                                        culprit_outcome = "crashed"
                                    culprit_entry: dict[str, Any] = {
                                        "nodeid": culprit,
                                        "outcome": culprit_outcome,
                                    }
                                    if confirm_status in {"crashed", "timeout"}:
                                        culprit_entry["longrepr"] = (
                                            confirm_err.strip() or confirm_out.strip()
                                        )
                                    else:
                                        crash_detail = (
                                            captured_stderr.strip()
                                            or captured_stdout.strip()
                                            or f"file-level pytest run crashed with rc={returncode}"
                                        )
                                        culprit_entry["longrepr"] = (
                                            "File-level pytest run crashed while this test was "
                                            "active; the test passed in isolation. "
                                            f"Original crash detail: {crash_detail}"
                                        )
                                        culprit_entry["isolation_outcome"] = "passed-in-isolation"
                                    if confirm_out.strip():
                                        culprit_entry["stdout"] = confirm_out
                                    if confirm_err.strip():
                                        culprit_entry["stderr"] = confirm_err
                                    if accumulated_detail is None:
                                        accumulated_detail = {
                                            "counts": _empty_counts(),
                                            "tests": [],
                                        }
                                    accumulated_detail["tests"].append(culprit_entry)
                                    if culprit_outcome in {"crashed", "timeout"}:
                                        accumulated_detail["counts"][culprit_outcome] = (
                                            accumulated_detail["counts"].get(culprit_outcome, 0) + 1
                                        )
                                    deselect_set.add(culprit)
                                    crash_count += 1
                                    if (
                                        max_crashes_per_file > 0
                                        and crash_count >= max_crashes_per_file
                                    ):
                                        if accumulated_detail is not None:
                                            per_unit_details[unit] = accumulated_detail
                                        _record_result(
                                            state,
                                            FileRunResult(
                                                target=unit,
                                                status="crashed",
                                                returncode=returncode,
                                                duration_s=(duration_s + total_retry_dur),
                                                stderr=(
                                                    "per-file crash limit reached after "
                                                    f"{crash_count} confirmed crashes"
                                                ),
                                            ),
                                        )
                                        save_run_state(state_file, state)
                                        console.print(
                                            "[yellow]Adaptive isolation:[/yellow] "
                                            f"reached the per-file crash limit for "
                                            f"{Path(unit).name} "
                                            f"({crash_count}/{max_crashes_per_file}); "
                                            "moving to the next unit."
                                        )
                                        exit_code = 1
                                        index += 1
                                        break

                                # - check exit conditions --
                                # No ARG_MAX limit - deselect via file, not args
                                if not culprit and not completed:
                                    # No info from JSONL - cannot deselect
                                    escalate = True
                                    break
                                if not deselect_set:
                                    # Nothing to deselect - escalate
                                    escalate = True
                                    break

                                # - retry with deselect via file --
                                # Write deselected nodeids to a temp file
                                # instead of --deselect args (avoids ARG_MAX).
                                deselect_path = write_deselect_file(deselect_set)
                                retry_temp_files.append(deselect_path)

                                retry_jsonl_fd, retry_jsonl_raw = tempfile.mkstemp(
                                    prefix="pkcs11-check-retry-",
                                    suffix=".jsonl",
                                )
                                os.close(retry_jsonl_fd)
                                retry_jsonl_path = Path(retry_jsonl_raw)
                                retry_temp_files.append(retry_jsonl_path)

                                retry_env = dict(env)
                                retry_env["PKCS11_CHECK_DESELECT_FILE"] = str(deselect_path)
                                retry_cmd = [
                                    sys.executable,
                                    "-m",
                                    "pytest",
                                    unit,
                                    *pytest_args,
                                    "--report-log",
                                    str(retry_jsonl_path),
                                ]
                                console.print(
                                    f"[yellow]Adaptive isolation:[/yellow] "
                                    f"retrying {unit} with "
                                    f"{len(deselect_set)} tests deselected"
                                )
                                retry_start = time.monotonic()
                                try:
                                    retry_rc, retry_out, retry_err = _run_subprocess_tee(
                                        retry_cmd,
                                        env=retry_env,
                                        timeout=_unit_timeout_seconds(timeout, unit_granularity),
                                    )
                                    retry_status = _status_from_returncode(retry_rc)
                                except subprocess.TimeoutExpired:
                                    retry_status = "timeout"
                                    retry_rc = _TIMEOUT_RETURN_CODE
                                    retry_out = retry_err = ""
                                retry_dur = time.monotonic() - retry_start
                                total_retry_dur += retry_dur

                                if retry_status not in ("crashed", "timeout"):
                                    # Retry succeeded - merge final results
                                    final_detail = _read_jsonl_results(retry_jsonl_path)
                                    if final_detail is not None:
                                        if accumulated_detail is None:
                                            accumulated_detail = final_detail
                                        else:
                                            for k in accumulated_detail["counts"]:
                                                accumulated_detail["counts"][k] += final_detail[
                                                    "counts"
                                                ].get(k, 0)
                                            accumulated_detail["tests"].extend(
                                                final_detail["tests"]
                                            )

                                    final_status = retry_status
                                    final_returncode = retry_rc
                                    if retry_status == "passed" and accumulated_detail is not None:
                                        if accumulated_detail["counts"].get("crashed", 0) > 0:
                                            final_status = "crashed"
                                            final_returncode = returncode
                                        elif accumulated_detail["counts"].get("timeout", 0) > 0:
                                            final_status = "timeout"
                                            final_returncode = _TIMEOUT_RETURN_CODE

                                    keep = final_status != "passed" or (
                                        accumulated_detail is not None
                                        and any(
                                            accumulated_detail["counts"].get(k, 0) > 0
                                            for k in (
                                                "failed",
                                                "xfailed",
                                                "xpassed",
                                                "error",
                                                "crashed",
                                                "timeout",
                                            )
                                        )
                                    )
                                    result = FileRunResult(
                                        target=unit,
                                        status=final_status,
                                        returncode=final_returncode,
                                        duration_s=(duration_s + total_retry_dur),
                                        stdout=(retry_out if keep else ""),
                                        stderr=(retry_err if keep else ""),
                                    )
                                    _record_result(state, result)
                                    save_run_state(state_file, state)
                                    if accumulated_detail is not None:
                                        per_unit_details[unit] = accumulated_detail
                                    console.print(
                                        f"[green]RETRY OK[/green] {unit} "
                                        f"({total_retry_dur:.1f}s, "
                                        f"{len(deselect_set)} deselected)"
                                    )
                                    if final_status in {"failed", "crashed", "timeout"}:
                                        exit_code = 1
                                    index += 1
                                    break  # exit deselect loop, continue

                                # Retry also crashed - loop with new JSONL
                                console.print(
                                    f"[red]RETRY CRASHED[/red] {unit} (iteration {crash_count + 1})"
                                )
                                iter_jsonl_path = retry_jsonl_path
                                # Continue the while loop

                        finally:
                            all_iter_jsonls = (
                                [crash_jsonl_path] if crash_jsonl_path else []
                            ) + retry_temp_files
                            if report_config is not None and report_config.jsonl_path is not None:
                                _write_unit_report_record_cache_from_jsonl_paths(
                                    state_file,
                                    unit,
                                    all_iter_jsonls,
                                )
                                save_run_state(state_file, state)
                            for tmp in all_iter_jsonls:
                                tmp.unlink(missing_ok=True)

                        if not escalate:
                            # Deselect loop broke via successful retry
                            continue

                        # Escalate: fall through to per-test isolation
                        if accumulated_detail is not None:
                            per_unit_details[unit] = accumulated_detail

                        escalated_units = _escalate_current_file(
                            unit=unit,
                            units=units,
                            index=index,
                            state=state,
                            pytest_args=pytest_args,
                            env=env,
                            console=console,
                            disabled_nodeids=unit_disabled_nodeids,
                            baseline_fingerprint=baseline_fingerprint,
                        )
                        if escalated_units:
                            _record_result(
                                state,
                                FileRunResult(
                                    target=unit,
                                    status="escalated",
                                    returncode=returncode,
                                    duration_s=duration_s,
                                ),
                            )
                            save_run_state(state_file, state)
                            pending_units.extend(escalated_units)
                            exit_code = 1
                            console.print(f"[red]CRASHED[/red] {unit} ({duration_s:.1f}s)")
                            index += 1
                            continue

                if (
                    granularity in {"mixed", "test"}
                    and unit_granularity == "test"
                    and not stop_on_failure
                    and status in {"crashed", "timeout"}
                ):
                    limited_units = _limit_remaining_units_for_file(
                        unit=unit,
                        units=units,
                        index=index,
                        pending_units=pending_units,
                        state=state,
                        pytest_args=pytest_args,
                        env=env,
                        console=console,
                        max_crashes_per_file=max_crashes_per_file,
                    )
                    if limited_units:
                        save_run_state(state_file, state)

                exit_code = 1
                console.print(f"[red]{status.upper()}[/red] {unit} ({duration_s:.1f}s)")
                if stop_on_failure:
                    console.print(
                        f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                        f"[bold]--resume --state-file {state_file}[/bold]."
                    )
                    return exit_code
                index += 1
            finally:
                if initial_deselect_path is not None:
                    initial_deselect_path.unlink(missing_ok=True)
                if unit_jsonl_path is not None:
                    unit_jsonl_path.unlink(missing_ok=True)
    finally:
        coverage_data = None
        quality_records = []
        merged_details = dict(per_unit_details)
        if report_config is not None:
            if report_config.jsonl_path is not None:
                inline_report_records_by_unit = {}
                for unit, records in state.report_records_by_unit.items():
                    inline_report_records_by_unit.setdefault(unit, records)
                if resume and report_config.jsonl_path.exists():
                    candidate_targets = set(state.units) | {
                        result.target for result in state.results
                    }
                    for unit in executed_units:
                        inline_report_records_by_unit.pop(unit, None)
                    _seed_missing_report_record_caches_from_jsonl(
                        state_file,
                        report_config.jsonl_path,
                        candidate_targets=candidate_targets,
                        skip_units=set(inline_report_records_by_unit) | executed_units,
                    )
                wrote_report_jsonl = _write_report_jsonl_from_record_sources(
                    state_file,
                    units=state.units,
                    inline_records_by_unit=inline_report_records_by_unit,
                    output_path=report_config.jsonl_path,
                )
                if wrote_report_jsonl or report_config.jsonl_path.exists():
                    merged_details = _build_per_unit_details_from_record_sources(
                        state_file,
                        units=state.units,
                        inline_records_by_unit=inline_report_records_by_unit,
                    )
                    merged_details = _merge_supplemental_special_details(
                        merged_details,
                        per_unit_details,
                    )
                    coverage_data = extract_coverage_from_jsonl(report_config.jsonl_path)
                    quality_records = extract_quality_report_records_from_jsonl(
                        report_config.jsonl_path
                    )
                    coverage_data = _augment_mechanism_coverage_from_unit_outcomes(
                        coverage_data,
                        state,
                        per_unit_details=merged_details,
                    )
                if coverage_data:
                    coverage_path = report_config.jsonl_path.parent / "coverage.json"
                    coverage_path.write_text(
                        json.dumps(coverage_data, indent=2) + "\n", encoding="utf-8"
                    )
                provisioning_data = extract_provisioning_from_jsonl(report_config.jsonl_path)
                if provisioning_data is not None:
                    provisioning_path = report_config.jsonl_path.parent / "provisioning.json"
                    provisioning_path.write_text(
                        json.dumps(provisioning_data, indent=2) + "\n", encoding="utf-8"
                    )
                    if provisioning_data["totals"].get("ran_via_external", 0) > 0:
                        _emit_external_provision_banner(
                            provisioning_data["totals"]["ran_via_external"]
                        )
            if report_config.output_format == "json":
                results_payload = write_isolated_json_report(
                    report_config.output_path,
                    state,
                    per_unit_details=merged_details,
                    coverage=coverage_data,
                    provenance=provenance,
                )
                quality_path = report_config.output_path.parent / "quality.json"
                write_quality_json_report(
                    quality_path,
                    results_payload,
                    coverage=coverage_data,
                    report_log_records=quality_records,
                )
            else:
                write_isolated_report(
                    report_config,
                    state,
                    per_unit_details=per_unit_details,
                )

    return exit_code


def state_results_by_status(path: Path) -> dict[str, int]:
    """Return a small status histogram for a saved state file."""
    state = load_run_state(path)
    if state is None:
        return {}

    summary = _state_summary(state)
    summary.pop("total", None)
    return summary
