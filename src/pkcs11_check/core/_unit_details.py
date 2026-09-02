"""Per-unit detail merging: grouping results by file, special-entry merges, unit status.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
    _canonical_executions as _canonical_executions,
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
    _reconcile_process_observations as _reconcile_process_observations,
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
from pkcs11_check.core.crash_codes import is_crash_returncode
from pkcs11_check.core.test_selection import extract_required_mechanisms


def _group_results_by_file(
    results: list[FileRunResult],
    details: dict[str, dict[str, Any]],
) -> list[tuple[str, list[FileRunResult], dict[str, Any]]]:
    """Group results into file-level aggregates for the unified report.

    If all results are already file-level (no ``::`` in targets), returns
    them ungrouped.  Otherwise, groups test-level results by their file
    prefix and merges counts/tests from *details*.
    """
    has_test_level = any("::" in r.target for r in results)
    if not has_test_level:
        return [(r.target, [r], details.get(r.target, {})) for r in results]

    groups: dict[str, list[FileRunResult]] = {}
    order: list[str] = []
    for result in results:
        file_key = result.target.split("::", 1)[0]
        if file_key not in groups:
            groups[file_key] = []
            order.append(file_key)
        groups[file_key].append(result)

    out: list[tuple[str, list[FileRunResult], dict[str, Any]]] = []
    for file_target in order:
        file_results = groups[file_target]
        merged_counts: dict[str, int] = _empty_counts()
        merged_tests: list[dict[str, Any]] = []
        merged_compliance_notes: list[dict[str, Any]] = []
        merged_skip_reasons: dict[str, int] = {}
        merged_executions: list[dict[str, Any]] = []
        file_skip = False
        for r in file_results:
            detail = _copy_detail(details.get(r.target, {}))
            for key in merged_counts:
                merged_counts[key] += detail.get("counts", {}).get(key, 0)
            merged_tests.extend(detail.get("tests", []))
            merged_compliance_notes.extend(detail.get("compliance_notes", []))
            for reason, count in detail.get("skip_reasons", {}).items():
                merged_skip_reasons[reason] = merged_skip_reasons.get(reason, 0) + count
            raw_executions = detail.get("executions")
            if isinstance(raw_executions, list):
                merged_executions = _reconcile_process_observations(
                    merged_executions,
                    [item for item in raw_executions if isinstance(item, Mapping)],
                )
            if detail.get("file_skip"):
                file_skip = True
        merged_detail: dict[str, Any] = {"counts": merged_counts, "tests": merged_tests}
        if merged_compliance_notes:
            merged_detail["compliance_notes"] = merged_compliance_notes
        if merged_skip_reasons:
            merged_detail["skip_reasons"] = merged_skip_reasons
        if file_skip:
            merged_detail["file_skip"] = True
        if merged_executions:
            merged_detail["executions"] = _canonical_executions(merged_executions)
        out.append((file_target, file_results, merged_detail))
    return out


def _copy_detail(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    counts = _empty_counts()
    tests: list[dict[str, Any]] = []
    compliance_notes: list[dict[str, Any]] = []
    skip_reasons: dict[str, int] = {}
    executions: list[dict[str, Any]] = []

    if isinstance(detail, Mapping):
        raw_counts = detail.get("counts")
        if isinstance(raw_counts, Mapping):
            for key in counts:
                value = raw_counts.get(key, 0)
                if isinstance(value, int):
                    counts[key] = value
        raw_tests = detail.get("tests")
        if isinstance(raw_tests, list):
            tests = [dict(item) for item in raw_tests if isinstance(item, Mapping)]
        raw_compliance_notes = detail.get("compliance_notes")
        if isinstance(raw_compliance_notes, list):
            compliance_notes = [
                dict(item) for item in raw_compliance_notes if isinstance(item, Mapping)
            ]
        raw_skip_reasons = detail.get("skip_reasons")
        if isinstance(raw_skip_reasons, Mapping):
            skip_reasons = {
                str(reason): int(count)
                for reason, count in raw_skip_reasons.items()
                if isinstance(count, int)
            }
        raw_executions = detail.get("executions")
        if isinstance(raw_executions, list):
            executions = [dict(item) for item in raw_executions if isinstance(item, Mapping)]
        else:
            executions = []

    copied: dict[str, Any] = {"counts": counts, "tests": tests}
    if compliance_notes:
        copied["compliance_notes"] = compliance_notes
    if skip_reasons:
        copied["skip_reasons"] = skip_reasons
    if executions:
        copied["executions"] = executions
    if isinstance(detail, Mapping) and detail.get("file_skip"):
        copied["file_skip"] = True
    return copied


def _ensure_timeout_recorded(detail: dict[str, Any] | None, unit: str) -> dict[str, Any]:
    """Guarantee a timed-out file keeps at least one timeout in its counts.

    Used on the timeout-retry success path: when a file timed out but the
    timeout could not be attributed to a specific test (no culprit, or the
    culprit passed in isolation) and the remaining tests then pass, the unit
    would otherwise be recorded as ``passed`` and the hang would vanish from the
    summary. This records an unattributed *file-level* timeout so a green retry
    never hides a real timeout (review finding R3).

    Idempotent: if a timeout is already counted (e.g. a confirmed culprit
    already added one) the detail is returned with only its structure
    normalized — never a second, double-counted timeout.
    """
    result: dict[str, Any] = detail if detail is not None else {}
    counts = result.setdefault("counts", _empty_counts())
    tests = result.setdefault("tests", [])
    if counts.get("timeout", 0) == 0:
        tests.append(
            {
                "nodeid": unit,
                "outcome": "timeout",
                "longrepr": (
                    "file timed out; cause not attributable to a single test "
                    "(remaining tests passed on retry after deselection)"
                ),
            }
        )
        counts["timeout"] = 1
    return result


def _synthetic_file_skip_detail(
    unit: str,
    reason: str,
    pytest_args: list[str],
    env: Mapping[str, str],
) -> dict[str, Any]:
    """Build counted skip detail for a file skipped before pytest execution."""
    collect_env = dict(env)
    collect_env[_DISABLE_COLLECTION_PROBES_ENV] = "1"
    try:
        nodeids = collect_pytest_nodeids([unit], pytest_args, env=collect_env)
    except ValueError:
        nodeids = []

    skipped = len(nodeids) if nodeids else 1
    counts = _empty_counts()
    counts["skipped"] = skipped
    return {
        "counts": counts,
        "tests": [],
        "skip_reasons": {reason: skipped},
        "file_skip": True,
    }


def _special_test_entry_from_result(result: FileRunResult) -> dict[str, Any] | None:
    status = result.status
    if result.status == "escalated":
        status = _effective_unit_status([result])
    if status not in {"crashed", "timeout", "crash_limited"} or (
        "::" not in result.target and result.status != "escalated"
    ):
        return None

    entry: dict[str, Any] = {
        "nodeid": result.target,
        "outcome": status,
        "duration": result.duration_s,
    }
    flat = result.stderr.strip() or result.stdout.strip()
    if not flat and status == "crash_limited":
        flat = "abandoned: per-file crash limit reached"
    if flat:
        entry["longrepr"] = flat
    if result.stdout.strip():
        entry["stdout"] = result.stdout
    if result.stderr.strip():
        entry["stderr"] = result.stderr
    return entry


def _merge_special_entries_into_detail(
    detail: Mapping[str, Any] | None,
    entries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    merged = _copy_detail(detail)
    existing = {
        (str(record.get("nodeid", "")), str(record.get("outcome", "")))
        for record in merged["tests"]
        if isinstance(record, Mapping)
    }

    for entry in entries:
        nodeid = str(entry.get("nodeid", "")).strip()
        outcome = str(entry.get("outcome", "")).strip()
        if not nodeid or not outcome:
            continue
        key = (nodeid, outcome)
        if key in existing:
            continue
        merged["tests"].append(dict(entry))
        existing.add(key)
        if outcome in {"crashed", "timeout", "crash_limited", "failed"}:
            merged["counts"][outcome] += 1

    return merged


def _overall_unit_status(file_results: list[FileRunResult]) -> str:
    seen = {result.status for result in file_results}
    for status in UNIT_STATUS_PRIORITY:
        if status in seen:
            return status
    return file_results[0].status


def _effective_unit_status(
    file_results: Sequence[FileRunResult], counts: Mapping[str, int] | None = None
) -> str:
    """Return the report status, retaining an escalated crash/timeout trigger.

    ``escalated`` is a resume-control marker kept in durable state.  A grouped
    report may also contain passing per-test children, so the trigger's exit
    code must still win at the reporting boundary.
    """
    results = list(file_results)
    status = _overall_unit_status(results)
    outer_deaths: set[str] = set()
    for result in file_results:
        if "::" not in result.target and result.status in {"crashed", "timeout"}:
            outer_deaths.add(result.status)
            continue
        # The runner records escalation only for the file-level crash/timeout
        # trigger.  Per-test results are never escalation triggers; preserving
        # such a synthetic marker keeps report writing compatible with callers
        # that use an arbitrary placeholder return code.
        if result.status != "escalated" or "::" in result.target:
            continue
        if result.returncode == _TIMEOUT_RETURN_CODE:
            outer_deaths.add("timeout")
        elif is_crash_returncode(result.returncode):
            outer_deaths.add("crashed")
        else:
            status = "escalated"
    if outer_deaths:
        return next(candidate for candidate in UNIT_STATUS_PRIORITY if candidate in outer_deaths)
    return _status_with_detail_counts(status, counts)


def _status_with_detail_counts(status: str, counts: Mapping[str, int] | None) -> str:
    if not counts:
        return status
    candidates = {status}
    candidates.update(
        outcome for outcome in ("timeout", "crashed", "failed") if counts.get(outcome, 0) > 0
    )
    if counts.get("error", 0) > 0:
        candidates.add("failed")
    return next(
        (candidate for candidate in UNIT_STATUS_PRIORITY if candidate in candidates),
        status,
    )


def _final_state_exit_code(state: FileRunState, existing_exit_code: int) -> int:
    """Keep infrastructure codes and reject any non-green durable result state."""
    if existing_exit_code >= 2:
        return existing_exit_code
    if any(
        not result.completion_verified or result.status not in {"passed", "empty"}
        for result in state.results
    ):
        return max(existing_exit_code, 1)
    return existing_exit_code


def _merge_supplemental_special_details(
    base_details: Mapping[str, dict[str, Any]],
    supplemental_details: Mapping[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    merged = {unit: _copy_detail(detail) for unit, detail in base_details.items()}

    for unit, detail in supplemental_details.items():
        if not isinstance(detail, Mapping):
            continue
        if detail.get("file_skip") is True:
            merged[unit] = _copy_detail(detail)
            continue
        source_executions = detail.get("executions")
        if isinstance(source_executions, list):
            target = merged.setdefault(unit, _copy_detail(None))
            prior_executions = target.get("executions", [])
            target["executions"] = _canonical_executions(
                _reconcile_process_observations(
                    prior_executions if isinstance(prior_executions, list) else [],
                    [item for item in source_executions if isinstance(item, Mapping)],
                )
            )
        raw_tests = detail.get("tests")
        if not isinstance(raw_tests, list):
            continue
        special_entries = [
            record
            for record in raw_tests
            if isinstance(record, Mapping)
            and str(record.get("outcome", "")).strip() in _SPECIAL_DETAIL_OUTCOMES.union({"failed"})
        ]
        if not special_entries:
            continue
        merged[unit] = _merge_special_entries_into_detail(merged.get(unit), special_entries)

    return merged


def _required_ckm_names_for_unit(unit: str) -> list[str]:
    required = extract_required_mechanisms(unit.split("::", 1)[0])
    if not required:
        return []
    return sorted(
        name if name.startswith("CKM_") else f"CKM_{name}"
        for name in required
        if isinstance(name, str) and name
    )


def _mechanism_name_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(name) for name in value if name is not None}


def _augment_mechanism_coverage_from_unit_outcomes(
    coverage: dict[str, Any] | None,
    state: FileRunState,
    *,
    per_unit_details: Mapping[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Annotate coverage states for explicit per-file mechanism outcomes."""
    if coverage is None:
        return None
    raw_mechanism_coverage = coverage.get("mechanism_coverage")
    if not isinstance(raw_mechanism_coverage, Mapping):
        return coverage

    augmented = dict(coverage)
    mechanism_coverage = dict(raw_mechanism_coverage)
    augmented["mechanism_coverage"] = mechanism_coverage

    bucket_names = {
        "skipped_by_capability_names": _mechanism_name_set(
            mechanism_coverage.get("skipped_by_capability_names")
        ),
        "crashed_names": _mechanism_name_set(mechanism_coverage.get("crashed_names")),
        "timeout_names": _mechanism_name_set(mechanism_coverage.get("timeout_names")),
    }

    for unit, file_results, merged_detail in _group_results_by_file(
        state.results,
        dict(per_unit_details or {}),
    ):
        required_names = _required_ckm_names_for_unit(unit)
        if not required_names:
            continue
        if merged_detail.get("file_skip") is True:
            bucket_names["skipped_by_capability_names"].update(required_names)
        status = _effective_unit_status(file_results, merged_detail.get("counts"))
        if status == "crashed":
            bucket_names["crashed_names"].update(required_names)
        elif status == "timeout":
            bucket_names["timeout_names"].update(required_names)

    for key, names in bucket_names.items():
        mechanism_coverage[key] = sorted(names)

    return augmented
