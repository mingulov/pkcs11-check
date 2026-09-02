"""Isolated-run report writers: results JSON payload, JUnit XML, and dispatch.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET  # nosec B405

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
from pkcs11_check.core._unit_details import (
    _augment_mechanism_coverage_from_unit_outcomes as _augment_mechanism_coverage_from_unit_outcomes,  # noqa: E501
)
from pkcs11_check.core._unit_details import (
    _copy_detail as _copy_detail,
)
from pkcs11_check.core._unit_details import (
    _effective_unit_status as _effective_unit_status,
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
    _required_ckm_names_for_unit as _required_ckm_names_for_unit,
)
from pkcs11_check.core._unit_details import (
    _special_test_entry_from_result as _special_test_entry_from_result,
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
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.run_metrics import (
    RESULT_OUTCOME_KEYS,
    compute_child_subprocess_counts,
    run_is_incomplete,
)


def write_isolated_json_report(
    path: Path,
    state: FileRunState,
    *,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write an aggregated JSON report for an isolated run in unified format."""
    payload = _build_isolated_json_payload(
        state,
        per_unit_details=per_unit_details,
        coverage=coverage,
        provenance=provenance,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return payload


def _build_isolated_json_payload(
    state: FileRunState,
    *,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details = per_unit_details or {}

    summary: dict[str, int] = {key: 0 for key in RESULT_OUTCOME_KEYS}

    grouped = _group_results_by_file(state.results, details)
    units_out: list[dict[str, Any]] = []

    executions_by_unit: dict[str, list[list[Mapping[str, Any]]]] = {}
    state_outer = [
        observation
        for observation in state.process_observations
        if isinstance(observation, Mapping) and observation.get("parent_nodeid") is None
    ]

    if state.process_observations_complete:
        for observation in state_outer:
            target = normalize_nodeid(str(observation.get("target", "")).split("::", 1)[0])
            if target:
                executions_by_unit.setdefault(target, []).append([observation])
        for detail in details.values():
            if not isinstance(detail, Mapping):
                continue
            executions = detail.get("executions")
            if not isinstance(executions, list):
                continue
            nested_executions = [
                execution
                for execution in executions
                if isinstance(execution, Mapping)
                and execution.get("parent_nodeid") is not None
                and _execution_owner_file(execution) is not None
            ]
            for execution in nested_executions:
                owner = _execution_owner_file(execution)
                if owner is not None:
                    executions_by_unit.setdefault(owner, []).append([execution])
    else:
        # Legacy direct helpers have no canonical global sequence. Keep recovered
        # detail observations in source order and append only unmatched state entries.
        cached_outer: list[Mapping[str, Any]] = []
        nested_by_unit: dict[str, list[list[Mapping[str, Any]]]] = {}
        for detail in details.values():
            if not isinstance(detail, Mapping):
                continue
            executions = detail.get("executions")
            if not isinstance(executions, list):
                continue
            outer = [
                execution
                for execution in executions
                if isinstance(execution, Mapping) and execution.get("parent_nodeid") is None
            ]
            nested = [
                execution
                for execution in executions
                if isinstance(execution, Mapping)
                and execution.get("parent_nodeid") is not None
                and _execution_owner_file(execution) is not None
            ]
            if outer:
                cached_outer.extend(outer)
            if nested:
                for execution in nested:
                    owner = _execution_owner_file(execution)
                    if owner is not None:
                        nested_by_unit.setdefault(owner, []).append([execution])

        for observation in _reconcile_process_observations(cached_outer, state_outer):
            owner = _execution_owner_file(observation)
            if owner is not None:
                executions_by_unit.setdefault(owner, []).append([observation])
        for target, groups in nested_by_unit.items():
            executions_by_unit.setdefault(target, []).extend(groups)

    for file_target, file_results, merged_detail in grouped:
        special_entries = [
            entry
            for result in file_results
            if (entry := _special_test_entry_from_result(result)) is not None
        ]
        detail = _merge_special_entries_into_detail(merged_detail, special_entries)
        counts = detail.get("counts")
        overall_status = _effective_unit_status(file_results, counts)
        if overall_status in {"failed", "crashed", "timeout"}:
            matching_outcome = "failed" if overall_status == "failed" else overall_status
            has_matching_evidence = detail["counts"].get(matching_outcome, 0) > 0
            if overall_status == "failed":
                has_matching_evidence |= detail["counts"].get("error", 0) > 0
            if not has_matching_evidence:
                detail["counts"][matching_outcome] = 1
        duration = sum(r.duration_s for r in file_results)
        stdout_parts = [r.stdout for r in file_results if r.stdout]
        stderr_parts = [r.stderr for r in file_results if r.stderr]

        unit: dict[str, Any] = {
            "target": file_target,
            "status": overall_status,
            "returncode": (
                max(abs(r.returncode) for r in file_results)
                if overall_status in {"failed", "crashed", "timeout"}
                or any(not r.completion_verified for r in file_results)
                else 0
            ),
            "duration_s": round(duration, 3),
        }
        if any(not r.completion_verified for r in file_results):
            unit["incomplete"] = True
            unit["completion_verified"] = False
        if stdout_parts:
            unit["stdout"] = "\n".join(stdout_parts)
        if stderr_parts:
            unit["stderr"] = "\n".join(stderr_parts)

        if counts and any(v > 0 for v in counts.values()):
            unit["counts"] = counts
            for key in summary:
                summary[key] += counts.get(key, 0)
        tests = detail.get("tests")
        if tests:
            unit["tests"] = tests
        compliance_notes = detail.get("compliance_notes")
        if compliance_notes:
            unit["compliance_notes"] = compliance_notes
        sr = detail.get("skip_reasons")
        if sr:
            unit["skip_reasons"] = sr
        if detail.get("file_skip"):
            unit["file_skip"] = True
        executions = _canonical_executions(
            *executions_by_unit.get(normalize_nodeid(file_target), [])
        )
        if executions:
            unit["executions"] = executions

        units_out.append(unit)

    recovery_events = _recovery_events_from_state(state)
    for event_index, event in enumerate(recovery_events, start=1):
        event_id = event.get("event_id", event_index)
        counts = {key: 0 for key in RESULT_OUTCOME_KEYS}
        counts["crashed"] = 1
        trigger = str(event.get("trigger_unit") or "provider")
        units_out.append(
            {
                "target": f"{trigger}::daemon-recovery-{event_id}",
                "status": "crashed",
                "returncode": 1,
                "duration_s": 0.0,
                "counts": counts,
                "recovery_event": event,
            }
        )
        for key, value in counts.items():
            summary[key] += value

    summary["total"] = sum(summary[key] for key in RESULT_OUTCOME_KEYS)
    child_crash, child_timeout = compute_child_subprocess_counts(units_out)
    summary["child_crash"] = child_crash
    summary["child_timeout"] = child_timeout
    summary["incomplete"] = run_is_incomplete(summary, units_out)

    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units_out,
    }
    if coverage:
        payload["coverage"] = coverage
    if provenance:
        payload["provenance"] = provenance
    if state.attempt_history:
        payload["attempt_history"] = state.attempt_history
    if recovery_events:
        payload["recovery_events"] = recovery_events
    return payload


def _recovery_events_from_state(state: FileRunState) -> list[dict[str, Any]]:
    """Return one event per confirmed daemon death, including legacy history-only state."""
    events = [event for event in state.recovery_events if isinstance(event, Mapping)]
    if events:
        return [dict(event) for event in events]
    recovered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for attempt in state.attempt_history:
        event = attempt.get("recovery_event") if isinstance(attempt, Mapping) else None
        if not isinstance(event, Mapping):
            continue
        key = json.dumps(event, sort_keys=True, separators=(",", ":"))
        if key in seen:
            continue
        seen.add(key)
        recovered.append(dict(event))
    return recovered


def _junit_case_identity(target: str) -> tuple[str, str]:
    if "::" not in target:
        path = Path(target)
        return (str(path.parent).replace("/", ".").strip(".") or "pkcs11-check", path.name)

    file_part, node_part = target.split("::", 1)
    class_name = str(Path(file_part).with_suffix("")).replace("/", ".").strip(".") or "pkcs11-check"
    return (class_name, node_part)


def write_isolated_junit_report(
    path: Path,
    state: FileRunState,
    *,
    suite_name: str = "pkcs11-check-isolated",
    per_unit_details: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Write an aggregated JUnit XML report for an isolated run."""
    path.parent.mkdir(parents=True, exist_ok=True)

    details = per_unit_details or {}
    recovery_events = _recovery_events_from_state(state)

    def effective_status(result: FileRunResult) -> str:
        detail = details.get(result.target)
        counts = detail.get("counts") if isinstance(detail, Mapping) else None
        return _effective_unit_status([result], counts)

    effective_results = [(result, effective_status(result)) for result in state.results]
    failures = sum(
        1
        for result, status in effective_results
        if status == "failed" and result.completion_verified
    )
    errors = sum(
        1
        for result, status in effective_results
        if status in {"crashed", "timeout", "escalated", "crash_limited"}
        or not result.completion_verified
    ) + len(recovery_events)
    skipped = sum(
        1
        for result, status in effective_results
        if status == "empty" and result.completion_verified
    )
    duration_s = sum(result.duration_s for result, _ in effective_results)

    suite = ET.Element(
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(state.results) + len(recovery_events)),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{duration_s:.6f}",
        },
    )

    for result, status in effective_results:
        detail = details.get(result.target)
        detail_longrepr = ""
        if isinstance(detail, Mapping):
            records = detail.get("tests")
            if isinstance(records, list):
                detail_longrepr = "\n\n".join(
                    str(record["longrepr"])
                    for record in records
                    if isinstance(record, Mapping) and record.get("longrepr")
                )
        class_name, case_name = _junit_case_identity(result.target)
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": class_name,
                "name": case_name,
                "time": f"{result.duration_s:.6f}",
            },
        )

        if not result.completion_verified:
            error = ET.SubElement(
                case,
                "error",
                {"message": "report log completion could not be verified", "type": "incomplete"},
            )
            error.text = (
                f"Unit {result.target} exited with code {result.returncode} without a "
                "matching SessionFinish record."
            )
        elif status == "failed":
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "message": f"pytest exited with code {result.returncode}",
                    "type": "failure",
                },
            )
            failure.text = detail_longrepr or f"Unit {result.target} failed in isolated mode."
        elif status == "crashed":
            error = ET.SubElement(
                case,
                "error",
                {
                    "message": f"isolated unit crashed (returncode {result.returncode})",
                    "type": "crashed",
                },
            )
            error.text = detail_longrepr or f"Unit {result.target} crashed in isolated mode."
        elif status == "timeout":
            error = ET.SubElement(
                case,
                "error",
                {
                    "message": "isolated unit timed out",
                    "type": "timeout",
                },
            )
            error.text = detail_longrepr or f"Unit {result.target} timed out in isolated mode."
        elif status == "empty":
            skipped_node = ET.SubElement(case, "skipped", {"message": "no tests collected"})
            skipped_node.text = f"Unit {result.target} collected no tests."
        elif status == "escalated":
            error = ET.SubElement(
                case,
                "error",
                {"message": "unit escalated to per-test isolation", "type": "escalated"},
            )
            error.text = detail_longrepr or (
                f"Unit {result.target} crashed at file granularity and was expanded to per-test "
                "isolation."
            )
        elif status == "crash_limited":
            error = ET.SubElement(
                case,
                "error",
                {
                    "message": "skipped after per-file crash limit was reached",
                    "type": "crash_limited",
                },
            )
            error.text = detail_longrepr or (
                f"Unit {result.target} was skipped because this file exceeded the configured "
                "per-file crash limit in isolated mode."
            )

    for event_index, event in enumerate(recovery_events, start=1):
        event_id = event.get("event_id", event_index)
        trigger = str(event.get("trigger_unit") or "provider")
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": "pkcs11_check.recovery",
                "name": f"daemon-recovery-{event_id}",
                "time": "0.000000",
            },
        )
        error = ET.SubElement(
            case,
            "error",
            {
                "message": f"daemon became unreachable after {trigger}",
                "type": "daemon-recovery",
            },
        )
        error.text = str(event.get("label") or "provider became unreachable")

    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)


def write_isolated_report(
    config: IsolatedReportConfig,
    state: FileRunState,
    *,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Write the requested aggregated report format for an isolated run."""
    if config.output_format == "json":
        write_isolated_json_report(
            config.output_path,
            state,
            per_unit_details=per_unit_details,
        )
        return
    write_isolated_junit_report(
        config.output_path,
        state,
        per_unit_details=per_unit_details,
    )
