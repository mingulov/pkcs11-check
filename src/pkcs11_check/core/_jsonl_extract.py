"""Coverage / provisioning extraction from report.jsonl and unified postprocessing.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
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
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import (
    map_report_outcome as _map_outcome,
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

    try:
        fh = jsonl_path.open(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None
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

    try:
        fh = jsonl_path.open(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None
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


def postprocess_jsonl_to_unified(
    jsonl_path: Path, output_path: Path, provenance: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Convert a pytest-reportlog JSONL file to pkcs11-check unified format.

    Groups tests by file and writes the unified JSON report.
    Used for ``--isolation none`` to produce consistent output.
    If ``provenance`` is provided, it is included in the output payload.
    """
    file_counts: dict[str, dict[str, int]] = {}
    session_finished = False

    def _accumulate_file_count(rec: Mapping[str, Any]) -> None:
        nodeid = str(rec.get("nodeid", ""))
        file_part = nodeid.split("::")[0]
        if not file_part:
            return
        if file_part not in file_counts:
            file_counts[file_part] = _empty_counts()
        outcome = _map_outcome(rec.get("outcome", "passed"), rec.get("wasxfail"))
        file_counts[file_part][outcome] = file_counts[file_part].get(outcome, 0) + 1

    def _records_with_completion() -> Iterator[dict[str, Any]]:
        nonlocal session_finished
        for record in _iter_report_log_records(jsonl_path):
            if (
                record.get("$report_type") == "SessionFinish"
                and type(record.get("exitstatus")) is int
            ):
                session_finished = True
            yield record

    # Parse the JSONL once: build the aggregate detail and the per-file counts
    # from the same streaming record pass.
    detail = _build_detail_from_report_records(
        _records_with_completion(),
        call_record_hook=_accumulate_file_count,
    )
    # An empty / vacuous JSONL (no records at all) returns None from the builder;
    # treat it as a zero-count run so we still produce a results.json payload.
    if detail is None:
        detail = {"counts": _empty_counts(), "tests": []}

    # Group tests by file
    by_file: dict[str, list[dict[str, Any]]] = {}
    for test in detail["tests"]:
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

    summary: dict[str, int] = _empty_counts()
    units: list[dict[str, Any]] = []

    for target in sorted(
        set(list(by_file.keys()) + list(file_counts.keys()) + list(compliance_notes_by_file.keys()))
    ):
        counts = file_counts.get(target, _empty_counts())
        for key in summary:
            summary[key] += counts.get(key, 0)
        has_failure = any(
            counts.get(key, 0) > 0 for key in ("failed", "error", "crashed", "timeout")
        )
        unit: dict[str, Any] = {
            "target": target,
            "status": "failed" if has_failure else "passed",
            "returncode": 1 if has_failure else 0,
            "duration_s": 0.0,
            "counts": counts,
        }
        tests = by_file.get(target, [])
        if tests:
            unit["tests"] = tests
        compliance_notes = compliance_notes_by_file.get(target, [])
        if compliance_notes:
            unit["compliance_notes"] = compliance_notes
        units.append(unit)

    summary["total"] = sum(summary[key] for key in RESULT_OUTCOME_KEYS)
    child_crash, child_timeout = compute_child_subprocess_counts(units)
    summary["child_crash"] = child_crash
    summary["child_timeout"] = child_timeout
    summary["incomplete"] = not session_finished
    summary["incomplete"] = run_is_incomplete(summary, units)
    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    if provenance:
        payload["provenance"] = provenance
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return payload
