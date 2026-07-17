"""Per-unit pytest runner with subprocess isolation and resume support."""

from __future__ import annotations

import hashlib
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
from dataclasses import asdict
from functools import cache
from pathlib import Path
from typing import IO, Any
from xml.etree import ElementTree as ET  # nosec B405

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
from pkcs11_check.core.collection import CollectedPytestItem, collect_pytest_item_metadata
from pkcs11_check.core.crash_codes import (
    crash_detail_name as _crash_detail_name,
)
from pkcs11_check.core.crash_codes import (
    is_windows_crash_code as _is_windows_crash_code,
)
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.preflight import load_manifest
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
from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS, compute_child_subprocess_counts
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

# The fingerprint detects when the run's effective configuration changed, so
# stale resume/policy state is not reused. By default it covers the framework's
# own env namespaces only. A provider exposes its token/config through its own
# env vars, so point PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES (and, rarely,
# PKCS11_CHECK_FINGERPRINT_ENV_KEYS) at any extra prefixes/keys to have that
# provider's configuration invalidate the fingerprint too. Both accept a comma-
# or whitespace-separated list.
_FINGERPRINT_ENV_PREFIXES_ENV = "PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES"
_FINGERPRINT_ENV_KEYS_ENV = "PKCS11_CHECK_FINGERPRINT_ENV_KEYS"
_DEFAULT_FINGERPRINT_ENV_KEYS = ("P11TEST_PIN",)
_DEFAULT_FINGERPRINT_ENV_PREFIXES = ("P11TEST_", "PKCS11_")
_REDACTED_ENV_KEYS = {"P11TEST_PIN"}
_POLICY_IGNORED_ENV_KEYS = {
    "P11TEST_ISOLATION",
    "P11TEST_POLICY_FILE",
    "P11TEST_RESUME",
    "P11TEST_STATE_FILE",
    "P11TEST_STOP_ON_FAILURE",
}


def _validate_pytest_target_exists(target: str) -> None:
    if "::" in target:
        file_part = target.split("::", 1)[0]
        if Path(file_part).exists():
            return
        msg = f"pytest target not found: {target}"
        raise FileNotFoundError(msg)

    if Path(target).exists():
        return

    msg = f"pytest target not found: {target}"
    raise FileNotFoundError(msg)


def _collection_args(pytest_args: list[str]) -> list[str]:
    args: list[str] = []
    skip_next = False
    for arg in pytest_args:
        if skip_next:
            skip_next = False
            continue

        if arg in {"-q", "-v", "--no-header", "--report-log"}:
            continue
        if arg.startswith("--tb="):
            continue
        if arg.startswith("--report-log="):
            continue
        if arg.startswith("--junit-xml="):
            continue
        if arg in {"--tb", "--junit-xml", "--report-log"}:
            skip_next = True
            continue

        args.append(arg)

    args.extend(["--collect-only", "-qq"])
    return args


def collect_pytest_nodeids(
    targets: list[str],
    pytest_args: list[str],
    *,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Collect pytest nodeids for the requested targets using a subprocess."""
    cmd = [sys.executable, "-m", "pytest", *targets, *_collection_args(pytest_args)]
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        env=dict(env or os.environ),
    )

    if completed.returncode not in {0, 5}:
        details = completed.stderr.strip() or completed.stdout.strip() or "unknown collection error"
        msg = f"pytest collection failed: {details}"
        raise ValueError(msg)

    nodeids: list[str] = []
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if not line or "::" not in line:
            continue
        # Canonicalize to forward slashes: on Windows pytest emits OS-native (\)
        # path separators in node-ids, but disabled/deselect sets are normalized
        # (core/nodeids.py), so a raw comparison in the escalation path would never
        # match and a disabled crashing test would be re-included. No-op on POSIX.
        nodeids.append(normalize_nodeid(line))

    return nodeids


def discover_pytest_units(
    targets: list[str],
    default_root: Path,
    *,
    granularity: IsolationGranularity = "file",
    pytest_args: list[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Expand pytest targets into an ordered list of file or test units."""
    requested = targets or [str(default_root)]

    for target in requested:
        _validate_pytest_target_exists(target)

    if granularity == "test":
        return collect_pytest_nodeids(requested, pytest_args or [], env=env)

    units: list[str] = []
    seen: set[str] = set()

    for target in requested:
        if "::" in target:
            if target not in seen:
                units.append(target)
                seen.add(target)
            continue

        path = Path(target)
        if path.is_dir():
            for file_path in sorted(path.rglob("test_*.py")):
                unit = str(file_path)
                if unit not in seen:
                    units.append(unit)
                    seen.add(unit)
            continue

        if path.is_file():
            unit = str(path)
            if unit not in seen:
                units.append(unit)
                seen.add(unit)
            continue

    return units


def file_isolation_mode(
    marker_names: set[str] | list[str] | tuple[str, ...],
) -> IsolationGranularity:
    """Return the preferred isolated granularity for collected marker names."""
    if "subprocess_per_test" in marker_names:
        return "test"
    return "file"


def file_forces_file_isolation(marker_names: set[str] | list[str] | tuple[str, ...]) -> bool:
    """Return True if collected marker names should stay at file granularity."""
    if "subprocess_per_test" in marker_names:
        return False
    return "subprocess" in marker_names


def _markers_by_file(items: list[CollectedPytestItem]) -> dict[str, set[str]]:
    markers_by_file: dict[str, set[str]] = {}
    for item in items:
        file_key = normalize_policy_file_key(item.file_path)
        markers_by_file.setdefault(file_key, set()).update(item.markers)
    return markers_by_file


def validate_subprocess_per_test_expansion(
    units: Sequence[str],
    collected_items: Sequence[CollectedPytestItem],
) -> None:
    """Refuse file-level units for files marked ``subprocess_per_test``."""
    marked_files = {
        normalize_policy_file_key(item.file_path)
        for item in collected_items
        if "subprocess_per_test" in item.markers
    }
    if not marked_files:
        return

    bare_file_units: set[str] = set()
    nodeid_units: set[str] = set()
    for unit in units:
        file_part = unit.split("::", 1)[0]
        file_key = normalize_policy_file_key(file_part)
        if "::" in unit:
            nodeid_units.add(file_key)
        else:
            bare_file_units.add(file_key)

    bad_files = sorted(file_key for file_key in marked_files if file_key in bare_file_units)
    missing_nodeids = sorted(file_key for file_key in marked_files if file_key not in nodeid_units)
    if bad_files or missing_nodeids:
        affected = sorted(set(bad_files) | set(missing_nodeids))
        msg = "subprocess_per_test file was not expanded to per-test units: " + ", ".join(affected)
        raise ValueError(msg)


def discover_auto_isolation_units(
    targets: list[str],
    default_root: Path,
    *,
    pytest_args: list[str],
    policy_file: Path | None = None,
    env: Mapping[str, str] | None = None,
    collected_out: list[CollectedPytestItem] | None = None,
) -> list[str]:
    """Expand targets into a mixed file/test unit list for auto isolation.

    If ``collected_out`` is provided, the per-item metadata gathered here (a
    full ``--collect-only`` pass over the suite) is appended to it so the caller
    can reuse it — e.g. for the disabled-baseline selection plan — instead of
    running a second identical collection pass over ~all tests at startup.
    """
    file_units = discover_pytest_units(targets, default_root, granularity="file")
    units: list[str] = []
    promoted_files = load_promoted_files(policy_file, pytest_args, env)
    collected_items = collect_pytest_item_metadata(
        targets,
        pytest_args,
        env=dict(env or os.environ),
    )
    if collected_out is not None:
        collected_out.extend(collected_items)
    markers_by_file = _markers_by_file(collected_items)

    # One pass over collected items builds BOTH the set of files that have
    # collected nodes (respects -m / -k filters) AND an index of nodeids per
    # file key. The per-file expansion below then does an O(1) lookup instead of
    # re-scanning every collected item (with a path resolve each) for every
    # test-isolated file — O(files x items). See review finding E4.
    collected_files: set[str] | None = None
    nodeids_by_file_key: dict[str, list[str]] = {}
    if collected_items:
        collected_files = set()
        for item in collected_items:
            fk = normalize_policy_file_key(item.file_path)
            collected_files.add(fk)
            nodeids_by_file_key.setdefault(fk, []).append(item.nodeid)

    for file_unit in file_units:
        file_path = Path(file_unit.split("::", 1)[0])
        file_key = normalize_policy_file_key(str(file_path))

        # Skip files with no collected items (filtered out by -m or -k)
        if collected_files is not None and file_key not in collected_files:
            continue

        marker_names = markers_by_file.get(file_key, set())
        mode = file_isolation_mode(marker_names)
        if normalize_policy_file_key(str(file_path)) in promoted_files:
            mode = "test"
        if mode == "test":
            nodeids = nodeids_by_file_key.get(file_key, [])
            if not nodeids:
                nodeids = discover_pytest_units(
                    [file_unit],
                    default_root,
                    granularity="test",
                    pytest_args=pytest_args,
                    env=env,
                )
            # Pin each per-test unit to the resolved absolute file path so it is
            # runnable and key-matchable regardless of pytest's rootdir (which can
            # be dragged to '/' by a stray absolute path on the command line for an
            # installed package with no config file above it).
            units.extend(_absolute_nodeid(file_key, nid) for nid in nodeids)
        else:
            if file_forces_file_isolation(marker_names):
                units.append(str(file_path))
            else:
                units.append(file_unit)

    validate_subprocess_per_test_expansion(units, collected_items)
    return units


def load_isolation_policy(path: Path) -> dict[str, BackendIsolationPolicy]:
    """Load the adaptive isolation policy file."""
    if not path.exists():
        return {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        msg = f"invalid isolation policy file: {path}"
        raise ValueError(msg)
    raw_backends = raw.get("backends", {})
    if not isinstance(raw_backends, dict):
        msg = f"invalid isolation policy file: {path}"
        raise ValueError(msg)

    policies: dict[str, BackendIsolationPolicy] = {}
    for fingerprint, item in raw_backends.items():
        if not isinstance(fingerprint, str) or not isinstance(item, dict):
            continue
        promoted_files = [
            str(value) for value in item.get("promoted_files", []) if isinstance(value, str)
        ]
        crashed_tests = [
            str(value) for value in item.get("crashed_tests", []) if isinstance(value, str)
        ]
        policies[fingerprint] = BackendIsolationPolicy(
            fingerprint=fingerprint,
            promoted_files=promoted_files,
            crashed_tests=crashed_tests,
        )

    return policies


def save_isolation_policy(path: Path, policies: Mapping[str, BackendIsolationPolicy]) -> None:
    """Persist the adaptive isolation policy file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "backends": {
            fingerprint: {
                "promoted_files": policy.promoted_files,
                "crashed_tests": policy.crashed_tests,
            }
            for fingerprint, policy in sorted(policies.items())
        }
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
        file_skip = False
        for r in file_results:
            detail = _copy_detail(details.get(r.target, {}))
            for key in merged_counts:
                merged_counts[key] += detail.get("counts", {}).get(key, 0)
            merged_tests.extend(detail.get("tests", []))
            merged_compliance_notes.extend(detail.get("compliance_notes", []))
            for reason, count in detail.get("skip_reasons", {}).items():
                merged_skip_reasons[reason] = merged_skip_reasons.get(reason, 0) + count
            if detail.get("file_skip"):
                file_skip = True
        merged_detail: dict[str, Any] = {"counts": merged_counts, "tests": merged_tests}
        if merged_compliance_notes:
            merged_detail["compliance_notes"] = merged_compliance_notes
        if merged_skip_reasons:
            merged_detail["skip_reasons"] = merged_skip_reasons
        if file_skip:
            merged_detail["file_skip"] = True
        out.append((file_target, file_results, merged_detail))
    return out


def _copy_detail(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    counts = _empty_counts()
    tests: list[dict[str, Any]] = []
    compliance_notes: list[dict[str, Any]] = []
    skip_reasons: dict[str, int] = {}

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

    copied: dict[str, Any] = {"counts": counts, "tests": tests}
    if compliance_notes:
        copied["compliance_notes"] = compliance_notes
    if skip_reasons:
        copied["skip_reasons"] = skip_reasons
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
    if result.status not in {"crashed", "timeout", "crash_limited"} or "::" not in result.target:
        return None

    entry: dict[str, Any] = {
        "nodeid": result.target,
        "outcome": result.status,
        "duration": result.duration_s,
    }
    flat = result.stderr.strip() or result.stdout.strip()
    if not flat and result.status == "crash_limited":
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
        if outcome in {"crashed", "timeout", "crash_limited"}:
            merged["counts"][outcome] += 1

    return merged


def _overall_unit_status(file_results: list[FileRunResult]) -> str:
    seen = {result.status for result in file_results}
    for status in UNIT_STATUS_PRIORITY:
        if status in seen:
            return status
    return file_results[0].status


def _status_with_detail_counts(status: str, counts: Mapping[str, int] | None) -> str:
    if not counts:
        return status
    if counts.get("timeout", 0) > 0:
        return "timeout"
    if counts.get("crashed", 0) > 0:
        return "crashed"
    return status


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
        raw_tests = detail.get("tests")
        if not isinstance(raw_tests, list):
            continue
        special_entries = [
            record
            for record in raw_tests
            if isinstance(record, Mapping)
            and str(record.get("outcome", "")).strip() in _SPECIAL_DETAIL_OUTCOMES
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
        status = _overall_unit_status(file_results)
        if status == "crashed":
            bucket_names["crashed_names"].update(required_names)
        elif status == "timeout":
            bucket_names["timeout_names"].update(required_names)

    for key, names in bucket_names.items():
        mechanism_coverage[key] = sorted(names)

    return augmented


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

    for file_target, file_results, merged_detail in grouped:
        overall_status = _overall_unit_status(file_results)
        special_entries = [
            entry
            for result in file_results
            if (entry := _special_test_entry_from_result(result)) is not None
        ]
        detail = _merge_special_entries_into_detail(merged_detail, special_entries)
        counts = detail.get("counts")
        overall_status = _status_with_detail_counts(overall_status, counts)
        if overall_status in {"crashed", "timeout"} and not any(detail["counts"].values()):
            detail["counts"][overall_status] = 1
        duration = sum(r.duration_s for r in file_results)
        stdout_parts = [r.stdout for r in file_results if r.stdout]
        stderr_parts = [r.stderr for r in file_results if r.stderr]

        unit: dict[str, Any] = {
            "target": file_target,
            "status": overall_status,
            "returncode": (
                max(abs(r.returncode) for r in file_results)
                if overall_status in {"failed", "crashed", "timeout"}
                else 0
            ),
            "duration_s": round(duration, 3),
        }
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

        units_out.append(unit)

    summary["total"] = sum(summary[key] for key in RESULT_OUTCOME_KEYS)
    child_crash, child_timeout = compute_child_subprocess_counts(units_out)
    summary["child_crash"] = child_crash
    summary["child_timeout"] = child_timeout
    summary["incomplete"] = summary["crash_limited"] > 0 or summary["timeout"] > 0

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
    return payload


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
) -> None:
    """Write an aggregated JUnit XML report for an isolated run."""
    path.parent.mkdir(parents=True, exist_ok=True)

    failures = sum(1 for result in state.results if result.status == "failed")
    errors = sum(1 for result in state.results if result.status in {"crashed", "timeout"})
    skipped = sum(
        1 for result in state.results if result.status in {"empty", "escalated", "crash_limited"}
    )
    duration_s = sum(result.duration_s for result in state.results)

    suite = ET.Element(
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(state.results)),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{duration_s:.6f}",
        },
    )

    for result in state.results:
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

        if result.status == "failed":
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "message": f"pytest exited with code {result.returncode}",
                    "type": "failure",
                },
            )
            failure.text = f"Unit {result.target} failed in isolated mode."
        elif result.status == "crashed":
            error = ET.SubElement(
                case,
                "error",
                {
                    "message": f"isolated unit crashed (returncode {result.returncode})",
                    "type": "crashed",
                },
            )
            error.text = f"Unit {result.target} crashed in isolated mode."
        elif result.status == "timeout":
            error = ET.SubElement(
                case,
                "error",
                {
                    "message": "isolated unit timed out",
                    "type": "timeout",
                },
            )
            error.text = f"Unit {result.target} timed out in isolated mode."
        elif result.status == "empty":
            skipped_node = ET.SubElement(case, "skipped", {"message": "no tests collected"})
            skipped_node.text = f"Unit {result.target} collected no tests."
        elif result.status == "escalated":
            skipped_node = ET.SubElement(
                case,
                "skipped",
                {"message": "unit escalated to per-test isolation"},
            )
            skipped_node.text = (
                f"Unit {result.target} crashed at file granularity and was expanded to per-test "
                "isolation."
            )
        elif result.status == "crash_limited":
            skipped_node = ET.SubElement(
                case,
                "skipped",
                {"message": "skipped after per-file crash limit was reached"},
            )
            skipped_node.text = (
                f"Unit {result.target} was skipped because this file exceeded the configured "
                "per-file crash limit in isolated mode."
            )

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
    write_isolated_junit_report(config.output_path, state)


def load_run_state(path: Path) -> FileRunState | None:
    """Load a resumable runner state from disk."""
    if not path.exists():
        return None

    raw = json.loads(path.read_text(encoding="utf-8"))
    results = [FileRunResult(**item) for item in raw.get("results", [])]
    report_records_by_unit: dict[str, list[dict[str, Any]]] = {}
    raw_records = raw.get("report_records_by_unit", {})
    if isinstance(raw_records, dict):
        for unit, records in raw_records.items():
            if not isinstance(unit, str) or not isinstance(records, list):
                continue
            parsed_records = [record for record in records if isinstance(record, dict)]
            if parsed_records:
                report_records_by_unit[unit] = parsed_records
    return FileRunState(
        units=list(raw.get("units", [])),
        fingerprint=str(raw.get("fingerprint", "")),
        results=results,
        report_records_by_unit=report_records_by_unit,
    )


def save_run_state(path: Path, state: FileRunState) -> None:
    """Persist the current runner state to disk.

    ``save_run_state`` is called once per completed unit (plus extra times on
    crash/timeout escalation), so its cost is paid ~N times over a full run.
    We deliberately do NOT serialize ``state.report_records_by_unit`` here:
    those per-test JSONL records are already persisted authoritatively as
    per-unit shards under ``<state>.report-records/`` (written by
    ``_write_unit_report_record_cache``) and the end-of-run merge always reads
    them back from those shards. Embedding the records in state.json made the
    payload grow to hundreds of MB and turned the per-unit save into an O(n^2)
    re-serialization (~14 min on a full slow-module round) for data that is never
    the sole source of truth. The in-memory dict is retained only as a
    legacy/debug inline-state fallback; normal runs reconstruct records from
    the shards (and the prior report.jsonl on resume).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "fingerprint": state.fingerprint,
        "units": state.units,
        "results": [asdict(result) for result in state.results],
    }
    if os.environ.get("PKCS11_CHECK_STATE_INLINE_RECORDS") == "1":
        # Opt-in legacy/debug behavior: embed the per-unit report records inline.
        # This is the O(n^2) re-serialization the default path deliberately
        # avoids (records already live in per-unit shards). Retained only as an
        # escape hatch for offline state inspection and for A/B perf measurement;
        # it is OFF by default and never needed for resume.
        payload["report_records_by_unit"] = state.report_records_by_unit
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _manifest_digest(pytest_args: list[str]) -> str | None:
    manifest_path = _extract_option_value(pytest_args, "--p11-manifest")
    if manifest_path is None:
        return None

    path = Path(manifest_path)
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_available_mechanisms(pytest_args: list[str]) -> frozenset[str] | None:
    """Load mechanism names from the manifest referenced by --p11-manifest.

    Returns a frozenset containing both 'CKM_AES_CBC' and 'AES_CBC' forms,
    or None if no manifest is available.
    """
    manifest_path = _extract_option_value(pytest_args, "--p11-manifest")
    if manifest_path is None:
        return None
    path = Path(manifest_path)
    if not path.exists():
        return None
    try:
        manifest = load_manifest(path)
    except Exception:  # noqa: BLE001
        return None
    if manifest.status != "ok":
        return None
    names: set[str] = set()
    for mech in manifest.mechanisms:
        names.add(mech)
        if mech.startswith("CKM_"):
            names.add(mech[4:])
    return frozenset(names)


def _backend_args_snapshot(pytest_args: list[str]) -> list[str]:
    args: list[str] = []
    skip_next = False
    for index, arg in enumerate(pytest_args):
        if skip_next:
            skip_next = False
            continue

        if arg in {
            "--p11-module",
            "--p11-interface",
            "--p11-slot",
            "--p11-pin",
            "--p11-manifest",
        }:
            value = pytest_args[index + 1] if index + 1 < len(pytest_args) else ""
            if arg == "--p11-pin":
                value = "<redacted>"
            elif arg == "--p11-manifest":
                value = "<manifest>"
            args.extend([arg, value])
            skip_next = True
            continue

        if any(
            arg.startswith(f"{option}=")
            for option in {
                "--p11-module",
                "--p11-interface",
                "--p11-slot",
                "--p11-pin",
                "--p11-manifest",
            }
        ):
            option, value = arg.split("=", 1)
            if option == "--p11-pin":
                value = "<redacted>"
            elif option == "--p11-manifest":
                value = "<manifest>"
            args.append(f"{option}={value}")
            continue

        if arg == "--p11-destructive":
            args.append(arg)

    return args


def build_policy_fingerprint(pytest_args: list[str], env: Mapping[str, str] | None = None) -> str:
    """Build a stable backend fingerprint for adaptive isolation policy."""
    module_snapshot = None
    module_path = _extract_option_value(pytest_args, "--p11-module")
    if module_path is not None:
        module_snapshot = _path_snapshot(module_path)

    payload = json.dumps(
        {
            "backend_args": _backend_args_snapshot(pytest_args),
            "env": _fingerprint_env(env or os.environ, ignored_keys=_POLICY_IGNORED_ENV_KEYS),
            "manifest_digest": _manifest_digest(pytest_args),
            "module": module_snapshot,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_promoted_files(
    path: Path | None,
    pytest_args: list[str],
    env: Mapping[str, str] | None = None,
) -> set[str]:
    """Return files promoted to per-test isolation for this backend."""
    if path is None:
        return set()

    policies = load_isolation_policy(path)
    fingerprint = build_policy_fingerprint(pytest_args, env)
    policy = policies.get(fingerprint)
    if policy is None:
        return set()
    return {normalize_policy_file_key(file_path) for file_path in policy.promoted_files}


def _path_snapshot(path_str: str) -> dict[str, int | str] | None:
    path = Path(path_str)
    if not path.exists():
        return None

    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _fingerprint_units(units: list[str]) -> list[dict[str, int | str]]:
    snapshots: list[dict[str, int | str]] = []
    seen: set[str] = set()
    for unit in units:
        file_part = unit.split("::", 1)[0]
        snapshot = _path_snapshot(file_part)
        if snapshot is None:
            continue
        path_key = str(snapshot["path"])
        if path_key in seen:
            continue
        snapshots.append(snapshot)
        seen.add(path_key)
    return snapshots


def _split_env_list(value: str | None) -> tuple[str, ...]:
    """Parse a comma- or whitespace-separated env value into a tuple of tokens."""
    if not value:
        return ()
    return tuple(value.replace(",", " ").split())


def _fingerprint_env_selectors(
    env: Mapping[str, str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (exact_keys, prefixes) to fingerprint: framework-generic defaults
    plus any provider-specific selectors registered via the extension env vars."""
    keys = _DEFAULT_FINGERPRINT_ENV_KEYS + _split_env_list(env.get(_FINGERPRINT_ENV_KEYS_ENV))
    prefixes = _DEFAULT_FINGERPRINT_ENV_PREFIXES + _split_env_list(
        env.get(_FINGERPRINT_ENV_PREFIXES_ENV)
    )
    return keys, prefixes


def _fingerprint_env(
    env: Mapping[str, str], *, ignored_keys: set[str] | frozenset[str] = frozenset()
) -> dict[str, str]:
    keys, prefixes = _fingerprint_env_selectors(env)
    snapshot: dict[str, str] = {}
    for key in sorted(env):
        if key in ignored_keys:
            continue
        if key in keys or key.startswith(prefixes):
            if key in _REDACTED_ENV_KEYS:
                snapshot[key] = "<set>" if env[key] else "<unset>"
            else:
                snapshot[key] = env[key]
    return snapshot


def build_state_fingerprint(
    units: list[str],
    pytest_args: list[str],
    env: Mapping[str, str] | None = None,
    *,
    baseline_fingerprint: str | None = None,
) -> str:
    """Build a stable fingerprint for resume validation."""
    redacted_args: list[str] = []
    redact_next = False
    manifest_digest = _manifest_digest(pytest_args)
    for arg in pytest_args:
        if redact_next:
            redacted_args.append("<redacted>")
            redact_next = False
            continue
        if arg.startswith("--p11-manifest="):
            redacted_args.append("--p11-manifest=<manifest>")
            continue
        redacted_args.append(arg)
        if arg in {"--p11-pin", "--p11-manifest"}:
            redact_next = True

    module_snapshot = None
    module_path = _extract_option_value(pytest_args, "--p11-module")
    if module_path is not None:
        module_snapshot = _path_snapshot(module_path)

    payload = json.dumps(
        {
            "baseline_fingerprint": baseline_fingerprint,
            "env": _fingerprint_env(env or os.environ),
            "manifest_digest": manifest_digest,
            "module": module_snapshot,
            "pytest_args": redacted_args,
            "unit_files": _fingerprint_units(units),
            "units": units,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def units_remaining_for_resume(units: list[str], state: FileRunState | None) -> list[str]:
    """Return units that still need to run for a resumed session."""
    if state is None:
        return list(units)

    completed_ok = {
        result.target for result in state.results if result.status in _RESUME_COMPLETE_STATUSES
    }
    return [unit for unit in units if unit not in completed_ok]


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
