"""Per-unit pytest runner with subprocess isolation and resume support."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import cache
from pathlib import Path
from typing import IO, Any

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
from pkcs11_check.core._escalation import (
    _count_test_level_crashes_for_file as _count_test_level_crashes_for_file,
)
from pkcs11_check.core._escalation import (
    _effective_granularity as _effective_granularity,
)
from pkcs11_check.core._escalation import (
    _escalate_current_file as _escalate_current_file,
)
from pkcs11_check.core._escalation import (
    _insert_escalated_units as _insert_escalated_units,
)
from pkcs11_check.core._escalation import (
    _limit_remaining_units_for_file as _limit_remaining_units_for_file,
)
from pkcs11_check.core._escalation import (
    _promote_crashing_unit as _promote_crashing_unit,
)
from pkcs11_check.core._escalation import (
    _record_result as _record_result,
)
from pkcs11_check.core._escalation import (
    _refresh_state_plan as _refresh_state_plan,
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
    _hydrate_process_observations as _hydrate_process_observations,
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
    _effective_unit_status as _effective_unit_status,
)
from pkcs11_check.core._unit_details import (
    _ensure_timeout_recorded as _ensure_timeout_recorded,
)
from pkcs11_check.core._unit_details import (
    _final_state_exit_code as _final_state_exit_code,
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
    _resume_exit_code as _resume_exit_code,
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
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.collection_errors import (
    collection_failure_sidecar_path,
    ensure_failed_collection_report,
)
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.core.recovery import (
    RecoveryConfig,
    RecoveryController,
    RecoveryOutcome,
    probe_provider_liveness,
    run_recover_cmd,
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


def _completion_verified_for_attempt(
    jsonl_path: Path | None,
    status: str,
    returncode: int,
    session_exitstatus: int | None,
) -> bool:
    """Verify normal pytest completion when an attempt emitted a report stream."""
    if status in {"crashed", "timeout"} or jsonl_path is None:
        return True
    return returncode in {0, 1, 5} and session_exitstatus == returncode


def _cache_attempt_report(
    *,
    state_file: Path,
    unit: str,
    jsonl_path: Path,
    jsonl_paths: Sequence[Path] | None = None,
    detail: dict[str, Any] | None,
    status: str,
    returncode: int,
    session_exitstatus: int | None,
    stdout: str = "",
    stderr: str = "",
    evidence_nodeid: str | None = None,
) -> tuple[dict[str, Any] | None, bool]:
    """Persist one attempt's report evidence, including unverified completion."""
    completion_verified = _completion_verified_for_attempt(
        jsonl_path, status, returncode, session_exitstatus
    )
    if not completion_verified:
        diagnostic = (
            stderr.strip()
            or stdout.strip()
            or (f"pytest exited with code {returncode} without a matching SessionFinish record")
        )
        marker_nodeid = evidence_nodeid or unit
        marker = {
            "$report_type": "HarnessError",
            "nodeid": marker_nodeid,
            "outcome": "error",
            "returncode": returncode,
            "completion_verified": False,
            "longrepr": diagnostic,
        }
        with jsonl_path.open("a", encoding="utf-8") as report_fh:
            report_fh.write(json.dumps(marker) + "\n")
        if detail is None:
            detail = {"counts": _empty_counts(), "tests": []}
        detail.setdefault("counts", _empty_counts())
        detail.setdefault("tests", [])
        detail["incomplete"] = True
        detail["harness_error"] = True
        detail["counts"]["error"] = detail["counts"].get("error", 0) + 1
        detail["tests"].append(
            {
                "nodeid": marker_nodeid,
                "outcome": "error",
                "evidence_type": "harness",
                "returncode": returncode,
                "completion_verified": False,
                "longrepr": diagnostic,
            }
        )
    _write_unit_report_record_cache_from_jsonl_paths(state_file, unit, jsonl_paths or [jsonl_path])
    return detail, completion_verified


def _unit_timeout_seconds(
    test_timeout: int,
    granularity: IsolationGranularity,
    *,
    num_tests: int = 0,
) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    fallback = max(test_timeout * 30, 900)
    if num_tests > 0:
        # 5s per test + 60s startup overhead, floor 300s, cap 14400s (4h)
        count_budget = min(max(num_tests * 5 + 60, 300), 14400)
        return max(fallback, count_budget)
    return fallback


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


# Kept as a literal rather than imported from plugin.py: the runner must not import
# the pytest plugin, which is loaded inside the children it launches.
_UNIT_CHILD_ENV = "PKCS11_CHECK_UNIT_CHILD"


def _subprocess_plugin_env(base_env: Mapping[str, str], unit: str) -> dict[str, str]:
    """Per-unit env that disables pytest plugin autoload and enables only the
    plugins the unit needs. Behavior-preserving; only trims startup cost."""
    env = dict(base_env)
    # Mark this as an isolated child unit. plugin.py arms its own per-test timeout timer
    # only when this is set: that timer calls os._exit(124) from a watchdog thread, which
    # is the only thing that can stop a hang inside native code -- but it must never run
    # in-process (`--isolation none`), where it would kill the CLI before results.json is
    # written. Set BEFORE the early return below so units without plugin addopts get it.
    env[_UNIT_CHILD_ENV] = "1"
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
) -> tuple[int, str, str, dict[str, object]]:
    """Run a subprocess with tee-style output: live display AND capture.

    Returns (returncode, captured_stdout, captured_stderr, observation).
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
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The child is still running at the deadline -- a genuine timeout. Kill
        # and reap it (never leave a zombie behind, R5), retaining the final
        # return code in structured evidence.
        timed_out = True
        proc.kill()
        proc.wait()
        _join_readers_bounded(threads, grace=max(0.0, deadline + 0.5 - time.monotonic()))
    else:
        # The child exited on its own -- cleanly OR via a crash signal (negative
        # returncode). Drain the readers, but only for a short grace: the child is
        # gone, so any un-read data is at most the OS pipe buffer. A surviving
        # grandchild that inherited the pipe (R2) must NOT hold the runner for the
        # full residual timeout (issue #3 Windows hang); abandon a stuck reader after
        # the grace and report the child's real returncode.
        _join_readers_bounded(threads, grace=_POST_EXIT_DRAIN_GRACE_S)
        timed_out = proc.returncode == _TIMEOUT_RETURN_CODE

    proc.wait()
    returncode = proc.returncode
    stdout = stdout_buf.getvalue().decode("utf-8", errors="replace")
    stderr = stderr_buf.getvalue().decode("utf-8", errors="replace")
    observation = build_process_observation(
        target="",
        role="unit",
        attempt=0,
        returncode=returncode,
        timed_out=timed_out,
        stderr=stderr,
    )
    return (
        _TIMEOUT_RETURN_CODE if timed_out else (returncode if returncode is not None else 1),
        stdout,
        stderr,
        observation,
    )


def _append_process_observation(
    state: FileRunState,
    observation: Mapping[str, object],
    *,
    target: str,
    role: str,
) -> None:
    entry = dict(observation)
    entry["target"] = target
    entry["parent_nodeid"] = None
    entry["role"] = role
    entry["attempt"] = sum(
        1
        for previous in state.process_observations
        if previous.get("target") == target
        and previous.get("parent_nodeid") is None
        and previous.get("role") == role
    )
    state.process_observations.append(entry)


def _run_outer_tee(
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: int,
    state: FileRunState,
    state_file: Path,
    target: str,
    role: str,
) -> tuple[int, str, str]:
    """Run one outer process, append its evidence, and preserve timeout flow."""
    try:
        tee_result = _run_subprocess_tee(cmd, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        _append_process_observation(
            state,
            build_process_observation(target, role, 0, _TIMEOUT_RETURN_CODE, timed_out=True),
            target=target,
            role=role,
        )
        save_run_state(state_file, state)
        raise

    returncode = tee_result[0]
    captured_stdout = tee_result[1]
    captured_stderr = tee_result[2]
    if len(tee_result) > 3 and isinstance(tee_result[3], dict):
        observation = tee_result[3]
    else:
        observation = build_process_observation(
            target,
            role,
            0,
            returncode,
            timed_out=returncode == _TIMEOUT_RETURN_CODE,
        )
    _append_process_observation(
        state,
        observation,
        target=target,
        role=role,
    )
    save_run_state(state_file, state)
    termination = observation.get("termination")
    if isinstance(termination, Mapping) and termination.get("kind") == "timeout":
        raise subprocess.TimeoutExpired(cmd, timeout)
    return returncode, captured_stdout, captured_stderr


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


@dataclass
class _RecoveryAction:
    """What the run loop must do after feeding a batch of results to the controller."""

    abort: bool = False
    requeue: list[str] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)
    requeue_events: list[tuple[dict[str, Any], list[str]]] = field(default_factory=list)


def _recovery_attempts_path(state_file: Path) -> Path:
    """Return the append-only sidecar used while superseded attempts are re-queued."""
    return state_file.with_name(f"{state_file.name}.recovery.jsonl")


def _reset_fresh_run_artifacts(
    state_file: Path,
    report_config: IsolatedReportConfig | None,
) -> None:
    """Remove durable artifacts that must not survive a fresh run."""
    state_file.unlink(missing_ok=True)
    collection_failure_sidecar_path(state_file).unlink(missing_ok=True)
    _recovery_attempts_path(state_file).unlink(missing_ok=True)
    report_cache_dir = _report_record_cache_dir(state_file)
    if report_cache_dir.is_symlink() or report_cache_dir.exists():
        shutil.rmtree(report_cache_dir)
    if report_config is None:
        return
    sidecar_paths = {
        report_config.output_path.parent / name
        for name in ("report.jsonl", "quality.json", "coverage.json", "provisioning.json")
    }
    if report_config.jsonl_path is not None:
        report_config.jsonl_path.unlink(missing_ok=True)
        sidecar_paths.update(
            {
                report_config.jsonl_path.parent / "coverage.json",
                report_config.jsonl_path.parent / "provisioning.json",
            }
        )
    report_config.output_path.unlink(missing_ok=True)
    for sidecar_path in sidecar_paths:
        sidecar_path.unlink(missing_ok=True)


def _collection_failure_reporting_copy(
    state_file: Path,
    state: FileRunState,
    inline_records_by_unit: dict[str, Sequence[Mapping[str, Any]]],
) -> tuple[FileRunState, dict[str, Sequence[Mapping[str, Any]]]]:
    """Add durable global collection evidence to an output-only state copy."""
    records = _collection_failure_records(state_file)
    if not records:
        return state, inline_records_by_unit

    target = "<collection>"
    output_units = list(state.units)
    output_results = [result for result in state.results if result.target != target]
    output_inline = dict(inline_records_by_unit)
    if target not in output_units:
        output_units.append(target)
    output_results.append(
        FileRunResult(
            target=target,
            status="failed",
            returncode=2,
            duration_s=0.0,
            completion_verified=False,
        )
    )
    # The state-adjacent sidecar is the authoritative global source. A stale
    # synthetic cache shard must not hide or add to its diagnostics.
    _delete_unit_report_record_cache(state_file, target)
    output_inline[target] = [*output_inline.get(target, ()), *records]
    return replace(state, units=output_units, results=output_results), output_inline


def _collection_failure_records(state_file: Path) -> list[dict[str, Any]]:
    return [
        record
        for record in _load_report_log_records(collection_failure_sidecar_path(state_file))
        if record.get("$report_type") == "CollectReport" and record.get("outcome") == "failed"
    ]


def _state_attempt_history(state: Any) -> list[dict[str, Any]]:
    history = getattr(state, "attempt_history", None)
    if not isinstance(history, list):
        history = []
        setattr(state, "attempt_history", history)
    return history


def _state_recovery_events(state: Any) -> list[dict[str, Any]]:
    events = getattr(state, "recovery_events", None)
    if not isinstance(events, list):
        events = []
        setattr(state, "recovery_events", events)
    return events


def _process_observations_for_target(state: Any, target: str) -> list[dict[str, Any]]:
    observations = getattr(state, "process_observations", [])
    if not isinstance(observations, list):
        return []
    selected: list[dict[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        if _process_observation_matches_target(observation, target):
            selected.append(dict(observation))
    return selected


def _process_observation_matches_target(observation: Mapping[str, Any], target: str) -> bool:
    file_target = target.split("::", 1)[0]
    observed_target = str(observation.get("target", ""))
    parent_nodeid = str(observation.get("parent_nodeid", "") or "")
    if "::" in target:
        return observed_target == target or parent_nodeid == target
    return observed_target == target or parent_nodeid.startswith(f"{file_target}::")


def _records_for_target(state: Any, state_file: Path | None, target: str) -> list[dict[str, Any]]:
    records_by_unit = getattr(state, "report_records_by_unit", {})
    records = records_by_unit.get(target, []) if isinstance(records_by_unit, Mapping) else []
    if records:
        return [dict(record) for record in records if isinstance(record, Mapping)]
    if state_file is None:
        return []
    return _load_report_log_records(_report_record_cache_path(state_file, target))


def _append_recovery_attempt_wrappers(
    state_file: Path | None, attempts: Sequence[Mapping[str, Any]]
) -> None:
    if state_file is None or not attempts:
        return
    path = _recovery_attempts_path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for attempt in attempts:
            fh.write(
                json.dumps(
                    {
                        "$report_type": "RecoveryAttempt",
                        "target": attempt.get("target", ""),
                        "attempt": dict(attempt),
                    }
                )
                + "\n"
            )
        fh.flush()
        os.fsync(fh.fileno())


def _scan_hint_rvs(result: FileRunResult, hint_rvs: frozenset[str]) -> frozenset[str]:
    """Return the configured hint CK_RV names that appear in this unit's captured output.

    The hint is only a cheap suspicion trigger deciding WHEN to run the liveness probe; it
    never decides that the daemon is dead on its own (a CK_RV allowlist would fire
    constantly on healthy modules that use generic error fallbacks).
    """
    if not hint_rvs:
        return frozenset()
    blob = f"{result.stderr}\n{result.stdout}"
    return frozenset(name for name in hint_rvs if name in blob)


def _apply_recovery_between_units(
    controller: RecoveryController,
    new_results: Sequence[FileRunResult],
    *,
    console: Console,
) -> _RecoveryAction:
    """Feed newly-completed unit results to the recovery controller, in order.

    Prints a never-silent banner on each confirmed daemon-death event (the crash finding is
    never hidden) and on abort. Returns the action for the run loop: abort, plus any units to
    re-queue and the synthetic crash records to persist.
    """
    action = _RecoveryAction()
    for result in new_results:
        hint_rvs = _scan_hint_rvs(result, controller.config.hint_rvs)
        assessment = controller.assess(result.target, result.status, hint_rvs)
        if not assessment.records:
            continue
        action.records.extend(assessment.records)
        for record in assessment.records:
            trigger = record.get("trigger_unit", result.target)
            console.print(f"[red]DAEMON UNREACHABLE[/red] after {trigger} (liveness probe failed)")
        if assessment.outcome is RecoveryOutcome.ABORT:
            console.print(
                "[red]Provider unrecoverable[/red] - stopping this run (recovery attempts or "
                "global budget exhausted). Remaining units not run."
            )
            action.abort = True
            return action
        if assessment.outcome is RecoveryOutcome.RECOVERED_RETRY:
            console.print("[green]Daemon recovered[/green] - re-running the units it took down.")
            requeue_units = list(assessment.requeue_units)
            action.requeue.extend(requeue_units)
            action.requeue_events.append((assessment.records[0], requeue_units))
        elif assessment.outcome is RecoveryOutcome.QUARANTINE:
            console.print(
                f"[yellow]Quarantining[/yellow] {result.target} - repeatedly crashed the daemon."
            )
    return action


def _record_recovery_findings(state: Any, records: Sequence[dict[str, Any]]) -> None:
    """Persist each confirmed daemon-death event as a real finding in report.jsonl.

    The controller emits these as standalone records with their own synthetic identity, so
    they survive the re-queue that deletes the dying daemon's false failures -- the crash
    itself is a finding and must never be dropped along with the noise it caused.
    """
    events = _state_recovery_events(state)
    for record in records:
        event = dict(record)
        event["event_id"] = len(events) + 1
        events.append(event)
        record["event_id"] = event["event_id"]
        trigger = str(record.get("trigger_unit") or "")
        entry = {
            "schema": 1,
            "$report_type": "RecoveryEvent",
            "event_id": event["event_id"],
            "target": trigger,
            "reason": record.get("reason", "crash"),
            "outcome": "fail",
            "severity": "HIGH",
            "kind": record.get("kind"),
            "label": record.get("label", ""),
            "summary": f"{trigger}: {record.get('label', 'provider became unreachable')}",
            "operation": None,
            "mechanism": None,
            "expected_ckr": None,
            "actual_ckr": None,
            "spec_ref": "",
            "source": None,
            "vector_id": None,
            "detail": {
                "mode": "daemon_death",
                "streak": record.get("streak", []),
                "recovery_event": event,
            },
        }
        state.report_records_by_unit.setdefault(f"{trigger}::daemon-recovery", []).append(entry)


def _requeue_units_after_recovery(
    requeue: Sequence[str],
    *,
    units: list[str],
    index: int,
    pending_units: list[str],
    state: Any,
    state_file: Path | None = None,
    recovery_event: Mapping[str, Any] | None = None,
) -> int | None:
    """Drop the failures a dying daemon produced and rewind so those units run again.

    A result recorded while the daemon was going down is not the module's verdict, it is an
    artifact of talking to a corpse: keeping it would report a cascade of false failures
    against the provider. Delete those results (and their report records) and rewind to the
    earliest one so they are re-run against the recovered daemon.

    Returns the index to rewind to, or None if none of the units have run yet. Bounded by the
    controller's per-unit quarantine counter: a unit that reproducibly kills the daemon is
    quarantined instead of re-queued, so this cannot loop forever.
    """
    wanted = set(requeue)
    positions = [i for i, unit in enumerate(units) if unit in wanted and i <= index]
    if not positions:
        return None
    targets = {units[i] for i in positions}
    attempts: list[dict[str, Any]] = []
    history = _state_attempt_history(state)
    for result in state.results:
        if result.target not in targets:
            continue
        attempt_number = (
            sum(1 for previous in history if previous.get("target") == result.target) + 1
        )
        attempt: dict[str, Any] = {
            "target": result.target,
            "status": result.status,
            "returncode": result.returncode,
            "completion_verified": result.completion_verified,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "records": _records_for_target(state, state_file, result.target),
            "reason": "daemon-recovery-requeue",
            "attempt": attempt_number,
            "recovery_event": dict(recovery_event) if recovery_event is not None else None,
            "process_observations": _process_observations_for_target(state, result.target),
        }
        history.append(attempt)
        attempts.append(attempt)
    _append_recovery_attempt_wrappers(state_file, attempts)
    observations = getattr(state, "process_observations", [])
    if isinstance(observations, list) and hasattr(state, "process_observations"):
        state.process_observations[:] = [
            observation
            for observation in observations
            if not isinstance(observation, Mapping)
            or not any(
                _process_observation_matches_target(observation, target) for target in targets
            )
        ]
    if state_file is not None:
        for target in targets:
            _delete_unit_report_record_cache(state_file, target)
    state.results[:] = [result for result in state.results if result.target not in targets]
    for unit in targets:
        state.report_records_by_unit.pop(unit, None)
        if unit not in pending_units:
            pending_units.append(unit)
    return min(positions)


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
    collected_items: Sequence[CollectedPytestItem] | None = None,
) -> int:
    """Run pytest units in fresh subprocesses and persist progress.

    ``recovery_config`` (default None / mode "off") enables crashing-daemon recovery: the run
    detects a dead daemon between units, pauses for it to return, supersedes the false-failure
    cascade, and resumes or aborts honestly. The wiring is inert unless mode != "off", so a
    default run is byte-identical. See core/recovery.py.
    """
    env = os.environ.copy()
    deselect_by_file = {unit: set(nodeids) for unit, nodeids in (deselect_by_file or {}).items()}
    file_test_counts: dict[str, int] = {}
    for item in collected_items or ():
        file_key = normalize_policy_file_key(item.file_path)
        file_test_counts[file_key] = file_test_counts.get(file_key, 0) + 1
    fingerprint = (
        build_state_fingerprint(
            units,
            pytest_args,
            env,
            baseline_fingerprint=baseline_fingerprint,
        )
        if units
        else ""
    )
    if not resume:
        _reset_fresh_run_artifacts(state_file, report_config)
    previous_state = load_run_state(state_file) if resume else None
    collection_failure_records = _collection_failure_records(state_file)
    collection_failure_present = bool(collection_failure_records)
    if collection_failure_present:
        console.print("[red]INCOMPLETE[/red] prior pytest collection failure evidence retained")
        for record in collection_failure_records:
            if diagnostic := str(record.get("longrepr", "")).strip():
                console.print(diagnostic)
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
        if resume and previous_state is not None:
            state = previous_state
        else:
            state = FileRunState(units=[], fingerprint=fingerprint, results=[])
            if not resume:
                save_run_state(state_file, state)
        pending_units: list[str] = []
    elif previous_state is not None and previous_state.fingerprint != fingerprint:
        msg = (
            f"state file {state_file} belongs to a different isolated run; "
            "use a different --state-file or remove the old one"
        )
        raise ValueError(msg)
    else:
        state = previous_state or FileRunState(units=units, fingerprint=fingerprint, results=[])
        pending_units = units_remaining_for_resume(units, previous_state)

    if units and resume and previous_state is not None and not state.process_observations_complete:
        state.process_observations = _hydrate_process_observations(
            state.process_observations,
            report_config.jsonl_path if report_config is not None else None,
        )
        state.process_observations_complete = True
        save_run_state(state_file, state)

    if resume and units:
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
    elif units:
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
    recovery_enabled = isinstance(recovery_controller, RecoveryController)
    # Number of results already fed to the recovery controller. Seed from any results already in
    # state (a --resume run) so the look-back only ever covers deaths in THIS session, not stale
    # historical failures (which are already recorded).
    recovery_assessed = len(state.results)

    if not pending_units:
        resume_exit_code = max(
            _NO_TESTS_COLLECTED_EXIT if not units else 0,
            1 if _state_recovery_events(state) or _state_attempt_history(state) else 0,
            1 if collection_failure_present else 0,
        )
        if report_config is not None:
            coverage_data: dict[str, Any] | None = None
            quality_records: list[dict[str, Any]] = []
            inline_report_records_by_unit: dict[str, Sequence[Mapping[str, Any]]] = {}
            for unit, records in state.report_records_by_unit.items():
                inline_report_records_by_unit.setdefault(unit, records)
            output_state, inline_report_records_by_unit = _collection_failure_reporting_copy(
                state_file,
                state,
                inline_report_records_by_unit,
            )
            if (
                resume
                and report_config.jsonl_path is not None
                and report_config.jsonl_path.exists()
            ):
                candidate_targets = set(output_state.units) | {
                    result.target for result in output_state.results
                }
                _seed_missing_report_record_caches_from_jsonl(
                    state_file,
                    report_config.jsonl_path,
                    candidate_targets=candidate_targets,
                    skip_units=set(state.report_records_by_unit)
                    | set(inline_report_records_by_unit),
                )
            merged_details = _build_per_unit_details_from_record_sources(
                state_file,
                units=output_state.units,
                inline_records_by_unit=inline_report_records_by_unit,
            )
            for result in state.results:
                if result.status not in {"crashed", "timeout"}:
                    continue
                resume_detail = merged_details.setdefault(
                    result.target,
                    {"counts": _empty_counts(), "tests": []},
                )
                counts = resume_detail.setdefault("counts", _empty_counts())
                counts[result.status] = max(counts.get(result.status, 0), 1)
            resume_exit_code = _final_state_exit_code(state, resume_exit_code, merged_details)
            if report_config.jsonl_path is not None:
                wrote_report_jsonl = _write_report_jsonl_from_record_sources(
                    state_file,
                    units=output_state.units,
                    inline_records_by_unit=inline_report_records_by_unit,
                    output_path=report_config.jsonl_path,
                    attempt_history=state.attempt_history,
                    recovery_events=state.recovery_events,
                    collection_failure_path=collection_failure_sidecar_path(state_file),
                )
                if wrote_report_jsonl or report_config.jsonl_path.exists():
                    coverage_data = extract_coverage_from_jsonl(report_config.jsonl_path)
                    quality_records = extract_quality_report_records_from_jsonl(
                        report_config.jsonl_path
                    )
                    coverage_data = _augment_mechanism_coverage_from_unit_outcomes(
                        coverage_data,
                        output_state,
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
                    output_state,
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
                    output_state,
                    per_unit_details=merged_details,
                )
        else:
            inline_report_records_by_unit = {
                unit: records for unit, records in state.report_records_by_unit.items()
            }
            merged_details = _build_per_unit_details_from_record_sources(
                state_file,
                units=state.units,
                inline_records_by_unit=inline_report_records_by_unit,
            )
            for result in state.results:
                if result.status not in {"crashed", "timeout"}:
                    continue
                resume_detail = merged_details.setdefault(
                    result.target,
                    {"counts": _empty_counts(), "tests": []},
                )
                counts = resume_detail.setdefault("counts", _empty_counts())
                counts[result.status] = max(counts.get(result.status, 0), 1)
            resume_exit_code = _final_state_exit_code(state, resume_exit_code, merged_details)
        if units:
            if resume_exit_code:
                console.print(
                    "[red]Nothing to do[/red] - durable isolated state is not green; "
                    "review the recorded failures before accepting this run."
                )
            else:
                console.print(
                    "[green]Nothing to do[/green] - all isolated units already completed."
                )
        return resume_exit_code

    exit_code = max(
        1 if _state_recovery_events(state) or _state_attempt_history(state) else 0,
        1 if collection_failure_present else 0,
    )
    index = 0
    try:
        while index < len(units) or (recovery_enabled and recovery_assessed < len(state.results)):
            # -- Crashing-daemon recovery (between-unit look-back) --
            # Feed every result completed since the last check to the controller, in order, BEFORE
            # running the next unit. A confirmed daemon death triggers wait/restart + re-probe here,
            # so the upcoming unit runs against a recovered daemon (or the run aborts honestly).
            # Inert unless recovery is enabled, so default runs are byte-identical.
            if (
                recovery_enabled
                and recovery_controller is not None
                and recovery_assessed < len(state.results)
            ):
                recovery_action = _apply_recovery_between_units(
                    recovery_controller,
                    state.results[recovery_assessed:],
                    console=console,
                )
                recovery_assessed = len(state.results)
                _record_recovery_findings(state, recovery_action.records)
                if recovery_action.records and not recovery_action.requeue:
                    save_run_state(state_file, state)
                if recovery_action.records:
                    exit_code = 1
                if recovery_action.abort:
                    exit_code = 1
                    break
                if recovery_action.requeue:
                    rewind_to: int | None = None
                    requeue_events = recovery_action.requeue_events or [
                        (
                            recovery_action.records[-1] if recovery_action.records else {},
                            recovery_action.requeue,
                        )
                    ]
                    for recovery_event, recovery_units in requeue_events:
                        candidate = _requeue_units_after_recovery(
                            recovery_units,
                            units=units,
                            index=index,
                            pending_units=pending_units,
                            state=state,
                            state_file=state_file,
                            recovery_event=recovery_event,
                        )
                        for recovery_unit in recovery_units:
                            per_unit_details.pop(recovery_unit, None)
                        if candidate is not None:
                            rewind_to = (
                                candidate if rewind_to is None else min(rewind_to, candidate)
                            )
                    if rewind_to is not None:
                        # The dropped results were never the module's verdict; re-run them
                        # against the recovered daemon so the report says what it really does.
                        recovery_assessed = len(state.results)
                        save_run_state(state_file, state)
                        index = rewind_to
                        continue

            if index >= len(units):
                break
            unit = units[index]
            if unit not in pending_units:
                index += 1
                continue

            unit_granularity = _effective_granularity(unit, granularity)
            executed_units.add(unit)
            prior_cache_snapshot: Path | None = None
            if resume:
                prior_cache = _report_record_cache_path(state_file, unit)
                if prior_cache.exists():
                    snapshot_fd, snapshot_raw = tempfile.mkstemp(
                        prefix="pkcs11-check-resume-cache-", suffix=".jsonl"
                    )
                    os.close(snapshot_fd)
                    prior_cache_snapshot = Path(snapshot_raw)
                    shutil.copyfile(prior_cache, prior_cache_snapshot)
            if report_config is not None and not resume:
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
            unit_disabled_nodeids = (
                set(deselect_by_file.get(unit, set())) if unit_granularity == "file" else set()
            )

            # Keep JSONL detail for every isolated subprocess so harness exits
            # and incomplete sessions retain direct evidence at any granularity.
            unit_jsonl_path: Path | None = None
            initial_deselect_path: Path | None = None
            run_env = _subprocess_plugin_env(env, unit)
            _maybe_set_crash_journal(run_env, unit)
            collect_report_log = True
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
                    returncode, captured_stdout, captured_stderr = _run_outer_tee(
                        cmd,
                        env=run_env,
                        timeout=_unit_timeout_seconds(
                            timeout,
                            unit_granularity,
                            num_tests=file_test_counts.get(_unit_file_key(unit), 0),
                        ),
                        state=state,
                        state_file=state_file,
                        target=unit,
                        role="unit",
                    )
                    status = _status_from_returncode(returncode)
                    if unit_jsonl_path is not None:
                        ensure_failed_collection_report(
                            unit_jsonl_path,
                            target=unit,
                            status=status,
                            returncode=returncode,
                            stdout=captured_stdout,
                            stderr=captured_stderr,
                        )
                except subprocess.TimeoutExpired:
                    duration_s = time.monotonic() - start
                    status = "timeout"
                    returncode = _TIMEOUT_RETURN_CODE
                    if unit_jsonl_path is not None:
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
                        to_report_jsonl_paths: list[Path] = (
                            [prior_cache_snapshot] if prior_cache_snapshot is not None else []
                        ) + ([unit_jsonl_path] if unit_jsonl_path is not None else [])
                        iter_status = status
                        iter_returncode = returncode
                        escalate = False
                        retry_count = 0
                        confirmed_crash_returncode: int | None = None
                        all_confirmation_completion_verified = True

                        try:
                            while retry_count < _MAX_TIMEOUT_RETRIES:
                                # Stream JSONL once for completed + culprit + detail.
                                if to_iter_jsonl is not None:
                                    (
                                        iter_detail,
                                        culprit,
                                        completed,
                                        _session_exitstatus,
                                    ) = _analyze_report_jsonl(to_iter_jsonl)
                                    iter_detail, _ = _cache_attempt_report(
                                        state_file=state_file,
                                        unit=unit,
                                        jsonl_path=to_iter_jsonl,
                                        jsonl_paths=to_report_jsonl_paths,
                                        detail=iter_detail,
                                        status=iter_status,
                                        returncode=iter_returncode,
                                        session_exitstatus=_session_exitstatus,
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
                                    confirmation_target = _absolute_nodeid(
                                        _unit_file_key(unit), culprit
                                    )
                                    confirm_jsonl_fd, confirm_jsonl_raw = tempfile.mkstemp(
                                        prefix="pkcs11-check-confirmation-",
                                        suffix=".jsonl",
                                    )
                                    os.close(confirm_jsonl_fd)
                                    confirm_jsonl_path = Path(confirm_jsonl_raw)
                                    to_report_jsonl_paths.append(confirm_jsonl_path)
                                    try:
                                        confirm_rc, confirm_out, confirm_err = _run_outer_tee(
                                            [
                                                sys.executable,
                                                "-m",
                                                "pytest",
                                                confirmation_target,
                                                *pytest_args,
                                                "--report-log",
                                                str(confirm_jsonl_path),
                                            ],
                                            env=env,
                                            timeout=_unit_timeout_seconds(timeout, "test"),
                                            state=state,
                                            state_file=state_file,
                                            target=unit,
                                            role="confirmation",
                                        )
                                        confirm_status = _status_from_returncode(confirm_rc)
                                        ensure_failed_collection_report(
                                            confirm_jsonl_path,
                                            target=culprit,
                                            status=confirm_status,
                                            returncode=confirm_rc,
                                            stdout=confirm_out,
                                            stderr=confirm_err,
                                        )
                                        (
                                            _confirm_detail,
                                            _confirm_culprit,
                                            _confirm_completed,
                                            confirm_exitstatus,
                                        ) = _analyze_report_jsonl(confirm_jsonl_path)
                                        _confirm_detail, confirm_completion_verified = (
                                            _cache_attempt_report(
                                                state_file=state_file,
                                                unit=unit,
                                                jsonl_path=confirm_jsonl_path,
                                                jsonl_paths=to_report_jsonl_paths,
                                                detail=_confirm_detail,
                                                status=confirm_status,
                                                returncode=confirm_rc,
                                                session_exitstatus=confirm_exitstatus,
                                                stdout=confirm_out,
                                                stderr=confirm_err,
                                                evidence_nodeid=culprit,
                                            )
                                        )
                                    except subprocess.TimeoutExpired:
                                        confirm_rc = _TIMEOUT_RETURN_CODE
                                        confirm_out = confirm_err = ""
                                        confirm_status = "timeout"
                                        ensure_failed_collection_report(
                                            confirm_jsonl_path,
                                            target=culprit,
                                            status=confirm_status,
                                            returncode=confirm_rc,
                                            stdout=confirm_out,
                                            stderr=confirm_err,
                                        )
                                        (
                                            _confirm_detail,
                                            _confirm_culprit,
                                            _confirm_completed,
                                            confirm_exitstatus,
                                        ) = _analyze_report_jsonl(confirm_jsonl_path)
                                        _confirm_detail, confirm_completion_verified = (
                                            _cache_attempt_report(
                                                state_file=state_file,
                                                unit=unit,
                                                jsonl_path=confirm_jsonl_path,
                                                jsonl_paths=to_report_jsonl_paths,
                                                detail=_confirm_detail,
                                                status=confirm_status,
                                                returncode=confirm_rc,
                                                session_exitstatus=confirm_exitstatus,
                                                stdout=confirm_out,
                                                stderr=confirm_err,
                                                evidence_nodeid=culprit,
                                            )
                                        )
                                    all_confirmation_completion_verified = (
                                        all_confirmation_completion_verified
                                        and confirm_completion_verified
                                    )
                                    culprit_outcome = (
                                        confirm_status
                                        if confirm_status in {"crashed", "timeout", "failed"}
                                        and confirm_completion_verified
                                        else (
                                            "error"
                                            if not confirm_completion_verified
                                            else "passed-in-isolation"
                                        )
                                    )
                                    to_culprit_entry: dict[str, Any] = {
                                        "nodeid": culprit,
                                        "outcome": culprit_outcome,
                                        "evidence_type": (
                                            "harness"
                                            if not confirm_completion_verified
                                            else "provider"
                                        ),
                                        "returncode": confirm_rc,
                                        "completion_verified": confirm_completion_verified,
                                    }
                                    if culprit_outcome in {
                                        "crashed",
                                        "timeout",
                                        "failed",
                                        "error",
                                    }:
                                        to_culprit_entry["longrepr"] = (
                                            confirm_err.strip()
                                            or confirm_out.strip()
                                            or f"confirmation exited with code {confirm_rc}"
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
                                    if not confirm_completion_verified:
                                        to_accum_detail["incomplete"] = True
                                        to_accum_detail["harness_error"] = True
                                    to_accum_detail["tests"].append(to_culprit_entry)
                                    if culprit_outcome in {
                                        "crashed",
                                        "timeout",
                                        "failed",
                                        "error",
                                    }:
                                        to_accum_detail["counts"][culprit_outcome] = (
                                            to_accum_detail["counts"].get(culprit_outcome, 0) + 1
                                        )
                                    if culprit_outcome == "crashed":
                                        confirmed_crash_returncode = confirm_rc
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
                                to_report_jsonl_paths.append(retry_jsonl_path)

                                retry_env = dict(run_env)
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
                                    retry_rc, retry_out, retry_err = _run_outer_tee(
                                        retry_cmd,
                                        env=retry_env,
                                        timeout=_unit_timeout_seconds(
                                            timeout,
                                            unit_granularity,
                                            num_tests=file_test_counts.get(_unit_file_key(unit), 0),
                                        ),
                                        state=state,
                                        state_file=state_file,
                                        target=unit,
                                        role="retry",
                                    )
                                    retry_status = _status_from_returncode(retry_rc)
                                    ensure_failed_collection_report(
                                        retry_jsonl_path,
                                        target=unit,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        stdout=retry_out,
                                        stderr=retry_err,
                                    )
                                except subprocess.TimeoutExpired:
                                    retry_status = "timeout"
                                    retry_rc = _TIMEOUT_RETURN_CODE
                                    retry_out = retry_err = ""
                                retry_dur = time.monotonic() - retry_start
                                total_retry_dur += retry_dur
                                iter_status = retry_status
                                iter_returncode = retry_rc

                                if retry_status != "timeout":
                                    # Retry completed (pass or fail) - merge
                                    (
                                        final_detail,
                                        _retry_culprit,
                                        _retry_completed,
                                        retry_exitstatus,
                                    ) = _analyze_report_jsonl(retry_jsonl_path)
                                    final_detail, retry_completion_verified = _cache_attempt_report(
                                        state_file=state_file,
                                        unit=unit,
                                        jsonl_path=retry_jsonl_path,
                                        jsonl_paths=to_report_jsonl_paths,
                                        detail=final_detail,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        session_exitstatus=retry_exitstatus,
                                        stdout=retry_out,
                                        stderr=retry_err,
                                    )
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

                                    final_result = FileRunResult(
                                        target=unit,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        duration_s=retry_dur,
                                    )
                                    final_status = _effective_unit_status(
                                        [final_result],
                                        to_accum_detail.get("counts")
                                        if to_accum_detail is not None
                                        else None,
                                    )
                                    final_returncode = retry_rc
                                    if final_status == "timeout":
                                        final_returncode = _TIMEOUT_RETURN_CODE
                                    elif final_status == "crashed":
                                        final_returncode = (
                                            confirmed_crash_returncode
                                            if confirmed_crash_returncode is not None
                                            else retry_rc
                                        )

                                    keep = (
                                        final_status != "passed"
                                        or not retry_completion_verified
                                        or (
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
                                    )
                                    result = FileRunResult(
                                        target=unit,
                                        status=final_status,
                                        returncode=final_returncode,
                                        duration_s=(duration_s + total_retry_dur),
                                        stdout=(retry_out if keep else ""),
                                        stderr=(retry_err if keep else ""),
                                        completion_verified=(
                                            retry_completion_verified
                                            and all_confirmation_completion_verified
                                        ),
                                    )
                                    _record_result(state, result)
                                    save_run_state(state_file, state)
                                    if to_accum_detail is not None:
                                        per_unit_details[unit] = to_accum_detail
                                    if not (
                                        retry_completion_verified
                                        and all_confirmation_completion_verified
                                    ):
                                        console.print(
                                            f"[red]INCOMPLETE[/red] {unit}: retry report log "
                                            "has no valid SessionFinish matching the exit code"
                                        )
                                        exit_code = 1
                                    elif final_status not in {"passed", "empty"}:
                                        console.print(
                                            f"[red]RETRY {final_status.upper()}[/red] {unit} "
                                            f"({total_retry_dur:.1f}s, "
                                            f"{len(to_deselect)} deselected)"
                                        )
                                    else:
                                        console.print(
                                            f"[green]RETRY OK[/green] {unit} "
                                            f"({total_retry_dur:.1f}s, "
                                            f"{len(to_deselect)} deselected)"
                                        )
                                    if final_status in {"failed", "crashed", "timeout"}:
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
                            all_iter_jsonls = to_report_jsonl_paths
                            _write_unit_report_record_cache_from_jsonl_paths(
                                state_file,
                                unit,
                                all_iter_jsonls,
                            )
                            save_run_state(state_file, state)
                            for tmp in dict.fromkeys(to_retry_temps + all_iter_jsonls):
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
                                    completion_verified=all_confirmation_completion_verified,
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
                        return _final_state_exit_code(state, exit_code, per_unit_details)
                    index += 1
                    continue

                duration_s = time.monotonic() - start

                # Extract per-test detail before building the result so we
                # can decide whether to keep stdout/stderr.
                # Keep the JSONL path for the crash handler (iterative deselect
                # needs to re-read it for culprit identification).
                crash_jsonl_path: Path | None = unit_jsonl_path
                detail: dict[str, Any] | None = None
                completion_verified = True
                if unit_jsonl_path is not None:
                    (
                        detail,
                        _culprit,
                        _completed,
                        _session_exitstatus,
                    ) = _analyze_report_jsonl(unit_jsonl_path)
                    detail, completion_verified = _cache_attempt_report(
                        state_file=state_file,
                        unit=unit,
                        jsonl_path=unit_jsonl_path,
                        jsonl_paths=(
                            ([prior_cache_snapshot] if prior_cache_snapshot is not None else [])
                            + [unit_jsonl_path]
                        ),
                        detail=detail,
                        status=status,
                        returncode=returncode,
                        session_exitstatus=_session_exitstatus,
                        stdout=captured_stdout,
                        stderr=captured_stderr,
                    )
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
                keep_output = (
                    status not in ("passed",) or has_notable_tests or not completion_verified
                )
                result = FileRunResult(
                    target=unit,
                    status=status,
                    returncode=returncode,
                    duration_s=duration_s,
                    stdout=captured_stdout if keep_output else "",
                    stderr=captured_stderr if keep_output else "",
                    completion_verified=completion_verified,
                )
                _record_result(state, result)
                save_run_state(state_file, state)
                if detail is not None:
                    per_unit_details[unit] = detail

                if not completion_verified:
                    console.print(
                        f"[red]INCOMPLETE[/red] {unit}: report log has no valid "
                        "SessionFinish matching the subprocess exit code"
                    )
                    exit_code = 1
                    if stop_on_failure:
                        console.print(
                            f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                            f"[bold]--resume --state-file {state_file}[/bold]."
                        )
                        return _final_state_exit_code(state, exit_code, per_unit_details)
                    index += 1
                    continue

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
                        report_jsonl_paths: list[Path] = (
                            [prior_cache_snapshot] if prior_cache_snapshot is not None else []
                        ) + ([crash_jsonl_path] if crash_jsonl_path is not None else [])
                        iter_status = status
                        iter_returncode = returncode
                        escalate = False
                        all_confirmation_completion_verified = True

                        try:
                            while True:
                                # Stream JSONL once for completed + culprit + detail.
                                if iter_jsonl_path is not None:
                                    (
                                        iter_detail,
                                        culprit,
                                        completed,
                                        _session_exitstatus,
                                    ) = _analyze_report_jsonl(iter_jsonl_path)
                                    iter_detail, _ = _cache_attempt_report(
                                        state_file=state_file,
                                        unit=unit,
                                        jsonl_path=iter_jsonl_path,
                                        jsonl_paths=report_jsonl_paths,
                                        detail=iter_detail,
                                        status=iter_status,
                                        returncode=iter_returncode,
                                        session_exitstatus=_session_exitstatus,
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
                                    confirmation_target = _absolute_nodeid(
                                        _unit_file_key(unit), culprit
                                    )
                                    confirm_jsonl_fd, confirm_jsonl_raw = tempfile.mkstemp(
                                        prefix="pkcs11-check-confirmation-",
                                        suffix=".jsonl",
                                    )
                                    os.close(confirm_jsonl_fd)
                                    confirm_jsonl_path = Path(confirm_jsonl_raw)
                                    report_jsonl_paths.append(confirm_jsonl_path)
                                    try:
                                        confirm_rc, confirm_out, confirm_err = _run_outer_tee(
                                            [
                                                sys.executable,
                                                "-m",
                                                "pytest",
                                                confirmation_target,
                                                *pytest_args,
                                                "--report-log",
                                                str(confirm_jsonl_path),
                                            ],
                                            env=env,
                                            timeout=_unit_timeout_seconds(timeout, "test"),
                                            state=state,
                                            state_file=state_file,
                                            target=unit,
                                            role="confirmation",
                                        )
                                        confirm_status = _status_from_returncode(confirm_rc)
                                        ensure_failed_collection_report(
                                            confirm_jsonl_path,
                                            target=culprit,
                                            status=confirm_status,
                                            returncode=confirm_rc,
                                            stdout=confirm_out,
                                            stderr=confirm_err,
                                        )
                                        (
                                            _confirm_detail,
                                            _confirm_culprit,
                                            _confirm_completed,
                                            confirm_exitstatus,
                                        ) = _analyze_report_jsonl(confirm_jsonl_path)
                                        _confirm_detail, confirm_completion_verified = (
                                            _cache_attempt_report(
                                                state_file=state_file,
                                                unit=unit,
                                                jsonl_path=confirm_jsonl_path,
                                                jsonl_paths=report_jsonl_paths,
                                                detail=_confirm_detail,
                                                status=confirm_status,
                                                returncode=confirm_rc,
                                                session_exitstatus=confirm_exitstatus,
                                                stdout=confirm_out,
                                                stderr=confirm_err,
                                                evidence_nodeid=culprit,
                                            )
                                        )
                                    except subprocess.TimeoutExpired:
                                        confirm_rc = _TIMEOUT_RETURN_CODE
                                        confirm_out = ""
                                        confirm_err = (
                                            "crash culprit confirmation timed out after "
                                            f"{_unit_timeout_seconds(timeout, 'test')} seconds"
                                        )
                                        confirm_status = "timeout"
                                        confirm_completion_verified = True
                                        ensure_failed_collection_report(
                                            confirm_jsonl_path,
                                            target=culprit,
                                            status=confirm_status,
                                            returncode=confirm_rc,
                                            stdout=confirm_out,
                                            stderr=confirm_err,
                                        )
                                        (
                                            _confirm_detail,
                                            _confirm_culprit,
                                            _confirm_completed,
                                            confirm_exitstatus,
                                        ) = _analyze_report_jsonl(confirm_jsonl_path)
                                        _confirm_detail, confirm_completion_verified = (
                                            _cache_attempt_report(
                                                state_file=state_file,
                                                unit=unit,
                                                jsonl_path=confirm_jsonl_path,
                                                jsonl_paths=report_jsonl_paths,
                                                detail=_confirm_detail,
                                                status=confirm_status,
                                                returncode=confirm_rc,
                                                session_exitstatus=confirm_exitstatus,
                                                stdout=confirm_out,
                                                stderr=confirm_err,
                                                evidence_nodeid=culprit,
                                            )
                                        )
                                    all_confirmation_completion_verified = (
                                        all_confirmation_completion_verified
                                        and confirm_completion_verified
                                    )
                                    # Record culprit as a standalone result
                                    if confirm_status in {"crashed", "timeout"}:
                                        culprit_outcome = confirm_status
                                    elif not confirm_completion_verified:
                                        culprit_outcome = "error"
                                    else:
                                        culprit_outcome = "crashed"
                                    culprit_entry: dict[str, Any] = {
                                        "nodeid": culprit,
                                        "outcome": culprit_outcome,
                                        "evidence_type": (
                                            "harness"
                                            if not confirm_completion_verified
                                            else "provider"
                                        ),
                                        "returncode": confirm_rc,
                                        "completion_verified": confirm_completion_verified,
                                    }
                                    if confirm_status in {"crashed", "timeout"} or (
                                        not confirm_completion_verified
                                    ):
                                        culprit_entry["longrepr"] = (
                                            confirm_err.strip()
                                            or confirm_out.strip()
                                            or f"confirmation exited with code {confirm_rc}"
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
                                    if not confirm_completion_verified:
                                        accumulated_detail["incomplete"] = True
                                        accumulated_detail["harness_error"] = True
                                    accumulated_detail["tests"].append(culprit_entry)
                                    if culprit_outcome in {"crashed", "timeout", "error"}:
                                        accumulated_detail["counts"][culprit_outcome] = (
                                            accumulated_detail["counts"].get(culprit_outcome, 0) + 1
                                        )
                                    if culprit_outcome == "error":
                                        # The file-level crash remains a finding even when
                                        # confirmation itself only produced harness evidence.
                                        accumulated_detail["counts"]["crashed"] += 1
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
                                                completion_verified=(
                                                    all_confirmation_completion_verified
                                                ),
                                                stderr=(
                                                    "per-file crash limit reached after "
                                                    f"{crash_count} confirmed crashes"
                                                ),
                                            ),
                                        )
                                        collection_error: str | None
                                        try:
                                            collected_nodeids = discover_pytest_units(
                                                [unit],
                                                Path(unit).parent,
                                                granularity="test",
                                                pytest_args=pytest_args,
                                                env=env,
                                            )
                                        except (OSError, ValueError) as exc:
                                            collected_nodeids = []
                                            collection_error = str(exc) or type(exc).__name__
                                        else:
                                            collected_nodeids = [
                                                _absolute_nodeid(unit, nodeid)
                                                for nodeid in collected_nodeids
                                            ]
                                            deselect_set = {
                                                _absolute_nodeid(unit, nodeid)
                                                for nodeid in deselect_set
                                            }
                                            collection_error = (
                                                "direct pytest collection returned no node IDs "
                                                "after crash limit"
                                                if not collected_nodeids
                                                else None
                                            )
                                        if collection_error is not None:
                                            _record_result(
                                                state,
                                                FileRunResult(
                                                    target=(
                                                        f"{unit}::[pkcs11-check-crash-limited-"
                                                        "uncollected]"
                                                    ),
                                                    status="crash_limited",
                                                    returncode=0,
                                                    duration_s=0.0,
                                                    stderr=collection_error,
                                                ),
                                            )
                                        else:
                                            for nodeid in collected_nodeids:
                                                if nodeid not in deselect_set:
                                                    _record_result(
                                                        state,
                                                        FileRunResult(
                                                            target=nodeid,
                                                            status="crash_limited",
                                                            returncode=0,
                                                            duration_s=0.0,
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
                                report_jsonl_paths.append(retry_jsonl_path)

                                retry_env = dict(run_env)
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
                                    retry_rc, retry_out, retry_err = _run_outer_tee(
                                        retry_cmd,
                                        env=retry_env,
                                        timeout=_unit_timeout_seconds(
                                            timeout,
                                            unit_granularity,
                                            num_tests=file_test_counts.get(_unit_file_key(unit), 0),
                                        ),
                                        state=state,
                                        state_file=state_file,
                                        target=unit,
                                        role="retry",
                                    )
                                    retry_status = _status_from_returncode(retry_rc)
                                    ensure_failed_collection_report(
                                        retry_jsonl_path,
                                        target=unit,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        stdout=retry_out,
                                        stderr=retry_err,
                                    )
                                except subprocess.TimeoutExpired:
                                    retry_status = "timeout"
                                    retry_rc = _TIMEOUT_RETURN_CODE
                                    retry_out = retry_err = ""
                                retry_dur = time.monotonic() - retry_start
                                total_retry_dur += retry_dur
                                iter_status = retry_status
                                iter_returncode = retry_rc

                                if retry_status not in ("crashed", "timeout"):
                                    # Retry succeeded - merge final results
                                    (
                                        final_detail,
                                        _retry_culprit,
                                        _retry_completed,
                                        retry_exitstatus,
                                    ) = _analyze_report_jsonl(retry_jsonl_path)
                                    final_detail, retry_completion_verified = _cache_attempt_report(
                                        state_file=state_file,
                                        unit=unit,
                                        jsonl_path=retry_jsonl_path,
                                        jsonl_paths=report_jsonl_paths,
                                        detail=final_detail,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        session_exitstatus=retry_exitstatus,
                                        stdout=retry_out,
                                        stderr=retry_err,
                                    )
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

                                    final_result = FileRunResult(
                                        target=unit,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        duration_s=retry_dur,
                                    )
                                    final_status = _effective_unit_status(
                                        [final_result],
                                        accumulated_detail.get("counts")
                                        if accumulated_detail is not None
                                        else None,
                                    )
                                    final_returncode = retry_rc
                                    if final_status == "timeout":
                                        final_returncode = _TIMEOUT_RETURN_CODE
                                    elif final_status == "crashed":
                                        final_returncode = returncode

                                    keep = (
                                        final_status != "passed"
                                        or not retry_completion_verified
                                        or (
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
                                    )
                                    result = FileRunResult(
                                        target=unit,
                                        status=final_status,
                                        returncode=final_returncode,
                                        duration_s=(duration_s + total_retry_dur),
                                        stdout=(retry_out if keep else ""),
                                        stderr=(retry_err if keep else ""),
                                        completion_verified=(
                                            retry_completion_verified
                                            and all_confirmation_completion_verified
                                        ),
                                    )
                                    _record_result(state, result)
                                    save_run_state(state_file, state)
                                    if accumulated_detail is not None:
                                        per_unit_details[unit] = accumulated_detail
                                    if not (
                                        retry_completion_verified
                                        and all_confirmation_completion_verified
                                    ):
                                        console.print(
                                            f"[red]INCOMPLETE[/red] {unit}: retry report log "
                                            "has no valid SessionFinish matching the exit code"
                                        )
                                        exit_code = 1
                                    elif final_status in {"passed", "empty"}:
                                        console.print(
                                            f"[green]RETRY OK[/green] {unit} "
                                            f"({total_retry_dur:.1f}s, "
                                            f"{len(deselect_set)} deselected)"
                                        )
                                    else:
                                        console.print(
                                            f"[red]RETRY {final_status.upper()}[/red] {unit} "
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
                            all_iter_jsonls = report_jsonl_paths
                            _write_unit_report_record_cache_from_jsonl_paths(
                                state_file,
                                unit,
                                all_iter_jsonls,
                            )
                            save_run_state(state_file, state)
                            for tmp in dict.fromkeys(retry_temp_files + all_iter_jsonls):
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
                    return _final_state_exit_code(state, exit_code, per_unit_details)
                index += 1
            finally:
                if initial_deselect_path is not None:
                    initial_deselect_path.unlink(missing_ok=True)
                if unit_jsonl_path is not None:
                    unit_jsonl_path.unlink(missing_ok=True)
                if prior_cache_snapshot is not None:
                    prior_cache_snapshot.unlink(missing_ok=True)
    finally:
        coverage_data = None
        quality_records = []
        merged_details = dict(per_unit_details)
        if report_config is not None:
            inline_report_records_by_unit = {}
            for unit, records in state.report_records_by_unit.items():
                inline_report_records_by_unit.setdefault(unit, records)
            output_state, inline_report_records_by_unit = _collection_failure_reporting_copy(
                state_file,
                state,
                inline_report_records_by_unit,
            )
            if report_config.jsonl_path is not None:
                if resume and report_config.jsonl_path.exists():
                    candidate_targets = set(output_state.units) | {
                        result.target for result in output_state.results
                    }
                    for unit in executed_units:
                        inline_report_records_by_unit.pop(unit, None)
                    _seed_missing_report_record_caches_from_jsonl(
                        state_file,
                        report_config.jsonl_path,
                        candidate_targets=candidate_targets,
                        skip_units=set(state.report_records_by_unit)
                        | set(inline_report_records_by_unit)
                        | executed_units,
                    )
                wrote_report_jsonl = _write_report_jsonl_from_record_sources(
                    state_file,
                    units=output_state.units,
                    inline_records_by_unit=inline_report_records_by_unit,
                    output_path=report_config.jsonl_path,
                    attempt_history=state.attempt_history,
                    recovery_events=state.recovery_events,
                    collection_failure_path=collection_failure_sidecar_path(state_file),
                )
                if wrote_report_jsonl or report_config.jsonl_path.exists():
                    merged_details = _build_per_unit_details_from_record_sources(
                        state_file,
                        units=output_state.units,
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
                        output_state,
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
            else:
                merged_details = _build_per_unit_details_from_record_sources(
                    state_file,
                    units=output_state.units,
                    inline_records_by_unit=inline_report_records_by_unit,
                )
                merged_details = _merge_supplemental_special_details(
                    merged_details,
                    per_unit_details,
                )
            if report_config.output_format == "json":
                results_payload = write_isolated_json_report(
                    report_config.output_path,
                    output_state,
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
                    output_state,
                    per_unit_details=merged_details,
                )

    return _final_state_exit_code(state, exit_code, merged_details)


def state_results_by_status(path: Path) -> dict[str, int]:
    """Return a small status histogram for a saved state file."""
    state = load_run_state(path)
    if state is None:
        return {}

    summary = _state_summary(state)
    summary.pop("total", None)
    return summary
