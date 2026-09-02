"""Run-state persistence, policy/state fingerprints, and resume selection.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import asdict
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
from pkcs11_check.core.preflight import load_manifest

# The fingerprint detects when the run's effective configuration changed, so
# stale resume/policy state is not reused. By default it covers the framework's
# own env namespaces only. A provider exposes its token/config through its own
# env vars, so point PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES (and, rarely,
# PKCS11_CHECK_FINGERPRINT_ENV_KEYS) at any extra prefixes/keys to have that
# provider's configuration invalidate the fingerprint too. Both accept a comma-
# or whitespace-separated list.
_FINGERPRINT_ENV_PREFIXES_ENV = "PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES"

_FINGERPRINT_ENV_KEYS_ENV = "PKCS11_CHECK_FINGERPRINT_ENV_KEYS"

_DEFAULT_FINGERPRINT_ENV_KEYS = ("P11TEST_PIN", "P11TEST_SO_PIN")

_DEFAULT_FINGERPRINT_ENV_PREFIXES = ("P11TEST_", "PKCS11_")

_REDACTED_ENV_KEYS = {"P11TEST_PIN", "P11TEST_SO_PIN"}

_POLICY_IGNORED_ENV_KEYS = {
    "P11TEST_ISOLATION",
    "P11TEST_POLICY_FILE",
    "P11TEST_RESUME",
    "P11TEST_STATE_FILE",
    "P11TEST_STOP_ON_FAILURE",
}


def _recovery_attempts_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.recovery.jsonl")


def _load_recovery_attempt_sidecar(path: Path) -> list[dict[str, Any]]:
    """Load and validate pending recovery archives before applying any of them."""
    sidecar = _recovery_attempts_path(path)
    if not sidecar.exists():
        return []
    attempts: list[dict[str, Any]] = []
    try:
        lines = sidecar.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read recovery sidecar {sidecar}: {exc}") from exc
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            wrapper = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed recovery sidecar {sidecar} at line {line_number}") from exc
        if not isinstance(wrapper, dict) or wrapper.get("$report_type") != "RecoveryAttempt":
            raise ValueError(
                f"invalid recovery sidecar {sidecar} at line {line_number}: "
                "expected RecoveryAttempt wrapper"
            )
        attempt = wrapper.get("attempt")
        if not isinstance(attempt, dict):
            raise ValueError(
                f"invalid recovery sidecar {sidecar} at line {line_number}: "
                "attempt must be an object"
            )
        target = attempt.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError(
                f"invalid recovery sidecar {sidecar} at line {line_number}: "
                "attempt target is required"
            )
        if wrapper.get("target", target) != target:
            raise ValueError(
                f"invalid recovery sidecar {sidecar} at line {line_number}: "
                "wrapper and attempt targets differ"
            )
        if attempt.get("reason") != "daemon-recovery-requeue":
            raise ValueError(
                f"invalid recovery sidecar {sidecar} at line {line_number}: "
                "unexpected attempt reason"
            )
        if (
            not isinstance(attempt.get("status"), str)
            or type(attempt.get("returncode")) is not int
            or type(attempt.get("completion_verified")) is not bool
            or type(attempt.get("attempt")) is not int
            or attempt["attempt"] < 1
            or not isinstance(attempt.get("records"), list)
        ):
            raise ValueError(
                f"invalid recovery sidecar {sidecar} at line {line_number}: "
                "incomplete attempt fields"
            )
        attempts.append(dict(attempt))
    return attempts


def _recovery_attempt_key(attempt: Mapping[str, Any]) -> str:
    return json.dumps(attempt, sort_keys=True, separators=(",", ":"))


def _reconcile_recovery_attempts(
    path: Path,
    state: FileRunState,
    sidecar_attempts: list[dict[str, Any]],
) -> None:
    if not sidecar_attempts:
        return
    known = {_recovery_attempt_key(attempt) for attempt in state.attempt_history}
    targets: set[str] = set()
    for attempt in sidecar_attempts:
        key = _recovery_attempt_key(attempt)
        if key not in known:
            state.attempt_history.append(attempt)
            known.add(key)
        target = attempt["target"]
        targets.add(target)

        event = attempt.get("recovery_event")
        if not isinstance(event, Mapping):
            continue
        event_key = _recovery_attempt_key(event)
        if any(_recovery_attempt_key(existing) == event_key for existing in state.recovery_events):
            continue
        state.recovery_events.append(dict(event))

    state.results[:] = [result for result in state.results if result.target not in targets]
    state.process_observations[:] = [
        observation
        for observation in state.process_observations
        if not isinstance(observation, Mapping)
        or not any(
            str(observation.get("target", "")) == target
            or str(observation.get("parent_nodeid", "") or "").startswith(f"{target}::")
            for target in targets
        )
    ]
    for target in targets:
        state.report_records_by_unit.pop(target, None)
        _delete_unit_report_record_cache(path, target)


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
    raw_observations = raw.get("process_observations", [])
    observations_well_formed = isinstance(raw_observations, list) and all(
        isinstance(observation, dict) for observation in raw_observations
    )
    process_observations = (
        [dict(observation) for observation in raw_observations if isinstance(observation, dict)]
        if isinstance(raw_observations, list)
        else []
    )
    raw_attempt_history = raw.get("attempt_history", [])
    attempt_history = (
        [dict(attempt) for attempt in raw_attempt_history if isinstance(attempt, Mapping)]
        if isinstance(raw_attempt_history, list)
        else []
    )
    raw_recovery_events = raw.get("recovery_events", [])
    recovery_events = (
        [dict(event) for event in raw_recovery_events if isinstance(event, Mapping)]
        if isinstance(raw_recovery_events, list)
        else []
    )
    state = FileRunState(
        units=list(raw.get("units", [])),
        fingerprint=str(raw.get("fingerprint", "")),
        results=results,
        report_records_by_unit=report_records_by_unit,
        process_observations=process_observations,
        process_observations_complete=(
            "process_observations" in raw
            and raw.get("process_observations_complete") is True
            and observations_well_formed
        ),
        attempt_history=attempt_history,
        recovery_events=recovery_events,
    )
    _reconcile_recovery_attempts(path, state, _load_recovery_attempt_sidecar(path))
    return state


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
        "process_observations": state.process_observations,
        "process_observations_complete": state.process_observations_complete,
        "attempt_history": state.attempt_history,
        "recovery_events": state.recovery_events,
    }
    if os.environ.get("PKCS11_CHECK_STATE_INLINE_RECORDS") == "1":
        # Opt-in legacy/debug behavior: embed the per-unit report records inline.
        # This is the O(n^2) re-serialization the default path deliberately
        # avoids (records already live in per-unit shards). Retained only as an
        # escape hatch for offline state inspection and for A/B perf measurement;
        # it is OFF by default and never needed for resume.
        payload["report_records_by_unit"] = state.report_records_by_unit
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _recovery_attempts_path(path).unlink(missing_ok=True)


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


#: Read size for content digests. Provider modules are a few MB at most.
_DIGEST_CHUNK = 1 << 20


def _content_digest(path: Path) -> str:
    """SHA-256 of the file's bytes, or a sentinel if it cannot be read."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(_DIGEST_CHUNK), b""):
                digest.update(chunk)
    except OSError:
        # Unreadable is itself a state change worth invalidating a resume on, and it must
        # not collide with any real digest.
        return "unreadable"
    return digest.hexdigest()


def _path_snapshot(path_str: str) -> dict[str, int | str] | None:
    path = Path(path_str)
    if not path.exists():
        return None

    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        # size+mtime_ns alone is NOT an identity. Filesystem timestamp granularity is
        # coarse enough that consecutive writes share one mtime_ns -- measured on Windows,
        # where five back-to-back writes to the same path produced a single identical
        # st_mtime_ns -- so swapping in a different provider module of the same size was
        # invisible here. Resume would then merge results from two different modules into
        # one report and call it a continuation, which for a conformance tool means
        # attributing one module's findings to another. Hash the bytes instead.
        "sha256": _content_digest(path),
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

    attempted = {result.target for result in state.results}
    return [unit for unit in units if unit not in attempted]
