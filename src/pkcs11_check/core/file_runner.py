"""Per-unit pytest runner with subprocess isolation and resume support."""

from __future__ import annotations

import hashlib
import io
import json
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from xml.etree import ElementTree as ET

from rich.console import Console

from pkcs11_check.core.collection import CollectedPytestItem, collect_pytest_item_metadata
from pkcs11_check.core.quality_audit import build_quality_audit

IsolationGranularity = Literal["file", "test"]
RunnerGranularity = Literal["file", "test", "mixed"]
CrashStatus = Literal["crashed", "timeout"]
_RESUME_COMPLETE_STATUSES = {"passed", "empty", "escalated", "crash_limited"}

_FINGERPRINT_ENV_KEYS = ("BOUNCY_HSM_CFG_STRING", "SOFTHSM2_CONF", "P11TEST_PIN")
_FINGERPRINT_ENV_PREFIXES = (
    "P11TEST_",
    "BOUNCY_HSM_",
    "NSS_",
    "OPENCRYPTOKI_",
    "PKCS11_",
    "QRYPTOTOKEN_",
    "SOFTHSM2_",
    "TPM2_",
)
_REDACTED_ENV_KEYS = {"P11TEST_PIN"}
_POLICY_IGNORED_ENV_KEYS = {
    "P11TEST_ISOLATION",
    "P11TEST_POLICY_FILE",
    "P11TEST_RESUME",
    "P11TEST_STATE_FILE",
    "P11TEST_STOP_ON_FAILURE",
}


@dataclass(frozen=True)
class FileRunResult:
    """Result for one isolated pytest target."""

    target: str
    status: str
    returncode: int
    duration_s: float
    stdout: str = ""
    stderr: str = ""


@dataclass
class FileRunState:
    """Persistent state for resumable isolated runs."""

    units: list[str]
    fingerprint: str
    results: list[FileRunResult]
    report_records_by_unit: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class BackendIsolationPolicy:
    """Persistent adaptive isolation policy for one backend fingerprint."""

    fingerprint: str
    promoted_files: list[str]
    crashed_tests: list[str]


@dataclass(frozen=True)
class IsolatedReportConfig:
    """Output configuration for aggregated isolated-run reports."""

    output_format: Literal["json", "junit"]
    output_path: Path
    jsonl_path: Path | None = None


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
        nodeids.append(line)

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


def _nodeids_for_unit(unit: str, items: list[CollectedPytestItem]) -> list[str]:
    file_key = normalize_policy_file_key(unit.split("::", 1)[0])
    if "::" in unit:
        prefix = unit
        return [
            item.nodeid
            for item in items
            if normalize_policy_file_key(item.file_path) == file_key
            and (item.nodeid == prefix or item.nodeid.startswith(prefix + "["))
        ]
    return [item.nodeid for item in items if normalize_policy_file_key(item.file_path) == file_key]


def discover_auto_isolation_units(
    targets: list[str],
    default_root: Path,
    *,
    pytest_args: list[str],
    policy_file: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Expand targets into a mixed file/test unit list for auto isolation."""
    file_units = discover_pytest_units(targets, default_root, granularity="file")
    units: list[str] = []
    promoted_files = load_promoted_files(policy_file, pytest_args, env)
    collected_items = collect_pytest_item_metadata(
        targets,
        pytest_args,
        env=dict(env or os.environ),
    )
    markers_by_file = _markers_by_file(collected_items)

    # Build set of files that have collected items (respects -m, -k filters).
    # If collection returned items, use them to filter files; otherwise include all
    # (fallback for environments where collection metadata is unavailable).
    collected_files: set[str] | None = None
    if collected_items:
        collected_files = set()
        for item in collected_items:
            collected_files.add(normalize_policy_file_key(item.file_path))

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
            nodeids = _nodeids_for_unit(file_unit, collected_items)
            if nodeids:
                units.extend(nodeids)
            else:
                units.extend(
                    discover_pytest_units(
                        [file_unit],
                        default_root,
                        granularity="test",
                        pytest_args=pytest_args,
                        env=env,
                    )
                )
        else:
            if file_forces_file_isolation(marker_names):
                units.append(str(file_path))
            else:
                units.append(file_unit)

    return units


def load_isolation_policy(path: Path) -> dict[str, BackendIsolationPolicy]:
    """Load the adaptive isolation policy file."""
    if not path.exists():
        return {}

    raw = json.loads(path.read_text())
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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _state_summary(state: FileRunState) -> dict[str, int]:
    summary: dict[str, int] = {}
    for result in state.results:
        summary[result.status] = summary.get(result.status, 0) + 1
    summary["total"] = len(state.results)
    return summary


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
        merged_counts: dict[str, int] = {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "error": 0,
        }
        merged_tests: list[dict[str, Any]] = []
        for r in file_results:
            detail = details.get(r.target, {})
            for key in merged_counts:
                merged_counts[key] += detail.get("counts", {}).get(key, 0)
            merged_tests.extend(detail.get("tests", []))
        out.append((file_target, file_results, {"counts": merged_counts, "tests": merged_tests}))
    return out


def write_isolated_json_report(
    path: Path,
    state: FileRunState,
    *,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write an aggregated JSON report for an isolated run in unified format."""
    payload = _build_isolated_json_payload(
        state,
        per_unit_details=per_unit_details,
        coverage=coverage,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def _build_isolated_json_payload(
    state: FileRunState,
    *,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details = per_unit_details or {}

    summary: dict[str, int] = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
    }

    grouped = _group_results_by_file(state.results, details)
    units_out: list[dict[str, Any]] = []

    for file_target, file_results, merged_detail in grouped:
        has_failure = any(r.status in {"failed", "crashed", "timeout"} for r in file_results)
        duration = sum(r.duration_s for r in file_results)
        stdout_parts = [r.stdout for r in file_results if r.stdout]
        stderr_parts = [r.stderr for r in file_results if r.stderr]

        unit: dict[str, Any] = {
            "target": file_target,
            "status": "failed" if has_failure else file_results[0].status,
            "returncode": max(abs(r.returncode) for r in file_results) if has_failure else 0,
            "duration_s": round(duration, 3),
        }
        if stdout_parts:
            unit["stdout"] = "\n".join(stdout_parts)
        if stderr_parts:
            unit["stderr"] = "\n".join(stderr_parts)

        counts = merged_detail.get("counts")
        if counts and any(v > 0 for v in counts.values()):
            unit["counts"] = counts
            for key in summary:
                summary[key] += counts.get(key, 0)
        tests = merged_detail.get("tests")
        if tests:
            unit["tests"] = tests
        sr = merged_detail.get("skip_reasons")
        if sr:
            unit["skip_reasons"] = sr

        units_out.append(unit)

    summary["total"] = sum(summary.values())

    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units_out,
    }
    if coverage:
        payload["coverage"] = coverage
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


def _load_report_log_records(jsonl_path: Path) -> list[dict[str, Any]]:
    """Load parseable JSONL report-log records from disk."""
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return []

    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records


def _report_record_cache_dir(state_file: Path) -> Path:
    return state_file.parent / f".{state_file.name}.report-records"


def _report_record_cache_path(state_file: Path, unit: str) -> Path:
    digest = hashlib.sha256(unit.encode("utf-8")).hexdigest()
    return _report_record_cache_dir(state_file) / f"{digest}.jsonl"


def _write_unit_report_record_cache(
    state_file: Path,
    unit: str,
    records: list[Mapping[str, Any]],
) -> None:
    cache_path = _report_record_cache_path(state_file, unit)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("".join(json.dumps(record) + "\n" for record in records))


def _delete_unit_report_record_cache(state_file: Path, unit: str) -> None:
    _report_record_cache_path(state_file, unit).unlink(missing_ok=True)


def _load_cached_report_records_by_unit(
    state_file: Path,
    units: list[str],
) -> dict[str, list[dict[str, Any]]]:
    cached: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        records = _load_report_log_records(_report_record_cache_path(state_file, unit))
        if records:
            cached[unit] = records
    return cached


def extract_quality_report_records_from_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
    """Extract report-log records relevant to the quality audit from JSONL."""
    records: list[dict[str, Any]] = []
    for rec in _load_report_log_records(jsonl_path):
        report_type = rec.get("$report_type", "TestReport")
        if report_type in {"TestReport", "SelectionReport"}:
            records.append(rec)
    return records


def write_quality_json_report(
    path: Path,
    results: Mapping[str, Any],
    *,
    coverage: Mapping[str, Any] | None = None,
    report_log_records: Iterable[Mapping[str, Any]] | None = None,
) -> None:
    """Write the quality audit artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_quality_audit(
        results=results,
        coverage=coverage,
        report_log_records=report_log_records,
    )
    path.write_text(json.dumps(payload, indent=2) + "\n")


def write_report_jsonl(jsonl_paths: list[Path], output_path: Path) -> None:
    """Stream-concatenate per-unit JSONL temp files into a single artifact.

    Writes to a sibling .tmp file first, then atomically renames to
    output_path.  Deletes all source JSONL temp files in a finally block
    regardless of success or failure.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(".jsonl.tmp")
    try:
        with tmp_path.open("wb") as out_fh:
            for src in jsonl_paths:
                try:
                    with src.open("rb") as in_fh:
                        shutil.copyfileobj(in_fh, out_fh)
                except (FileNotFoundError, OSError):
                    pass  # missing temp file - skip silently
        tmp_path.rename(output_path)
    finally:
        tmp_path.unlink(missing_ok=True)
        for src in jsonl_paths:
            src.unlink(missing_ok=True)


def _infer_unit_target_from_records(
    records: list[Mapping[str, Any]],
    candidate_targets: set[str],
) -> str | None:
    nodeids = [
        str(record.get("nodeid", "")).strip()
        for record in records
        if record.get("$report_type", "TestReport") in {"TestReport", "CollectReport"}
        and str(record.get("nodeid", "")).strip()
    ]
    if not nodeids:
        return None

    unique_nodeids = sorted(set(nodeids))
    file_targets = sorted({nodeid.split("::", 1)[0] for nodeid in unique_nodeids})

    if len(unique_nodeids) == 1 and unique_nodeids[0] in candidate_targets:
        return unique_nodeids[0]
    if len(file_targets) == 1 and file_targets[0] in candidate_targets:
        return file_targets[0]
    if len(unique_nodeids) == 1:
        return unique_nodeids[0]
    if len(file_targets) == 1:
        return file_targets[0]
    return None


def _unit_candidate_from_record(
    record: Mapping[str, Any],
    candidate_targets: set[str],
) -> str | None:
    report_type = record.get("$report_type", "TestReport")
    if report_type not in {"TestReport", "CollectReport"}:
        return None
    nodeid = str(record.get("nodeid", "")).strip()
    if not nodeid:
        return None
    file_target = nodeid.split("::", 1)[0]
    if file_target in candidate_targets and nodeid not in candidate_targets:
        return file_target
    if nodeid in candidate_targets:
        return nodeid
    if file_target in candidate_targets:
        return file_target
    return nodeid


def _extract_unit_report_records_from_jsonl(
    jsonl_path: Path,
    *,
    candidate_targets: set[str],
) -> dict[str, list[dict[str, Any]]]:
    """Split a merged report.jsonl back into per-unit record chunks."""
    records = _load_report_log_records(jsonl_path)
    if not records:
        return {}

    chunks: list[list[dict[str, Any]]] = []
    current_chunk: list[dict[str, Any]] = []
    current_target: str | None = None
    for record in records:
        record_target = _unit_candidate_from_record(record, candidate_targets)
        if (
            current_chunk
            and current_target is not None
            and record_target is not None
            and record_target != current_target
        ):
            chunks.append(current_chunk)
            current_chunk = []
            current_target = None
        current_chunk.append(record)
        if current_target is None and record_target is not None:
            current_target = record_target
        if record.get("$report_type") == "CoverageReport":
            chunks.append(current_chunk)
            current_chunk = []
            current_target = None
    if current_chunk:
        chunks.append(current_chunk)

    records_by_unit: dict[str, list[dict[str, Any]]] = {}
    for chunk in chunks:
        unit_target = _infer_unit_target_from_records(chunk, candidate_targets)
        if unit_target is None:
            continue
        records_by_unit.setdefault(unit_target, []).extend(chunk)
    return records_by_unit


def _write_report_jsonl_from_record_map(
    report_records_by_unit: Mapping[str, list[Mapping[str, Any]]],
    *,
    units: list[str],
    output_path: Path,
) -> None:
    """Write a merged report.jsonl from in-memory per-unit record groups."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(".jsonl.tmp")
    written_units: set[str] = set()
    try:
        with tmp_path.open("w", encoding="utf-8") as out_fh:
            for unit in units:
                for record in report_records_by_unit.get(unit, []):
                    out_fh.write(json.dumps(record) + "\n")
                written_units.add(unit)
            for unit in sorted(report_records_by_unit):
                if unit in written_units:
                    continue
                for record in report_records_by_unit[unit]:
                    out_fh.write(json.dumps(record) + "\n")
        tmp_path.rename(output_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _build_detail_from_report_records(records: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Build per-unit detail payload from parsed report-log records."""
    if not records:
        return None

    counts: dict[str, int] = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
    }
    non_passing: list[dict[str, Any]] = []
    skip_reasons: dict[str, int] = {}
    seen_call: set[str] = set()
    setup_events: list[Mapping[str, Any]] = []
    call_events: list[Mapping[str, Any]] = []
    collect_errors: list[Mapping[str, Any]] = []

    for rec in records:
        if not isinstance(rec, Mapping):
            continue

        report_type = rec.get("$report_type", "TestReport")
        when = rec.get("when", "")
        outcome = rec.get("outcome", "")
        nodeid = rec.get("nodeid", "")

        if report_type == "CollectReport":
            if outcome == "passed":
                continue
            collect_errors.append(rec)
            continue

        if report_type != "TestReport":
            continue

        if when == "call":
            seen_call.add(str(nodeid))
            call_events.append(rec)
        elif when == "setup" and outcome in ("skipped", "failed", "error"):
            setup_events.append(rec)

    for rec in call_events:
        nodeid = rec.get("nodeid", "")
        raw_outcome = rec.get("outcome", "passed")
        wasxfail = rec.get("wasxfail")
        mapped = _map_outcome(raw_outcome, wasxfail)
        counts[mapped] = counts.get(mapped, 0) + 1

        if mapped == "skipped":
            reason = _flatten_longrepr(rec.get("longrepr")) or "skipped"
            if reason.startswith("(") and "Skipped:" in reason:
                parts = reason.split("Skipped:", 1)
                if len(parts) > 1:
                    reason = parts[1].strip().rstrip("')")
            elif reason.startswith("Skipped:"):
                reason = reason[8:].strip()
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue
        if mapped == "passed":
            continue

        entry: dict[str, Any] = {
            "nodeid": nodeid,
            "outcome": mapped,
            "duration": rec.get("duration", 0.0),
        }
        if rec.get("start") is not None:
            entry["start"] = rec["start"]
        if wasxfail is not None:
            entry["wasxfail"] = wasxfail
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            entry["longrepr"] = flat
        if rec.get("location"):
            entry["location"] = rec["location"]
        for section in rec.get("sections", []):
            if isinstance(section, list) and len(section) >= 2:
                name, content = section[0], section[1]
                if "stdout" in name.lower():
                    entry["stdout"] = content
                elif "stderr" in name.lower():
                    entry["stderr"] = content
        non_passing.append(entry)

    seen_error_reprs: set[str] = set()
    for rec in setup_events:
        nodeid = rec.get("nodeid", "")
        if nodeid in seen_call:
            continue
        raw_outcome = rec.get("outcome", "")
        if raw_outcome == "skipped":
            counts["skipped"] = counts.get("skipped", 0) + 1
            reason = _flatten_longrepr(rec.get("longrepr")) or "skipped"
            if "Skipped:" in reason:
                parts = reason.split("Skipped:", 1)
                reason = parts[1].strip().rstrip("')")
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue

        counts["error"] = counts.get("error", 0) + 1
        flat = _flatten_longrepr(rec.get("longrepr"))
        dedup_key = flat or str(nodeid)
        if dedup_key in seen_error_reprs:
            continue
        seen_error_reprs.add(dedup_key)
        entry = {
            "nodeid": nodeid,
            "outcome": "error",
            "duration": rec.get("duration", 0.0),
        }
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    for rec in collect_errors:
        counts["error"] = counts.get("error", 0) + 1
        entry = {
            "nodeid": rec.get("nodeid", ""),
            "outcome": "error",
            "duration": rec.get("duration", 0.0),
        }
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    if not any(counts.values()):
        return None
    result: dict[str, Any] = {"counts": counts, "tests": non_passing}
    if skip_reasons:
        result["skip_reasons"] = skip_reasons
    return result


def _build_per_unit_details_from_record_map(
    report_records_by_unit: Mapping[str, list[Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for unit, records in report_records_by_unit.items():
        detail = _build_detail_from_report_records(records)
        if detail is not None:
            details[unit] = detail
    return details


def extract_coverage_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Extract and merge CoverageReport entries from a JSONL artifact.

    Returns a merged coverage dict with function_coverage and mechanism_coverage,
    or None if no CoverageReport entries are found.
    """
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return None

    from collections import Counter

    all_called: set[str] = set()
    all_uncalled: set[str] = set()
    func_available = 0
    all_invoked: set[str] = set()
    all_not_invoked: set[str] = set()
    all_available_mechs: set[str] = set()
    all_detail: set[str] = set()
    all_func_counts: Counter[str] = Counter()
    all_bootstrap_counts: Counter[str] = Counter()
    all_mech_counts: Counter[str] = Counter()
    all_detail_counts: Counter[str] = Counter()
    found = False

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("$report_type") != "CoverageReport":
            continue
        found = True
        fc = rec.get("function_coverage", {})
        func_available = max(func_available, fc.get("available", 0))
        all_called.update(fc.get("called_names", []))
        all_uncalled.update(fc.get("uncalled_names", []))
        all_func_counts.update(fc.get("called_counts", {}))
        all_bootstrap_counts.update(fc.get("bootstrap_counts", {}))
        mc = rec.get("mechanism_coverage", {})
        all_available_mechs.update(mc.get("available_names", []))
        all_invoked.update(mc.get("invoked_names", []))
        all_not_invoked.update(mc.get("not_invoked_names", []))
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
            "bootstrap_counts": dict(all_bootstrap_counts),
            "uncalled_names": merged_uncalled,
        },
        "mechanism_coverage": {
            "available": len(all_available_mechs),
            "available_names": sorted(all_available_mechs),
            "invoked": len(all_invoked),
            "invoked_names": sorted(all_invoked),
            "invoked_counts": dict(all_mech_counts),
            "not_invoked": len(merged_not_invoked),
            "not_invoked_names": merged_not_invoked,
            "invoked_detail": sorted(all_detail),
            "invoked_detail_counts": dict(all_detail_counts),
        },
    }


def postprocess_jsonl_to_unified(jsonl_path: Path, output_path: Path) -> dict[str, Any] | None:
    """Convert a pytest-reportlog JSONL file to pkcs11-check unified format.

    Groups tests by file and writes the unified JSON report.
    Used for ``--isolation none`` to produce consistent output.
    """
    detail = _read_jsonl_results(jsonl_path)
    if detail is None:
        return None

    # Group tests by file
    by_file: dict[str, list[dict[str, Any]]] = {}
    for test in detail["tests"]:
        file_part = test.get("nodeid", "").split("::")[0]
        by_file.setdefault(file_part, []).append(test)

    # Also need per-file counts - rebuild from the full JSONL
    # Since _read_jsonl_results only gives us aggregated counts,
    # we re-read the JSONL for per-file counting.
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return

    file_counts: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("$report_type") != "TestReport" or rec.get("when") != "call":
            continue
        nodeid = rec.get("nodeid", "")
        file_part = nodeid.split("::")[0]
        if file_part not in file_counts:
            file_counts[file_part] = {
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
            }
        outcome = _map_outcome(rec.get("outcome", "passed"), rec.get("wasxfail"))
        file_counts[file_part][outcome] = file_counts[file_part].get(outcome, 0) + 1

    summary: dict[str, int] = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
    }
    units: list[dict[str, Any]] = []

    for target in sorted(set(list(by_file.keys()) + list(file_counts.keys()))):
        counts = file_counts.get(
            target,
            {
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
            },
        )
        for key in summary:
            summary[key] += counts.get(key, 0)
        has_failure = counts.get("failed", 0) > 0 or counts.get("error", 0) > 0
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
        units.append(unit)

    summary["total"] = sum(summary.values())
    payload = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def load_run_state(path: Path) -> FileRunState | None:
    """Load a resumable runner state from disk."""
    if not path.exists():
        return None

    raw = json.loads(path.read_text())
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
    """Persist the current runner state to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fingerprint": state.fingerprint,
        "units": state.units,
        "results": [asdict(result) for result in state.results],
        "report_records_by_unit": state.report_records_by_unit,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _extract_option_value(args: list[str], option: str) -> str | None:
    for index, arg in enumerate(args):
        if arg == option:
            if index + 1 < len(args):
                return args[index + 1]
            return None
        if arg.startswith(f"{option}="):
            return arg.split("=", 1)[1]
    return None


def _manifest_digest(pytest_args: list[str]) -> str | None:
    manifest_path = _extract_option_value(pytest_args, "--p11-manifest")
    if manifest_path is None:
        return None

    path = Path(manifest_path)
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def normalize_policy_file_key(path_str: str) -> str:
    """Normalize a test file path for policy matching."""
    return str(Path(path_str).resolve())


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


def _fingerprint_env(
    env: Mapping[str, str], *, ignored_keys: set[str] | frozenset[str] = frozenset()
) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for key in sorted(env):
        if key in ignored_keys:
            continue
        if key in _FINGERPRINT_ENV_KEYS or key.startswith(_FINGERPRINT_ENV_PREFIXES):
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
    if returncode < 0:
        return "crashed"
    return "failed"


def _flatten_longrepr(longrepr: Any) -> str:
    """Flatten a JSONL longrepr value to a plain string.

    longrepr can be a dict (with reprcrash/reprtraceback), a string,
    a list/tuple ``[path, lineno, reason]`` (for skips), or None.
    """
    if longrepr is None:
        return ""
    if isinstance(longrepr, str):
        return longrepr
    # Skip-style: [path, lineno, "Skipped: reason"] or (path, lineno, reason)
    if isinstance(longrepr, (list, tuple)) and len(longrepr) >= 3:
        return str(longrepr[2])
    if isinstance(longrepr, dict):
        parts: list[str] = []
        # Extract crash summary
        reprcrash = longrepr.get("reprcrash")
        if isinstance(reprcrash, dict):
            msg = reprcrash.get("message", "")
            if msg:
                parts.append(msg)
        # Concatenate traceback entries
        reprtraceback = longrepr.get("reprtraceback")
        if isinstance(reprtraceback, dict):
            for entry in reprtraceback.get("reprentries", []):
                if isinstance(entry, dict):
                    lines = entry.get("lines", [])
                    if lines:
                        parts.append("\n".join(lines))
        return "\n".join(parts) if parts else ""
    return str(longrepr)


def _map_outcome(raw_outcome: str, wasxfail: str | None) -> str:
    """Map a raw pytest-reportlog outcome to the unified outcome value."""
    if raw_outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if raw_outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    # "failed" stays "failed" regardless of wasxfail (strict xfail)
    return raw_outcome


def _identify_crash_culprit(jsonl_path: Path) -> tuple[str | None, list[str]]:
    """Identify crash culprit and completed tests from partial JSONL.

    Returns ``(culprit_nodeid, list_of_completed_nodeids)``.
    *culprit* is the nodeid that has ``setup`` started but no ``teardown``
    completed - i.e. the test that was running when the process crashed.
    Returns ``(None, completed_list)`` if every test finished cleanly.
    """
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return None, []
    if not text.strip():
        return None, []

    # Per-nodeid phase tracking, preserving insertion order.
    phases: dict[str, set[str]] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        report_type = rec.get("$report_type", "TestReport")
        if report_type != "TestReport":
            continue
        nodeid: str = rec.get("nodeid", "")
        when: str = rec.get("when", "")
        if not nodeid or not when:
            continue
        if nodeid not in phases:
            phases[nodeid] = set()
        phases[nodeid].add(when)

    completed: list[str] = []
    culprit: str | None = None

    for nid, ph in phases.items():
        if "teardown" in ph:
            completed.append(nid)
        elif "setup" in ph and culprit is None:
            culprit = nid

    return culprit, completed


def _read_jsonl_results(jsonl_path: Path) -> dict[str, Any] | None:
    """Read a pytest-reportlog JSONL file and return per-test outcomes.

    Returns ``{"counts": {...}, "tests": [...]}`` where ``tests`` contains
    only non-passing entries (failed, xfailed, xpassed, error).
    Returns ``None`` if the file is missing or empty.
    """
    records = _load_report_log_records(jsonl_path)
    if not records:
        return None
    return _build_detail_from_report_records(records)


def _unit_timeout_seconds(test_timeout: int, granularity: IsolationGranularity) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    return max(test_timeout * 30, 900)


def _effective_granularity(unit: str, granularity: RunnerGranularity) -> IsolationGranularity:
    if granularity == "mixed":
        return "test" if "::" in unit else "file"
    return granularity


def _unit_file_key(unit: str) -> str:
    return normalize_policy_file_key(unit.split("::", 1)[0])


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

    additions = _insert_escalated_units(
        state,
        units,
        index,
        nodeids,
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

    sel = selectors.DefaultSelector()
    if proc.stdout:
        sel.register(proc.stdout, selectors.EVENT_READ, ("stdout", stdout_buf))
    if proc.stderr:
        sel.register(proc.stderr, selectors.EVENT_READ, ("stderr", stderr_buf))

    try:
        deadline = time.monotonic() + timeout
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise subprocess.TimeoutExpired(cmd, timeout)
            for key, _ in sel.select(timeout=min(remaining, 0.5)):
                stream = key.fileobj
                tag, buf = key.data
                chunk = stream.read1(8192) if hasattr(stream, "read1") else stream.read(8192)  # type: ignore[union-attr]
                if not chunk:
                    sel.unregister(stream)
                    continue
                buf.write(chunk)
                # Tee to console
                target = sys.stdout.buffer if tag == "stdout" else sys.stderr.buffer
                target.write(chunk)
                target.flush()
    finally:
        sel.close()

    proc.wait()
    return (
        proc.returncode,
        stdout_buf.getvalue().decode("utf-8", errors="replace"),
        stderr_buf.getvalue().decode("utf-8", errors="replace"),
    )


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
    max_crashes_per_file: int = 3,
) -> int:
    """Run pytest units in fresh subprocesses and persist progress."""
    env = os.environ.copy()
    del deselect_by_file
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
    report_records_by_unit: dict[str, list[dict[str, Any]]] = {}
    executed_units: set[str] = set()

    if not pending_units:
        console.print("[green]Nothing to do[/green] - all isolated units already completed.")
        if report_config is not None:
            coverage_data: dict[str, Any] | None = None
            quality_records: list[dict[str, Any]] = []
            merged_report_records_by_unit = _load_cached_report_records_by_unit(
                state_file, state.units
            )
            for unit, records in state.report_records_by_unit.items():
                merged_report_records_by_unit.setdefault(unit, records)
            if (
                resume
                and report_config.jsonl_path is not None
                and report_config.jsonl_path.exists()
            ):
                candidate_targets = set(state.units) | {result.target for result in state.results}
                parsed_report_records = _extract_unit_report_records_from_jsonl(
                    report_config.jsonl_path,
                    candidate_targets=candidate_targets,
                )
                for unit, records in parsed_report_records.items():
                    merged_report_records_by_unit.setdefault(unit, records)
            merged_details = _build_per_unit_details_from_record_map(
                merged_report_records_by_unit
            )
            if report_config.jsonl_path is not None:
                if merged_report_records_by_unit:
                    _write_report_jsonl_from_record_map(
                        merged_report_records_by_unit,
                        units=state.units,
                        output_path=report_config.jsonl_path,
                    )
                if report_config.jsonl_path.exists():
                    coverage_data = extract_coverage_from_jsonl(report_config.jsonl_path)
                    quality_records = extract_quality_report_records_from_jsonl(
                        report_config.jsonl_path
                    )
                    if coverage_data:
                        coverage_path = report_config.jsonl_path.parent / "coverage.json"
                        coverage_path.write_text(json.dumps(coverage_data, indent=2) + "\n")
            if report_config.output_format == "json":
                results_payload = write_isolated_json_report(
                    report_config.output_path,
                    state,
                    per_unit_details=merged_details,
                    coverage=coverage_data,
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

            executed_units.add(unit)
            if report_config is not None and report_config.jsonl_path is not None:
                _delete_unit_report_record_cache(state_file, unit)
                state.report_records_by_unit.pop(unit, None)
            console.print(f"[cyan][{index + 1}/{len(units)}][/cyan] {unit}")
            start = time.monotonic()
            unit_granularity = _effective_granularity(unit, granularity)

            # File-level runs always benefit from JSONL detail. Test-level runs
            # only need it when we are building merged JSON artifacts.
            unit_jsonl_path: Path | None = None
            collect_report_log = unit_granularity == "file" or (
                report_config is not None and report_config.jsonl_path is not None
            )
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
                        env=env,
                        timeout=_unit_timeout_seconds(timeout, unit_granularity),
                    )
                    status = _status_from_returncode(returncode)
                except subprocess.TimeoutExpired:
                    duration_s = time.monotonic() - start
                    if unit_jsonl_path is not None:
                        unit_records = _load_report_log_records(unit_jsonl_path)
                        if unit_records:
                            report_records_by_unit[unit] = unit_records
                            state.report_records_by_unit[unit] = unit_records
                            if report_config is not None and report_config.jsonl_path is not None:
                                _write_unit_report_record_cache(state_file, unit, unit_records)
                    result = FileRunResult(
                        target=unit,
                        status="timeout",
                        returncode=124,
                        duration_s=duration_s,
                    )
                    _record_result(state, result)
                    save_run_state(state_file, state)
                    _promote_crashing_unit(
                        policy_file,
                        pytest_args,
                        env,
                        unit,
                        unit_granularity,
                        "timeout",
                        console,
                    )
                    if (
                        granularity == "mixed"
                        and unit_granularity == "file"
                        and not stop_on_failure
                    ):
                        escalated_units = _escalate_current_file(
                            unit=unit,
                            units=units,
                            index=index,
                            state=state,
                            pytest_args=pytest_args,
                            env=env,
                            console=console,
                            baseline_fingerprint=baseline_fingerprint,
                        )
                        if escalated_units:
                            _record_result(
                                state,
                                FileRunResult(
                                    target=unit,
                                    status="escalated",
                                    returncode=124,
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
                    unit_records = _load_report_log_records(unit_jsonl_path)
                    report_records_by_unit[unit] = unit_records
                    state.report_records_by_unit[unit] = unit_records
                    if report_config is not None and report_config.jsonl_path is not None:
                        _write_unit_report_record_cache(state_file, unit, unit_records)
                    detail = _read_jsonl_results(unit_jsonl_path)
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
                        deselect_set: set[str] = set()
                        crash_count = 0
                        accumulated_detail: dict[str, Any] | None = None
                        total_retry_dur = 0.0
                        iter_jsonl_path: Path | None = crash_jsonl_path
                        retry_temp_files: list[Path] = []
                        escalate = False

                        try:
                            while True:
                                # - read JSONL for completed + culprit --
                                if iter_jsonl_path is not None:
                                    culprit, completed = _identify_crash_culprit(iter_jsonl_path)
                                    iter_detail = _read_jsonl_results(iter_jsonl_path)
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
                                    # Record culprit as a standalone result
                                    culprit_outcome = (
                                        "crashed"
                                        if confirm_status == "crashed"
                                        else "passed-in-isolation"
                                    )
                                    culprit_entry: dict[str, Any] = {
                                        "nodeid": culprit,
                                        "outcome": culprit_outcome,
                                    }
                                    if confirm_status == "crashed":
                                        culprit_entry["longrepr"] = (
                                            confirm_err.strip() or confirm_out.strip()
                                        )
                                    if confirm_out.strip():
                                        culprit_entry["stdout"] = confirm_out
                                    if confirm_err.strip():
                                        culprit_entry["stderr"] = confirm_err
                                    if accumulated_detail is None:
                                        accumulated_detail = {
                                            "counts": {
                                                "passed": 0,
                                                "failed": 0,
                                                "skipped": 0,
                                                "xfailed": 0,
                                                "xpassed": 0,
                                                "error": 0,
                                            },
                                            "tests": [],
                                        }
                                    accumulated_detail["tests"].append(culprit_entry)
                                    if confirm_status == "crashed":
                                        accumulated_detail["counts"]["error"] = (
                                            accumulated_detail["counts"].get("error", 0) + 1
                                        )
                                    deselect_set.add(culprit)
                                    crash_count += 1

                                # - check exit conditions --
                                # No max_crashes_per_file limit here --
                                # iterative deselect keeps going until
                                # the file passes or safety caps are hit.
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
                                deselect_fd, deselect_raw = tempfile.mkstemp(
                                    prefix="pkcs11-check-deselect-",
                                    suffix=".txt",
                                )
                                os.close(deselect_fd)
                                deselect_path = Path(deselect_raw)
                                deselect_path.write_text("\n".join(sorted(deselect_set)) + "\n")
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
                                    retry_rc = 124
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

                                    keep = retry_status != "passed" or (
                                        accumulated_detail is not None
                                        and any(
                                            accumulated_detail["counts"].get(k, 0) > 0
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
                                    if accumulated_detail is not None:
                                        per_unit_details[unit] = accumulated_detail
                                    console.print(
                                        f"[green]RETRY OK[/green] {unit} "
                                        f"({total_retry_dur:.1f}s, "
                                        f"{len(deselect_set)} deselected)"
                                    )
                                    if retry_status == "failed":
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
                                unit_records: list[dict[str, Any]] = []
                                for tmp in all_iter_jsonls:
                                    if not tmp.exists():
                                        continue
                                    unit_records.extend(_load_report_log_records(tmp))
                                report_records_by_unit[unit] = unit_records
                                state.report_records_by_unit[unit] = unit_records
                                _write_unit_report_record_cache(state_file, unit, unit_records)
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
                if unit_jsonl_path is not None:
                    unit_jsonl_path.unlink(missing_ok=True)
    finally:
        coverage_data: dict[str, Any] | None = None
        quality_records: list[dict[str, Any]] = []
        merged_details = dict(per_unit_details)
        if report_config is not None:
            if report_config.jsonl_path is not None:
                merged_report_records_by_unit = _load_cached_report_records_by_unit(
                    state_file, state.units
                )
                for unit, records in state.report_records_by_unit.items():
                    merged_report_records_by_unit.setdefault(unit, records)
                if resume and report_config.jsonl_path.exists():
                    candidate_targets = (
                        set(state.units) | {result.target for result in state.results}
                    )
                    parsed_report_records = _extract_unit_report_records_from_jsonl(
                        report_config.jsonl_path,
                        candidate_targets=candidate_targets,
                    )
                    for unit, records in parsed_report_records.items():
                        merged_report_records_by_unit.setdefault(unit, records)
                    for unit in executed_units:
                        merged_report_records_by_unit.pop(unit, None)
                    merged_report_records_by_unit.update(report_records_by_unit)
                if merged_report_records_by_unit:
                    _write_report_jsonl_from_record_map(
                        merged_report_records_by_unit,
                        units=state.units,
                        output_path=report_config.jsonl_path,
                    )
                if report_config.jsonl_path.exists():
                    merged_details = _build_per_unit_details_from_record_map(
                        merged_report_records_by_unit
                    )
                    coverage_data = extract_coverage_from_jsonl(report_config.jsonl_path)
                    quality_records = extract_quality_report_records_from_jsonl(
                        report_config.jsonl_path
                    )
                if coverage_data:
                    coverage_path = report_config.jsonl_path.parent / "coverage.json"
                    coverage_path.write_text(json.dumps(coverage_data, indent=2) + "\n")
            if report_config.output_format == "json":
                results_payload = write_isolated_json_report(
                    report_config.output_path,
                    state,
                    per_unit_details=merged_details,
                    coverage=coverage_data,
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
