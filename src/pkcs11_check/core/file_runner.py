"""Per-unit pytest runner with subprocess isolation and resume support."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from xml.etree import ElementTree as ET

from rich.console import Console

from pkcs11_check.core.collection import CollectedPytestItem, collect_pytest_item_metadata

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

        if arg in {"-q", "-v", "--no-header", "--json-report", "--report-log"}:
            continue
        if arg.startswith("--tb="):
            continue
        if arg.startswith("--json-report-file=") or arg.startswith("--json-report-omit=") or arg.startswith("--report-log="):
            continue
        if arg.startswith("--junit-xml="):
            continue
        if arg in {"--tb", "--json-report-file", "--json-report-omit", "--junit-xml", "--report-log"}:
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
    return [
        item.nodeid
        for item in items
        if normalize_policy_file_key(item.file_path) == file_key
    ]


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
        return [
            (r.target, [r], details.get(r.target, {}))
            for r in results
        ]

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
            "passed": 0, "failed": 0, "skipped": 0,
            "xfailed": 0, "xpassed": 0, "error": 0,
        }
        merged_tests: list[dict[str, Any]] = []
        for r in file_results:
            detail = details.get(r.target, {})
            for key in merged_counts:
                merged_counts[key] += detail.get("counts", {}).get(key, 0)
            merged_tests.extend(detail.get("tests", []))
        out.append(
            (file_target, file_results, {"counts": merged_counts, "tests": merged_tests})
        )
    return out


def write_isolated_json_report(
    path: Path,
    state: FileRunState,
    *,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Write an aggregated JSON report for an isolated run in unified format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    details = per_unit_details or {}

    summary: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }

    grouped = _group_results_by_file(state.results, details)
    units_out: list[dict[str, Any]] = []

    for file_target, file_results, merged_detail in grouped:
        has_failure = any(
            r.status in {"failed", "crashed", "timeout"} for r in file_results
        )
        duration = sum(r.duration_s for r in file_results)
        stdout_parts = [r.stdout for r in file_results if r.stdout]
        stderr_parts = [r.stderr for r in file_results if r.stderr]

        unit: dict[str, Any] = {
            "target": file_target,
            "status": "failed" if has_failure else file_results[0].status,
            "returncode": max(abs(r.returncode) for r in file_results)
            if has_failure
            else 0,
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

        units_out.append(unit)

    summary["total"] = sum(summary.values())

    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units_out,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def postprocess_json_report_to_unified(json_path: Path) -> None:
    """Convert a pytest-json-report file to pkcs11-check unified format.

    Reads the native pytest-json-report JSON, groups tests by file,
    and overwrites the file with the unified format.  Used for
    ``--isolation none`` to produce consistent output.
    """
    try:
        data = json.loads(json_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return

    tests_raw = data.get("tests", [])
    if not tests_raw:
        return

    by_file: dict[str, list[dict[str, Any]]] = {}
    for test in tests_raw:
        file_part = test.get("nodeid", "").split("::")[0]
        by_file.setdefault(file_part, []).append(test)

    summary: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }
    units: list[dict[str, Any]] = []

    for target in sorted(by_file):
        file_tests = by_file[target]
        counts: dict[str, int] = {
            "passed": 0, "failed": 0, "skipped": 0,
            "xfailed": 0, "xpassed": 0, "error": 0,
        }
        non_passing: list[dict[str, Any]] = []
        duration = 0.0

        for test in file_tests:
            outcome = test.get("outcome", "passed")
            counts[outcome] = counts.get(outcome, 0) + 1
            summary[outcome] = summary.get(outcome, 0) + 1
            call_stage = test.get("call", {})
            duration += call_stage.get("duration", 0.0)
            if outcome not in {"failed", "xfailed", "xpassed", "error"}:
                continue
            entry: dict[str, Any] = {
                "nodeid": test["nodeid"],
                "outcome": outcome,
                "duration": call_stage.get("duration", 0.0),
            }
            longrepr = call_stage.get("longrepr", "")
            if longrepr:
                entry["longrepr"] = longrepr
            if outcome == "xfailed" and longrepr:
                entry["wasxfail"] = _extract_xfail_reason(longrepr)
            if call_stage.get("stdout"):
                entry["stdout"] = call_stage["stdout"]
            if call_stage.get("stderr"):
                entry["stderr"] = call_stage["stderr"]
            non_passing.append(entry)

        has_failure = counts["failed"] > 0 or counts["error"] > 0
        unit: dict[str, Any] = {
            "target": target,
            "status": "failed" if has_failure else "passed",
            "returncode": 1 if has_failure else 0,
            "duration_s": round(duration, 3),
            "counts": counts,
        }
        if non_passing:
            unit["tests"] = non_passing
        units.append(unit)

    summary["total"] = sum(summary.values())

    payload = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n")


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
            config.output_path, state,
            per_unit_details=per_unit_details,
        )
        return
    write_isolated_junit_report(config.output_path, state)


def load_run_state(path: Path) -> FileRunState | None:
    """Load a resumable runner state from disk."""
    if not path.exists():
        return None

    raw = json.loads(path.read_text())
    results = [FileRunResult(**item) for item in raw.get("results", [])]
    return FileRunState(
        units=list(raw.get("units", [])),
        fingerprint=str(raw.get("fingerprint", "")),
        results=results,
    )


def save_run_state(path: Path, state: FileRunState) -> None:
    """Persist the current runner state to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fingerprint": state.fingerprint,
        "units": state.units,
        "results": [asdict(result) for result in state.results],
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
    units: list[str], pytest_args: list[str], env: Mapping[str, str] | None = None
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


def _extract_xfail_reason(longrepr: str) -> str:
    """Extract a concise xfail reason from pytest longrepr text.

    For imperative ``pytest.xfail("reason")``, the longrepr contains
    ``XFailed: reason``.  For marker-based ``@pytest.mark.xfail(reason=...)``,
    the reason appears on the decorator line.  Falls back to the last
    assertion/error line.
    """
    # Imperative xfail: "XFailed: some reason"
    m = re.search(r"XFailed:\s*(.+)", longrepr)
    if m:
        return m.group(1).strip()

    # Marker-based: @pytest.mark.xfail(reason="...")
    m = re.search(r'reason=["\']([^"\']+)["\']', longrepr)
    if m:
        return m.group(1).strip()

    # Fallback: last E line (assertion message)
    for line in reversed(longrepr.splitlines()):
        stripped = line.strip()
        if stripped.startswith("E "):
            return stripped[2:].strip()

    return ""


def _flatten_longrepr(longrepr: Any) -> str:
    """Flatten a JSONL longrepr value to a plain string.

    longrepr can be a dict (with reprcrash/reprtraceback), a string, or None.
    """
    if longrepr is None:
        return ""
    if isinstance(longrepr, str):
        return longrepr
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


def _read_jsonl_results(jsonl_path: Path) -> dict[str, Any] | None:
    """Read a pytest-reportlog JSONL file and return per-test outcomes.

    Returns ``{"counts": {...}, "tests": [...]}`` where ``tests`` contains
    only non-passing entries (failed, xfailed, xpassed, error).
    Returns ``None`` if the file is missing or empty.
    """
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return None
    if not text.strip():
        return None

    counts: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }
    non_passing: list[dict[str, Any]] = []
    # Track nodeids that had a when=call record, so we know if a setup
    # skip/error is standalone.
    seen_call: set[str] = set()
    # First pass: collect when=call records; second pass not needed if we
    # process in order and handle setup records that lack a following call.
    # Instead, buffer setup skip/error and resolve after full scan.
    setup_events: list[dict[str, Any]] = []
    call_events: list[dict[str, Any]] = []
    collect_errors: list[dict[str, Any]] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip truncated lines

        report_type = rec.get("$report_type", "TestReport")
        when = rec.get("when", "")
        outcome = rec.get("outcome", "")
        nodeid = rec.get("nodeid", "")

        # CollectReport handling
        if report_type == "CollectReport":
            if outcome == "passed":
                continue  # skip successful collection
            # Collection error (import/syntax error)
            collect_errors.append(rec)
            continue

        # TestReport handling
        if when == "call":
            seen_call.add(nodeid)
            call_events.append(rec)
        elif when == "setup" and outcome in ("skipped", "failed", "error"):
            setup_events.append(rec)
        # when=teardown is ignored

    # Process call events (primary source of truth)
    for rec in call_events:
        nodeid = rec.get("nodeid", "")
        raw_outcome = rec.get("outcome", "passed")
        wasxfail = rec.get("wasxfail")
        mapped = _map_outcome(raw_outcome, wasxfail)
        counts[mapped] = counts.get(mapped, 0) + 1

        if mapped in ("passed", "skipped"):
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
        longrepr = rec.get("longrepr")
        flat = _flatten_longrepr(longrepr)
        if flat:
            entry["longrepr"] = flat
        if rec.get("location"):
            entry["location"] = rec["location"]
        # Extract stdout/stderr from sections
        for section in rec.get("sections", []):
            if isinstance(section, list) and len(section) >= 2:
                name, content = section[0], section[1]
                if "stdout" in name.lower():
                    entry["stdout"] = content
                elif "stderr" in name.lower():
                    entry["stderr"] = content
        non_passing.append(entry)

    # Process setup events for tests that never got a call record
    for rec in setup_events:
        nodeid = rec.get("nodeid", "")
        if nodeid in seen_call:
            continue  # call record already handled this test
        raw_outcome = rec.get("outcome", "")
        if raw_outcome == "skipped":
            mapped = "skipped"
        else:
            mapped = "error"
        counts[mapped] = counts.get(mapped, 0) + 1

        if mapped == "skipped":
            continue  # skipped tests excluded from non-passing list per spec

        entry = {
            "nodeid": nodeid,
            "outcome": mapped,
            "duration": rec.get("duration", 0.0),
        }
        flat = _flatten_longrepr(rec.get("longrepr"))
        if flat:
            entry["longrepr"] = flat
        non_passing.append(entry)

    # Process collect errors
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

    return {"counts": counts, "tests": non_passing}


def _extract_per_unit_test_detail(json_path: Path) -> dict[str, Any] | None:
    """Read a pytest-json-report file and return per-test outcomes.

    Returns ``{"counts": {...}, "tests": [...]}`` where ``tests`` contains
    only non-passing entries (failed, xfailed, xpassed, error).
    Returns ``None`` if the file is missing or corrupt.
    """
    try:
        data = json.loads(json_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    tests_raw = data.get("tests", [])
    if not tests_raw:
        return None

    counts: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }
    non_passing: list[dict[str, Any]] = []

    for test in tests_raw:
        outcome = test.get("outcome", "passed")
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome not in {"failed", "xfailed", "xpassed", "error"}:
            continue
        call_stage = test.get("call", {})
        entry: dict[str, Any] = {
            "nodeid": test["nodeid"],
            "outcome": outcome,
            "duration": call_stage.get("duration", 0.0),
        }
        longrepr = call_stage.get("longrepr", "")
        if longrepr:
            entry["longrepr"] = longrepr
        if outcome == "xfailed" and longrepr:
            entry["wasxfail"] = _extract_xfail_reason(longrepr)
        if call_stage.get("stdout"):
            entry["stdout"] = call_stage["stdout"]
        if call_stage.get("stderr"):
            entry["stderr"] = call_stage["stderr"]
        non_passing.append(entry)

    return {"counts": counts, "tests": non_passing}


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
) -> None:
    state.units = list(units)
    state.fingerprint = build_state_fingerprint(units, pytest_args, env)


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
    _refresh_state_plan(state, units, pytest_args, env)
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
) -> list[str]:
    existing = set(units)
    additions = [unit for unit in new_units if unit not in existing]
    if not additions:
        return []

    insert_at = index + 1
    units[insert_at:insert_at] = additions
    _refresh_state_plan(state, units, pytest_args, env)
    return additions


def _deselect_args_for_crash(
    unit: str,
    captured_stdout: str,
    pytest_args: list[str],
    env: Mapping[str, str],
) -> list[str] | None:
    """Build --deselect args to skip passed/crashed tests on retry.

    Parses captured pytest output for PASSED/SKIPPED/XFAILED nodeids,
    identifies the likely crash culprit (next test after last completed),
    and returns --deselect arguments for all of them.  Returns ``None``
    if we cannot determine what to deselect (e.g. crash during setup).
    """
    completed: list[str] = []
    for line in captured_stdout.splitlines():
        stripped = line.strip()
        for marker in (" PASSED", " SKIPPED", " XFAIL", " xfail"):
            if marker in stripped:
                # Extract nodeid: "test_foo.py::TestBar::test_baz PASSED"
                nodeid_part = stripped.split(marker)[0].strip()
                if "::" in nodeid_part:
                    completed.append(nodeid_part)
                break

    if not completed:
        return None

    # Collect all nodeids in this file to find the crash culprit
    try:
        all_nodeids = collect_pytest_nodeids([unit], pytest_args, env=env)
    except ValueError:
        return None

    completed_set = set(completed)
    crash_candidate: str | None = None
    for nid in all_nodeids:
        if nid not in completed_set:
            crash_candidate = nid
            break

    deselect = [f"--deselect={nid}" for nid in completed]
    if crash_candidate:
        deselect.append(f"--deselect={crash_candidate}")

    remaining = len(all_nodeids) - len(completed) - (1 if crash_candidate else 0)
    if remaining <= 0:
        return None

    return deselect


def _escalate_current_file(
    *,
    unit: str,
    units: list[str],
    index: int,
    state: FileRunState,
    pytest_args: list[str],
    env: Mapping[str, str],
    console: Console,
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

    additions = _insert_escalated_units(state, units, index, nodeids, pytest_args, env)
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
    fingerprint = build_state_fingerprint(units, pytest_args, env)
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

    if not pending_units:
        console.print("[green]Nothing to do[/green] — all isolated units already completed.")
        if report_config is not None:
            write_isolated_report(
                report_config, state,
                per_unit_details={},
            )
        return 0

    exit_code = 0
    per_unit_details: dict[str, dict[str, Any]] = {}
    index = 0
    try:
        while index < len(units):
            unit = units[index]
            if unit not in pending_units:
                index += 1
                continue

            console.print(f"[cyan][{index + 1}/{len(units)}][/cyan] {unit}")
            start = time.monotonic()
            unit_granularity = _effective_granularity(unit, granularity)

            # Inject --json-report and --report-log for file-level units only
            # (spec guard: 75K temp files for test-level units is unacceptable).
            unit_json_path: Path | None = None
            unit_jsonl_path: Path | None = None
            if unit_granularity == "file":
                unit_json_fd, unit_json_raw = tempfile.mkstemp(
                    prefix="pkcs11-check-unit-", suffix=".json"
                )
                os.close(unit_json_fd)
                unit_json_path = Path(unit_json_raw)
                unit_jsonl_fd, unit_jsonl_raw = tempfile.mkstemp(
                    prefix="pkcs11-check-jsonl-", suffix=".jsonl"
                )
                os.close(unit_jsonl_fd)
                unit_jsonl_path = Path(unit_jsonl_raw)
                cmd = [
                    sys.executable, "-m", "pytest", unit, *pytest_args,
                    "--json-report",
                    f"--json-report-file={unit_json_path}",
                    "--json-report-omit=collectors",
                    "--report-log", str(unit_jsonl_path),
                ]
            else:
                cmd = [sys.executable, "-m", "pytest", unit, *pytest_args]

            try:
                try:
                    returncode, captured_stdout, captured_stderr = (
                        _run_subprocess_tee(
                            cmd,
                            env=env,
                            timeout=_unit_timeout_seconds(timeout, unit_granularity),
                        )
                    )
                    status = _status_from_returncode(returncode)
                except subprocess.TimeoutExpired:
                    duration_s = time.monotonic() - start
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
                            console.print(
                                f"[red]TIMEOUT[/red] {unit} ({duration_s:.1f}s)"
                            )
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
                # Prefer JSONL (report-log) over json-report when available.
                detail: dict[str, Any] | None = None
                if unit_jsonl_path is not None:
                    detail = _read_jsonl_results(unit_jsonl_path)
                    unit_jsonl_path.unlink(missing_ok=True)
                    unit_jsonl_path = None
                if detail is None and unit_json_path is not None:
                    detail = _extract_per_unit_test_detail(unit_json_path)

                # Keep output for non-passing units AND for units that
                # contain xfailed/xpassed/error tests (useful for debugging
                # even when the overall unit status is "passed").
                has_notable_tests = (
                    detail is not None
                    and any(
                        detail["counts"].get(k, 0) > 0
                        for k in ("failed", "xfailed", "xpassed", "error")
                    )
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
                    console.print(
                        f"[green]{status.upper()}[/green] {unit} ({duration_s:.1f}s)"
                    )
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
                        # Try retry-with-deselect first: re-run the file
                        # skipping passed tests + the crash culprit.
                        # Only fall through to per-test if retry also crashes.
                        deselect = _deselect_args_for_crash(
                            unit, captured_stdout, pytest_args, env,
                        )
                        if deselect:
                            console.print(
                                f"[yellow]Adaptive isolation:[/yellow] retrying "
                                f"{unit} with {len(deselect)} tests deselected"
                            )
                            retry_json_fd, retry_json_raw = tempfile.mkstemp(
                                prefix="pkcs11-check-retry-", suffix=".json"
                            )
                            os.close(retry_json_fd)
                            retry_json_path = Path(retry_json_raw)
                            retry_cmd = [
                                sys.executable, "-m", "pytest",
                                unit, *pytest_args, *deselect,
                                "--json-report",
                                f"--json-report-file={retry_json_path}",
                                "--json-report-omit=collectors",
                            ]
                            retry_start = time.monotonic()
                            try:
                                retry_rc, retry_out, retry_err = (
                                    _run_subprocess_tee(
                                        retry_cmd,
                                        env=env,
                                        timeout=_unit_timeout_seconds(
                                            timeout, unit_granularity
                                        ),
                                    )
                                )
                                retry_status = _status_from_returncode(retry_rc)
                            except subprocess.TimeoutExpired:
                                retry_status = "timeout"
                                retry_rc = 124
                                retry_out = retry_err = ""
                            retry_dur = time.monotonic() - retry_start

                            if retry_status not in ("crashed", "timeout"):
                                # Retry succeeded — record the retry result
                                retry_detail = _extract_per_unit_test_detail(
                                    retry_json_path
                                )
                                retry_json_path.unlink(missing_ok=True)
                                keep = retry_status != "passed" or (
                                    retry_detail is not None
                                    and any(
                                        retry_detail["counts"].get(k, 0) > 0
                                        for k in (
                                            "failed", "xfailed", "xpassed", "error",
                                        )
                                    )
                                )
                                result = FileRunResult(
                                    target=unit,
                                    status=retry_status,
                                    returncode=retry_rc,
                                    duration_s=duration_s + retry_dur,
                                    stdout=retry_out if keep else "",
                                    stderr=retry_err if keep else "",
                                )
                                _record_result(state, result)
                                save_run_state(state_file, state)
                                if retry_detail is not None:
                                    per_unit_details[unit] = retry_detail
                                console.print(
                                    f"[green]RETRY OK[/green] {unit} "
                                    f"({retry_dur:.1f}s, {len(deselect)} deselected)"
                                )
                                if retry_status == "failed":
                                    exit_code = 1
                                index += 1
                                continue
                            retry_json_path.unlink(missing_ok=True)
                            console.print(
                                f"[red]RETRY CRASHED[/red] {unit} — "
                                f"falling back to per-test isolation"
                            )

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
                            console.print(
                                f"[red]CRASHED[/red] {unit} ({duration_s:.1f}s)"
                            )
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
                console.print(
                    f"[red]{status.upper()}[/red] {unit} ({duration_s:.1f}s)"
                )
                if stop_on_failure:
                    console.print(
                        f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                        f"[bold]--resume --state-file {state_file}[/bold]."
                    )
                    return exit_code
                index += 1
            finally:
                if unit_json_path is not None:
                    unit_json_path.unlink(missing_ok=True)
                if unit_jsonl_path is not None:
                    unit_jsonl_path.unlink(missing_ok=True)
    finally:
        if report_config is not None:
            write_isolated_report(
                report_config, state,
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
