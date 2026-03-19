"""Per-unit pytest runner with subprocess isolation and resume support."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal
from xml.etree import ElementTree as ET

from rich.console import Console

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

        if arg in {"-q", "-v", "--no-header", "--json-report"}:
            continue
        if arg.startswith("--tb="):
            continue
        if arg.startswith("--json-report-file=") or arg.startswith("--json-report-omit="):
            continue
        if arg.startswith("--junit-xml="):
            continue
        if arg in {"--tb", "--json-report-file", "--json-report-omit", "--junit-xml"}:
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


def file_isolation_mode(path: Path) -> IsolationGranularity:
    """Return the preferred isolated granularity for a collected test file."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return "file"

    if "pytest.mark.subprocess_per_test" in text:
        return "test"
    return "file"


def file_forces_file_isolation(path: Path) -> bool:
    """Return True if the file should stay at file granularity in auto mode."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    if "pytest.mark.subprocess_per_test" in text:
        return False
    return "pytest.mark.subprocess" in text


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

    for file_unit in file_units:
        file_path = Path(file_unit.split("::", 1)[0])
        mode = file_isolation_mode(file_path)
        if normalize_policy_file_key(str(file_path)) in promoted_files:
            mode = "test"
        if mode == "test":
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
            if file_forces_file_isolation(file_path):
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


def write_isolated_json_report(
    path: Path,
    state: FileRunState,
    *,
    state_file: Path,
) -> None:
    """Write an aggregated JSON report for an isolated run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "pkcs11-check",
        "kind": "isolated-run",
        "state_file": str(state_file),
        "summary": _state_summary(state),
        "units": state.units,
        "results": [asdict(result) for result in state.results],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


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
    state_file: Path,
) -> None:
    """Write the requested aggregated report format for an isolated run."""
    if config.output_format == "json":
        write_isolated_json_report(config.output_path, state, state_file=state_file)
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


def _unit_timeout_seconds(test_timeout: int, granularity: IsolationGranularity) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    return max(test_timeout * 10, 300)


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
            write_isolated_report(report_config, state, state_file=state_file)
        return 0

    exit_code = 0
    index = 0
    try:
        while index < len(units):
            unit = units[index]
            if unit not in pending_units:
                index += 1
                continue

            console.print(f"[cyan][{index + 1}/{len(units)}][/cyan] {unit}")
            start = time.monotonic()
            cmd = [sys.executable, "-m", "pytest", unit, *pytest_args]
            unit_granularity = _effective_granularity(unit, granularity)

            try:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    env=env,
                    timeout=_unit_timeout_seconds(timeout, unit_granularity),
                )
                returncode = completed.returncode
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
                if granularity == "mixed" and unit_granularity == "file" and not stop_on_failure:
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
            result = FileRunResult(
                target=unit,
                status=status,
                returncode=returncode,
                duration_s=duration_s,
            )
            _record_result(state, result)
            save_run_state(state_file, state)

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
                if granularity == "mixed" and unit_granularity == "file" and not stop_on_failure:
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
        if report_config is not None:
            write_isolated_report(report_config, state, state_file=state_file)

    return exit_code


def state_results_by_status(path: Path) -> dict[str, int]:
    """Return a small status histogram for a saved state file."""
    state = load_run_state(path)
    if state is None:
        return {}

    summary = _state_summary(state)
    summary.pop("total", None)
    return summary
