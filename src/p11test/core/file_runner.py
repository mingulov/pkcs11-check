"""Per-file pytest runner with subprocess isolation and resume support."""

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

from rich.console import Console

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


def discover_pytest_units(targets: list[str], default_root: Path) -> list[str]:
    """Expand pytest targets into an ordered list of file-or-node units."""
    requested = targets or [str(default_root)]
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

        msg = f"pytest target not found: {target}"
        raise FileNotFoundError(msg)

    return units


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


def _fingerprint_env(env: Mapping[str, str]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for key in sorted(env):
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
        return units

    completed_ok = {
        result.target
        for result in state.results
        if result.status in {"passed", "empty"}
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


def _file_timeout_seconds(test_timeout: int) -> int:
    return max(test_timeout * 10, 300)


def _record_result(state: FileRunState, result: FileRunResult) -> None:
    for index, existing in enumerate(state.results):
        if existing.target == result.target:
            state.results[index] = result
            return
    state.results.append(result)


def run_isolated_pytest_units(
    units: list[str],
    pytest_args: list[str],
    *,
    timeout: int,
    state_file: Path,
    resume: bool,
    stop_on_failure: bool,
    console: Console,
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
        console.print(
            f"[cyan]Running[/cyan] {len(units)} pytest units with per-file isolation "
            f"(state: [bold]{state_file}[/bold])"
        )

    if not pending_units:
        console.print("[green]Nothing to do[/green] — all isolated units already completed.")
        return 0

    exit_code = 0
    total = len(units)

    for index, unit in enumerate(units, start=1):
        if unit not in pending_units:
            continue

        console.print(f"[cyan][{index}/{total}][/cyan] {unit}")
        start = time.monotonic()
        cmd = [sys.executable, "-m", "pytest", unit, *pytest_args]

        try:
            completed = subprocess.run(
                cmd,
                check=False,
                env=env,
                timeout=_file_timeout_seconds(timeout),
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
            console.print(f"[red]TIMEOUT[/red] {unit} ({duration_s:.1f}s)")
            exit_code = 1
            if stop_on_failure:
                console.print(
                    f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                    f"[bold]--resume --state-file {state_file}[/bold]."
                )
                return exit_code
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
            continue

        exit_code = 1
        console.print(f"[red]{status.upper()}[/red] {unit} ({duration_s:.1f}s)")
        if stop_on_failure:
            console.print(
                f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                f"[bold]--resume --state-file {state_file}[/bold]."
            )
            return exit_code

    return exit_code


def state_results_by_status(path: Path) -> dict[str, int]:
    """Return a small status histogram for a saved state file."""
    state = load_run_state(path)
    counts: dict[str, int] = {}
    if state is None:
        return counts

    for result in state.results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts
