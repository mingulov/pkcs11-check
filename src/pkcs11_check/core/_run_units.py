"""Shared unit/run types, constants, and pure helpers for the isolated pytest runner.

Moved verbatim from file_runner.py (god-module split, 2026-07-17).  Base module of the
file_runner sibling extractions: siblings import from here (or from earlier siblings),
never from file_runner, so the re-export surface in file_runner stays cycle-free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS

IsolationGranularity = Literal["file", "test"]

RunnerGranularity = Literal["file", "test", "mixed"]

CrashStatus = Literal["crashed", "timeout"]

# Priority-ordered set of unit-level statuses _overall_unit_status can return.
# Single source of truth: the results-comparison tool binds its status classifier
# to this so the two cannot drift (see core/compare_results.py).
UNIT_STATUS_PRIORITY: tuple[str, ...] = (
    "timeout",
    "crashed",
    "failed",
    "crash_limited",
    "passed",
    "empty",
    "escalated",
)

_RESUME_COMPLETE_STATUSES = {"passed", "empty", "escalated", "crash_limited"}

_DETAIL_COUNT_KEYS = RESULT_OUTCOME_KEYS

_SPECIAL_DETAIL_OUTCOMES = {"crashed", "timeout", "passed-in-isolation"}


def _empty_counts() -> dict[str, int]:
    """A fresh per-unit outcome-counts dict, every canonical outcome key zeroed."""
    return dict.fromkeys(_DETAIL_COUNT_KEYS, 0)


# Match the conventional GNU timeout exit code; pytest itself uses only 0-5.
_TIMEOUT_RETURN_CODE = 124

_DISABLE_COLLECTION_PROBES_ENV = "PKCS11_CHECK_DISABLE_COLLECTION_PROBES"


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


def _absolute_nodeid(file_key: str, nodeid: str) -> str:
    """Rebuild a per-test nodeid with an absolute, resolved file path.

    pytest emits the path part of a nodeid relative to its ``rootdir``, and that
    base is not always the CWD: when a stray absolute path rides on the pytest
    command line (e.g. the ``--p11-manifest /tmp/...`` value), pytest's early
    rootdir scan can settle on ``/`` for an installed package with no config file
    above it, yielding slash-less paths like ``home/user/...``. Such a path does
    not round-trip through ``normalize_policy_file_key`` (which resolves against
    the CWD) and is not runnable from the CWD. Pinning the path part to the
    already-resolved ``file_key`` makes the unit both rootdir-independent and
    runnable. The test part (after ``::``) is rootdir-independent and preserved.
    """
    _, sep, test_part = nodeid.partition("::")
    return f"{file_key}::{test_part}" if sep else file_key


def _state_summary(state: FileRunState) -> dict[str, int]:
    summary: dict[str, int] = {}
    for result in state.results:
        summary[result.status] = summary.get(result.status, 0) + 1
    summary["total"] = len(state.results)
    return summary


def _extract_option_value(args: list[str], option: str) -> str | None:
    for index, arg in enumerate(args):
        if arg == option:
            if index + 1 < len(args):
                return args[index + 1]
            return None
        if arg.startswith(f"{option}="):
            return arg.split("=", 1)[1]
    return None


def normalize_policy_file_key(path_str: str) -> str:
    """Normalize a test file path for policy matching."""
    return str(Path(path_str).resolve())


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


def _unit_file_key(unit: str) -> str:
    return normalize_policy_file_key(unit.split("::", 1)[0])
