"""Shared run-quality constants and derived-metric helpers.

Single source of truth for the result outcome keys (so the three summary-building
paths agree) and for the child-subprocess crash/timeout markers (so the framework
and the docker pool count them identically).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pkcs11_check.core.crash_codes import ctypes_access_violation_from_stderr

# The full set of test-outcome counters carried in a results.json ``summary`` and
# summed into ``summary["total"]``. ``crash_limited`` (a skipped-class outcome for
# tests abandoned after the per-file crash budget is exhausted) is last so the
# legacy eight keep their order for any positional reader.
RESULT_OUTCOME_KEYS: tuple[str, ...] = (
    "passed",
    "failed",
    "skipped",
    "xfailed",
    "xpassed",
    "error",
    "crashed",
    "timeout",
    "crash_limited",
)

# Markers that identify a crash-safe child subprocess finding living *inside* a
# test that pytest still recorded as outcome=="failed" (the security suite runs an
# untrusted child; its crash/timeout is the finding). Matched case-insensitively.
_CHILD_CRASH_MARKERS = (
    # All child-crash emitters phrase it as "<what> crashed with signal <n>" (module /
    # subprocess / reload cycle), so match the common substring rather than each prefix.
    "crashed with signal",
)
_CHILD_TIMEOUT_MARKERS = (
    "subprocess.timeoutexpired",
    "subprocess timeout",
    "timed out after",
)


def compute_child_subprocess_counts(units: Iterable[Mapping[str, Any]]) -> tuple[int, int]:
    """Count child-subprocess crash/timeout findings across ``units``.

    Associates nested structured executions with failed ``tests[]`` by parent nodeid, using
    the latest execution per failed test. Unmatched failed tests fall back to legacy ``longrepr``
    markers. Returns ``(child_crash, child_timeout)``; these are a SUBSET of ``failed`` and must
    never be added to ``summary["total"]``.
    """
    child_crash = 0
    child_timeout = 0
    for unit in units:
        tests = unit.get("tests")
        test_records = (
            [record for record in tests if isinstance(record, Mapping)]
            if isinstance(tests, list)
            else []
        )
        failed_records = {
            str(record.get("nodeid")): record
            for record in test_records
            if record.get("outcome") == "failed" and record.get("nodeid")
        }
        failed_nodeids = set(failed_records)
        structured = unit.get("executions")
        structured_nested = (
            [
                record
                for record in structured
                if isinstance(record, Mapping) and record.get("parent_nodeid")
            ]
            if isinstance(structured, list)
            else []
        )
        structured_by_parent: dict[str, Mapping[str, Any]] = {}
        if structured_nested:
            for record in structured_nested:
                parent_nodeid = str(record.get("parent_nodeid") or "")
                if parent_nodeid not in failed_nodeids:
                    continue
                structured_by_parent[parent_nodeid] = record
            for record in structured_by_parent.values():
                termination = record.get("termination")
                kind = termination.get("kind") if isinstance(termination, Mapping) else None
                if kind in {"signal", "exception", "external-kill"}:
                    child_crash += 1
                elif (
                    isinstance(termination, Mapping)
                    and kind == "exit"
                    and termination.get("raw_code") == 1
                    and (
                        parent_record := failed_records.get(str(record.get("parent_nodeid") or ""))
                    )
                    is not None
                    and ctypes_access_violation_from_stderr(str(parent_record.get("longrepr", "")))
                    is not None
                ):
                    child_crash += 1
                elif kind == "timeout":
                    child_timeout += 1
        for record in test_records:
            if record.get("outcome") != "failed":
                continue
            nodeid = str(record.get("nodeid") or "")
            # Old unified artifacts may omit the failed test's nodeid. With structured
            # executions present there is no safe ownership match, so keep their precedence.
            if nodeid in structured_by_parent or (not nodeid and structured_nested):
                continue
            longrepr = str(record.get("longrepr", "")).lower()
            if any(marker in longrepr for marker in _CHILD_CRASH_MARKERS):
                child_crash += 1
            elif any(marker in longrepr for marker in _CHILD_TIMEOUT_MARKERS):
                child_timeout += 1
    return child_crash, child_timeout


def run_is_incomplete(summary: Mapping[str, Any], units: Iterable[Mapping[str, Any]]) -> bool:
    """Return whether a run abandoned test coverage.

    A watchdog may time out after pytest has already reported partial test counts. In that
    case the unit status carries the timeout while the test-level timeout counter correctly
    remains zero.
    """
    return (
        bool(summary.get("incomplete", False))
        or int(summary.get("crash_limited", 0) or 0) > 0
        or int(summary.get("timeout", 0) or 0) > 0
        or any(
            unit.get("status") == "timeout"
            or unit.get("incomplete") is True
            or unit.get("completion_verified") is False
            for unit in units
        )
    )
