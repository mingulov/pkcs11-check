"""Shared run-quality constants and derived-metric helpers.

Single source of truth for the result outcome keys (so the three summary-building
paths agree) and for the child-subprocess crash/timeout markers (so the framework
and the docker pool count them identically).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

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

    Scans ``units[].tests[]`` for ``outcome == "failed"`` entries whose ``longrepr``
    contains a crash or timeout marker. Returns ``(child_crash, child_timeout)``.
    These are a SUBSET of ``failed`` and must never be added to ``summary["total"]``.
    """
    child_crash = 0
    child_timeout = 0
    for unit in units:
        tests = unit.get("tests")
        if not isinstance(tests, list):
            continue
        for record in tests:
            if not isinstance(record, Mapping) or record.get("outcome") != "failed":
                continue
            longrepr = str(record.get("longrepr", "")).lower()
            if any(marker in longrepr for marker in _CHILD_CRASH_MARKERS):
                child_crash += 1
            elif any(marker in longrepr for marker in _CHILD_TIMEOUT_MARKERS):
                child_timeout += 1
    return child_crash, child_timeout
