"""Shared helpers for raw ctypes PKCS#11 subprocess tests.

Since the probe-script extraction (Phase 3) the inline ``python -c`` launcher
(``run_raw_script``) is gone: raw-path probe children are launched via
``python -m pkcs11_check.testcases._probes.<probe>`` by ``_probes/runner.py``'s
:func:`run_probe` (``coverage="raw"``).  This module now holds only the pieces
still shared with that launcher path:

- :func:`ingest_raw_subprocess_coverage` / :func:`get_raw_subprocess_coverage`
  -- the parent-side raw-path function/mechanism/RV coverage accumulators (Invariant I6).
- :func:`parse_output` -- parse ``KEY:value`` lines from child stdout, used by
  the migrated test_operation_state / test_dual_function / test_sign_recover
  parents.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

from pkcs11_check.core.call_counters import add_lost_probes, ingest_child_counts
from pkcs11_check.testcases._subprocess_coverage import (
    normalize_mechanism_counts,
    normalize_mechanism_rv_counts,
)

_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[int] = Counter()
_subprocess_call_ok_counts: Counter[str] = Counter()
_subprocess_mechanism_rv_counts: defaultdict[int, Counter[int]] = defaultdict(Counter)


def ingest_raw_subprocess_coverage(path: str) -> bool:
    """Read a child coverage JSON file into the raw-path accumulators (I6).

    No-op when ``path`` is empty or the file does not exist (e.g. the child
    crashed before writing it).  All I/O and parse errors are silently swallowed
    so a missing or corrupt coverage file never aborts the parent.

    Returns True when usable ``call_counters`` were folded into the process-global
    fw#73 counters (under the active bucket), False otherwise.  True means the
    channel worked (counters present and well-shaped), not that any particular
    call was recovered.  A present but empty list reports True: the child
    reported zero calls, so nothing was lost.
    """
    if not path or not os.path.exists(path):
        return False
    try:
        # UTF-8 to match the child's write side (_probes/_emit.write_coverage); an
        # unpinned read would decode as the platform codepage (cp1252 on Windows).
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    _subprocess_call_counts.update(data.get("call_log", {}))
    _subprocess_mechanism_counts.update(normalize_mechanism_counts(data.get("mechanism_counts")))
    _subprocess_call_ok_counts.update(data.get("call_log_ok", {}))
    for mechanism, counts in normalize_mechanism_rv_counts(data.get("mechanism_rv_counts")).items():
        _subprocess_mechanism_rv_counts[mechanism].update(counts)
    counters = data.get("call_counters")
    if not isinstance(counters, (list, tuple)):
        # Unusable channel: the launcher owns this child as one loss, so the
        # payload's inner loss claims (if any) are dropped, never accumulated.
        return False
    ingest_child_counts(list(counters))
    # .get default: payloads written before the wire extension carry no key.
    add_lost_probes(data.get("probes_lost", 0))
    return True


def get_raw_subprocess_coverage() -> tuple[
    Counter[str], Counter[int], Counter[str], dict[int, Counter[int]]
]:
    """Return accumulated subprocess coverage (func, mech, func_ok, mech_rv) and clear it."""
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    func_ok = Counter(_subprocess_call_ok_counts)
    mech_rv = {
        mechanism: Counter(counts) for mechanism, counts in _subprocess_mechanism_rv_counts.items()
    }
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    _subprocess_call_ok_counts.clear()
    _subprocess_mechanism_rv_counts.clear()
    return func, mech, func_ok, mech_rv


def parse_output(stdout: str) -> dict[str, str]:
    """Parse ``KEY:value`` lines from subprocess stdout into a dict.

    Lines without a colon or starting with FATAL/DEBUG are ignored.
    Multiple values for the same key: last wins.
    """
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key and not key.startswith(("FATAL", "DEBUG", "#")):
            result[key] = value.strip()
    return result
