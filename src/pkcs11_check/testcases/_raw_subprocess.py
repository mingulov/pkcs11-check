"""Shared helpers for raw ctypes PKCS#11 subprocess tests.

Since the probe-script extraction (Phase 3) the inline ``python -c`` launcher
(``run_raw_script``) is gone: raw-path probe children are launched via
``python -m pkcs11_check.testcases._probes.<probe>`` by ``_probes/runner.py``'s
:func:`run_probe` (``coverage="raw"``).  This module now holds only the pieces
still shared with that launcher path:

- :func:`ingest_raw_subprocess_coverage` / :func:`get_raw_subprocess_coverage`
  -- the parent-side raw-path coverage accumulators (Invariant I6).
- :func:`parse_output` -- parse ``KEY:value`` lines from child stdout, used by
  the migrated test_operation_state / test_dual_function / test_sign_recover
  parents.
"""

from __future__ import annotations

import json
import os
from collections import Counter

_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[str] = Counter()
_subprocess_call_ok_counts: Counter[str] = Counter()


def ingest_raw_subprocess_coverage(path: str) -> None:
    """Read a child coverage JSON file into the raw-path accumulators (I6).

    No-op when ``path`` is empty or the file does not exist (e.g. the child
    crashed before writing it).  All I/O and parse errors are silently swallowed
    so a missing or corrupt coverage file never aborts the parent.
    """
    if not path or not os.path.exists(path):
        return
    try:
        # UTF-8 to match the child's write side (_probes/_emit.write_coverage); an
        # unpinned read would decode as the platform codepage (cp1252 on Windows).
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    _subprocess_call_counts.update(data.get("call_log", {}))
    _subprocess_mechanism_counts.update(data.get("mechanism_counts", {}))
    _subprocess_call_ok_counts.update(data.get("call_log_ok", {}))


def get_raw_subprocess_coverage() -> tuple[Counter[str], Counter[str], Counter[str]]:
    """Return accumulated subprocess coverage (func, mech, func_ok) and clear it."""
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    func_ok = Counter(_subprocess_call_ok_counts)
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    _subprocess_call_ok_counts.clear()
    return func, mech, func_ok


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
