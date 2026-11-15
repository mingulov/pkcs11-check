"""Shared subprocess helpers for PKCS#11 test scripts.

Since the probe-script extraction (Phase 3) the inline ``python -c`` launchers
(``run_with_coverage`` / ``subprocess_session_preamble``) are gone: probe
children are launched via ``python -m pkcs11_check.testcases._probes.<probe>`` by
``_probes/runner.py``'s :func:`run_probe`.  This module now holds only the pieces
still shared with that launcher path:

- :func:`pin_from_config` -- unwrap the configured ``SecretStr`` PIN so callers
  can forward it to ``run_probe(pin=...)`` (which injects it into the child env
  under ``_P11CHECK_PIN``; it is never embedded in a script string or the argv).
- :func:`ingest_subprocess_coverage` / :func:`get_preamble_subprocess_coverage`
  -- the parent-side session-path function/mechanism/RV coverage accumulators (Invariant I6).
- ``SUBPROCESS_TIMEOUT_MARKER`` / ``SUBPROCESS_TIMEOUT_RC`` -- the timeout
  sentinel that ``run_probe`` emits so a hang classifies as a crash-class finding.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from typing import Any

from pkcs11_check.core.call_counters import add_lost_probes, ingest_child_counts
from pkcs11_check.testcases._subprocess_coverage import (
    normalize_mechanism_counts,
    normalize_mechanism_rv_counts,
)

# A probe subprocess that hangs (the module did not return on the probe input)
# is surfaced via this marker on stderr + a sentinel returncode, so the parent's
# assert_subprocess_completed classifies the hang as a crash-class finding rather
# than letting subprocess.TimeoutExpired escape as a record-less runtime-gate leak.
SUBPROCESS_TIMEOUT_MARKER = "_P11CHECK_SUBPROCESS_TIMEOUT"
SUBPROCESS_TIMEOUT_RC = 124  # conventional timeout exit code (GNU timeout)


_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[int] = Counter()
_subprocess_call_ok_counts: Counter[str] = Counter()
_subprocess_mechanism_rv_counts: defaultdict[int, Counter[int]] = defaultdict(Counter)


def pin_from_config(p11_config: Any) -> str | None:
    """Return the configured user PIN as a plain ``str`` (or None).

    Centralises the ``SecretStr`` unwrap so call sites can pass the PIN to
    ``run_probe`` without sprinkling ``get_secret_value()`` (and the accompanying
    leak surface) across every test. The returned value is only ever forwarded
    into the child env by the runner, never embedded in a script string.
    """
    pin = getattr(p11_config, "pin", None)
    if pin is None:
        return None
    value: str = pin.get_secret_value()
    return value


def ingest_subprocess_coverage(path: str) -> bool:
    """Read a child coverage JSON file into the preamble-path accumulators (I6).

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
            data: Any = json.load(fh)
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


def get_preamble_subprocess_coverage() -> tuple[
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
