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
  -- the parent-side session-path coverage accumulators (Invariant I6).
- ``SUBPROCESS_TIMEOUT_MARKER`` / ``SUBPROCESS_TIMEOUT_RC`` -- the timeout
  sentinel that ``run_probe`` emits so a hang classifies as a crash-class finding.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

# A probe subprocess that hangs (the module did not return on the probe input)
# is surfaced via this marker on stderr + a sentinel returncode, so the parent's
# assert_subprocess_completed classifies the hang as a crash-class finding rather
# than letting subprocess.TimeoutExpired escape as a record-less runtime-gate leak.
SUBPROCESS_TIMEOUT_MARKER = "_P11CHECK_SUBPROCESS_TIMEOUT"
SUBPROCESS_TIMEOUT_RC = 124  # conventional timeout exit code (GNU timeout)


_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[str] = Counter()


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


def ingest_subprocess_coverage(path: str) -> None:
    """Read a child coverage JSON file into the preamble-path accumulators (I6).

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
            data: Any = json.load(fh)
    except (OSError, ValueError):
        return
    _subprocess_call_counts.update(data.get("call_log", {}))
    _subprocess_mechanism_counts.update(data.get("mechanism_counts", {}))


def get_preamble_subprocess_coverage() -> tuple[Counter[str], Counter[str]]:
    """Return accumulated subprocess coverage and clear it."""
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    return func, mech
