"""Portable subprocess termination facts and nested-observation recording."""

from __future__ import annotations

import signal
import sys
from contextvars import ContextVar

from pkcs11_check.core.crash_codes import (
    ctypes_access_violation_from_stderr,
    is_windows_crash_code,
)

_OBSERVATIONS: ContextVar[list[dict[str, object]] | None] = ContextVar(
    "pkcs11_process_observations", default=None
)


# Appended to a probe child's stderr by the launcher when the child exited non-zero
# WITHOUT running its own finalizer (observed via the coverage file the finalizer always
# writes). That distinguishes "the module called exit() from inside the PKCS#11 call and
# took the process down" from "Python raised and died normally" -- two situations that
# are otherwise byte-identical at the parent, and that must not share a verdict.
SUBPROCESS_ABRUPT_EXIT_MARKER = "_P11CHECK_SUBPROCESS_ABRUPT_EXIT"


def termination_from_returncode(
    returncode: int | None,
    *,
    platform: str | None = None,
    timed_out: bool = False,
    external_kill: bool = False,
    stderr: str | None = None,
) -> dict[str, object]:
    """Normalize a subprocess return code without discarding its raw value."""
    termination: dict[str, object] = {
        "kind": "unknown",
        "raw_code": returncode,
        "signal_name": None,
        "windows_status": None,
    }
    if timed_out:
        termination["kind"] = "timeout"
    elif external_kill:
        termination["kind"] = "external-kill"
    elif returncode is None:
        pass
    elif (platform or sys.platform) == "win32" and is_windows_crash_code(returncode):
        termination["kind"] = "exception"
        termination["windows_status"] = returncode & 0xFFFFFFFF
    elif (
        (platform or sys.platform) == "win32"
        and returncode == 1
        and (windows_status := ctypes_access_violation_from_stderr(stderr)) is not None
    ):
        termination["kind"] = "exception"
        termination["windows_status"] = windows_status
    elif returncode < 0:
        try:
            signal_name = signal.Signals(-returncode).name
        except ValueError:
            pass
        else:
            termination["kind"] = "signal"
            termination["signal_name"] = signal_name
    elif returncode > 0 and stderr is not None and SUBPROCESS_ABRUPT_EXIT_MARKER in stderr:
        # The child process ended without running its own exit path. Only the module can
        # do that on a positive exit code: a C ``exit()``/``_exit()`` from inside a
        # PKCS#11 call bypasses CPython finalization entirely. A positive exit is NOT by
        # itself evidence of this -- the marker is appended only when the launcher
        # observed that the child's own finalizer never ran.
        termination["kind"] = "abrupt_exit"
    else:
        termination["kind"] = "exit"
    return termination


def build_process_observation(
    target: str,
    role: str,
    attempt: int,
    returncode: int | None,
    *,
    platform: str | None = None,
    timed_out: bool = False,
    external_kill: bool = False,
    parent_nodeid: str | None = None,
    peak_rss_bytes: int | None = None,
    limit_bytes: int | None = None,
    stderr: str | None = None,
) -> dict[str, object]:
    """Build the additive process-execution evidence object."""
    return {
        "target": target,
        "parent_nodeid": parent_nodeid,
        "role": role,
        "attempt": attempt,
        "termination": termination_from_returncode(
            returncode,
            platform=platform,
            timed_out=timed_out,
            external_kill=external_kill,
            stderr=stderr,
        ),
        "memory": {
            "peak_rss_bytes": peak_rss_bytes,
            "limit_bytes": limit_bytes,
        },
        "oom": {"status": "unknown", "sources": []},
    }


def record_process_observation(observation: dict[str, object]) -> None:
    """Record an observation in the current execution context."""
    observations = _OBSERVATIONS.get()
    if observations is None:
        observations = []
    else:
        observations = list(observations)
    observations.append(dict(observation))
    _OBSERVATIONS.set(observations)


def drain_process_observations() -> list[dict[str, object]]:
    """Return and clear observations recorded in the current context."""
    observations = _OBSERVATIONS.get() or []
    _OBSERVATIONS.set([])
    return [dict(item) for item in observations]
