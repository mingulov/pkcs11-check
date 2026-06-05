"""Regression tests for crash-vs-timeout classification in the tee runner.

``_run_subprocess_tee`` ends its read loop on pipe-EOF, not process death. A
crashed child whose stdout/stderr is held open by a surviving grandchild (e.g. a
module that spawned a daemon inheriting the pipe fds) keeps the pipes open past
the deadline. The runner must report the child's real (crash) returncode rather
than synthesizing a timeout — otherwise "a segfault IS the finding" is silently
downgraded to a timeout (review findings R2/R5).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from pkcs11_check.core.file_runner import _run_subprocess_tee

# Direct child spawns a grandchild that inherits stdout/stderr (close_fds keeps
# 0/1/2) and sleeps, holding the pipe open; then the child kills itself with a
# signal so its returncode is negative. The pipe never EOFs before the deadline.
_CRASH_WITH_LINGERING_GRANDCHILD = (
    "import subprocess, sys, os, signal\n"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(8)'])\n"
    "os.kill(os.getpid(), signal.SIGKILL)\n"
)


def test_crash_is_not_misreported_as_timeout_when_grandchild_holds_pipe() -> None:
    start = time.monotonic()
    rc, _out, _err = _run_subprocess_tee(
        [sys.executable, "-c", _CRASH_WITH_LINGERING_GRANDCHILD],
        env=dict(os.environ),
        timeout=2,
    )
    elapsed = time.monotonic() - start

    # The child crashed (negative returncode == killed by a signal), NOT 124.
    assert rc < 0, rc
    assert rc == -signal.SIGKILL, rc
    # And it returned at the deadline, not after the grandchild's 8s sleep.
    assert elapsed < 6, elapsed


def test_genuinely_hung_child_still_times_out() -> None:
    # A live child producing no output must still raise TimeoutExpired (and be
    # reaped, not leaked, by the kill+wait on the timeout path).
    with pytest.raises(subprocess.TimeoutExpired):
        _run_subprocess_tee(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            env=dict(os.environ),
            timeout=1,
        )
