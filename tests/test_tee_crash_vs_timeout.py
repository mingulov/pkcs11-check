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

from pkcs11_check.core.crash_codes import crash_detail_name, is_crash_returncode
from pkcs11_check.core.file_runner import _run_subprocess_tee

# Direct child spawns a grandchild that inherits stdout/stderr (close_fds keeps
# 0/1/2) and sleeps, holding the pipe open; then the child kills itself abruptly so its
# returncode denotes a crash. The pipe never EOFs before the deadline.
#
# The self-kill is necessarily platform-specific: Windows has no signals at all (there is
# no signal.SIGKILL, so the POSIX form raised AttributeError there). Its ABI-equivalent is
# terminating with an NTSTATUS exception code, which is exactly what crash_codes.py
# recognizes as a crash, so both branches exercise the same product contract.
_SELF_KILL = (
    # argtypes/restype are REQUIRED, not decoration: GetCurrentProcess returns the
    # pseudo-handle (HANDLE)-1, and under ctypes' default c_int signature it is truncated,
    # so the call silently fails and the process exits 0 -- which reads as "no crash".
    # Measured: typed -> 0xC0000005, untyped -> 0.
    "import ctypes\n"
    "k = ctypes.windll.kernel32\n"
    "k.GetCurrentProcess.restype = ctypes.c_void_p\n"
    "k.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]\n"
    # 0xC0000005 == EXCEPTION_ACCESS_VIOLATION, the NTSTATUS a real faulting module yields.
    # Note ctypes.string_at(0) is NOT usable here: Windows SEH translates the fault into a
    # catchable OSError, so the child exits 1 and never reports a crash code at all.
    "k.TerminateProcess(k.GetCurrentProcess(), 0xC0000005)\n"
    if sys.platform == "win32"
    else "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n"
)
_CRASH_WITH_LINGERING_GRANDCHILD = (
    "import subprocess, sys\n"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(8)'])\n" + _SELF_KILL
)


def test_crash_is_not_misreported_as_timeout_when_grandchild_holds_pipe() -> None:
    start = time.monotonic()
    rc, _out, _err = _run_subprocess_tee(
        [sys.executable, "-c", _CRASH_WITH_LINGERING_GRANDCHILD],
        env=dict(os.environ),
        timeout=2,
    )
    elapsed = time.monotonic() - start

    # The child crashed, NOT timed out (124). Assert via the product's own platform-aware
    # classifier rather than a POSIX signal number, so this pins the contract the runner
    # actually relies on: negative signal on POSIX, NTSTATUS on Windows.
    assert is_crash_returncode(rc), f"{rc} ({crash_detail_name(rc)}) must classify as a crash"
    assert rc != 124, rc
    if sys.platform == "win32":
        assert rc & 0xFFFFFFFF == 0xC0000005, crash_detail_name(rc)
    else:
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


def test_tee_captures_both_streams_and_returncode() -> None:
    # tee must capture stdout AND stderr in full and return the real exit code.
    # (The reader must not depend on select(), which cannot poll OS pipes on
    # Windows -- issue #3.)
    script = (
        "import sys\n"
        "sys.stdout.write('OUT-marker\\n'); sys.stdout.flush()\n"
        "sys.stderr.write('ERR-marker\\n'); sys.stderr.flush()\n"
        "sys.exit(3)\n"
    )
    rc, out, err = _run_subprocess_tee(
        [sys.executable, "-c", script], env=dict(os.environ), timeout=10
    )
    assert rc == 3, rc
    assert "OUT-marker" in out, out
    assert "ERR-marker" in err, err


def test_tee_captures_output_larger_than_pipe_buffer() -> None:
    # Output bigger than the OS pipe buffer (~64KiB) must be captured in full:
    # the reader has to drain concurrently with the child, not after it exits,
    # or the child blocks on a full pipe and we deadlock/truncate.
    n = 300_000
    script = f"import sys\nsys.stdout.write('x' * {n})\nsys.stdout.flush()\n"
    rc, out, _err = _run_subprocess_tee(
        [sys.executable, "-c", script], env=dict(os.environ), timeout=10
    )
    assert rc == 0, rc
    assert len(out) == n, len(out)
