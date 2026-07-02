"""Safety properties of application-supplied mutex callbacks.

PKCS#11 v3.2 §5.4 says the library may call into application-supplied
mutex callbacks at any time on any thread.  Two properties matter for
robustness:

1.  If the application's callback returns a non-CKR_OK value, the
    library must propagate the failure cleanly (not crash, not deadlock).
2.  If the application's callback raises an exception (in a language
    binding like Python), the library must not be left in inconsistent
    state.

Modules that ignore caller-side error returns from mutex callbacks risk
silent data races — they think they hold a lock that the callback
refused to take.

Marked `@pytest.mark.destructive` because of the Init/Finalize cycles
each test performs in subprocess.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.destructive, pytest.mark.access]


def _run_callback_probe(p11_config: Any, probe: str, timeout: int = 15) -> tuple[int, str, str]:
    """Run the mutex-callback probe in a subprocess and return (rc, stdout, stderr).

    The child (``_probes/mutex_callback_safety.py``) loads the module via raw ctypes and
    exercises ``C_Initialize`` with application-supplied mutex callbacks selected by
    ``probe``.  The raw CDLL path has no RawPKCS11 wrapper, so coverage routes to the raw
    accumulator (``coverage="raw"``).  No PIN / session / login is involved (I3).
    """
    result = run_probe(
        "mutex_callback_safety",
        {"module_path": str(p11_config.module), "slot_id": p11_config.slot, "probe": probe},
        timeout=timeout,
        coverage="raw",
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestMutexCallbackErrorHandling:
    """When application callbacks signal failure, the module must not crash."""

    def test_create_mutex_callback_returning_general_error(self, p11_config: Any) -> None:
        """CreateMutex returning CKR_GENERAL_ERROR — module should propagate cleanly.

        Per spec §5.4 the module sees the failed return and should fail
        C_Initialize with a defined CKR.  Crash here is a real bug.
        """
        rc, stdout, stderr = _run_callback_probe(p11_config, "create_returns_general_error")
        assert_subprocess_completed(
            rc,
            stdout,
            stderr,
            context="C_Initialize with failing CreateMutex callback",
        )
        # rv should be some defined CKR — most likely CKR_GENERAL_ERROR
        # propagated, CKR_CANT_LOCK, or a related error.  rv == CKR_OK
        # (0) would mean the module ignored the callback failure — also
        # buggy but harder to assert without false positives across
        # diverse modules.  We're primarily checking for "no crash".
        rv_lines = [line for line in stdout.splitlines() if line.startswith("RV=")]
        if not rv_lines:
            fail_as(
                "crash",
                label="C_Initialize with failing CreateMutex callback",
                summary=f"No RV produced — subprocess exited abnormally.  Stderr: {stderr!r}",
            )
        rv = int(rv_lines[0][len("RV=") :], 16)
        if rv == CKR_OK:
            classify(
                "honest_deviation",
                kind="lifecycle",
                label="CreateMutex callback returning CKR_GENERAL_ERROR",
                operation="C_Initialize",
                summary=(
                    "Module returned CKR_OK despite CreateMutex callback "
                    "returning CKR_GENERAL_ERROR.  Module may be ignoring "
                    "caller-side mutex errors — data-race risk in concurrent "
                    "use.  Non-compliant but not a crash."
                ),
            )

    def test_lock_mutex_callback_returning_general_error_during_call(self, p11_config: Any) -> None:
        """LockMutex returning CKR_GENERAL_ERROR during a normal C_* call.

        After init, make some PKCS#11 call that internally locks; the
        callback fails.  Module should propagate as defined CKR.
        """
        rc, stdout, stderr = _run_callback_probe(p11_config, "lock_returns_general_error")
        assert_subprocess_completed(
            rc,
            stdout,
            stderr,
            context="LockMutex callback returning CKR_GENERAL_ERROR during C_GetInfo",
        )
        # If init failed (module wouldn't use app callbacks), that's fine.
        init_lines = [ln for ln in stdout.splitlines() if ln.startswith("INIT_RV=")]
        if not init_lines:
            fail_as(
                "crash",
                label="LockMutex callback returning CKR_GENERAL_ERROR during C_GetInfo",
                summary=f"No INIT_RV produced. Stderr: {stderr!r}",
            )
        init_rv = int(init_lines[0].split("=")[1], 16)
        if init_rv != CKR_OK:
            pytest.skip(
                f"Module did not accept app-supplied callbacks (init returned "
                f"0x{init_rv:08x}); cannot exercise lock-failure path"
            )
        # If we got here, init succeeded and we made a follow-up call.
        # The follow-up may have crashed (caught above), errored, or
        # succeeded.  All are interesting but no-crash is what matters.

    def test_python_exception_in_create_mutex_callback(self, p11_config: Any) -> None:
        """A Python exception thrown from a mutex callback must not crash the module.

        ctypes propagates the exception by returning a default value (0)
        and printing a traceback.  The module sees CKR_OK and proceeds —
        this is its own kind of bug because the callback intended failure,
        but we're testing that the *binding* doesn't segfault.
        """
        rc, _stdout, stderr = _run_callback_probe(p11_config, "python_exception_in_create")
        assert_subprocess_completed(
            rc,
            _stdout,
            stderr,
            context="CreateMutex callback raising Python exception",
        )
        # We don't assert on RV — the interesting property is "no crash".
        # stderr will contain the Python traceback; that's expected.
