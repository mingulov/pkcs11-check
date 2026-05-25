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

import subprocess
import sys
import textwrap
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OK

pytestmark = [pytest.mark.destructive, pytest.mark.access]


def _run_callback_script(p11_config: Any, body: str, timeout: int = 15) -> tuple[int, str, str]:
    """Run a subprocess that loads the module and exercises mutex callbacks.

    The body snippet has access to:
      - ``lib`` (ctypes.CDLL)
      - ``raw`` (RawPKCS11 instance after C_Initialize)
      - All `CK_*` types/constants from `types_std`.
    """
    module_path = str(p11_config.module)
    script = textwrap.dedent(f"""
        import ctypes
        from ctypes import POINTER, byref, c_void_p, c_ulong, cast

        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import (
            CK_C_INITIALIZE_ARGS,
            CK_CREATEMUTEX, CK_DESTROYMUTEX, CK_LOCKMUTEX, CK_UNLOCKMUTEX,
            CK_RV, CKF_OS_LOCKING_OK,
            CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK, CKR_GENERAL_ERROR,
        )

        lib = ctypes.CDLL({module_path!r})

        {textwrap.indent(body, "        ").strip()}
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestMutexCallbackErrorHandling:
    """When application callbacks signal failure, the module must not crash."""

    def test_create_mutex_callback_returning_general_error(self, p11_config: Any) -> None:
        """CreateMutex returning CKR_GENERAL_ERROR — module should propagate cleanly.

        Per spec §5.4 the module sees the failed return and should fail
        C_Initialize with a defined CKR.  Crash here is a real bug.
        """
        rc, stdout, stderr = _run_callback_script(
            p11_config,
            """
            def _create_fail(pp):
                return int(CKR_GENERAL_ERROR)

            def _stub(p):
                return int(CKR_OK)

            create_fn = CK_CREATEMUTEX(_create_fail)
            destroy_fn = CK_DESTROYMUTEX(_stub)
            lock_fn = CK_LOCKMUTEX(_stub)
            unlock_fn = CK_UNLOCKMUTEX(_stub)

            args = CK_C_INITIALIZE_ARGS()
            args.CreateMutex = create_fn
            args.DestroyMutex = destroy_fn
            args.LockMutex = lock_fn
            args.UnlockMutex = unlock_fn

            c_init = lib.C_Initialize
            c_init.restype = CK_RV
            c_init.argtypes = [c_void_p]
            rv = c_init(cast(byref(args), c_void_p))
            print(f"RV=0x{rv:08x}")

            # Cleanup best-effort.
            c_final = lib.C_Finalize
            c_final.restype = CK_RV
            c_final.argtypes = [c_void_p]
            c_final(None)
            """,
        )
        if rc < 0:
            pytest.fail(
                f"C_Initialize with failing CreateMutex callback segfaulted "
                f"(signal {-rc}).  Module crashed when caller-side mutex "
                f"creation reported failure — this is a real provider bug. "
                f"Stderr: {stderr}"
            )
        # rv should be some defined CKR — most likely CKR_GENERAL_ERROR
        # propagated, CKR_CANT_LOCK, or a related error.  rv == CKR_OK
        # (0) would mean the module ignored the callback failure — also
        # buggy but harder to assert without false positives across
        # diverse modules.  We're primarily checking for "no crash".
        rv_lines = [line for line in stdout.splitlines() if line.startswith("RV=")]
        if not rv_lines:
            pytest.fail(f"No RV produced — subprocess exited abnormally.  Stderr: {stderr!r}")
        rv = int(rv_lines[0][len("RV=") :], 16)
        if rv == CKR_OK:
            pytest.xfail(
                "Module returned CKR_OK despite CreateMutex callback "
                "returning CKR_GENERAL_ERROR.  Module may be ignoring "
                "caller-side mutex errors — data-race risk in concurrent "
                "use.  Non-compliant but not a crash."
            )

    def test_lock_mutex_callback_returning_general_error_during_call(self, p11_config: Any) -> None:
        """LockMutex returning CKR_GENERAL_ERROR during a normal C_* call.

        After init, make some PKCS#11 call that internally locks; the
        callback fails.  Module should propagate as defined CKR.
        """
        rc, stdout, stderr = _run_callback_script(
            p11_config,
            """
            def _create(pp):
                # Allocate a unique sentinel for each mutex.
                # Module passes a void** — we write a non-NULL value.
                pp[0] = 0x1
                return int(CKR_OK)

            def _destroy(p):
                return int(CKR_OK)

            def _lock_fail(p):
                return int(CKR_GENERAL_ERROR)

            def _unlock(p):
                return int(CKR_OK)

            create_fn = CK_CREATEMUTEX(_create)
            destroy_fn = CK_DESTROYMUTEX(_destroy)
            lock_fn = CK_LOCKMUTEX(_lock_fail)
            unlock_fn = CK_UNLOCKMUTEX(_unlock)

            args = CK_C_INITIALIZE_ARGS()
            args.CreateMutex = create_fn
            args.DestroyMutex = destroy_fn
            args.LockMutex = lock_fn
            args.UnlockMutex = unlock_fn

            c_init = lib.C_Initialize
            c_init.restype = CK_RV
            c_init.argtypes = [c_void_p]
            rv = c_init(cast(byref(args), c_void_p))
            print(f"INIT_RV=0x{rv:08x}")

            if rv == CKR_OK:
                # Try a trivial call that should internally lock.
                # C_GetInfo is the safest probe.
                from pkcs11_check.raw.types_std import CK_INFO
                info = CK_INFO()
                c_getinfo = lib.C_GetInfo
                c_getinfo.restype = CK_RV
                c_getinfo.argtypes = [c_void_p]
                rv2 = c_getinfo(cast(byref(info), c_void_p))
                print(f"CALL_RV=0x{rv2:08x}")

                c_final = lib.C_Finalize
                c_final.restype = CK_RV
                c_final.argtypes = [c_void_p]
                c_final(None)
            """,
        )
        if rc < 0:
            pytest.fail(
                f"Module crashed when LockMutex callback returned "
                f"CKR_GENERAL_ERROR (signal {-rc}). Stderr: {stderr}"
            )
        # If init failed (module wouldn't use app callbacks), that's fine.
        init_lines = [ln for ln in stdout.splitlines() if ln.startswith("INIT_RV=")]
        if not init_lines:
            pytest.fail(f"No INIT_RV produced. Stderr: {stderr!r}")
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
        rc, _stdout, stderr = _run_callback_script(
            p11_config,
            """
            def _create_raise(pp):
                raise RuntimeError("callback failure")

            def _stub(p):
                return int(CKR_OK)

            create_fn = CK_CREATEMUTEX(_create_raise)
            destroy_fn = CK_DESTROYMUTEX(_stub)
            lock_fn = CK_LOCKMUTEX(_stub)
            unlock_fn = CK_UNLOCKMUTEX(_stub)

            args = CK_C_INITIALIZE_ARGS()
            args.CreateMutex = create_fn
            args.DestroyMutex = destroy_fn
            args.LockMutex = lock_fn
            args.UnlockMutex = unlock_fn

            c_init = lib.C_Initialize
            c_init.restype = CK_RV
            c_init.argtypes = [c_void_p]
            rv = c_init(cast(byref(args), c_void_p))
            print(f"RV=0x{rv:08x}")

            try:
                c_final = lib.C_Finalize
                c_final.restype = CK_RV
                c_final.argtypes = [c_void_p]
                c_final(None)
            except Exception:
                pass
            """,
        )
        if rc < 0:
            pytest.fail(
                f"Module crashed (signal {-rc}) when CreateMutex callback "
                f"raised a Python exception.  ctypes propagated the "
                f"exception via default return value, but the module "
                f"did not handle the resulting state cleanly. "
                f"Stderr: {stderr}"
            )
        # We don't assert on RV — the interesting property is "no crash".
        # stderr will contain the Python traceback; that's expected.
