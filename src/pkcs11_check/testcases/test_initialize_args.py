"""CK_C_INITIALIZE_ARGS matrix tests.

PKCS#11 v3.2 §5.4 specifies four mutually-exclusive initialization
modes via the `CK_C_INITIALIZE_ARGS` struct passed to `C_Initialize`:

| Callbacks supplied | CKF_OS_LOCKING_OK | Meaning                                  |
|--------------------|-------------------|------------------------------------------|
| None (all NULL)    | unset             | Library uses no locks (single-thread)    |
| None               | set               | Library uses OS locks                    |
| All 4              | unset             | Library uses caller's mutex callbacks    |
| All 4              | set               | Library may use either (caller's choice) |

Edge cases the spec calls out:
- Three of four callbacks set, one NULL → `CKR_ARGUMENTS_BAD`
- `pReserved` non-NULL → `CKR_ARGUMENTS_BAD`

These tests verify each mode is honored.  Real-module bugs that historically
appeared here:
- Some NSS softoken builds segfault when callbacks are supplied without
  `CKF_OS_LOCKING_OK` then concurrent calls follow.
- Some modules ignore application callbacks silently (return `CKR_OK`
  but use OS locks anyway).
- Real HSMs sometimes reject all but one specific mode.

All tests run in subprocesses because each calls `C_Initialize` /
`C_Finalize` independently — running in the parent process would
collide with the shared session managed by `p11_raw_session`.

Marked `@pytest.mark.destructive` because of the Init/Finalize cycles.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, CKR_OK
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.destructive, pytest.mark.access]


def _run_init_args_script(p11_config: Any, args_setup: str) -> tuple[int, str, str]:
    """Execute a subprocess that loads the module, runs C_Initialize with the
    args_setup snippet (which must define a variable `init_args_ptr`), and
    prints the returned CKR as `RV=0x<hex>`.

    The args_setup snippet runs after the imports and CDLL load.  Available
    bindings inside it:
      - ``lib`` — ctypes.CDLL of the module
      - ``CK_C_INITIALIZE_ARGS``, ``CK_CREATEMUTEX`` etc — from types_std
      - ``ctypes``, ``byref``, ``c_void_p``, ``cast``
    """
    module_path = str(p11_config.module)
    script = textwrap.dedent(f"""
        import ctypes
        from ctypes import POINTER, byref, c_void_p, cast

        from pkcs11_check.raw.types_std import (
            CK_C_INITIALIZE_ARGS,
            CK_CREATEMUTEX, CK_DESTROYMUTEX, CK_LOCKMUTEX, CK_UNLOCKMUTEX,
            CK_RV,
            CKF_OS_LOCKING_OK,
            CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK,
        )

        lib = ctypes.CDLL({module_path!r})

        # The args_setup block defines `init_args_ptr` — either None
        # (meaning pass NULL to C_Initialize) or a pointer to a struct.
        {textwrap.indent(args_setup, "        ").strip()}

        # Call C_Initialize directly; bypass RawPKCS11 wrapper to avoid
        # any framework-level fallback logic.
        c_init = lib.C_Initialize
        c_init.restype = CK_RV
        c_init.argtypes = [c_void_p]

        rv = c_init(init_args_ptr)
        print(f"RV=0x{{rv:08x}}")

        # Best-effort Finalize so the module is left clean.
        try:
            c_final = lib.C_Finalize
            c_final.restype = CK_RV
            c_final.argtypes = [c_void_p]
            c_final(None)
        except Exception:
            pass
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _parse_rv(stdout: str) -> int | None:
    for line in stdout.splitlines():
        if line.startswith("RV=0x"):
            return int(line[len("RV=") :], 16)
    return None


class TestInitArgsMatrix:
    """Each row of the CK_C_INITIALIZE_ARGS matrix runs in its own subprocess."""

    def test_init_null_args(self, p11_config: Any) -> None:
        """Mode A: `C_Initialize(NULL)` is the universally-accepted default."""
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            "init_args_ptr = None",
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(NULL)",
                operation="C_Initialize",
                summary=f"C_Initialize(NULL) segfaulted (signal {-rc}). Stderr: {stderr}",
            )
        rv = _parse_rv(stdout)
        assert rv == CKR_OK, (
            f"C_Initialize(NULL) returned 0x{rv:08x}; expected CKR_OK.  "
            f"Stdout: {stdout!r} Stderr: {stderr!r}"
        )

    def test_init_empty_struct(self, p11_config: Any) -> None:
        """Mode B: zeroed CK_C_INITIALIZE_ARGS (no callbacks, no flags).

        Per spec §5.4 this is a "no-locks" mode — module must not crash.
        """
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            """
            args = CK_C_INITIALIZE_ARGS()  # all fields zero-initialised
            init_args_ptr = cast(byref(args), c_void_p)
            """,
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(empty struct)",
                operation="C_Initialize",
                summary=f"C_Initialize(empty struct) segfaulted (signal {-rc}). Stderr: {stderr}",
            )
        rv = _parse_rv(stdout)
        # Acceptable: CKR_OK (no-lock mode honored) or CKR_CANT_LOCK
        # (module insists on locking).  Not acceptable: segfault.
        assert rv is not None, f"No RV produced. Stdout: {stdout!r} Stderr: {stderr!r}"
        assert rv in (CKR_OK, CKR_CANT_LOCK), (
            f"C_Initialize(empty struct) returned 0x{rv:08x}; expected CKR_OK or CKR_CANT_LOCK"
        )

    def test_init_os_locking_only(self, p11_config: Any) -> None:
        """Mode C: CKF_OS_LOCKING_OK set, no callbacks.

        The standard initialization mode for multi-threaded apps.  Module
        is expected to succeed unless it's strictly single-threaded.
        """
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            """
            args = CK_C_INITIALIZE_ARGS()
            args.flags = int(CKF_OS_LOCKING_OK)
            init_args_ptr = cast(byref(args), c_void_p)
            """,
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(OS_LOCKING_OK)",
                operation="C_Initialize",
                summary=f"C_Initialize(OS_LOCKING_OK) segfaulted (signal {-rc}). Stderr: {stderr}",
            )
        rv = _parse_rv(stdout)
        assert rv == CKR_OK, (
            f"C_Initialize(OS_LOCKING_OK) returned 0x{rv:08x}; "
            f"expected CKR_OK on any multi-threaded-capable module"
        )

    def test_init_app_mutex_callbacks(self, p11_config: Any) -> None:
        """Mode D: all 4 mutex callbacks set, no CKF_OS_LOCKING_OK.

        Module is required to call into the supplied callbacks for any
        synchronization.  We supply trivial no-op stubs that just return
        CKR_OK; the module should accept them or reject with
        CKR_CANT_LOCK if it can't use app-supplied locks.
        """
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            """
            def _create(pp):
                return int(CKR_OK)
            def _destroy(p):
                return int(CKR_OK)
            def _lock(p):
                return int(CKR_OK)
            def _unlock(p):
                return int(CKR_OK)

            create_fn = CK_CREATEMUTEX(_create)
            destroy_fn = CK_DESTROYMUTEX(_destroy)
            lock_fn = CK_LOCKMUTEX(_lock)
            unlock_fn = CK_UNLOCKMUTEX(_unlock)

            args = CK_C_INITIALIZE_ARGS()
            args.CreateMutex = create_fn
            args.DestroyMutex = destroy_fn
            args.LockMutex = lock_fn
            args.UnlockMutex = unlock_fn
            init_args_ptr = cast(byref(args), c_void_p)
            """,
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(app callbacks)",
                operation="C_Initialize",
                summary=(
                    f"C_Initialize(app callbacks) segfaulted (signal {-rc}). "
                    f"This is a real provider bug — supplied mutex callbacks "
                    f"must not crash the module.  Stderr: {stderr}"
                ),
            )
        rv = _parse_rv(stdout)
        # Spec permits CKR_OK (callbacks accepted) or CKR_CANT_LOCK
        # (module unable to honor caller-supplied locking).
        assert rv is not None
        assert rv in (CKR_OK, CKR_CANT_LOCK), (
            f"C_Initialize(app callbacks) returned 0x{rv:08x}; expected CKR_OK or CKR_CANT_LOCK"
        )

    def test_init_both_callbacks_and_os_locking_ok(self, p11_config: Any) -> None:
        """Mode E: callbacks set AND CKF_OS_LOCKING_OK set.

        Spec §5.4 says module MAY use either OS locks or app callbacks.
        Both CKR_OK and CKR_CANT_LOCK are spec-compliant; the test
        verifies no crash.
        """
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            """
            def _create(pp):
                return int(CKR_OK)
            def _destroy(p):
                return int(CKR_OK)
            def _lock(p):
                return int(CKR_OK)
            def _unlock(p):
                return int(CKR_OK)

            create_fn = CK_CREATEMUTEX(_create)
            destroy_fn = CK_DESTROYMUTEX(_destroy)
            lock_fn = CK_LOCKMUTEX(_lock)
            unlock_fn = CK_UNLOCKMUTEX(_unlock)

            args = CK_C_INITIALIZE_ARGS()
            args.CreateMutex = create_fn
            args.DestroyMutex = destroy_fn
            args.LockMutex = lock_fn
            args.UnlockMutex = unlock_fn
            args.flags = int(CKF_OS_LOCKING_OK)
            init_args_ptr = cast(byref(args), c_void_p)
            """,
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(callbacks + OS_LOCKING_OK)",
                operation="C_Initialize",
                summary=(
                    f"C_Initialize(callbacks + OS_LOCKING_OK) segfaulted "
                    f"(signal {-rc}). Stderr: {stderr}"
                ),
            )
        rv = _parse_rv(stdout)
        assert rv is not None
        assert rv in (CKR_OK, CKR_CANT_LOCK), (
            f"C_Initialize(callbacks + OS_LOCKING_OK) returned 0x{rv:08x}; "
            f"expected CKR_OK or CKR_CANT_LOCK"
        )

    def test_init_reserved_non_null_rejected(self, p11_config: Any) -> None:
        """`pReserved != NULL` must return CKR_ARGUMENTS_BAD.

        The field is explicitly reserved; any non-NULL value is a spec
        violation by the caller.  Modules that accept it silently are
        non-compliant.
        """
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            """
            args = CK_C_INITIALIZE_ARGS()
            args.pReserved = c_void_p(0xDEADBEEF)
            init_args_ptr = cast(byref(args), c_void_p)
            """,
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(non-NULL pReserved)",
                operation="C_Initialize",
                summary=(
                    f"C_Initialize with non-NULL pReserved segfaulted "
                    f"(signal {-rc}) — module dereferenced reserved field. "
                    f"Stderr: {stderr}"
                ),
            )
        rv = _parse_rv(stdout)
        assert rv is not None, f"No RV produced. Stdout: {stdout!r} Stderr: {stderr!r}"
        # CKR_ARGUMENTS_BAD is the spec-mandated return.  Some
        # modules return CKR_OK ignoring the field; record but don't fail.
        if rv == CKR_OK:
            classify(
                "honest_deviation",
                kind="metadata",
                label="C_Initialize non-NULL pReserved accepted",
                operation="C_Initialize",
                summary=(
                    "Module accepts non-NULL pReserved (returns CKR_OK); spec "
                    "§5.4 requires CKR_ARGUMENTS_BAD.  Non-compliant but not "
                    "security-impacting."
                ),
            )
        classify_negative_rv(
            rv,
            (CKR_ARGUMENTS_BAD,),
            label="C_Initialize with a non-NULL pReserved field (spec Sec.5.4)",
        )

    def test_init_partial_callbacks_rejected(self, p11_config: Any) -> None:
        """Three callbacks set, one NULL — spec requires CKR_ARGUMENTS_BAD.

        The spec is unambiguous: either ALL four callbacks must be
        supplied, or NONE.  Partial callbacks indicate caller bug.
        """
        rc, stdout, stderr = _run_init_args_script(
            p11_config,
            """
            def _create(pp):
                return int(CKR_OK)
            def _destroy(p):
                return int(CKR_OK)
            def _lock(p):
                return int(CKR_OK)

            create_fn = CK_CREATEMUTEX(_create)
            destroy_fn = CK_DESTROYMUTEX(_destroy)
            lock_fn = CK_LOCKMUTEX(_lock)

            args = CK_C_INITIALIZE_ARGS()
            args.CreateMutex = create_fn
            args.DestroyMutex = destroy_fn
            args.LockMutex = lock_fn
            # UnlockMutex left as NULL — deliberate
            init_args_ptr = cast(byref(args), c_void_p)
            """,
        )
        if rc < 0:
            classify(
                "crash",
                label="C_Initialize(partial callbacks)",
                operation="C_Initialize",
                summary=(
                    f"C_Initialize with partial callbacks segfaulted (signal {-rc}).  "
                    f"Stderr: {stderr}"
                ),
            )
        rv = _parse_rv(stdout)
        assert rv is not None, f"No RV produced. Stdout: {stdout!r} Stderr: {stderr!r}"
        # Spec Sec.5.4 requires all-or-none mutex callbacks; some modules accept
        # 3-of-4 (CKR_OK). That is honest non-compliance, not security-impacting
        # -- xfail (symmetric with the non-NULL pReserved sibling above).
        if rv == CKR_OK:
            classify(
                "honest_deviation",
                kind="metadata",
                label="C_Initialize partial mutex callbacks accepted",
                operation="C_Initialize",
                summary=(
                    "Module accepts partial (3-of-4) mutex callbacks (returns CKR_OK); "
                    "spec Sec.5.4 requires CKR_ARGUMENTS_BAD. Non-compliant but not "
                    "security-impacting."
                ),
            )
        classify_negative_rv(
            rv,
            (CKR_ARGUMENTS_BAD,),
            label="C_Initialize with 3-of-4 mutex callbacks supplied (spec Sec.5.4)",
        )
