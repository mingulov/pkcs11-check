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
- Some module builds segfault when callbacks are supplied without
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

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, CKR_OK
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.destructive, pytest.mark.access]


def _run_init_args_probe(p11_config: Any, probe: str, timeout: int = 15) -> tuple[int, str, str]:
    """Run the ``initialize_args`` probe in a subprocess and return (rc, stdout, stderr).

    The child (``_probes/initialize_args.py``) loads the module via raw ctypes and calls
    ``C_Initialize`` (or, for the ``finalize_reserved_non_null`` probe, ``C_Finalize``) with
    the ``CK_C_INITIALIZE_ARGS`` setup selected by ``probe``.  The raw CDLL path has no
    RawPKCS11 wrapper, so coverage routes to the raw accumulator (``coverage="raw"``).  No
    PIN / session / login is involved (I3).
    """
    result = run_probe(
        "initialize_args",
        {"module_path": str(p11_config.module), "slot_id": p11_config.slot, "probe": probe},
        timeout=timeout,
        coverage="raw",
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
        rc, stdout, stderr = _run_init_args_probe(p11_config, "null_args")
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
        rc, stdout, stderr = _run_init_args_probe(p11_config, "empty_struct")
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
        assert (
            rv
            in (  # audit-ok: positive-op init — CKR_OK is success; CKR_CANT_LOCK is spec-legal
                CKR_OK,
                CKR_CANT_LOCK,
            )
        ), f"C_Initialize(empty struct) returned 0x{rv:08x}; expected CKR_OK or CKR_CANT_LOCK"

    def test_init_os_locking_only(self, p11_config: Any) -> None:
        """Mode C: CKF_OS_LOCKING_OK set, no callbacks.

        The standard initialization mode for multi-threaded apps.  Module
        is expected to succeed unless it's strictly single-threaded.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "os_locking_only")
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
        rc, stdout, stderr = _run_init_args_probe(p11_config, "app_mutex_callbacks")
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
        assert (
            rv
            in (  # audit-ok: positive-op init — CKR_OK is success; CKR_CANT_LOCK is spec-legal
                CKR_OK,
                CKR_CANT_LOCK,
            )
        ), f"C_Initialize(app callbacks) returned 0x{rv:08x}; expected CKR_OK or CKR_CANT_LOCK"

    def test_init_both_callbacks_and_os_locking_ok(self, p11_config: Any) -> None:
        """Mode E: callbacks set AND CKF_OS_LOCKING_OK set.

        Spec §5.4 says module MAY use either OS locks or app callbacks.
        Both CKR_OK and CKR_CANT_LOCK are spec-compliant; the test
        verifies no crash.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "both_callbacks_and_os_locking")
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
        assert (
            rv
            in (  # audit-ok: positive-op init — CKR_OK is success; CKR_CANT_LOCK is spec-legal
                CKR_OK,
                CKR_CANT_LOCK,
            )
        ), (
            f"C_Initialize(callbacks + OS_LOCKING_OK) returned 0x{rv:08x}; "
            f"expected CKR_OK or CKR_CANT_LOCK"
        )

    def test_init_reserved_non_null_rejected(self, p11_config: Any) -> None:
        """`pReserved != NULL` must return CKR_ARGUMENTS_BAD.

        The field is explicitly reserved; any non-NULL value is a spec
        violation by the caller.  Modules that accept it silently are
        non-compliant.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "reserved_non_null")
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
        else:
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
        rc, stdout, stderr = _run_init_args_probe(p11_config, "partial_callbacks")
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


class TestFinalizeArgs:
    """C_Finalize argument-validation tests, each run in its own subprocess."""

    def test_finalize_reserved_non_null(self, p11_config: Any) -> None:
        """`C_Finalize(pReserved != NULL)` should return CKR_ARGUMENTS_BAD.

        PKCS#11 v3.2 §11.4 specifies that `pReserved` must be NULL; any non-NULL
        value must cause C_Finalize to return CKR_ARGUMENTS_BAD.  Some modules
        ignore the reserved field and return CKR_OK — lenient but not
        security-impacting (the field carries no caller-supplied data that could
        affect the module's behavior).

        Classification:
        - CKR_ARGUMENTS_BAD -> pass (spec-compliant rejection).
        - CKR_OK -> xfail/honest_deviation (common benign leniency; the field is
          truly reserved and ignoring it is safe).
        - Any other clean code -> xfail/nonspec_reject (noted deviation).
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "finalize_reserved_non_null")
        if rc < 0:
            classify(
                "crash",
                label="C_Finalize(non-NULL pReserved)",
                operation="C_Finalize",
                summary=(
                    f"C_Finalize with non-NULL pReserved segfaulted "
                    f"(signal {-rc}) — module dereferenced reserved field. "
                    f"Stderr: {stderr}"
                ),
            )
        rv = _parse_rv(stdout)
        assert rv is not None, f"No RV produced. Stdout: {stdout!r} Stderr: {stderr!r}"
        # CKR_OK is a common benign leniency (module ignores the reserved field):
        # record as honest_deviation xfail, not a fail, because the field carries no
        # caller data that could affect module behaviour.
        if rv == CKR_OK:
            classify(
                "honest_deviation",
                kind="metadata",
                label="C_Finalize non-NULL pReserved accepted",
                operation="C_Finalize",
                summary=(
                    "Module accepts non-NULL pReserved in C_Finalize (returns CKR_OK); "
                    "spec §11.4 requires CKR_ARGUMENTS_BAD.  Non-compliant but not "
                    "security-impacting (reserved field carries no caller data)."
                ),
            )
        classify_negative_rv(
            rv,
            (CKR_ARGUMENTS_BAD,),
            label="C_Finalize with a non-NULL pReserved field (spec §11.4)",
        )
