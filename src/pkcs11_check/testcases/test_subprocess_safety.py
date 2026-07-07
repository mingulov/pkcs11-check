"""Subprocess safety tests - post-Finalize, fork, library reload.

These tests drive the module in a fresh subprocess (via the ``subprocess_safety`` probe) to
avoid corrupting the main test session. They exercise crash scenarios safely.

References: rep11.md Iteration 3, fork detection and exit crash bugs found in some modules.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config

pytestmark = [pytest.mark.security, pytest.mark.stress]

# os.fork() is POSIX-only. On Windows/Wine `os.fork` does not exist, so a fork-based
# probe raises AttributeError and exits 1 - which the isolated runner would otherwise
# record as a (false) module crash. Skip such tests where fork is absent; fork-safety is
# a POSIX concept, so no coverage is lost on platforms that cannot fork.
requires_fork = pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="os.fork() is POSIX-only; fork-safety is inapplicable on this platform",
)


def _run_probe(
    p11_config: Any,
    probe: str,
    *,
    timeout: int,
    with_pin: bool = False,
    with_slot: bool = False,
) -> tuple[int, str]:
    """Run a ``subprocess_safety`` probe; return ``(returncode, stdout + stderr)``.

    Mirrors the legacy ``_run_script`` return contract so each per-test classifier keeps
    scanning a single combined-output string. When ``with_pin`` is set the PIN travels ONLY
    via ``run_probe(pin=...)`` -> ``_P11CHECK_PIN`` env (Invariant I3); it is never embedded
    in the probe params or source. Coverage routes to the session accumulator; rv-trace is
    recorded by ``run_probe`` (I7).
    """
    params: dict[str, Any] = {"module_path": str(p11_config.module), "probe": probe}
    if with_slot:
        params["slot_id"] = p11_config.slot
    result = run_probe(
        "subprocess_safety",
        params,
        pin=pin_from_config(p11_config) if with_pin else None,
        timeout=timeout,
        coverage="session",
    )
    return result.returncode, result.stdout + result.stderr


class TestPostFinalize:
    """Test behavior after C_Finalize - must not crash (task 7.3)."""

    def test_post_finalize_get_slot_list(self, p11_config: Any) -> None:
        """C_GetSlotList after C_Finalize must not crash."""
        rc, output = _run_probe(p11_config, "post_finalize_get_slot_list", timeout=30)
        assert rc == 0, f"Post-finalize crashed (rc={rc}): {output}"
        assert "OK:" in output

    def test_reinitialize_after_finalize(self, p11_config: Any) -> None:
        """C_Initialize after C_Finalize must work."""
        rc, output = _run_probe(p11_config, "reinitialize_after_finalize", timeout=30)
        assert rc == 0, f"Reinit crashed (rc={rc}): {output}"
        assert "OK:" in output


class TestForkSafety:
    """Test fork behavior - child must not crash or deadlock (task 7.4)."""

    @requires_fork
    @pytest.mark.slow
    def test_fork_after_initialize(self, p11_config: Any) -> None:
        """Fork after C_Initialize - child reinitializes."""
        rc, output = _run_probe(p11_config, "fork_after_initialize", timeout=15)
        if rc != 0:
            classify(
                "crash",
                label="fork-after-initialize",
                summary=f"Fork test crashed (rc={rc}): {output}",
            )
        if "CHILD_SIGNAL:" in output:
            classify(
                "crash",
                label="fork-after-initialize",
                summary=f"Fork child was killed by a signal: {output}",
            )

        child_exit: int | None = None
        for line in output.splitlines():
            if line.startswith("CHILD_EXIT:"):
                try:
                    child_exit = int(line.split(":", 1)[1])
                except ValueError:
                    fail_as(
                        "crash",
                        label="fork-after-initialize",
                        summary=f"Fork child reported malformed exit status: {output}",
                    )
                break
        if child_exit is None:
            fail_as(
                "crash",
                label="fork-after-initialize",
                summary=f"Fork child did not report exit status: {output}",
            )
        if child_exit != 0:
            classify(
                "crash",
                label="fork-after-initialize",
                summary=f"Fork child failed (exit={child_exit}): {output}",
            )


class TestSessionObjectProcessIsolation:
    """CROSS-PROC-001: cross-process session-object isolation.

    PKCS#11 v3.2 says session objects belong to a session, and
    sessions belong to an "application". An application is whatever
    called C_Initialize — distinct processes are distinct applications.
    Session objects MUST NOT be visible to a different process even if
    the underlying module backend is shared (e.g. a SQLite DB on disk,
    a dbus broker, or a daemon socket for daemon-backed modules).

    The existing same-process cross-session tests in
    test_object_visibility.py validate that two sessions in the SAME
    process see each other's session objects (spec-mandated). This
    test validates the complementary security boundary: a different
    process MUST NOT see them.
    """

    @requires_fork
    def test_session_object_not_visible_to_other_process(self, p11_config: Any) -> None:
        """Parent creates a session object; subprocess MUST NOT find it.

        Steps:
        1. Subprocess A opens a session, creates a session-scope (CKA_TOKEN=False)
           data object with a unique label, prints the label, sleeps until
           told to exit (so the session — and thus the object — stays alive).
           Actually we can't easily coordinate two long-lived subprocesses
           from a single pytest, so instead use a single subprocess that
           verifies the negative property internally:
           - Initialize, open session, create session object with label X,
             then within the SAME process (different session — visible) and
             via a fork+re-Initialize child (different application — not
             visible).
        2. Compare results.

        Closes Phase 4.5 follow-up CROSS-PROC-001 (LOW-MED). Skips when
        the module doesn't support fork-after-initialize cleanly. Those modules
        need additional setup that the subprocess test framework already
        documents.
        """
        # 90s timeout: daemon-backed modules may need cold-start headroom
        # for post-fork re-Initialize. Real-world fork+TPM2_Startup
        # can exceed 30s on busy systems.
        rc, output = _run_probe(
            p11_config,
            "session_object_isolation",
            timeout=90,
            with_pin=True,
            with_slot=True,
        )
        if rc != 0:
            if "FATAL:Parent_CreateObject:" in output:
                classify(
                    "not_operational",
                    label="cross-process session-object isolation (setup)",
                    operation="C_CreateObject",
                    summary=(
                        "session-object setup rejected before cross-process isolation "
                        f"could be tested: {output}"
                    ),
                )
            classify(
                "crash",
                label="cross-process session-object isolation",
                summary=f"Cross-process session-object isolation test crashed (rc={rc}): {output}",
            )

        # Parse output: PARENT_LABEL must be set; child must report
        # CHILD_FOUND:0 (didn't see parent's session object).
        if "PARENT_LABEL:" not in output:
            classify(
                "crash",
                label="cross-process session-object isolation",
                summary=f"Parent didn't create the session object: {output}",
            )
        if "CHILD_EXIT:" not in output:
            classify(
                "crash",
                label="cross-process session-object isolation",
                summary=f"Child didn't exit cleanly: {output}",
            )
        # A child killed by signal (CHILD_SIGNAL: in output) is a CRASH
        # — that IS the finding, not a skip condition. Project rule:
        # "A segfault IS the finding."
        if "CHILD_SIGNAL:" in output:
            classify(
                "crash",
                label="cross-process session-object isolation",
                summary=(
                    "SECURITY: child process was killed by a signal (likely "
                    f"crash) during cross-process isolation test:\n{output}"
                ),
            )

        # Narrow skip-on-CHILD_FATAL/EXC: skip only on documented
        # daemon-coordination cases — namely CHILD_FATAL:Init or
        # CHILD_FATAL:Login with daemon-related CKRs (CKR_FUNCTION_FAILED
        # / CKR_DEVICE_ERROR / CKR_GENERAL_ERROR / CKR_TOKEN_NOT_PRESENT
        # / CKR_SLOT_ID_INVALID). CHILD_EXC paths and other CHILD_FATAL
        # paths fail the test — those represent real bugs, not
        # module-environment limits.
        daemon_failure_ckrs = (
            "0x00000005",  # CKR_FUNCTION_FAILED
            "0x00000030",  # CKR_DEVICE_ERROR
            "0x00000020",  # CKR_GENERAL_ERROR
            "0x000000E0",  # CKR_TOKEN_NOT_PRESENT
            "0x00000003",  # CKR_SLOT_ID_INVALID
        )
        is_daemon_init_failure = (
            any(f"CHILD_FATAL:Init:{code}" in output for code in daemon_failure_ckrs)
            or "CHILD_FATAL:Login:" in output
        )
        if "CHILD_FATAL" in output and is_daemon_init_failure:
            pytest.skip(
                f"Child couldn't re-initialize the module after fork "
                f"(daemon-backed module limit): {output}"
            )
        if "CHILD_FATAL" in output or "CHILD_EXC" in output:
            classify(
                "crash",
                label="cross-process session-object isolation",
                summary=(
                    "Child failed unexpectedly during cross-process test "
                    f"(not a documented daemon limitation): {output}"
                ),
            )
        if "CHILD_FOUND:0" not in output:
            # Extract just the diagnostic lines for the failure message.
            diag = "\n".join(
                line
                for line in output.splitlines()
                if any(
                    line.startswith(p)
                    for p in (
                        "PARENT_LABEL:",
                        "CHILD_FOUND:",
                        "CHILD_EXIT:",
                        "CHILD_FATAL",
                        "CHILD_EXC",
                        "FATAL:",
                    )
                )
            )
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"Cross-process session-object leak detected: a session "
                f"object created in the parent process was visible to a "
                f"child process that re-Initialized the module. PKCS#11 "
                f"v3.2 says session objects belong to a single "
                f"application, and distinct processes are distinct "
                f"applications. Diagnostic: {diag}",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.2",
            )
            classify(
                "self_contradiction",
                kind="policy",
                label="cross-process session-object isolation",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "SECURITY: cross-process session-object isolation violated "
                    "— child process saw the parent's session object. "
                    f"Diagnostic:\n{diag}"
                ),
            )


class TestLibraryReload:
    """Test library reload cycle (task 7.15)."""

    def test_reload_cycle_5x(self, p11_config: Any) -> None:
        """Load -> init -> ops -> finalize, 5 times. No crash or leak.

        A negative exit code (signal/segfault) is a module bug and kept as failure.
        A positive exit code (rc > 0) means the module raised a Python exception
        during reinit -- common causes: token label not found after reinit,
        or daemon not provisioned. These are module
        environment limitations, not crashes, so xfail.
        """
        rc, output = _run_probe(p11_config, "reload_cycle_5x", timeout=30, with_pin=True)
        if rc < 0:
            # Negative exit code = killed by signal (crash/segfault) -- real module bug
            classify(
                "crash",
                label="library reload cycle (5x)",
                summary=f"Reload cycle crashed with signal (rc={rc}): {output}",
            )
        if rc != 0:
            # Non-zero but no signal: module raised an exception during reinit
            # (e.g. token not found after reinit, daemon not provisioned).
            # This is an environment/module limitation, not a crash.
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module does not survive repeated C_Finalize/C_Initialize cycles "
                "in a single process (returns error on reinit); "
                "PKCS#11 spec does not require multi-cycle reinit support",
                ComplianceLevel.VENDOR,
            )
            classify(
                "honest_deviation",
                kind="lifecycle",
                label="library reload cycle (5x)",
                summary=f"Module fails reload cycle (rc={rc}): {output[:200]}",
            )
        assert "OK:" in output
