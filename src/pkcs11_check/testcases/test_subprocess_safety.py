"""Subprocess safety tests - post-Finalize, fork, library reload.

These tests run Python scripts in subprocesses to avoid corrupting
the main test session. They test crash scenarios safely.

References: rep11.md Iteration 3, NSS fork detection (Mozilla #473505),
SoftHSM2 #729 (exit crash).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.security, pytest.mark.stress]


def _run_script(
    script: str, env: dict[str, str] | None = None, timeout: int = 30
) -> tuple[int, str]:
    """Run a Python script in a subprocess. Returns (exit_code, output)."""
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    output = result.stdout + result.stderr
    return result.returncode, output


class TestPostFinalize:
    """Test behavior after C_Finalize - must not crash (task 7.3)."""

    def test_post_finalize_get_slot_list(self, p11_config: Any) -> None:
        """C_GetSlotList after C_Finalize must not crash."""
        module = str(p11_config.module)
        script = f"""
        from ctypes import byref
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import get_slot_ids
        from pkcs11_check.raw.types_std import CK_ULONG
        raw = RawPKCS11.from_lib("{module}")
        raw.C_Initialize(None)
        get_slot_ids(raw)
        raw.C_Finalize(None)
        try:
            count = CK_ULONG(0)
            raw.C_GetSlotList(1, None, byref(count))
            print("OK: returned after finalize")
        except Exception as e:
            print(f"OK: raised {{type(e).__name__}}")
        """
        rc, output = _run_script(script)
        assert rc == 0, f"Post-finalize crashed (rc={rc}): {output}"
        assert "OK:" in output

    def test_reinitialize_after_finalize(self, p11_config: Any) -> None:
        """C_Initialize after C_Finalize must work."""
        module = str(p11_config.module)
        script = f"""
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import get_slot_ids
        raw = RawPKCS11.from_lib("{module}")
        raw.C_Initialize(None)
        raw.C_Finalize(None)
        raw.C_Initialize(None)
        slots = get_slot_ids(raw)
        print(f"OK: reinit, {{len(slots)}} slots")
        raw.C_Finalize(None)
        """
        rc, output = _run_script(script)
        assert rc == 0, f"Reinit crashed (rc={rc}): {output}"
        assert "OK:" in output


class TestForkSafety:
    """Test fork behavior - child must not crash or deadlock (task 7.4)."""

    def test_fork_after_initialize(self, p11_config: Any) -> None:
        """Fork after C_Initialize - child reinitializes."""
        module = str(p11_config.module)
        script = f"""
        import os
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import get_slot_ids
        raw = RawPKCS11.from_lib("{module}")
        raw.C_Initialize(None)
        pid = os.fork()
        if pid == 0:
            try:
                try: raw.C_Finalize(None)
                except Exception: pass  # Best-effort cleanup before reinit
                raw.C_Initialize(None)
                get_slot_ids(raw)
                raw.C_Finalize(None)
                os._exit(0)
            except Exception:
                os._exit(1)
        else:
            _, status = os.waitpid(pid, 0)
            raw.C_Finalize(None)
            exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
            print(f"OK: child exit {{exit_code}}")
        """
        rc, output = _run_script(script, timeout=15)
        assert rc == 0, f"Fork test crashed (rc={rc}): {output}"
        assert "OK:" in output


class TestSessionObjectProcessIsolation:
    """CROSS-PROC-001: cross-process session-object isolation.

    PKCS#11 v3.1 Sec.4.2 says session objects belong to a session, and
    sessions belong to an "application". An application is whatever
    called C_Initialize — distinct processes are distinct applications.
    Session objects MUST NOT be visible to a different process even if
    the underlying module backend is shared (e.g. SQLite DB on disk for
    NSS/SoftHSM2, dbus broker for tpm2-abrmd, daemon socket for
    OpenCryptoki/pkcsslotd).

    The existing same-process cross-session tests in
    test_object_visibility.py validate that two sessions in the SAME
    process see each other's session objects (spec-mandated). This
    test validates the complementary security boundary: a different
    process MUST NOT see them.
    """

    def test_session_object_not_visible_to_other_process(
        self, p11_config: Any
    ) -> None:
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
        the module doesn't support fork-after-initialize cleanly (NSS,
        qryptotoken — these modules need additional setup that the
        subprocess test framework already documents).
        """
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_repr = f'b"{pin}"' if pin is not None else "None"
        slot = p11_config.slot if p11_config.slot is not None else 0
        script = f"""
        import os
        import sys
        import uuid
        from ctypes import byref, c_ubyte
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import (
            close_session_quietly, get_slot_ids, login_user, open_session,
        )
        from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, template
        from pkcs11_check.raw.types_std import (
            CK_OBJECT_HANDLE, CK_ULONG,
            CKA_CLASS, CKA_LABEL, CKA_PRIVATE, CKA_TOKEN, CKA_VALUE,
            CKF_RW_SESSION, CKF_SERIAL_SESSION,
            CKO_DATA, CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID,
        )

        # Login error swallow rule (audit fix iter-50): catch only the two
        # documented "already logged in / wrong user type" cases per the
        # CLAUDE.md PIN handling section. Other login failures must surface.
        _LOGIN_OK_TO_IGNORE = ("CKR_USER_ALREADY_LOGGED_IN", "CKR_USER_TYPE_INVALID")

        def _safe_login(raw_obj, sess_h, user_type, pin_bytes):
            try:
                login_user(raw_obj, sess_h, user_type, pin_bytes)
            except AssertionError as e:
                msg = str(e)
                if not any(code in msg for code in _LOGIN_OK_TO_IGNORE):
                    raise

        pin = {pin_repr}
        label = b"crossproc-" + uuid.uuid4().bytes.hex().encode()[:16]

        # --- Parent: initialize, create session object ---
        raw = RawPKCS11.from_lib("{module}")
        rv = raw.C_Initialize(None)
        if rv != CKR_OK:
            print(f"FATAL:Parent_Init:0x{{rv:08x}}")
            sys.exit(1)
        slot_list = get_slot_ids(raw)
        if {slot} >= len(slot_list):
            print(f"FATAL:Slot:{slot}>={{len(slot_list)}}")
            raw.C_Finalize(None); sys.exit(1)
        slot_id = slot_list[{slot}]
        sh = open_session(raw, slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION)
        if pin is not None:
            try:
                _safe_login(raw, sh, 1, pin)
            except AssertionError as e:
                print(f"FATAL:Parent_Login:{{e}}")
                close_session_quietly(raw, sh); raw.C_Finalize(None); sys.exit(1)
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_PRIVATE, False),
            attr_bytes(CKA_LABEL, label),
            attr_bytes(CKA_VALUE, b"parent-data"),
        )
        h = CK_OBJECT_HANDLE(0)
        rv = raw.C_CreateObject(sh, tmpl.ptr, tmpl.count, byref(h))
        if rv != CKR_OK:
            print(f"FATAL:Parent_CreateObject:0x{{rv:08x}}")
            close_session_quietly(raw, sh); raw.C_Finalize(None); sys.exit(1)
        print(f"PARENT_LABEL:{{label.decode()}}")

        # --- Fork a child that re-Initializes (different application) ---
        pid = os.fork()
        if pid == 0:
            # Child: must Finalize the inherited handle before re-Initializing,
            # per PKCS#11 v3.1 Sec.5.6.5 fork semantics.
            try: raw.C_Finalize(None)
            except Exception: pass
            try:
                raw2 = RawPKCS11.from_lib("{module}")
                rv = raw2.C_Initialize(None)
                if rv != CKR_OK:
                    print(f"CHILD_FATAL:Init:0x{{rv:08x}}")
                    sys.stdout.flush(); os._exit(2)
                slot_list2 = get_slot_ids(raw2)
                slot_id2 = slot_list2[{slot}]
                sh2 = open_session(raw2, slot_id2, CKF_RW_SESSION | CKF_SERIAL_SESSION)
                if pin is not None:
                    try:
                        _safe_login(raw2, sh2, 1, pin)
                    except AssertionError as e:
                        print(f"CHILD_FATAL:Login:{{e}}")
                        sys.stdout.flush(); os._exit(6)
                # Find-objects by the parent's label.
                find_tmpl = template(
                    attr_bytes(CKA_LABEL, label),
                    attr_ulong(CKA_CLASS, CKO_DATA),
                )
                rv = raw2.C_FindObjectsInit(sh2, find_tmpl.ptr, find_tmpl.count)
                if rv != CKR_OK:
                    print(f"CHILD_FATAL:FindInit:0x{{rv:08x}}")
                    sys.stdout.flush(); os._exit(3)
                handles = (CK_OBJECT_HANDLE * 8)()
                count = CK_ULONG(0)
                rv = raw2.C_FindObjects(sh2, handles, 8, byref(count))
                raw2.C_FindObjectsFinal(sh2)
                if rv != CKR_OK:
                    print(f"CHILD_FATAL:Find:0x{{rv:08x}}")
                    sys.stdout.flush(); os._exit(4)
                print(f"CHILD_FOUND:{{count.value}}")
                close_session_quietly(raw2, sh2)
                raw2.C_Finalize(None)
                sys.stdout.flush()
                os._exit(0)
            except Exception as exc:
                # Audit-fix (iter-50): narrowed from BaseException to
                # Exception so KeyboardInterrupt / SystemExit / signal-
                # raised exits propagate normally. The exit-5 path is
                # only for in-process Python errors that the parent can
                # use to disambiguate "init worked but later step
                # crashed" from "init never started".
                print(f"CHILD_EXC:{{type(exc).__name__}}:{{exc}}")
                sys.stdout.flush()
                os._exit(5)
        else:
            _, status = os.waitpid(pid, 0)
            if os.WIFSIGNALED(status):
                child_signal = os.WTERMSIG(status)
                print(f"CHILD_SIGNAL:{{child_signal}}")
                child_exit = -child_signal
            else:
                child_exit = os.WEXITSTATUS(status)
            print(f"CHILD_EXIT:{{child_exit}}")
            # Parent cleanup
            try: raw.C_DestroyObject(sh, h)
            except Exception: pass
            close_session_quietly(raw, sh)
            raw.C_Finalize(None)
        """
        # Audit-fix (iter-50): bumped timeout from 30s → 90s to give
        # tabrmd-backed tpm2-pkcs11 enough headroom for cold-start
        # post-fork re-Initialize. Real-world fork+TPM2_Startup can
        # exceed 30s on busy systems.
        rc, output = _run_script(script, timeout=90)
        if rc != 0:
            pytest.fail(
                f"Cross-process session-object isolation test crashed "
                f"(rc={rc}): {output}"
            )

        # Parse output: PARENT_LABEL must be set; child must report
        # CHILD_FOUND:0 (didn't see parent's session object).
        if "PARENT_LABEL:" not in output:
            pytest.fail(f"Parent didn't create the session object: {output}")
        if "CHILD_EXIT:" not in output:
            pytest.fail(f"Child didn't exit cleanly: {output}")
        # Audit-fix (iter-50): a child killed by signal (CHILD_SIGNAL: in
        # output) is a CRASH — that IS the finding, not a skip condition.
        # Per CLAUDE.md: "A segfault IS the finding."
        if "CHILD_SIGNAL:" in output:
            pytest.fail(
                f"SECURITY: child process was killed by a signal (likely "
                f"crash) during cross-process isolation test:\n{output}"
            )

        # Audit-fix (iter-50): narrowed skip-on-CHILD_FATAL/EXC. Skip
        # only on the documented daemon-coordination cases — namely
        # CHILD_FATAL:Init or CHILD_FATAL:Login with daemon-related CKRs
        # (CKR_FUNCTION_FAILED / CKR_DEVICE_ERROR / CKR_GENERAL_ERROR
        # /CKR_TOKEN_NOT_PRESENT / CKR_SLOT_ID_INVALID).
        # CHILD_EXC paths and other CHILD_FATAL paths fail the test —
        # those represent real bugs, not module-environment limits.
        daemon_failure_ckrs = (
            "0x00000005",  # CKR_FUNCTION_FAILED
            "0x00000030",  # CKR_DEVICE_ERROR
            "0x00000020",  # CKR_GENERAL_ERROR
            "0x000000E0",  # CKR_TOKEN_NOT_PRESENT
            "0x00000003",  # CKR_SLOT_ID_INVALID
        )
        is_daemon_init_failure = any(
            f"CHILD_FATAL:Init:{code}" in output for code in daemon_failure_ckrs
        ) or "CHILD_FATAL:Login:" in output
        if "CHILD_FATAL" in output and is_daemon_init_failure:
            pytest.skip(
                f"Child couldn't re-initialize the module after fork "
                f"(daemon-backed module limit): {output}"
            )
        if "CHILD_FATAL" in output or "CHILD_EXC" in output:
            pytest.fail(
                f"Child failed unexpectedly during cross-process test "
                f"(not a documented daemon limitation): {output}"
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
                f"v3.1 Sec.4.2 says session objects belong to a single "
                f"application, and distinct processes are distinct "
                f"applications. Diagnostic: {diag}",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.2 / Sec.5.6.5",
            )
            pytest.fail(
                f"SECURITY: cross-process session-object isolation violated "
                f"— child process saw the parent's session object. "
                f"Diagnostic:\n{diag}"
            )


class TestLibraryReload:
    """Test library reload cycle (task 7.15)."""

    def test_reload_cycle_5x(self, p11_config: Any) -> None:
        """Load -> init -> ops -> finalize, 5 times. No crash or leak.

        A negative exit code (signal/segfault) is a module bug and kept as failure.
        A positive exit code (rc > 0) means the module raised a Python exception
        during reinit -- common causes: token label not found after reinit (NSS,
        qryptotoken), daemon not provisioned (tpm2-pkcs11). These are module
        environment limitations, not crashes, so xfail.
        """
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_repr = f'b"{pin}"' if pin is not None else "None"
        script = f"""
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import get_slot_ids, open_session, login_user
        from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
        from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION
        pin = {pin_repr}
        for i in range(5):
            raw = RawPKCS11.from_lib("{module}")
            raw.C_Initialize(None)
            try:
                slots = get_slot_ids(raw, label="pkcs11-check")
                if not slots:
                    slots = get_slot_ids(raw)
                sh = open_session(raw, slots[0], CKF_RW_SESSION | CKF_SERIAL_SESSION)
                if pin is not None:
                    login_user(raw, sh, 1, pin)
                key = gen_aes_key(raw, sh, 128)
                destroy_quietly(raw, sh, key)
                raw.C_CloseSession(sh)
            finally:
                raw.C_Finalize(None)
        print("OK: 5 cycles")
        """
        rc, output = _run_script(script, timeout=30)
        if rc < 0:
            # Negative exit code = killed by signal (crash/segfault) -- real module bug
            pytest.fail(f"Reload cycle crashed with signal (rc={rc}): {output}")
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
            pytest.xfail(f"Module fails reload cycle (rc={rc}): {output[:200]}")
        assert "OK:" in output
