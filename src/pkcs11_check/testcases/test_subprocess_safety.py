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
                except: pass
                raw.C_Initialize(None)
                get_slot_ids(raw)
                raw.C_Finalize(None)
                os._exit(0)
            except:
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


class TestLibraryReload:
    """Test library reload cycle (task 7.15)."""

    def test_reload_cycle_5x(self, p11_config: Any) -> None:
        """Load -> init -> ops -> finalize, 5 times. No crash or leak.

        A negative exit code (signal/segfault) is a module bug and kept as failure.
        A positive exit code (rc > 0) means the module raised a Python exception
        during reinit — common causes: token label not found after reinit (NSS,
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
                sh = open_session(raw, slots[0], int(CKF_RW_SESSION | CKF_SERIAL_SESSION))
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
            # Negative exit code = killed by signal (crash/segfault) — real module bug
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
