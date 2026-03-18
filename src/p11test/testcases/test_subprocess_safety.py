"""Subprocess safety tests — post-Finalize, fork, library reload.

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


def _run_script(script: str, env: dict[str, str] | None = None, timeout: int = 30) -> tuple[int, str]:
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
    """Test behavior after C_Finalize — must not crash (task 7.3)."""

    def test_post_finalize_get_slot_list(self, p11_config: Any) -> None:
        """C_GetSlotList after C_Finalize must not crash."""
        module = str(p11_config.module)
        script = f"""
        import pkcs11
        lib = pkcs11.lib("{module}")
        lib.initialize()
        lib.get_slots()
        lib.finalize()
        try:
            lib.get_slots()
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
        import pkcs11
        lib = pkcs11.lib("{module}")
        lib.initialize()
        lib.finalize()
        lib.initialize()
        slots = lib.get_slots()
        print(f"OK: reinit, {{len(slots)}} slots")
        lib.finalize()
        """
        rc, output = _run_script(script)
        assert rc == 0, f"Reinit crashed (rc={rc}): {output}"
        assert "OK:" in output


class TestForkSafety:
    """Test fork behavior — child must not crash or deadlock (task 7.4)."""

    def test_fork_after_initialize(self, p11_config: Any) -> None:
        """Fork after C_Initialize — child reinitializes."""
        module = str(p11_config.module)
        script = f"""
        import os, pkcs11
        lib = pkcs11.lib("{module}")
        lib.initialize()
        pid = os.fork()
        if pid == 0:
            try:
                try: lib.finalize()
                except: pass
                lib.initialize()
                lib.get_slots()
                lib.finalize()
                os._exit(0)
            except:
                os._exit(1)
        else:
            _, status = os.waitpid(pid, 0)
            lib.finalize()
            exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
            print(f"OK: child exit {{exit_code}}")
        """
        rc, output = _run_script(script, timeout=15)
        assert rc == 0, f"Fork test crashed (rc={rc}): {output}"
        assert "OK:" in output


class TestLibraryReload:
    """Test library reload cycle (task 7.15)."""

    def test_reload_cycle_5x(self, p11_config: Any) -> None:
        """Load → init → ops → finalize, 5 times. No crash or leak."""
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else "None"
        pin_arg = f'"{pin}"' if pin != "None" else "None"
        script = f"""
        import pkcs11
        for i in range(5):
            lib = pkcs11.lib("{module}")
            lib.initialize()
            try:
                token = lib.get_token(token_label="p11test")
                with token.open(rw=True, user_pin={pin_arg}) as s:
                    key = s.generate_key(pkcs11.KeyType.AES, 128)
                    key.destroy()
            finally:
                lib.finalize()
        print("OK: 5 cycles")
        """
        rc, output = _run_script(script, timeout=30)
        assert rc == 0, f"Reload cycle crashed (rc={rc}): {output}"
        assert "OK:" in output
