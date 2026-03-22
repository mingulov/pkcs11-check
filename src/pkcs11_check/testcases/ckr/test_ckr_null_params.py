"""CKR NULL parameter tests via ctypes.

Tests that C_* functions properly validate NULL pointers and return
CKR_ARGUMENTS_BAD (0x00000007) instead of segfaulting.

All tests run in subprocess - modules may crash on NULL parameters.
A segfault (returncode < 0) is recorded as "module doesn't validate
NULL params" - that's a valid test finding, not a test failure.

Source: PKCS#11 v3.1 Sec.5.1.6 (CKR_ARGUMENTS_BAD).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.ckr._ctypes_raw import CKR_ARGUMENTS_BAD, run_null_test

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _check_null_result(
    func_name: str,
    rc: int,
    out: str,
    err: str,
) -> None:
    """Validate NULL parameter test result.

    Expected outcomes:
    - CKR_ARGUMENTS_BAD (0x07): correct per spec
    - Other CKR: module validates but returns different error (acceptable)
    - Segfault (rc < 0): module doesn't validate NULL (finding, not failure)
    """
    if rc < 0:
        # Segfault - record as compliance finding
        from pkcs11_check.compliance import ComplianceLevel, note
        note(
            f"{func_name}(NULL): segfault (signal {-rc})",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="PKCS#11 v3.1 Sec.5.1.6: CKR_ARGUMENTS_BAD",
        )
        return  # Not a test failure - it's a finding

    # Parse CKR from stdout
    assert "CKR:" in out, f"{func_name}: unexpected output: {out} | stderr: {err}"
    ckr_str = out.split("CKR:")[1].split(":")[0].strip()
    ckr = int(ckr_str, 16)

    if ckr == CKR_ARGUMENTS_BAD:
        pass  # Correct per spec
    elif ckr == 0:  # CKR_OK
        # Module accepted NULL - compliance deviation
        from pkcs11_check.compliance import ComplianceLevel, note
        note(
            f"{func_name}(NULL): accepted without error",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="PKCS#11 v3.1 Sec.5.1.6: CKR_ARGUMENTS_BAD",
        )
    else:
        # Other CKR - module validates but returns different error
        from pkcs11_check.compliance import ComplianceLevel, note
        note(
            f"{func_name}(NULL): returned CKR 0x{ckr:08x} (expected ARGUMENTS_BAD)",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="PKCS#11 v3.1 Sec.5.1.6: CKR_ARGUMENTS_BAD",
        )


class TestNullParameters:
    """NULL pointer parameter tests for C_* functions."""

    def test_get_info_null(self, p11_config: Any) -> None:
        """C_GetInfo(NULL) -> CKR_ARGUMENTS_BAD or segfault."""
        rc, out, err = run_null_test(
            str(p11_config.module),
            'rv = call_func("C_GetInfo", c_void_p(None))\n'
            'print(f"CKR:0x{rv:08x}")',
        )
        _check_null_result("C_GetInfo", rc, out, err)

    def test_get_slot_list_null_count(self, p11_config: Any) -> None:
        """C_GetSlotList(1, NULL, NULL) -> CKR_ARGUMENTS_BAD or segfault."""
        rc, out, err = run_null_test(
            str(p11_config.module),
            'rv = call_func("C_GetSlotList", c_ubyte(1), c_void_p(None), c_void_p(None))\n'
            'print(f"CKR:0x{rv:08x}")',
        )
        _check_null_result("C_GetSlotList", rc, out, err)

    def test_open_session_null_handle(self, p11_config: Any) -> None:
        """C_OpenSession with NULL phSession -> CKR_ARGUMENTS_BAD or segfault.

        Most modules don't export C_OpenSession as a direct symbol - only
        via CK_FUNCTION_LIST. Uses pkcs11 wrapper to get slot, then tries
        raw ctypes. Skips if function not directly exported.
        """
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        import subprocess
        import sys
        import textwrap
        script = textwrap.dedent(f"""\
            import pkcs11
            import ctypes
            lib = pkcs11.lib("{module}")
            slots = lib.get_slots(token_present=True)
            if not slots:
                print("CKR:0x00000000:no_slots")
            else:
                slot_id = slots[0].slot_id
                # Load raw .so and call C_OpenSession with NULL phSession
                raw = ctypes.CDLL("{module}")
                try:
                    C_OpenSession = raw.C_OpenSession
                except AttributeError:
                    print("CKR:0x00000000:not_exported")
                    lib.finalize()
                    exit(0)
                C_OpenSession.restype = ctypes.c_ulong
                C_OpenSession.argtypes = [
                    ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                    ctypes.c_void_p, ctypes.c_void_p,
                ]
                rv = C_OpenSession(slot_id, 0x06, None, None, None)
                print(f"CKR:0x{{rv:08x}}")
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        _check_null_result("C_OpenSession", result.returncode, result.stdout.strip(), result.stderr)

    def test_generate_random_null_buffer(self, p11_config: Any) -> None:
        """C_GenerateRandom with NULL buffer -> CKR_ARGUMENTS_BAD or segfault."""
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"
        import subprocess
        import sys
        import textwrap
        script = textwrap.dedent(f"""\
            import pkcs11
            import ctypes
            lib = pkcs11.lib("{module}")
            slots = lib.get_slots(token_present=True)
            if not slots:
                print("CKR:0x00000000:no_slots")
            else:
                token = slots[0].get_token()
                pin = {pin_arg}
                session = token.open(rw=True, user_pin=pin) if pin else token.open(rw=True)
                # Get session handle for raw call
                sess_handle = session.handle
                raw = ctypes.CDLL("{module}")
                try:
                    C_GenerateRandom = raw.C_GenerateRandom
                except AttributeError:
                    print("CKR:0x00000000:not_exported")
                    session.close()
                    lib.finalize()
                    exit(0)
                C_GenerateRandom.restype = ctypes.c_ulong
                C_GenerateRandom.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
                rv = C_GenerateRandom(sess_handle, None, 32)
                print(f"CKR:0x{{rv:08x}}")
                session.close()
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        _check_null_result("C_GenerateRandom", result.returncode, result.stdout.strip(), result.stderr)
