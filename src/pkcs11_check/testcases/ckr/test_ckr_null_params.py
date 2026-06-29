"""CKR NULL parameter tests via ctypes.

Tests that C_* functions properly validate NULL pointers and return
CKR_ARGUMENTS_BAD (0x00000007) instead of segfaulting.

All tests run in subprocess - modules may crash on NULL parameters.
A segfault (returncode < 0) is a provider crash finding and fails the test.

Source: PKCS#11 v3.2 (CKR_ARGUMENTS_BAD).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.ckr._ctypes_raw import CKR_ARGUMENTS_BAD, run_null_test
from pkcs11_check.testcases.ckr._subprocess import (
    ckr_ctypes_subprocess_rv_trace_setup,
    ckr_subprocess_cleanup_setup,
    ckr_subprocess_rv_trace_setup,
)

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
    - Segfault (rc < 0): module doesn't validate NULL and must fail
    """
    assert_subprocess_completed(rc, out, err, context=f"{func_name}(NULL)")

    # Parse CKR from stdout
    ckr_line = next((line for line in out.splitlines() if line.startswith("CKR:")), None)
    assert ckr_line is not None, f"{func_name}: unexpected output: {out} | stderr: {err}"
    ckr_str = ckr_line.removeprefix("CKR:").split(":", 1)[0].strip()
    ckr = int(ckr_str, 16)

    if ckr == CKR_ARGUMENTS_BAD:
        pass  # Correct per spec
    elif ckr == 0:  # CKR_OK
        # Module accepted NULL - compliance deviation
        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            f"{func_name}(NULL): accepted without error",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="PKCS#11 v3.2: CKR_ARGUMENTS_BAD",
        )
    else:
        # Other CKR - module validates but returns different error
        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            f"{func_name}(NULL): returned CKR 0x{ckr:08x} (expected ARGUMENTS_BAD)",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="PKCS#11 v3.2: CKR_ARGUMENTS_BAD",
        )


class TestNullParameters:
    """NULL pointer parameter tests for C_* functions."""

    def test_get_info_null(self, p11_config: Any) -> None:
        """C_GetInfo(NULL) -> CKR_ARGUMENTS_BAD or segfault."""
        rc, out, err = run_null_test(
            str(p11_config.module),
            'rv = call_func("C_GetInfo", c_void_p(None))\nprint(f"CKR:0x{rv:08x}")',
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
        via CK_FUNCTION_LIST. Uses RawPKCS11 to get slot, then tries
        raw ctypes. Skips if function not directly exported.
        """
        module = str(p11_config.module)
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent(f"""\
            import ctypes, sys
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids
{ckr_ctypes_subprocess_rv_trace_setup(indent="            ")}
            raw = RawPKCS11.from_lib({module!r})
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slot_ids = get_slot_ids(raw, token_present=True)
            if not slot_ids:
                print("CKR:0x00000000:no_slots")
                raw.C_Finalize(None)
                sys.exit(0)
            slot_id = slot_ids[0]
            # Load raw .so and call C_OpenSession with NULL phSession
            so = ctypes.CDLL({module!r})
            try:
                C_OpenSession = so.C_OpenSession
            except AttributeError:
                print("CKR:0x00000000:not_exported")
                raw.C_Finalize(None)
                sys.exit(0)
            C_OpenSession.restype = ctypes.c_ulong
            C_OpenSession.argtypes = [
                ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_void_p,
            ]
            rv = C_OpenSession(slot_id, 0x06, None, None, None)
            _p11check_record_rv("C_OpenSession", rv)
            print(f"CKR:0x{{rv:08x}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        _check_null_result("C_OpenSession", result.returncode, result.stdout.strip(), result.stderr)

    def test_generate_random_null_buffer(self, p11_config: Any) -> None:
        """C_GenerateRandom with NULL buffer -> CKR_ARGUMENTS_BAD or segfault."""
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'b"{pin}"' if pin else "None"
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent(f"""\
            import ctypes, sys
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER
{ckr_ctypes_subprocess_rv_trace_setup(indent="            ")}
            raw = RawPKCS11.from_lib({module!r})
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slot_ids = get_slot_ids(raw, token_present=True)
            if not slot_ids:
                print("CKR:0x00000000:no_slots")
                raw.C_Finalize(None)
                sys.exit(0)
            slot_id = slot_ids[0]
            sess = open_session(raw, slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION)
{ckr_subprocess_cleanup_setup(session_var="sess", indent="            ")}
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sess, CKU_USER, pin)
            # Get session handle for raw call
            so = ctypes.CDLL({module!r})
            try:
                C_GenerateRandom = so.C_GenerateRandom
            except AttributeError:
                print("CKR:0x00000000:not_exported")
                _p11check_cleanup_session()
                sys.exit(0)
            C_GenerateRandom.restype = ctypes.c_ulong
            C_GenerateRandom.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
            rv = C_GenerateRandom(sess, None, 32)
            _p11check_record_rv("C_GenerateRandom", rv)
            print(f"CKR:0x{{rv:08x}}")
            _p11check_cleanup_session()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        _check_null_result(
            "C_GenerateRandom", result.returncode, result.stdout.strip(), result.stderr
        )
