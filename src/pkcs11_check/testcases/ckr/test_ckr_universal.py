"""CKR universal error code infrastructure tests.

Verifies that the 14 universal CKR codes (returned by any function)
are properly handled by full_compat() and can be triggered on real modules.

These are NOT duplicated per-function - they verify the infrastructure
that handles them across all functions.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_TOKEN_NOT_PRESENT,
)
from pkcs11_check.testcases.ckr._ckr_spec import (
    _SESSION_UNIVERSAL,
    _TOKEN_UNIVERSAL,
    _UNIVERSAL,
    full_compat,
)

pytestmark = pytest.mark.access


class TestUniversalInfrastructure:
    """Verify full_compat() includes all universal CKR codes."""

    def test_universal_codes_in_tuple(self) -> None:
        """All 3 universal codes present in _UNIVERSAL."""
        assert CKR_GENERAL_ERROR in _UNIVERSAL
        assert CKR_HOST_MEMORY in _UNIVERSAL
        assert CKR_FUNCTION_FAILED in _UNIVERSAL

    def test_session_universal_in_tuple(self) -> None:
        """Session-universal codes present."""
        assert CKR_SESSION_HANDLE_INVALID in _SESSION_UNIVERSAL
        assert CKR_DEVICE_REMOVED in _SESSION_UNIVERSAL
        assert CKR_SESSION_CLOSED in _SESSION_UNIVERSAL

    def test_token_universal_in_tuple(self) -> None:
        """Token-universal codes present."""
        assert CKR_DEVICE_MEMORY in _TOKEN_UNIVERSAL
        assert CKR_DEVICE_ERROR in _TOKEN_UNIVERSAL
        assert CKR_TOKEN_NOT_PRESENT in _TOKEN_UNIVERSAL

    def test_full_compat_includes_all(self) -> None:
        """full_compat() with empty base includes all 9 universal codes."""
        result = full_compat(())
        assert CKR_GENERAL_ERROR in result
        assert CKR_HOST_MEMORY in result
        assert CKR_FUNCTION_FAILED in result
        assert CKR_SESSION_HANDLE_INVALID in result
        assert CKR_DEVICE_REMOVED in result
        assert CKR_SESSION_CLOSED in result
        assert CKR_DEVICE_MEMORY in result
        assert CKR_DEVICE_ERROR in result
        assert CKR_TOKEN_NOT_PRESENT in result

    def test_full_compat_no_session(self) -> None:
        """full_compat() without session doesn't include session/token codes."""
        result = full_compat((), uses_session=False)
        assert CKR_GENERAL_ERROR in result
        assert CKR_SESSION_HANDLE_INVALID not in result
        assert CKR_DEVICE_MEMORY not in result


class TestUniversalRealTriggers:
    """Trigger universal CKR codes on real modules."""

    def test_session_handle_invalid(self, p11_raw_session: Any) -> None:
        """CKR_SESSION_HANDLE_INVALID - use invalid session handle via raw."""
        import ctypes

        from pkcs11_check.raw.types_std import (
            CK_SESSION_INFO,
            CKR_ARGUMENTS_BAD,
        )

        rs = p11_raw_session
        session_info = CK_SESSION_INFO()
        rv = rs.raw.C_GetSessionInfo(0xDEADBEEF, ctypes.byref(session_info))
        # SESSION_HANDLE_INVALID or ARGUMENTS_BAD - both prove invalid handle is detected
        assert rv in (
            CKR_SESSION_HANDLE_INVALID,
            CKR_ARGUMENTS_BAD,
        ), f"Got 0x{rv:08x}"

    def test_cryptoki_not_initialized_via_subprocess(self, p11_config: Any) -> None:
        """CKR_CRYPTOKI_NOT_INITIALIZED - call after C_Finalize."""
        import os

        script = textwrap.dedent(f"""\
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.types_std import CKR_CRYPTOKI_NOT_INITIALIZED
            import ctypes
            raw = RawPKCS11.from_lib("{p11_config.module}")
            raw.C_Initialize(None)
            raw.C_Finalize(None)
            # Now call something - should get NOT_INITIALIZED
            sc = ctypes.c_ulong(0)
            rv = raw.C_GetSlotList(1, None, ctypes.byref(sc))
            print(f"CKR:0x{{rv:08x}}")
            assert rv == CKR_CRYPTOKI_NOT_INITIALIZED, f"Got 0x{{rv:08x}}"
            print("OK")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Crash: {result.stderr[-200:]}"
        assert "OK" in result.stdout

    def test_device_removed_via_fault_proxy(self, p11_config: Any) -> None:
        """CKR_DEVICE_REMOVED - triggered via fault-proxy."""
        import os
        from pathlib import Path

        proxy = Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so"
        if not proxy.exists():
            pytest.skip("fault-proxy not built")

        script = textwrap.dedent(f"""\
            import os, ctypes
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.types_std import (
                CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_DEVICE_REMOVED, CKR_OK,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{p11_config.module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_GenerateRandom"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000032"  # DEVICE_REMOVED
            raw = RawPKCS11.from_lib("{proxy}")
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], (CKF_SERIAL_SESSION | CKF_RW_SESSION))
            buf = (ctypes.c_ubyte * 32)()
            rv = raw.C_GenerateRandom(sh, buf, 32)
            if rv == CKR_DEVICE_REMOVED:
                print("OK:DEVICE_REMOVED")
            elif rv == CKR_OK:
                print("FAIL")
            else:
                print(f"OTHER:0x{{rv:08x}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Crash: {result.stderr[-200:]}"
        assert "OK:DEVICE_REMOVED" in result.stdout
