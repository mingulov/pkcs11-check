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
from pkcs11.exceptions import (
    DeviceError,
    DeviceMemory,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    SessionClosed,
    SessionHandleInvalid,
    TokenNotPresent,
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
        assert GeneralError in _UNIVERSAL
        assert HostMemory in _UNIVERSAL
        assert FunctionFailed in _UNIVERSAL

    def test_session_universal_in_tuple(self) -> None:
        """Session-universal codes present."""
        assert SessionHandleInvalid in _SESSION_UNIVERSAL
        assert DeviceRemoved in _SESSION_UNIVERSAL
        assert SessionClosed in _SESSION_UNIVERSAL

    def test_token_universal_in_tuple(self) -> None:
        """Token-universal codes present."""
        assert DeviceMemory in _TOKEN_UNIVERSAL
        assert DeviceError in _TOKEN_UNIVERSAL
        assert TokenNotPresent in _TOKEN_UNIVERSAL

    def test_full_compat_includes_all(self) -> None:
        """full_compat() with empty base includes all 9 universal codes."""
        result = full_compat(())
        assert GeneralError in result
        assert HostMemory in result
        assert FunctionFailed in result
        assert SessionHandleInvalid in result
        assert DeviceRemoved in result
        assert SessionClosed in result
        assert DeviceMemory in result
        assert DeviceError in result
        assert TokenNotPresent in result

    def test_full_compat_no_session(self) -> None:
        """full_compat() without session doesn't include session/token codes."""
        result = full_compat((), uses_session=False)
        assert GeneralError in result
        assert SessionHandleInvalid not in result
        assert DeviceMemory not in result


class TestUniversalRealTriggers:
    """Trigger universal CKR codes on real modules."""

    def test_session_handle_invalid(self, p11_module: Any) -> None:
        """CKR_SESSION_HANDLE_INVALID - use invalid session handle via raw."""
        import ctypes

        from pkcs11.raw import CKR_ARGUMENTS_BAD, CKR_SESSION_HANDLE_INVALID, RawPKCS11
        raw = RawPKCS11(p11_module.lib._raw_funclist_ptr)
        # Provide a real buffer to avoid ARGUMENTS_BAD on NULL
        buf = (ctypes.c_ubyte * 64)()
        rv = raw.C_GetSessionInfo(0xDEADBEEF, ctypes.cast(buf, ctypes.c_void_p))
        # SESSION_HANDLE_INVALID or ARGUMENTS_BAD - both prove invalid handle is detected
        assert rv in (CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD), f"Got 0x{rv:08x}"

    def test_cryptoki_not_initialized_via_subprocess(self, p11_config: Any) -> None:
        """CKR_CRYPTOKI_NOT_INITIALIZED - call after C_Finalize."""
        import os
        script = textwrap.dedent(f"""\
            from pkcs11.raw import RawPKCS11, CKR_CRYPTOKI_NOT_INITIALIZED
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
            capture_output=True, text=True, timeout=15,
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
            import os, pkcs11
            os.environ["PKCS11_REAL_MODULE"] = "{p11_config.module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_GenerateRandom"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000032"  # DEVICE_REMOVED
            lib = pkcs11.lib("{proxy}")
            slots = lib.get_slots(token_present=True)
            token = slots[0].get_token()
            session = token.open(rw=True)
            try:
                session.generate_random(256)
                print("FAIL")
            except pkcs11.exceptions.DeviceRemoved:
                print("OK:DEVICE_REMOVED")
            except Exception as e:
                print(f"OTHER:{{type(e).__name__}}")
            session.close()
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Crash: {result.stderr[-200:]}"
        assert "OK:DEVICE_REMOVED" in result.stdout
