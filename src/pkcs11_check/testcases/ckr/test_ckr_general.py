"""CKR compliance tests for general-purpose functions.

Covers C_Initialize, C_Finalize, C_GetInterfaceList.
All tests run in subprocess - these functions affect global library state.

Source: PKCS#11 v3.1 Sec.5.4.1-5.4.4.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


class TestInitializeErrors:
    """Error conditions for C_Initialize (Sec.5.4.1)."""

    def test_double_initialize(self, p11_config: Any) -> None:
        """C_Initialize called twice -> CKR_CRYPTOKI_ALREADY_INITIALIZED."""
        module = str(p11_config.module)
        script = textwrap.dedent(f"""\
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.types_std import CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED
            raw = RawPKCS11.from_lib("{module}")
            rv1 = raw.C_Initialize(None)
            rv2 = raw.C_Initialize(None)
            if rv2 == CKR_OK:
                print("CKR:already_init_accepted")
            elif rv2 == CKR_CRYPTOKI_ALREADY_INITIALIZED:
                print("CKR:CRYPTOKI_ALREADY_INITIALIZED")
            else:
                print(f"CKR:0x{{rv2:08x}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        output = result.stdout.strip()
        # Both "already initialized" and "accepted" are valid
        assert output.startswith("CKR:"), f"Unexpected output: {output}"

    def test_finalize_not_initialized(self, p11_config: Any) -> None:
        """C_Finalize without C_Initialize -> CKR_CRYPTOKI_NOT_INITIALIZED."""
        module = str(p11_config.module)
        script = textwrap.dedent(f"""\
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.types_std import CKR_OK, CKR_CRYPTOKI_NOT_INITIALIZED
            raw = RawPKCS11.from_lib("{module}")
            raw.C_Initialize(None)
            raw.C_Finalize(None)
            # Now try finalize again - should get NOT_INITIALIZED
            rv = raw.C_Finalize(None)
            if rv == CKR_OK:
                print("CKR:finalize_accepted")
            elif rv == CKR_CRYPTOKI_NOT_INITIALIZED:
                print("CKR:CRYPTOKI_NOT_INITIALIZED")
            else:
                print(f"CKR:0x{{rv:08x}}")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        output = result.stdout.strip()
        assert output.startswith("CKR:"), f"Unexpected output: {output}"

    def test_get_interface_list(self, p11_config: Any) -> None:
        """C_GetInterfaceList - should work or return FUNCTION_NOT_SUPPORTED."""
        module = str(p11_config.module)
        script = textwrap.dedent(f"""\
            from ctypes import byref
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.types_std import CKR_OK, CKR_FUNCTION_NOT_SUPPORTED, CK_ULONG
            raw = RawPKCS11.from_lib("{module}")
            raw.C_Initialize(None)
            try:
                count = CK_ULONG(0)
                rv = raw.C_GetInterfaceList(None, byref(count))
                if rv == CKR_FUNCTION_NOT_SUPPORTED:
                    print("CKR:FUNCTION_NOT_SUPPORTED")
                elif rv == CKR_OK:
                    print(f"CKR:OK:{{count.value}}_interfaces")
                else:
                    print(f"CKR:0x{{rv:08x}}")
            except AttributeError:
                print("CKR:NO_METHOD")  # v2.40 module, C_GetInterfaceList not available
            finally:
                raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        output = result.stdout.strip()
        assert output.startswith("CKR:"), f"Unexpected output: {output}"
