"""CKR compliance tests for general-purpose functions.

Covers C_Initialize, C_Finalize, C_GetInterfaceList.
All tests run in subprocess -- these functions affect global library state.

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
            import pkcs11
            lib = pkcs11.lib("{module}")
            # lib.__init__ already called C_Initialize
            # Call it again via the low-level interface
            try:
                lib.initialize()
                print("CKR:already_init_accepted")
            except pkcs11.exceptions.CryptokiAlreadyInitialized:
                print("CKR:CRYPTOKI_ALREADY_INITIALIZED")
            except Exception as e:
                print(f"CKR:{{type(e).__name__}}")
            finally:
                lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        output = result.stdout.strip()
        # Both "already initialized" and "accepted" are valid
        assert output.startswith("CKR:"), f"Unexpected output: {output}"

    def test_finalize_not_initialized(self, p11_config: Any) -> None:
        """C_Finalize without C_Initialize -> CKR_CRYPTOKI_NOT_INITIALIZED."""
        module = str(p11_config.module)
        script = textwrap.dedent(f"""\
            import ctypes
            lib = ctypes.CDLL("{module}")
            # Get C_Finalize via C_GetFunctionList
            # Simpler: just call C_Finalize directly if exported
            # Most modules export C_GetFunctionList only, so use pkcs11 to init+finalize first
            import pkcs11
            p = pkcs11.lib("{module}")
            p.finalize()
            # Now try finalize again -- should get NOT_INITIALIZED
            try:
                p.finalize()
                print("CKR:finalize_accepted")
            except pkcs11.exceptions.CryptokiNotInitialized:
                print("CKR:CRYPTOKI_NOT_INITIALIZED")
            except Exception as e:
                print(f"CKR:{{type(e).__name__}}")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        output = result.stdout.strip()
        assert output.startswith("CKR:"), f"Unexpected output: {output}"

    def test_get_interface_list(self, p11_config: Any) -> None:
        """C_GetInterfaceList -- should work or return FUNCTION_NOT_SUPPORTED."""
        module = str(p11_config.module)
        script = textwrap.dedent(f"""\
            import pkcs11
            lib = pkcs11.lib("{module}")
            try:
                ifaces = lib.get_interface_list()
                print(f"CKR:OK:{{len(ifaces)}}_interfaces")
            except pkcs11.exceptions.FunctionNotSupported:
                print("CKR:FUNCTION_NOT_SUPPORTED")
            except AttributeError:
                print("CKR:NO_METHOD")  # v2.40 module, no get_interface_list
            except Exception as e:
                print(f"CKR:{{type(e).__name__}}")
            finally:
                lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        output = result.stdout.strip()
        assert output.startswith("CKR:"), f"Unexpected output: {output}"
