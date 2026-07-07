"""CKR universal error code infrastructure tests.

Verifies that the 14 universal CKR codes (returned by any function)
are properly handled by full_compat() and can be triggered on real modules.

These are NOT duplicated per-function - they verify the infrastructure
that handles them across all functions.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
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
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases.ckr._ckr_spec import (
    _SESSION_UNIVERSAL,
    _TOKEN_UNIVERSAL,
    _UNIVERSAL,
    full_compat,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

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
        """CKR_CRYPTOKI_NOT_INITIALIZED - call after C_Finalize.

        PKCS#11 v3.2: After C_Finalize, any function call MUST return
        CKR_CRYPTOKI_NOT_INITIALIZED. Some modules return CKR_OK because they
        auto-initialize on each function call (vendor extension). This is an intentional
        design choice, not a crash, but deviates from the PKCS#11 spec.
        """
        result = run_probe(
            "ckr_universal",
            {"module_path": str(p11_config.module), "probe": "not_initialized"},
            timeout=15,
            coverage="session",
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_GetSlotList after C_Finalize",
        )
        assert "OK" in result.stdout
        # CKR_OK after C_Finalize means the module auto-re-initializes.
        if "CKR:0x00000000" in result.stdout:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKR_OK for C_GetSlotList after C_Finalize (expected "
                "CKR_CRYPTOKI_NOT_INITIALIZED), which indicates implicit reinitialization "
                "after finalization.",
                ComplianceLevel.VENDOR,
                reference="PKCS#11 v3.2",
            )
            classify(
                "honest_deviation",
                label="C_GetSlotList:after-finalize",
                operation="C_GetSlotList",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Module auto-initializes after C_Finalize, returning CKR_OK "
                    "instead of CKR_CRYPTOKI_NOT_INITIALIZED (PKCS#11 v3.2)"
                ),
            )

    def test_device_removed_via_fault_proxy(self, p11_config: Any) -> None:
        """CKR_DEVICE_REMOVED - triggered via fault-proxy."""
        import os
        from pathlib import Path

        proxy_candidates = [
            Path("/usr/lib/pkcs11/fault-proxy.so"),
        ]
        _env_proxy = os.environ.get("P11TEST_FAULT_PROXY_SO")
        if _env_proxy:
            proxy_candidates.insert(0, Path(_env_proxy))
        proxy = next((p for p in proxy_candidates if p.exists()), None)
        if proxy is None:
            pytest.skip("fault-proxy not built")

        # module_path is the fault-proxy; the real module + injection config travel as
        # plain data through extra (never a PIN) and are set into the child environment
        # (PKCS11_REAL_MODULE / PKCS11_INJECT_FUNCTION / PKCS11_INJECT_ERROR) before the
        # proxy loads -- the probe module does this in _main, ahead of probe_main.
        result = run_probe(
            "ckr_universal",
            {
                "module_path": str(proxy),
                "probe": "device_removed",
                "real_module": str(p11_config.module),
                "inject_function": "C_GenerateRandom",
                "inject_error": "0x00000032",  # DEVICE_REMOVED
            },
            timeout=15,
            coverage="session",
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy C_GenerateRandom CKR_DEVICE_REMOVED injection",
        )
        assert "OK:DEVICE_REMOVED" in result.stdout
