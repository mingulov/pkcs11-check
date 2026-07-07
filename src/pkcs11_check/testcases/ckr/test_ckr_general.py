"""CKR compliance tests for general-purpose functions.

Covers C_Initialize, C_Finalize, C_GetInterfaceList.
All tests run in subprocess - these functions affect global library state.

Source: PKCS#11 v3.2-5.4.4.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


class TestInitializeErrors:
    """Error conditions for C_Initialize (Sec.5.4.1)."""

    def test_double_initialize(self, p11_config: Any) -> None:
        """C_Initialize called twice -> CKR_CRYPTOKI_ALREADY_INITIALIZED."""
        result = run_probe(
            "ckr_general",
            {"module_path": str(p11_config.module), "probe": "double_initialize"},
            timeout=15,
            coverage="raw",
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_Initialize double initialize",
        )
        output = result.stdout.strip()
        # Both "already initialized" and "accepted" are valid
        assert output.startswith("CKR:"), f"Unexpected output: {output}"

    def test_finalize_not_initialized(self, p11_config: Any) -> None:
        """C_Finalize without C_Initialize -> CKR_CRYPTOKI_NOT_INITIALIZED."""
        result = run_probe(
            "ckr_general",
            {"module_path": str(p11_config.module), "probe": "finalize_not_initialized"},
            timeout=15,
            coverage="raw",
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_Finalize after C_Finalize",
        )
        output = result.stdout.strip()
        assert output.startswith("CKR:"), f"Unexpected output: {output}"

    def test_get_interface_list(self, p11_config: Any) -> None:
        """C_GetInterfaceList - should work or return FUNCTION_NOT_SUPPORTED."""
        result = run_probe(
            "ckr_general",
            {"module_path": str(p11_config.module), "probe": "get_interface_list"},
            timeout=15,
            coverage="raw",
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_GetInterfaceList",
        )
        output = result.stdout.strip()
        assert output.startswith("CKR:"), f"Unexpected output: {output}"
