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

from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

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
        result = run_probe(
            "ckr_null_params",
            {"module_path": str(p11_config.module), "probe": "get_info"},
            timeout=10,
            coverage="raw",
        )
        _check_null_result("C_GetInfo", result.returncode, result.stdout, result.stderr)

    def test_get_slot_list_null_count(self, p11_config: Any) -> None:
        """C_GetSlotList(1, NULL, NULL) -> CKR_ARGUMENTS_BAD or segfault."""
        result = run_probe(
            "ckr_null_params",
            {"module_path": str(p11_config.module), "probe": "get_slot_list"},
            timeout=10,
            coverage="raw",
        )
        _check_null_result("C_GetSlotList", result.returncode, result.stdout, result.stderr)

    def test_open_session_null_handle(self, p11_config: Any) -> None:
        """C_OpenSession with NULL phSession -> CKR_ARGUMENTS_BAD or segfault.

        Most modules don't export C_OpenSession as a direct symbol - only via
        CK_FUNCTION_LIST. The probe runs at Level.SESSION (init + slot discovery,
        no login), then resolves the direct exported symbol and calls it with a
        NULL output handle; a module that doesn't export it emits ``:not_exported``.
        """
        module = str(p11_config.module)
        result = run_probe(
            "ckr_null_params_session",
            {
                "module_path": module,
                "slot_id": p11_config.slot,
                "extra": {"module_path": module},
            },
            timeout=15,
            coverage="session",
        )
        _check_null_result("C_OpenSession", result.returncode, result.stdout, result.stderr)

    def test_generate_random_null_buffer(self, p11_config: Any) -> None:
        """C_GenerateRandom with NULL buffer -> CKR_ARGUMENTS_BAD or segfault.

        Runs at Level.LOGIN: the probe infra opens a logged-in session (the PIN
        travels only via the ``_P11CHECK_PIN`` env var, never embedded in source or
        params -- Invariant I3), then the probe calls the direct exported symbol with
        a NULL buffer.
        """
        module = str(p11_config.module)
        result = run_probe(
            "ckr_null_params_login",
            {
                "module_path": module,
                "slot_id": p11_config.slot,
                "extra": {"module_path": module},
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        _check_null_result("C_GenerateRandom", result.returncode, result.stdout, result.stderr)
