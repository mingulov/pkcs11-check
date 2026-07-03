"""CKR tests for v3.0 functions via raw ctypes calls.

Tests C_MessageEncryptInit, C_MessageDecryptInit, C_MessageSignInit,
C_MessageVerifyInit, C_EncryptMessage, C_SessionCancel using RawPKCS11
with funclist3_ptr for v3.0 function access.

Requires v3.0+ module. Skips on v2.40 modules.

Each test launches the ``ckr_v30_raw`` probe module (``_probes/ckr_v30_raw.py``) via
``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a PIN is
configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var
(never embedded in source or params -- Invariant I3).  This CLOSES the legacy leak that
formatted the PIN literal into the generated child-script source.  The probe drives the
per-test v3.0 call and prints the resulting ``CKR:0x...`` line for the ``_check`` classifier.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    result = run_probe(
        "ckr_v30_raw",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


def _check(rc: int, out: str, err: str, func: str) -> None:
    if "SKIP:" in out:
        pytest.skip(out.split("SKIP:")[1])
    if rc < 0:
        fail_as(
            "crash",
            label=func,
            summary=f"{func}: subprocess crashed with signal {-rc}; stderr: {err[-300:]}",
        )
    if rc != 0:
        fail_as(
            "crash",
            label=func,
            summary=(
                f"{func}: subprocess failed with exit code {rc}; "
                f"stdout: {out[-300:]}; stderr: {err[-300:]}"
            ),
        )
    assert "OK" in out, f"{func}: {out} | {err[-200:]}"


@pytest.mark.needs_function("C_MessageEncryptInit")
class TestMessageEncryptErrors:
    """v3.0 C_MessageEncryptInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageEncryptInit with digest mechanism -> CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "message_encrypt_mech_invalid")
        _check(rc, out, err, "C_MessageEncryptInit")

    def test_operation_not_initialized(self, p11_config: Any) -> None:
        """C_EncryptMessage without Init -> CKR_OPERATION_NOT_INITIALIZED."""
        rc, out, err = _run_probe(p11_config, "encrypt_message_no_init")
        _check(rc, out, err, "C_EncryptMessage")


@pytest.mark.needs_function("C_MessageDecryptInit")
class TestMessageDecryptErrors:
    """v3.0 C_MessageDecryptInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageDecryptInit with digest mechanism."""
        rc, out, err = _run_probe(p11_config, "message_decrypt_mech_invalid")
        _check(rc, out, err, "C_MessageDecryptInit")


@pytest.mark.needs_function("C_MessageSignInit")
class TestMessageSignErrors:
    """v3.0 C_MessageSignInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageSignInit with encrypt mechanism."""
        rc, out, err = _run_probe(p11_config, "message_sign_mech_invalid")
        _check(rc, out, err, "C_MessageSignInit")


@pytest.mark.needs_function("C_MessageVerifyInit")
class TestMessageVerifyErrors:
    """v3.0 C_MessageVerifyInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageVerifyInit with encrypt mechanism."""
        rc, out, err = _run_probe(p11_config, "message_verify_mech_invalid")
        _check(rc, out, err, "C_MessageVerifyInit")


@pytest.mark.needs_function("C_SessionCancel")
class TestSessionCancelErrors:
    """v3.0 C_SessionCancel error conditions."""

    def test_cancel_no_operation(self, p11_config: Any) -> None:
        """C_SessionCancel with no active operation."""
        rc, out, err = _run_probe(p11_config, "session_cancel_no_operation")
        _check(rc, out, err, "C_SessionCancel")
