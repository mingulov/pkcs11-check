"""CKR tests for v3.2 functions via raw ctypes calls.

Tests C_VerifySignatureInit, C_EncapsulateKey, C_DecapsulateKey,
C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated, C_AsyncGetID
using RawPKCS11 with funclist32_ptr.

Requires a v3.2 module. Skips on v2.40/v3.0 modules.

Each test launches the ``ckr_v32_raw`` probe module (``_probes/ckr_v32_raw.py``) via
``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a PIN is
configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var
(never embedded in source or params -- Invariant I3).  This CLOSES the legacy leak that
formatted the PIN literal into the generated child-script source.  The probe drives the
per-test v3.2 call and prints the resulting ``CKR:0x...`` line for the ``_check`` classifier.
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
        "ckr_v32_raw",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=30,
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


@pytest.mark.needs_function("C_VerifySignatureInit")
class TestVerifySignatureErrors:
    """v3.2 C_VerifySignatureInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_VerifySignatureInit with encrypt mechanism -> error."""
        rc, out, err = _run_probe(p11_config, "verify_signature_mech_invalid")
        _check(rc, out, err, "C_VerifySignatureInit")

    def test_operation_not_initialized(self, p11_config: Any) -> None:
        """C_VerifySignature without Init -> CKR_OPERATION_NOT_INITIALIZED."""
        rc, out, err = _run_probe(p11_config, "verify_signature_no_init")
        _check(rc, out, err, "C_VerifySignature")


@pytest.mark.needs_function("C_EncapsulateKey")
class TestEncapsulateKeyErrors:
    """v3.2 C_EncapsulateKey via raw calls."""

    def test_encapsulate_wrong_mechanism(self, p11_config: Any) -> None:
        """C_EncapsulateKey with AES mechanism -> error."""
        rc, out, err = _run_probe(p11_config, "encapsulate_wrong_mechanism")
        _check(rc, out, err, "C_EncapsulateKey")

    def test_encapsulate_null_pointers(self, p11_config: Any) -> None:
        """C_EncapsulateKey with NULL pointers must return CKR_ARGUMENTS_BAD without crashing."""
        rc, out, err = _run_probe(p11_config, "encapsulate_null_pointers")
        _check(rc, out, err, "C_EncapsulateKey_NULLs")


@pytest.mark.needs_function("C_DecapsulateKey")
class TestDecapsulateKeyErrors:
    """v3.2 C_DecapsulateKey via raw calls."""

    def test_decapsulate_wrong_mechanism(self, p11_config: Any) -> None:
        """C_DecapsulateKey with AES mechanism -> error."""
        rc, out, err = _run_probe(p11_config, "decapsulate_wrong_mechanism")
        _check(rc, out, err, "C_DecapsulateKey")

    def test_decapsulate_null_pointers(self, p11_config: Any) -> None:
        """C_DecapsulateKey with NULL pointers must return CKR_ARGUMENTS_BAD without crashing."""
        rc, out, err = _run_probe(p11_config, "decapsulate_null_pointers")
        _check(rc, out, err, "C_DecapsulateKey_NULLs")


@pytest.mark.needs_function("C_AsyncGetID")
class TestAsyncErrors:
    """v3.2 async function error conditions."""

    def test_async_get_id_no_operation(self, p11_config: Any) -> None:
        """C_AsyncGetID with no pending async operation."""
        rc, out, err = _run_probe(p11_config, "async_get_id_no_operation")
        _check(rc, out, err, "C_AsyncGetID")


@pytest.mark.needs_function("C_WrapKeyAuthenticated")
class TestWrapKeyAuthenticatedErrors:
    """v3.2 C_WrapKeyAuthenticated error conditions."""

    def test_wrap_auth_wrong_mechanism(self, p11_config: Any) -> None:
        """C_WrapKeyAuthenticated with SHA mechanism -> error."""
        rc, out, err = _run_probe(p11_config, "wrap_auth_wrong_mechanism")
        _check(rc, out, err, "C_WrapKeyAuthenticated")
