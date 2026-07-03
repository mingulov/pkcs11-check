"""CKR_ARGUMENTS_BAD tests via raw ctypes - NULL pointers to C_* functions.

Tests that passing NULL where a valid pointer is required returns
CKR_ARGUMENTS_BAD (0x07). Modules that segfault instead are documented.

Each test launches the ``ckr_raw_args_bad`` probe module (``_probes/ckr_raw_args_bad.py``)
via ``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a
PIN is configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN``
env var (never embedded in source or params -- Invariant I3).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _assert_ok(rc: int, out: str, err: str, name: str) -> None:
    assert_ckr_subprocess_ok(rc, out, err, context=name)


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    result = run_probe(
        "ckr_raw_args_bad",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


class TestArgsBadNullPointers:
    """Pass NULL to functions that require valid pointers."""

    def test_encrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_EncryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "encrypt_init")
        _assert_ok(rc, out, err, "C_EncryptInit(NULL mech)")

    def test_decrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DecryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "decrypt_init")
        _assert_ok(rc, out, err, "C_DecryptInit(NULL mech)")

    def test_sign_init_null_mechanism(self, p11_config: Any) -> None:
        """C_SignInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "sign_init")
        _assert_ok(rc, out, err, "C_SignInit(NULL mech)")

    def test_verify_init_null_mechanism(self, p11_config: Any) -> None:
        """C_VerifyInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "verify_init")
        _assert_ok(rc, out, err, "C_VerifyInit(NULL mech)")

    def test_digest_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DigestInit(session, NULL) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run_probe(p11_config, "digest_init")
        _assert_ok(rc, out, err, "C_DigestInit(NULL mech)")

    def test_generate_key_null_mechanism(self, p11_config: Any) -> None:
        """C_GenerateKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run_probe(p11_config, "generate_key")
        _assert_ok(rc, out, err, "C_GenerateKey(NULL mech)")

    def test_wrap_key_null_mechanism(self, p11_config: Any) -> None:
        """C_WrapKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run_probe(p11_config, "wrap_key")
        _assert_ok(rc, out, err, "C_WrapKey(NULL mech)")

    def test_derive_key_null_mechanism(self, p11_config: Any) -> None:
        """C_DeriveKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "derive_key")
        _assert_ok(rc, out, err, "C_DeriveKey(NULL mech)")
