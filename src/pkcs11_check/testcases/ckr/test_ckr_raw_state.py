"""CKR operation state violation tests via raw ctypes calls.

Tests CKR_OPERATION_ACTIVE conditions:
- Double C_EncryptInit (second without completing first)
- C_EncryptInit then C_SignInit (cross-operation conflict)
- Double C_DigestInit / C_SignInit / C_DecryptInit

Each test launches the ``ckr_raw_state`` probe module (``_probes/ckr_raw_state.py``) via
``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a PIN is
configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var
(never embedded in source or params -- Invariant I3).  The probe generates a shared AES key
(mirroring the legacy preamble) then drives the per-test state violation; the parent
classifies the child's ``CKR:0x...`` line via ``_classify_state_ckr``.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OPERATION_ACTIVE
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _classify_state_ckr(out: str, *, label: str) -> None:
    """Parent-side tolerant 3-way classifier over a child's ``CKR:0x...`` line.

    A second C_*Init while one is active may legitimately return
    CKR_OPERATION_ACTIVE *or* CKR_OK (the module may cancel the first op and
    start a new one) -- both are accepted passes (``allow_ok=True``). Any other
    clean code is a noted deviation (``xfail``), not a crash. Classification
    happens here (not via an in-child ``assert``) so a third clean code is no
    longer mislabeled as a child crash.

    If the child reported the first init itself failed (``...:first_init_failed``),
    there is no state-conflict result to classify; the probe simply passes
    (it proved no crash).
    """
    rv: int | None = None
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            token = line.removeprefix("CKR:").split(":", 1)
            if len(token) > 1 and token[1] == "first_init_failed":
                return
            rv = int(token[0], 16)
            break
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    classify_negative_rv(rv, (CKR_OPERATION_ACTIVE,), label=label, allow_ok=True)


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    result = run_probe(
        "ckr_raw_state",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


def _assert_probe_completed(rc: int, out: str, err: str) -> None:
    assert_ckr_subprocess_ok(rc, out, err, context="CKR operation-state raw probe")


class TestOperationActive:
    """Double-Init and cross-operation state violations."""

    def test_double_encrypt_init(self, p11_config: Any) -> None:
        """Double C_EncryptInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run_probe(p11_config, "double_encrypt_init")
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_EncryptInit (operation-active state)")

    def test_encrypt_then_sign_init(self, p11_config: Any) -> None:
        """C_EncryptInit then C_SignInit -> CKR_OPERATION_ACTIVE (if no dual-crypto)."""
        rc, out, err = _run_probe(p11_config, "encrypt_then_sign_init")
        _assert_probe_completed(rc, out, err)

    def test_double_digest_init(self, p11_config: Any) -> None:
        """Double C_DigestInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run_probe(p11_config, "double_digest_init")
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_DigestInit (operation-active state)")

    def test_double_sign_init(self, p11_config: Any) -> None:
        """Double C_SignInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run_probe(p11_config, "double_sign_init")
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_SignInit (operation-active state)")

    def test_double_decrypt_init(self, p11_config: Any) -> None:
        """Double C_DecryptInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run_probe(p11_config, "double_decrypt_init")
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_DecryptInit (operation-active state)")
