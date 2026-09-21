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

from pkcs11_check.classification import xfail_as
from pkcs11_check.core.process_observation import record_process_observation
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKR_OK, CKR_OPERATION_ACTIVE
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _extract_child_ckr(out: str) -> tuple[int | None, bool]:
    """Parse the child's ``CKR:0x...`` line.

    Returns ``(rv, first_init_failed)``: ``rv`` is None when no CKR line is
    present; ``first_init_failed`` is True when the child reported its first
    init failed (no state-conflict outcome exists to classify or retain).
    """
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            token = line.removeprefix("CKR:").split(":", 1)
            if len(token) > 1 and token[1] == "first_init_failed":
                return None, True
            return int(token[0], 16), False
    return None, False


def _classify_state_ckr(out: str, *, label: str) -> None:
    """Parent-side tolerant 3-way classifier over a child's ``CKR:0x...`` line.

    A second C_*Init while one is active must return CKR_OPERATION_ACTIVE. A
    module that silently cancels the first op and restarts (CKR_OK) is
    tolerated but recorded (M-35 honest_deviation xfail), never passed
    silently. Any other clean code is a noted deviation (``xfail``), not a
    crash. Classification happens here (not via an in-child ``assert``) so a
    third clean code is no longer mislabeled as a child crash.

    If the child reported the first init itself failed (``...:first_init_failed``),
    there is no state-conflict result to classify; the probe simply passes
    (it proved no crash).
    """
    rv, first_init_failed = _extract_child_ckr(out)
    if first_init_failed:
        return
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    if rv == CKR_OK:
        xfail_as(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            actual=rv,
            expected=(CKR_OPERATION_ACTIVE,),
            summary=(
                f"{label}: second init returned CKR_OK (silent restart); "
                "spec requires CKR_OPERATION_ACTIVE"
            ),
        )
    classify_negative_rv(rv, (CKR_OPERATION_ACTIVE,), label=label)


def _record_cross_operation_ckr(out: str) -> None:
    """Retain the cross-operation probe's child CKR as a durable observation.

    F-003: this probe is a crash-survival probe -- any clean outcome passes
    and this function never changes the verdict. But the observed second-init
    CKR is useful evidence, so keep it on the call report (via the process
    observations channel) instead of dropping it. Nothing is recorded when
    there is no state-conflict outcome (missing line or first-init failure).
    """
    rv, first_init_failed = _extract_child_ckr(out)
    if rv is None or first_init_failed:
        return
    record_process_observation(
        {
            "target": "ckr_raw_state",
            "role": "probe-ckr",
            "probe": "encrypt_then_sign_init",
            "ckr": f"0x{rv:08x}",
            "ckr_name": ckr_name(rv),
        }
    )


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
        """C_EncryptInit then C_SignInit: cross-type Inits hold independent state.

        F-14: cross-type Inits do not conflict (dual-function operations need
        digest+encrypt simultaneously active), so no CKR is asserted here --
        the probe only survives the pair and retains the observed child CKR.
        """
        rc, out, err = _run_probe(p11_config, "encrypt_then_sign_init")
        _assert_probe_completed(rc, out, err)
        _record_cross_operation_ckr(out)

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
