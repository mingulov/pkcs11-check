"""Regression tests: subprocess test files must not embed the PIN in script text.

Batch B / M1 follow-up. Three files build their own subprocess boilerplate and
previously interpolated the user PIN into the ``-c`` script (exposing it in the
child argv via ``ps``/``/proc`` and in any traceback):

- ``ckr/test_ckr_raw_state.py`` (now via ``run_probe`` -> ``_probes/ckr_raw_state.py``)
- ``test_dual_function.py`` (now via ``run_probe`` -> ``_probes/dual_function.py``)
- ``test_sign_recover.py`` (now via ``run_probe`` -> ``_probes/sign_recover.py``)

These assert that the generated script text never contains the PIN and that the
PIN is forwarded into the CHILD ENVIRONMENT (under ``_P11CHECK_PIN``), never into
the child argv.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases import test_dual_function, test_sign_recover
from pkcs11_check.testcases.ckr import test_ckr_raw_state

_PIN = "s3cr3t-PIN-DO-NOT-LEAK"


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(
        module="/tmp/fake-pkcs11.so",
        slot=0,
        pin=SimpleNamespace(get_secret_value=lambda: _PIN),
    )


# --- ckr/test_ckr_raw_state.py (via run_probe) -----------------------------


def test_ckr_raw_state_pin_routed_to_run_probe_not_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_probe(
        probe: str, params: dict[str, Any], *, pin: str | None = None, **_kwargs: Any
    ) -> SimpleNamespace:
        captured["probe"] = probe
        captured["params"] = params
        captured["pin"] = pin
        return SimpleNamespace(returncode=0, stdout="CKR:0x00000000\nOK", stderr="")

    monkeypatch.setattr(test_ckr_raw_state, "run_probe", _fake_run_probe)

    # Run a probe that goes through _run_probe() and launches the child probe module.
    test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(_cfg())

    # The PIN must be forwarded to run_probe via pin= only (the runner injects it into
    # the child env under _P11CHECK_PIN); it must never appear in the probe params.
    assert captured["pin"] == _PIN
    assert _PIN not in str(captured["params"])


def test_ckr_raw_state_no_pin_means_pin_none(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_probe(
        probe: str, params: dict[str, Any], *, pin: str | None = None, **_kwargs: Any
    ) -> SimpleNamespace:
        captured["pin"] = pin
        return SimpleNamespace(returncode=0, stdout="CKR:0x00000000\nOK", stderr="")

    monkeypatch.setattr(test_ckr_raw_state, "run_probe", _fake_run_probe)

    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0, pin=None)
    test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(cfg)

    assert captured["pin"] is None


# --- test_dual_function.py (via run_probe) ---------------------------------


def test_dual_function_pin_routed_to_run_probe_not_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_probe(
        probe: str, params: dict[str, Any], *, pin: str | None = None, **_kwargs: Any
    ) -> SimpleNamespace:
        captured["probe"] = probe
        captured["params"] = params
        captured["pin"] = pin
        # A SKIP line short-circuits the parent before the crypto assertions.
        return SimpleNamespace(
            returncode=0, stdout="SKIP:GenerateKeyUnsupported:0x00000054", stderr=""
        )

    monkeypatch.setattr(test_dual_function, "run_probe", _fake_run_probe)

    raw_session = SimpleNamespace(has_mechanism=lambda _name: True)
    with pytest.raises(pytest.skip.Exception):
        test_dual_function.TestDigestEncryptUpdate().test_digest_encrypt_update_round_trip(
            _cfg(), raw_session
        )

    # The PIN must be forwarded to run_probe via pin= only (the runner injects it into
    # the child env under _P11CHECK_PIN); it must never appear in the probe params.
    assert captured["pin"] == _PIN
    assert _PIN not in str(captured["params"])


def test_dual_function_no_pin_means_pin_none(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_probe(
        probe: str, params: dict[str, Any], *, pin: str | None = None, **_kwargs: Any
    ) -> SimpleNamespace:
        captured["pin"] = pin
        return SimpleNamespace(
            returncode=0, stdout="SKIP:GenerateKeyUnsupported:0x00000054", stderr=""
        )

    monkeypatch.setattr(test_dual_function, "run_probe", _fake_run_probe)

    raw_session = SimpleNamespace(has_mechanism=lambda _name: True)
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0, pin=None)
    with pytest.raises(pytest.skip.Exception):
        test_dual_function.TestDecryptDigestUpdate().test_decrypt_digest_update_round_trip(
            cfg, raw_session
        )

    assert captured["pin"] is None


# --- test_sign_recover.py (via run_probe) ----------------------------------


def _rsa_x509_module() -> SimpleNamespace:
    """Fake p11_module whose first token advertises CKM_RSA_X_509 (passes _has_rsa_x509)."""
    slot = SimpleNamespace(get_mechanisms=lambda: [SimpleNamespace(name="RSA_X_509")])
    return SimpleNamespace(get_slots=lambda token_present=True: [slot])


def test_sign_recover_pin_routed_to_run_probe_not_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_probe(
        probe: str, params: dict[str, Any], *, pin: str | None = None, **_kwargs: Any
    ) -> SimpleNamespace:
        captured["probe"] = probe
        captured["params"] = params
        captured["pin"] = pin
        # A SKIP line short-circuits the parent before the crypto assertions.
        return SimpleNamespace(
            returncode=0, stdout="SKIP:SignRecoverInitUnsupported:0x00000054", stderr=""
        )

    monkeypatch.setattr(test_sign_recover, "run_probe", _fake_run_probe)

    with pytest.raises(pytest.skip.Exception):
        test_sign_recover.TestSignRecover().test_sign_recover_produces_output(
            _cfg(), _rsa_x509_module()
        )

    # The PIN must be forwarded to run_probe via pin= only (the runner injects it into
    # the child env under _P11CHECK_PIN); it must never appear in the probe params.
    assert captured["pin"] == _PIN
    assert _PIN not in str(captured["params"])


def test_sign_recover_no_pin_means_pin_none(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_probe(
        probe: str, params: dict[str, Any], *, pin: str | None = None, **_kwargs: Any
    ) -> SimpleNamespace:
        captured["pin"] = pin
        return SimpleNamespace(
            returncode=0, stdout="SKIP:SignRecoverInitUnsupported:0x00000054", stderr=""
        )

    monkeypatch.setattr(test_sign_recover, "run_probe", _fake_run_probe)

    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0, pin=None)
    with pytest.raises(pytest.skip.Exception):
        test_sign_recover.TestSignRecover().test_sign_recover_produces_output(
            cfg, _rsa_x509_module()
        )

    assert captured["pin"] is None
