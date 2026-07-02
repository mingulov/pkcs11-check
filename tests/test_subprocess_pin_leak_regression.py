"""Regression tests: subprocess test files must not embed the PIN in script text.

Batch B / M1 follow-up. Three files build their own subprocess boilerplate and
previously interpolated the user PIN into the ``-c`` script (exposing it in the
child argv via ``ps``/``/proc`` and in any traceback):

- ``ckr/test_ckr_raw_state.py`` (now via ``run_probe`` -> ``_probes/ckr_raw_state.py``)
- ``test_dual_function.py`` (via ``run_raw_script``)
- ``test_sign_recover.py`` (via ``run_raw_script``)

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


# --- test_dual_function.py / test_sign_recover.py (run_raw_script) ---------


def test_dual_function_pin_not_in_script_routed_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_raw_script(
        boilerplate: str, script_body: str, *, pin: str | None = None, **_k: Any
    ) -> tuple[int, str, str]:
        captured["boilerplate"] = boilerplate
        captured["pin"] = pin
        return 0, "", ""

    monkeypatch.setattr(test_dual_function, "run_raw_script", _fake_run_raw_script)

    module_path, slot_index, pin = test_dual_function._get_params(_cfg())
    test_dual_function._run_script(module_path, slot_index, pin, "    pass\n")

    assert _PIN not in captured["boilerplate"]
    assert "_os.environ.get" in captured["boilerplate"]
    # The PIN is forwarded to run_raw_script's pin= (which injects the env),
    # never embedded in the script text.
    assert captured["pin"] == _PIN


def test_sign_recover_pin_not_in_script_routed_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_raw_script(
        boilerplate: str, script_body: str, *, pin: str | None = None, **_k: Any
    ) -> tuple[int, str, str]:
        captured["boilerplate"] = boilerplate
        captured["pin"] = pin
        return 0, "", ""

    monkeypatch.setattr(test_sign_recover, "run_raw_script", _fake_run_raw_script)

    module_path, slot_index, pin = test_sign_recover._get_params(_cfg())
    test_sign_recover._run_script(module_path, slot_index, pin, "    pass\n")

    assert _PIN not in captured["boilerplate"]
    assert "_os.environ.get" in captured["boilerplate"]
    assert captured["pin"] == _PIN


def test_dual_function_get_params_returns_str_pin() -> None:
    _module, _slot, pin = test_dual_function._get_params(_cfg())
    assert pin == _PIN
    no_pin = SimpleNamespace(module="/tmp/x.so", slot=0, pin=None)
    assert test_dual_function._get_params(no_pin)[2] is None


def test_sign_recover_get_params_returns_str_pin() -> None:
    _module, _slot, pin = test_sign_recover._get_params(_cfg())
    assert pin == _PIN
    no_pin = SimpleNamespace(module="/tmp/x.so", slot=0, pin=None)
    assert test_sign_recover._get_params(no_pin)[2] is None
