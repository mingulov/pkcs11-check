"""Regression tests: subprocess test files must not embed the PIN in script text.

Batch B / M1 follow-up. Three files build their own subprocess boilerplate and
previously interpolated the user PIN into the ``-c`` script (exposing it in the
child argv via ``ps``/``/proc`` and in any traceback):

- ``ckr/test_ckr_raw_state.py`` (own ``subprocess.run``)
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
from pkcs11_check.testcases._subprocess_preamble import _P11CHECK_PIN_ENV
from pkcs11_check.testcases.ckr import test_ckr_raw_state

_PIN = "s3cr3t-PIN-DO-NOT-LEAK"


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(
        module="/tmp/fake-pkcs11.so",
        slot=0,
        pin=SimpleNamespace(get_secret_value=lambda: _PIN),
    )


# --- ckr/test_ckr_raw_state.py (own subprocess.run) ------------------------


def test_ckr_raw_state_pin_not_in_script_or_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = "CKR:0x00000000\nOK"
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return _Result()

    monkeypatch.setattr(test_ckr_raw_state.subprocess, "run", _fake_run)

    # Run a probe that goes through _run() and builds + spawns the child script.
    test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(_cfg())

    args = captured["args"]
    env = captured["env"]
    # The script is the last argv element ("-c", <script>). The PIN must not be
    # anywhere in the argv (script text included).
    assert all(_PIN not in arg for arg in args)
    # The PIN must be forwarded via the child env under the agreed key.
    assert env[_P11CHECK_PIN_ENV] == _PIN
    # Sanity: the script reads the PIN from the environment, not a literal.
    script = args[-1]
    assert "_os.environ.get" in script
    assert "login_user(" in script


def test_ckr_raw_state_no_pin_means_no_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = "CKR:0x00000000\nOK"
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        captured["env"] = kwargs.get("env")
        return _Result()

    monkeypatch.setattr(test_ckr_raw_state.subprocess, "run", _fake_run)

    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0, pin=None)
    test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(cfg)

    assert _P11CHECK_PIN_ENV not in captured["env"]


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
