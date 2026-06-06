"""Meta-tests for the OP-TEE PKCS#11 guest runner."""

from __future__ import annotations

import importlib.util
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUEST_RUNNER = ROOT / "docker/optee-pkcs11/guest-runner.py"


def load_guest_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("optee_guest_runner", GUEST_RUNNER)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_env(**overrides: str) -> Mapping[str, str]:
    env = {
        "PKCS11_CHECK_MODULE": "/usr/lib/libckteec.so",
        "PKCS11_CHECK_PIN": "1234",
        "PKCS11_CHECK_SO_PIN": "87654321",
        "PKCS11_CHECK_SLOT": "0",
        "PKCS11_CHECK_INTERFACE": "2.40",
        "PKCS11_CHECK_ARTIFACT_DIR": "/mnt/artifacts",
    }
    env.update(overrides)
    return env


def test_build_cli_args_uses_artifact_files_and_targets() -> None:
    runner = load_guest_runner()
    args = runner.build_cli_args(
        make_env(
            PKCS11_CHECK_EXTRA_ARGS="--timeout 30 --match test_interface",
            PKCS11_CHECK_TARGETS="src/pkcs11_check/testcases/test_interface.py",
        )
    )

    assert args[:2] == ["test", "--module"]
    assert "/usr/lib/libckteec.so" in args
    assert "--interface" in args
    assert "2.40" in args
    assert "--slot" in args
    assert "0" in args
    assert "--output" in args
    assert "json" in args
    assert "--output-file" in args
    assert "/mnt/artifacts/results.json" in args
    assert "--state-file" in args
    assert "/mnt/artifacts/state.json" in args
    assert "--policy-file" in args
    assert "/mnt/artifacts/policy.json" in args
    assert "--timeout" in args
    assert "30" in args
    assert "--match" in args
    assert "test_interface" in args
    assert args[-1] == "src/pkcs11_check/testcases/test_interface.py"


def test_build_cli_args_defaults_to_testcases_dir() -> None:
    runner = load_guest_runner()
    args = runner.build_cli_args(make_env(PKCS11_CHECK_TARGETS=""))

    assert args[-1] == "src/pkcs11_check/testcases/"


def test_render_serial_command_never_contains_pin() -> None:
    runner = load_guest_runner()
    env = make_env(PKCS11_CHECK_PIN="1234", PKCS11_CHECK_SO_PIN="87654321")

    rendered = runner.render_serial_command(env)

    assert "guest-runner.py" in rendered
    assert "1234" not in rendered
    assert "87654321" not in rendered
    assert "--pin" not in rendered


def test_pin_env_is_set_only_for_cli_call(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = load_guest_runner()
    captured: dict[str, str | None] = {}

    def stub_main() -> None:
        import os

        captured["pin"] = os.environ.get("P11TEST_PIN")

    monkeypatch.setattr(runner, "pkcs11_cli_main", stub_main)

    exit_code = runner.run_pkcs11_check_cli(
        make_env(), ["test", "--module", "/usr/lib/libckteec.so"]
    )

    assert exit_code == 0
    assert captured["pin"] == "1234"
