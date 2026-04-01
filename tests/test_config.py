"""Tests for pkcs11-check configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.config import P11TestConfig


class TestP11TestConfigDefaults:
    def test_module_is_required(self) -> None:
        with pytest.raises(Exception):
            P11TestConfig()  # type: ignore[call-arg]

    def test_defaults(self, tmp_path: Path) -> None:
        config = P11TestConfig(module=tmp_path / "fake.so")
        assert config.slot == 0
        assert config.pin is None
        assert config.interface == "auto"
        assert config.timeout_operation == 30
        assert config.timeout_test == 120
        assert config.destructive is False
        assert config.max_sessions == 1
        assert config.skip_unsupported is True
        assert config.log_level == "INFO"
        assert config.output == "rich"
        assert config.disabled_tests_file is None


class TestP11TestConfigEnv:
    def test_env_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("P11TEST_MODULE", str(tmp_path / "env.so"))
        monkeypatch.setenv("P11TEST_SLOT", "3")
        monkeypatch.setenv("P11TEST_INTERFACE", "3.2")
        config = P11TestConfig()  # type: ignore[call-arg]
        assert config.slot == 3
        assert config.interface == "3.2"

    def test_pin_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("P11TEST_MODULE", str(tmp_path / "m.so"))
        monkeypatch.setenv("P11TEST_PIN", "secret123")
        config = P11TestConfig()  # type: ignore[call-arg]
        assert config.pin is not None
        assert config.pin.get_secret_value() == "secret123"

    def test_pin_not_in_repr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("P11TEST_MODULE", str(tmp_path / "m.so"))
        monkeypatch.setenv("P11TEST_PIN", "secret123")
        config = P11TestConfig()  # type: ignore[call-arg]
        assert "secret123" not in repr(config)
        assert "secret123" not in str(config)

    def test_disabled_tests_file_from_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("P11TEST_MODULE", str(tmp_path / "m.so"))
        monkeypatch.setenv("P11TEST_DISABLED_TESTS_FILE", str(tmp_path / "env-disabled.txt"))

        config = P11TestConfig()  # type: ignore[call-arg]

        assert config.disabled_tests_file == tmp_path / "env-disabled.txt"


def test_disabled_tests_file_is_none_without_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    config = P11TestConfig(module=tmp_path / "fake.so")

    assert config.disabled_tests_file is None
