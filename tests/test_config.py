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
        assert config.timeout_test == 180
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

    def test_so_pin_default_none(self, tmp_path: Path) -> None:
        config = P11TestConfig(module=tmp_path / "fake.so")
        assert config.so_pin is None

    def test_so_pin_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("P11TEST_MODULE", str(tmp_path / "m.so"))
        monkeypatch.setenv("P11TEST_SO_PIN", "so-secret-1")
        config = P11TestConfig()  # type: ignore[call-arg]
        assert config.so_pin is not None
        assert config.so_pin.get_secret_value() == "so-secret-1"

    def test_so_pin_not_in_repr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("P11TEST_MODULE", str(tmp_path / "m.so"))
        monkeypatch.setenv("P11TEST_SO_PIN", "so-secret-1")
        config = P11TestConfig()  # type: ignore[call-arg]
        assert "so-secret-1" not in repr(config)
        assert "so-secret-1" not in str(config)

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


def test_so_pin_env_key_fingerprinted_and_redacted() -> None:
    from pkcs11_check.core import _run_state

    assert "P11TEST_SO_PIN" in _run_state._DEFAULT_FINGERPRINT_ENV_KEYS
    assert "P11TEST_SO_PIN" in _run_state._REDACTED_ENV_KEYS


class TestWrapKeyValueValidation:
    def test_valid_hex_lengths_accepted(self, tmp_path: Path) -> None:
        for hexstr in ("00" * 16, "11" * 24, "ab" * 32):
            config = P11TestConfig(module=tmp_path / "m.so", wrap_key_value=hexstr)
            assert config.wrap_key_value == hexstr

    def test_non_hex_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(Exception, match="hex"):
            P11TestConfig(module=tmp_path / "m.so", wrap_key_value="zz" * 16)

    def test_wrong_length_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(Exception, match="16, 24, or 32"):
            P11TestConfig(module=tmp_path / "m.so", wrap_key_value="00" * 15)

    def test_odd_length_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(Exception, match="hex"):
            P11TestConfig(module=tmp_path / "m.so", wrap_key_value="0" * 33)


class TestWrapKeySourceValidation:
    def test_bootstrap_accepted(self, tmp_path: Path) -> None:
        config = P11TestConfig(module=tmp_path / "m.so", wrap_key_source="bootstrap")
        assert config.wrap_key_source == "bootstrap"

    def test_configured_accepted(self, tmp_path: Path) -> None:
        config = P11TestConfig(module=tmp_path / "m.so", wrap_key_source="configured")
        assert config.wrap_key_source == "configured"

    def test_bogus_value_rejected_at_construction(self, tmp_path: Path) -> None:
        """A typo'd --p11-wrap-key-source must fail fast at config construction,
        not escape as a raw ValueError out of build_wrap_context later."""
        with pytest.raises(Exception):
            P11TestConfig(module=tmp_path / "m.so", wrap_key_source="bogus")
