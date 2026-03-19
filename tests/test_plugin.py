"""Tests for pytest plugin registration and fixtures."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from p11test.fixtures import p11_config


class TestPluginRegistration:
    def test_plugin_is_registered(self, pytestconfig: pytest.Config) -> None:
        """Verify p11test plugin is loaded."""
        plugin = pytestconfig.pluginmanager.get_plugin("p11test")
        assert plugin is not None

    def test_p11_module_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_module", default="MISSING")
        assert val != "MISSING"

    def test_p11_interface_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_interface", default="MISSING")
        assert val != "MISSING"

    def test_p11_slot_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_slot", default="MISSING")
        assert val != "MISSING"

    def test_p11_destructive_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_destructive", default="MISSING")
        assert val != "MISSING"


def test_p11_config_uses_env_pin_when_cli_pin_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("P11TEST_PIN", "secret123")

    options = {
        "p11_module": str(tmp_path / "module.so"),
        "p11_interface": "auto",
        "p11_slot": 0,
        "p11_pin": None,
        "p11_destructive": False,
    }
    request = SimpleNamespace(config=SimpleNamespace(getoption=options.__getitem__))

    config = p11_config.__wrapped__(request)

    assert config.pin is not None
    assert config.pin.get_secret_value() == "secret123"
