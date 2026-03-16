"""Tests for pytest plugin registration and fixtures."""

from __future__ import annotations

import pytest


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
