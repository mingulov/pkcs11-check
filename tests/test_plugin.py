"""Tests for pytest plugin registration and fixtures."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import p11test.plugin as plugin_mod
from p11test.core.preflight import CapabilityManifest
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

    def test_p11_manifest_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_manifest", default="MISSING")
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


class _FakeItem:
    def __init__(self, path: Path, markers: dict[str, object]) -> None:
        self.path = path
        self.fspath = path
        self._markers = markers
        self.added: list[object] = []

    def get_closest_marker(self, name: str) -> object | None:
        return self._markers.get(name)

    def add_marker(self, marker: object) -> None:
        self.added.append(marker)


def test_collection_modifyitems_applies_only_static_skips() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {
            "destructive": SimpleNamespace(args=()),
            "requires_v32": SimpleNamespace(args=()),
        },
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {
            "p11_module": "/tmp/module.so",
            "p11_destructive": False,
            "p11_thread_safe": False,
        }.get(name, default)
    )

    plugin_mod.pytest_collection_modifyitems(config, [item])

    reasons = [getattr(marker, "kwargs", {}).get("reason") for marker in item.added]
    assert "Destructive test (use --p11-destructive to enable)" in reasons
    assert not any(reason and "Requires v" in reason for reason in reasons)


def test_runtime_skip_reason_uses_manifest() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {
            "requires_v32": SimpleNamespace(args=()),
            "needs_mechanism": SimpleNamespace(args=("CKM_AES_ECB",)),
        },
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version="3.0",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_RSA_PKCS"],
    )

    reason = plugin_mod._runtime_skip_reason(item, config, manifest)

    assert reason == "Requires v32, module has v3.0"
