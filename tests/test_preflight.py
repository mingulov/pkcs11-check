"""Tests for collection-safe capability probing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkcs11_check.core.preflight import (
    CapabilityManifest,
    load_manifest,
    probe_capabilities,
    save_manifest,
)


def test_probe_capabilities_returns_manifest(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()

    mock_slot = MagicMock()
    mock_mech1 = MagicMock()
    mock_mech1.name = "CKM_AES_ECB"
    mock_mech2 = MagicMock()
    mock_mech2.name = "CKM_RSA_PKCS"
    mock_slot.get_mechanisms.return_value = [mock_mech2, mock_mech1]

    mock_module = MagicMock()
    mock_module.interface_version = "3.2"
    mock_module.get_slots.return_value = [mock_slot]

    with patch("pkcs11_check.core.preflight.load_module", return_value=mock_module):
        manifest = probe_capabilities(module_path, interface="auto", slot=0)

    assert manifest.status == "ok"
    assert manifest.module_path == str(module_path)
    assert manifest.requested_interface == "auto"
    assert manifest.interface_version == "3.2"
    assert manifest.slot_index == 0
    assert manifest.slot_count == 1
    assert manifest.mechanisms == ["CKM_AES_ECB", "CKM_RSA_PKCS"]
    assert set(manifest.mechanism_info.keys()) == {"CKM_AES_ECB", "CKM_RSA_PKCS"}
    for info in manifest.mechanism_info.values():
        assert "flags" in info
        assert "min_key_size" in info
        assert "max_key_size" in info


def test_probe_capabilities_returns_error_manifest(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()

    with patch("pkcs11_check.core.preflight.load_module", side_effect=RuntimeError("boom")):
        manifest = probe_capabilities(module_path, interface="3.2", slot=0)

    assert manifest.status == "error"
    assert manifest.module_path == str(module_path)
    assert manifest.requested_interface == "3.2"
    assert manifest.error == "RuntimeError: boom"


def test_manifest_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    manifest = CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version="3.0",
        slot_index=1,
        slot_count=2,
        mechanisms=["CKM_AES_ECB"],
    )

    save_manifest(path, manifest)

    assert load_manifest(path) == manifest


def test_probe_capabilities_records_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe_capabilities populates manifest.functions from available_function_names()."""
    import pkcs11_check.core.preflight as preflight_mod

    class _FakeSlot:
        def get_mechanisms(self) -> list[object]:
            return []

        def get_mechanism_info(self, mech: object) -> None:
            return None

    class _FakeRaw:
        def available_function_names(self) -> set[str]:
            return {"C_Sign", "C_Verify", "C_GenerateKeyPair"}

    class _FakeP11:
        interface_version = "2.40"
        raw = _FakeRaw()

        def get_slots(self, token_present: bool = True) -> list[_FakeSlot]:
            return [_FakeSlot()]

    monkeypatch.setattr(preflight_mod, "load_module", lambda module, interface: _FakeP11())

    manifest = preflight_mod.probe_capabilities(Path("/tmp/m.so"), interface="auto", slot=0)

    assert manifest.status == "ok"
    assert manifest.functions == ["C_GenerateKeyPair", "C_Sign", "C_Verify"]  # sorted


def test_manifest_serialization_roundtrip_with_and_without_functions(tmp_path: Path) -> None:
    """Old manifests (no functions key) deserialize to []; new ones round-trip."""
    import json

    # Forward: a manifest WITH functions survives asdict->json->load
    m = CapabilityManifest(
        status="ok",
        module_path="/tmp/m.so",
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_KEM"],
        functions=["C_EncapsulateKey"],
    )
    path = tmp_path / "m.json"
    save_manifest(path, m)
    assert load_manifest(path).functions == ["C_EncapsulateKey"]

    # Backward: a manifest file lacking "functions" loads with [] default
    legacy = {
        "status": "ok",
        "module_path": "/tmp/m.so",
        "requested_interface": "auto",
        "interface_version": "2.40",
        "slot_index": 0,
        "slot_count": 1,
        "mechanisms": [],
    }
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    assert load_manifest(legacy_path).functions == []
