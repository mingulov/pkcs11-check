"""Tests for collection-safe capability probing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

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

    assert manifest == CapabilityManifest(
        status="ok",
        module_path=str(module_path),
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_AES_ECB", "CKM_RSA_PKCS"],
    )


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
