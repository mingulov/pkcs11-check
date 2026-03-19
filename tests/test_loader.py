"""Tests for PKCS#11 module loader."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkcs11_check.core.loader import P11Module, load_module


class TestLoadModule:
    def test_load_module_returns_p11module(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_lib = MagicMock()
        mock_lib.interface_version = "2.40"
        mock_lib.get_slots.return_value = [MagicMock()]
        with patch("pkcs11_check.core.loader.pkcs11_lib", return_value=mock_lib):
            module = load_module(fake_so)
        assert isinstance(module, P11Module)
        assert module.interface_version == "2.40"

    def test_load_module_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_module(Path("/nonexistent/module.so"))

    def test_interface_version_auto(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_lib = MagicMock()
        mock_lib.interface_version = "3.2"
        with patch("pkcs11_check.core.loader.pkcs11_lib", return_value=mock_lib):
            module = load_module(fake_so, interface="auto")
        assert module.interface_version == "3.2"

    @pytest.mark.parametrize("iface", ["2.40", "3.0", "3.1", "3.2", "auto"])
    def test_supported_interfaces(self, tmp_path: Path, iface: str) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_lib = MagicMock()
        mock_lib.interface_version = iface if iface != "auto" else "3.2"
        with patch("pkcs11_check.core.loader.pkcs11_lib", return_value=mock_lib):
            module = load_module(fake_so, interface=iface)
        assert isinstance(module, P11Module)

    def test_unsupported_interface_raises(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        with pytest.raises(ValueError, match="Unknown interface"):
            load_module(fake_so, interface="99.9")


class TestP11Module:
    def test_get_slots(self) -> None:
        mock_lib = MagicMock()
        mock_lib.get_slots.return_value = [MagicMock(), MagicMock()]
        module = P11Module(path=Path("/fake.so"), lib=mock_lib)
        slots = module.get_slots()
        assert len(slots) == 2

    def test_get_token_invalid_slot(self) -> None:
        mock_lib = MagicMock()
        mock_lib.get_slots.return_value = [MagicMock()]
        module = P11Module(path=Path("/fake.so"), lib=mock_lib)
        with pytest.raises(IndexError, match="Slot 5 not found"):
            module.get_token(slot_index=5)
