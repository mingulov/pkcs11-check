"""Tests for PKCS#11 module loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from pkcs11_check.core.loader import P11Module, RawSlot, load_module
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED


def _mock_raw(version: str = "2.40") -> MagicMock:
    """Return a RawPKCS11 mock whose C_Initialize succeeds (CKR_OK = 0)."""
    mock_raw = MagicMock(spec=RawPKCS11)
    mock_raw.interface_version = version
    mock_raw.C_Initialize.return_value = 0  # CKR_OK
    mock_raw.available_function_names.return_value = set()
    return mock_raw


class TestLoadModule:
    def test_load_module_returns_p11module(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_raw = _mock_raw("2.40")
        with patch("pkcs11_check.core.loader.RawPKCS11") as mock_cls:
            mock_cls.from_lib.return_value = mock_raw
            module = load_module(fake_so)
        assert isinstance(module, P11Module)
        assert module.interface_version == "2.40"

    def test_load_module_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_module(Path("/nonexistent/module.so"))

    def test_interface_version_auto(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_raw = _mock_raw("3.2")
        with patch("pkcs11_check.core.loader.RawPKCS11") as mock_cls:
            mock_cls.from_lib.return_value = mock_raw
            module = load_module(fake_so, interface="auto")
        assert module.interface_version == "3.2"

    def test_c_initialize_already_initialized_is_ok(self, tmp_path: Path) -> None:
        """CKR_CRYPTOKI_ALREADY_INITIALIZED (0x00000191) is not an error."""
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_raw = _mock_raw("2.40")
        mock_raw.C_Initialize.return_value = 0x00000191
        with patch("pkcs11_check.core.loader.RawPKCS11") as mock_cls:
            mock_cls.from_lib.return_value = mock_raw
            module = load_module(fake_so)
        assert isinstance(module, P11Module)

    def test_c_initialize_failure_raises(self, tmp_path: Path) -> None:
        """Unexpected C_Initialize failure raises RuntimeError."""
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_raw = _mock_raw("2.40")
        mock_raw.C_Initialize.return_value = 0x00000001  # CKR_CANCEL — unexpected
        with patch("pkcs11_check.core.loader.RawPKCS11") as mock_cls:
            mock_cls.from_lib.return_value = mock_raw
            with pytest.raises(RuntimeError, match="C_Initialize failed"):
                load_module(fake_so)

    @pytest.mark.parametrize("iface", ["2.40", "3.0", "3.1", "3.2", "auto"])
    def test_supported_interfaces(self, tmp_path: Path, iface: str) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_raw = _mock_raw(iface if iface != "auto" else "3.2")
        with patch("pkcs11_check.core.loader.RawPKCS11") as mock_cls:
            mock_cls.from_lib.return_value = mock_raw
            module = load_module(fake_so, interface=iface)
        assert isinstance(module, P11Module)

    def test_unsupported_interface_raises(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        with pytest.raises(ValueError, match="Unknown interface"):
            load_module(fake_so, interface="99.9")


class TestP11Module:
    def test_raw_property(self) -> None:
        mock_raw = _mock_raw()
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        assert module.raw is mock_raw

    def test_interface_version_from_raw(self) -> None:
        mock_raw = _mock_raw("3.1")
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        assert module.interface_version == "3.1"

    def test_lib_is_none(self) -> None:
        """lib is None — fork no longer used."""
        mock_raw = _mock_raw()
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        assert module.lib is None

    def test_get_slots_returns_rawslot_list(self) -> None:
        mock_raw = _mock_raw()
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        with patch("pkcs11_check.core.loader.get_slot_ids", return_value=[10, 20]):
            slots = module.get_slots()
        assert len(slots) == 2
        assert slots[0].slot_id == 10
        assert slots[1].slot_id == 20

    def test_get_interface_list_empty_for_v240(self) -> None:
        mock_raw = _mock_raw()
        mock_raw.available_function_names.return_value = set()
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        assert module.get_interface_list() == []

    def test_get_token_invalid_slot(self) -> None:
        mock_raw = _mock_raw()
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        with patch("pkcs11_check.core.loader.get_slot_ids", return_value=[10]):
            with pytest.raises(IndexError, match=r"slot 5 not found"):
                module.get_token(slot_index=5)

    def test_get_token_negative_slot_rejected_not_wrapped(self) -> None:
        # H-9: get_token(-1) wrapped to the last slot (only a >= guard).
        # The single resolver rejects negatives like any out-of-range index.
        mock_raw = _mock_raw()
        module = P11Module(path=Path("/fake.so"), _raw=mock_raw)
        with patch("pkcs11_check.core.loader.get_slot_ids", return_value=[10, 20]):
            with pytest.raises(IndexError, match=r"slot -1 not found"):
                module.get_token(slot_index=-1)

    def test_loader_exports_rawpkcs11(self) -> None:
        from pkcs11_check.raw.api import RawPKCS11 as ApiRawPKCS11

        assert RawPKCS11 is ApiRawPKCS11


def test_raw_slot_mechanism_info_failure_preserves_exact_ckr() -> None:
    raw = _mock_raw()
    raw.C_GetMechanismInfo.return_value = int(CKR_FUNCTION_FAILED)

    with pytest.raises(CkrAssertionError) as caught:
        RawSlot(0, raw).get_mechanism_info(1)

    assert caught.value.rv == int(CKR_FUNCTION_FAILED)


def _raw_with_token_info(label: bytes, manufacturer: bytes, model: bytes) -> MagicMock:
    """Fake ``C_GetTokenInfo`` filling the struct with the given field bytes."""
    import ctypes

    from pkcs11_check.raw.types_std import CK_TOKEN_INFO

    raw = _mock_raw()

    def _fill(_slot_id: int, info_ptr: Any) -> int:
        info = ctypes.cast(info_ptr, ctypes.POINTER(CK_TOKEN_INFO)).contents
        for dest, value, size in (
            (info.label, label, 32),
            (info.manufacturerID, manufacturer, 32),
            (info.model, model, 16),
        ):
            padded = value.ljust(size, b" ")
            ctypes.memmove(dest, padded, size)
        return 0  # CKR_OK

    raw.C_GetTokenInfo.side_effect = _fill
    return raw


class TestRawTokenFieldDecoding:
    """F-024: malformed UTF-8 in token fields must not interrupt diagnostics."""

    def test_valid_fields_unchanged(self) -> None:
        from pkcs11_check.core.loader import RawToken

        raw = _raw_with_token_info(b"valid-token", b"vendor", b"model-1")
        token = RawToken(0, raw)
        assert token.label == "valid-token"
        assert token.manufacturer_id == "vendor"
        assert token.model == "model-1"

    @pytest.mark.parametrize("field", ["label", "manufacturer_id", "model"])
    def test_malformed_field_renders_escaped_bytes(self, field: str) -> None:
        """Offending bytes surface as escapes in strict-encodable output.

        RED proof: the pre-fix strict ``.decode("utf-8")`` raises
        ``UnicodeDecodeError`` here instead of rendering anything.
        """
        from pkcs11_check.core.loader import RawToken

        bad = b"tok\xffen"
        fields = {"label": b"ok-label", "manufacturer_id": b"ok-vendor", "model": b"ok-model"}
        fields[field] = bad
        raw = _raw_with_token_info(fields["label"], fields["manufacturer_id"], fields["model"])
        rendered = getattr(RawToken(0, raw), field)
        assert isinstance(rendered, str)
        assert "\\xff" in rendered, f"offending byte lost from {field}: {rendered!r}"
        rendered.encode("utf-8")  # strict-encodable: no surrogates
        assert "tok" in rendered and "en" in rendered
