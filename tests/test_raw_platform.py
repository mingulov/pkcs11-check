"""The shared Windows DLL-search-path helper (raw._platform)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.raw import _platform
from pkcs11_check.raw._platform import windows_dll_directory


def test_windows_dll_directory_is_none_on_posix() -> None:
    # On the (POSIX) test host, ctypes.CDLL resolves dependents itself -> no dir to add.
    assert windows_dll_directory("/opt/prov/libsofthsm2.so") is None


def test_windows_dll_directory_returns_module_dir_on_win32(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_platform.sys, "platform", "win32")
    monkeypatch.setattr(_platform.os, "add_dll_directory", lambda d: None, raising=False)
    lib = tmp_path / "provider.dll"
    lib.write_text("stub", encoding="utf-8")
    assert windows_dll_directory(str(lib)) == str(tmp_path)


def test_windows_dll_directory_none_when_add_dll_directory_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_platform.sys, "platform", "win32")
    monkeypatch.delattr(_platform.os, "add_dll_directory", raising=False)
    lib = tmp_path / "provider.dll"
    lib.write_text("stub", encoding="utf-8")
    assert windows_dll_directory(str(lib)) is None
