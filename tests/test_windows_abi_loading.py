"""S4: on Windows, register a module's own directory on the DLL search path so its
dependent DLLs (e.g. a provider's bundled OpenSSL) resolve. No-op on POSIX.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw import api


def test_windows_dll_directory_returns_module_dir_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(api.sys, "platform", "win32")
    # os.add_dll_directory only exists on Windows; provide a stub so the gate passes.
    if not hasattr(api.os, "add_dll_directory"):
        monkeypatch.setattr(api.os, "add_dll_directory", lambda d: None, raising=False)
    dll = tmp_path / "provider.dll"
    dll.write_bytes(b"")
    assert api._windows_dll_directory(str(dll)) == str(tmp_path)


def test_windows_dll_directory_noop_on_posix(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(api.sys, "platform", "linux")
    dll = tmp_path / "provider.so"
    dll.write_bytes(b"")
    assert api._windows_dll_directory(str(dll)) is None
