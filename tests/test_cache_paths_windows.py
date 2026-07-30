"""On Windows the private cache lives under %LOCALAPPDATA% (per-user by OS default),
not ~/.cache; POSIX keeps XDG_CACHE_HOME/~/.cache with mode-bit tightening."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.core import cache_paths


def test_windows_uses_localappdata(monkeypatch) -> None:
    monkeypatch.setattr(cache_paths.sys, "platform", "win32", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(Path("C:/Users/x/AppData/Local")))
    root = cache_paths._cache_root()
    assert "AppData/Local" in root.as_posix()
    assert root.name == "cache"
    assert "pkcs11-check" in root.as_posix()


def test_posix_uses_xdg(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cache_paths.sys, "platform", "linux", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    root = cache_paths._cache_root()
    assert root == tmp_path / "pkcs11-check"
