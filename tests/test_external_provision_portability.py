"""On Windows the external-provision tier must still function: missing os.fchmod must
not disable it, and a Windows command path must not be mangled by POSIX shlex."""

from __future__ import annotations

from pkcs11_check.testcases import _provisioning


def test_shlex_split_windows_path_preserved(monkeypatch) -> None:
    # POSIX shlex eats the backslashes; the code must use posix=False on Windows.
    monkeypatch.setattr(_provisioning.sys, "platform", "win32", raising=False)
    parsed = _provisioning._split_provision_cmd(r"C:\tools\prov.exe --key C:\tmp\k.bin")
    assert parsed[0] == r"C:\tools\prov.exe"
    assert r"C:\tmp\k.bin" in parsed


def test_shlex_split_posix_unchanged(monkeypatch) -> None:
    monkeypatch.setattr(_provisioning.sys, "platform", "linux", raising=False)
    assert _provisioning._split_provision_cmd("prov --key /tmp/k.bin") == [
        "prov",
        "--key",
        "/tmp/k.bin",
    ]
