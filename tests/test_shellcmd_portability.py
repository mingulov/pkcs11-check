"""The opt-in token-mint shell hook must use a portable shell invocation."""

from __future__ import annotations

from pkcs11_check.testcases import _shellcmd


def test_posix_shell(monkeypatch) -> None:
    monkeypatch.setattr(_shellcmd.sys, "platform", "linux", raising=False)
    assert _shellcmd.shell_invocation("echo hi") == ["/bin/sh", "-c", "echo hi"]


def test_windows_shell(monkeypatch) -> None:
    monkeypatch.setattr(_shellcmd.sys, "platform", "win32", raising=False)
    assert _shellcmd.shell_invocation("echo hi") == ["cmd", "/c", "echo hi"]
