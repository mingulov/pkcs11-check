"""The opt-in token-mint shell hook must use a portable shell invocation."""

from __future__ import annotations

from pkcs11_check.testcases import _shellcmd


def test_posix_shell(monkeypatch) -> None:
    monkeypatch.setattr(_shellcmd.sys, "platform", "linux", raising=False)
    assert _shellcmd.shell_invocation("echo hi") == ["/bin/sh", "-c", "echo hi"]


def test_windows_shell(monkeypatch) -> None:
    monkeypatch.setattr(_shellcmd.sys, "platform", "win32", raising=False)
    # Single string, not argv: subprocess renders argv lists via list2cmdline,
    # which wraps the command in quotes and backslash-escapes inner quotes,
    # breaking cmd parsing for any mint template containing double quotes.
    assert _shellcmd.shell_invocation("echo hi") == 'cmd /s /c "echo hi"'


def test_windows_shell_preserves_inner_quotes(monkeypatch) -> None:
    monkeypatch.setattr(_shellcmd.sys, "platform", "win32", raising=False)
    # /s makes cmd strip exactly the outer pair and run the rest verbatim,
    # so inner quotes survive (cf. list2cmdline mangling of the old argv form).
    assert _shellcmd.shell_invocation(r'echo qc11 > "C:\T\x.conf"') == (
        r'cmd /s /c "echo qc11 > "C:\T\x.conf""'
    )
