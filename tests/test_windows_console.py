"""Windows console must not crash on rich's Unicode marks.

On a cp1252 Windows console (the GitHub Actions default) rich's checkmarks / dashes
raise UnicodeEncodeError (\\u2713). The CLI reconfigures stdout/stderr to UTF-8 before
any Console is built, and the isolated runner gives its pytest subprocesses UTF-8 too.
"""

from __future__ import annotations

import pytest

from pkcs11_check.cli import _encoding
from pkcs11_check.core import file_runner


class _FakeStream:
    def __init__(self) -> None:
        self.kwargs: list[dict[str, str]] = []

    def reconfigure(self, **kwargs: str) -> None:
        self.kwargs.append(kwargs)


def test_ensure_utf8_reconfigures_both_streams_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = _FakeStream(), _FakeStream()
    monkeypatch.setattr(_encoding.sys, "platform", "win32")
    monkeypatch.setattr(_encoding.sys, "stdout", out)
    monkeypatch.setattr(_encoding.sys, "stderr", err)
    _encoding.ensure_utf8_streams()
    assert out.kwargs == [{"encoding": "utf-8"}]
    assert err.kwargs == [{"encoding": "utf-8"}]


def test_ensure_utf8_is_noop_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _FakeStream()
    monkeypatch.setattr(_encoding.sys, "platform", "linux")
    monkeypatch.setattr(_encoding.sys, "stdout", out)
    _encoding.ensure_utf8_streams()
    assert out.kwargs == []


def test_subprocess_env_forces_utf8_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_runner.sys, "platform", "win32")
    env = file_runner._subprocess_plugin_env({}, "test_anything.py")
    assert env.get("PYTHONUTF8") == "1"


def test_subprocess_env_unchanged_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_runner.sys, "platform", "linux")
    env = file_runner._subprocess_plugin_env({}, "test_anything.py")
    assert "PYTHONUTF8" not in env
