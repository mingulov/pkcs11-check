"""Constrained CLI options and fetch timeouts (v0.2.1 Group E: M-20, M-28, M-29).

M-28/M-29: ``--interface`` / ``--log-level`` are typer Choices, so a typo is a
usage error (exit 2 with "Invalid value") -- never an exit-3 miscode ("Error
loading module") or an uncaught traceback (``ValueError: Unknown level``).

M-20 (timeout half): both ``urlopen`` calls in ``fetch_cmd`` pass an explicit
``timeout`` so a stalled server cannot hang ``fetch-data``/``fetch-disabled``
forever. PLACEHOLDER checksum semantics are intentionally untouched.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, get_args

import pytest

from pkcs11_check.cli import fetch_cmd
from pkcs11_check.cli._choices import InterfaceChoice, LogLevelChoice
from pkcs11_check.cli.app import app
from pkcs11_check.core.loader import SUPPORTED_INTERFACES
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()

VALID_INTERFACES = ["auto", "2.40", "3.0", "3.1", "3.2"]
VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Every command exposing --interface, with argv *except* the interface value.
INTERFACE_ARGV: dict[str, list[str]] = {
    "info": ["info", "--module", "x.so"],
    "doctor": ["doctor", "--module", "x.so"],
    "test": ["test", "--module", "x.so"],
    "list-tests": ["list-tests"],
    "compliance-report": ["compliance-report", "--module", "x.so"],
}


class TestInterfaceChoiceDrift:
    def test_choice_matches_loader_supported_interfaces(self) -> None:
        """The CLI Choice must accept exactly what the loader supports."""
        assert set(get_args(InterfaceChoice)) == set(SUPPORTED_INTERFACES)

    def test_log_level_choice_covers_standard_levels(self) -> None:
        """The --log-level Choice must accept exactly the logging levels."""
        assert set(get_args(LogLevelChoice)) == set(VALID_LOG_LEVELS)


class TestInterfaceChoice:
    @pytest.mark.parametrize("command", sorted(INTERFACE_ARGV))
    def test_invalid_interface_is_usage_error(self, command: str) -> None:
        """A bad --interface is exit 2 ("Invalid value"), not exit 3."""
        result = runner.invoke(app, [*INTERFACE_ARGV[command], "--interface", "bogus"])
        assert result.exit_code == 2, result.output
        assert "Invalid value" in result.output
        assert isinstance(result.exception, SystemExit)

    @pytest.mark.parametrize("value", VALID_INTERFACES)
    def test_valid_interface_reaches_module_check(self, value: str) -> None:
        """Valid values pass Choice: info then fails on the missing module."""
        result = runner.invoke(app, ["info", "--module", "x.so", "--interface", value])
        assert result.exit_code == 3, result.output
        assert "Module not found" in result.output


class TestLogLevelChoice:
    def test_invalid_log_level_is_usage_error(self) -> None:
        """A bad --log-level is exit 2, not a ValueError traceback."""
        result = runner.invoke(app, ["--log-level", "BOGUS", "version"])
        assert result.exit_code == 2, result.output
        assert "Invalid value" in result.output
        assert isinstance(result.exception, SystemExit)

    @pytest.mark.parametrize("level", VALID_LOG_LEVELS)
    def test_valid_log_levels_accepted(self, level: str) -> None:
        result = runner.invoke(app, ["--log-level", level, "version"])
        assert result.exit_code == 0, result.output
        assert "pkcs11-check" in result.output

    def test_lowercase_log_level_still_accepted(self) -> None:
        """Choice is case-insensitive: setup_logging's .upper() still applies."""
        result = runner.invoke(app, ["--log-level", "debug", "version"])
        assert result.exit_code == 0, result.output
        assert "pkcs11-check" in result.output


class _FakeFetchResponse(io.BytesIO):
    """Minimal urlopen response: context manager + headers + read()."""

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.headers = {"Content-Length": str(len(payload))}


def _recording_urlopen(payload: bytes, calls: dict[str, Any]) -> Any:  # noqa: ANN401
    def fake(url: str, **kwargs: Any) -> _FakeFetchResponse:
        calls["url"] = url
        calls["kwargs"] = kwargs
        return _FakeFetchResponse(payload)

    return fake


class TestFetchTimeouts:
    def test_download_with_progress_passes_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: dict[str, Any] = {}
        monkeypatch.setattr(fetch_cmd, "urlopen", _recording_urlopen(b"data", calls))
        dest = tmp_path / "f.zip"
        fetch_cmd._download_with_progress("https://example.com/f.zip", dest, "label")
        assert dest.read_bytes() == b"data"
        assert calls["kwargs"].get("timeout") == fetch_cmd._DOWNLOAD_TIMEOUT_S
        assert calls["kwargs"]["timeout"] > 0

    def test_fetch_disabled_passes_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        baseline = "src/pkcs11_check/testcases/test_x.py::test_a\n"
        calls: dict[str, Any] = {}
        monkeypatch.setattr(fetch_cmd, "urlopen", _recording_urlopen(baseline.encode(), calls))
        result = runner.invoke(app, ["fetch-disabled", "--data-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert calls["kwargs"].get("timeout") == fetch_cmd._DOWNLOAD_TIMEOUT_S
        assert calls["kwargs"]["timeout"] > 0
