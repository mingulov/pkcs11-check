"""Tests for p11test CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from p11test.cli import test_cmd
from p11test.cli.app import app

runner = CliRunner()


class TestVersionCommand:
    def test_version_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "p11test 0.1.0" in result.output


class TestTestCommand:
    def test_test_requires_module(self) -> None:
        result = runner.invoke(app, ["test"])
        assert result.exit_code != 0

    def test_test_nonexistent_module(self) -> None:
        result = runner.invoke(app, ["test", "--module", "/nonexistent.so"])
        assert result.exit_code == 3

    def test_test_file_isolation_invokes_runner(self, tmp_path: Path, monkeypatch: object) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        state_file = tmp_path / "state.json"
        called: dict[str, object] = {}

        def fake_run(
            units: list[str],
            pytest_args: list[str],
            *,
            timeout: int,
            state_file: Path,
            resume: bool,
            stop_on_failure: bool,
            console: object,
        ) -> int:
            del console
            called["units"] = units
            called["pytest_args"] = pytest_args
            called["timeout"] = timeout
            called["state_file"] = state_file
            called["resume"] = resume
            called["stop_on_failure"] = stop_on_failure
            return 7

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root: [str(default_root / "test_alpha.py")],
        )

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "1234",
                "--isolation",
                "file",
                "--timeout",
                "33",
                "--resume",
                "--stop-on-failure",
                "--state-file",
                str(state_file),
            ],
        )

        assert result.exit_code == 7
        assert called["units"] == [str(Path(test_cmd._TESTCASES_DIR) / "test_alpha.py")]
        assert called["timeout"] == 33
        assert called["state_file"] == state_file
        assert called["resume"] is True
        assert called["stop_on_failure"] is True
        assert "--p11-pin" not in called["pytest_args"]

    def test_test_file_isolation_rejects_non_rich_output(self, tmp_path: Path) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", "file", "--output", "junit"],
        )

        assert result.exit_code == 2
        assert "--isolation file currently supports only --output rich" in result.output

    def test_test_file_isolation_resume_mismatch_is_reported(self, tmp_path: Path) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        state_file = tmp_path / "state.json"
        state_file.write_text('{"fingerprint":"old","results":[],"units":["a.py"]}\n')

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--resume",
                "--state-file",
                str(state_file),
            ],
        )

        assert result.exit_code == 2
        assert "belongs to a different isolated run" in " ".join(result.output.split())


class TestInfoCommand:
    def test_info_requires_module(self) -> None:
        result = runner.invoke(app, ["info"])
        assert result.exit_code != 0

    def test_info_nonexistent_module(self) -> None:
        result = runner.invoke(app, ["info", "--module", "/nonexistent.so"])
        assert result.exit_code == 3


class TestListCommand:
    def test_list_shows_categories(self) -> None:
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "encrypt" in result.output
        assert "sign" in result.output

    def test_list_filter_category(self) -> None:
        result = runner.invoke(app, ["list", "--category", "pqc"])
        assert result.exit_code == 0
        assert "pqc" in result.output.lower()
