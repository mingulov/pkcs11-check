"""Tests for p11test CLI commands."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from p11test.cli import test_cmd
from p11test.cli.app import app
from p11test.core.preflight import CapabilityManifest

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
            policy_file: Path | None,
            report_config: object | None,
            resume: bool,
            stop_on_failure: bool,
            console: object,
            granularity: str,
        ) -> int:
            del console
            called["units"] = units
            called["pytest_args"] = pytest_args
            called["timeout"] = timeout
            called["state_file"] = state_file
            called["policy_file"] = policy_file
            called["report_config"] = report_config
            called["resume"] = resume
            called["stop_on_failure"] = stop_on_failure
            called["granularity"] = granularity
            return 7

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [  # type: ignore[arg-type]
                str(default_root / "test_alpha.py")
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}"),
                CapabilityManifest(
                    status="ok",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version="3.2",
                    slot_index=slot,
                    slot_count=1,
                    mechanisms=[],
                ),
            )[1],
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
        assert called["policy_file"] == Path(".p11test-isolation-policy.json")
        assert called["resume"] is True
        assert called["stop_on_failure"] is True
        assert called["granularity"] == "file"
        assert "--p11-pin" not in called["pytest_args"]
        assert "--p11-manifest" in called["pytest_args"]

    def test_test_test_isolation_invokes_runner(self, tmp_path: Path, monkeypatch: object) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        called: dict[str, object] = {}

        def fake_run(
            units: list[str],
            pytest_args: list[str],
            *,
            timeout: int,
            state_file: Path,
            policy_file: Path | None,
            report_config: object | None,
            resume: bool,
            stop_on_failure: bool,
            console: object,
            granularity: str,
        ) -> int:
            del (
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                resume,
                stop_on_failure,
                console,
            )
            called["units"] = units
            called["granularity"] = granularity
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [  # type: ignore[arg-type]
                "src/p11test/testcases/test_demo.py::test_case"
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}"),
                CapabilityManifest(
                    status="ok",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version="3.2",
                    slot_index=slot,
                    slot_count=1,
                    mechanisms=[],
                ),
            )[1],
        )

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", "test", "src/p11test/testcases"],
        )

        assert result.exit_code == 0
        assert called["units"] == ["src/p11test/testcases/test_demo.py::test_case"]
        assert called["granularity"] == "test"

    def test_test_auto_isolation_invokes_mixed_runner(
        self, tmp_path: Path, monkeypatch: object
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        called: dict[str, object] = {}

        def fake_run(
            units: list[str],
            pytest_args: list[str],
            *,
            timeout: int,
            state_file: Path,
            policy_file: Path | None,
            report_config: object | None,
            resume: bool,
            stop_on_failure: bool,
            console: object,
            granularity: str,
        ) -> int:
            del (
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                resume,
                stop_on_failure,
                console,
            )
            called["units"] = units
            called["granularity"] = granularity
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file: [  # type: ignore[arg-type]
                "src/p11test/testcases/test_demo.py",
                "src/p11test/testcases/test_marked.py::test_case",
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}"),
                CapabilityManifest(
                    status="ok",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version="3.2",
                    slot_index=slot,
                    slot_count=1,
                    mechanisms=[],
                ),
            )[1],
        )

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", "auto", "src/p11test/testcases"],
        )

        assert result.exit_code == 0
        assert called["units"] == [
            "src/p11test/testcases/test_demo.py",
            "src/p11test/testcases/test_marked.py::test_case",
        ]
        assert called["granularity"] == "mixed"

    def test_test_auto_resume_reuses_saved_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
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
            policy_file: Path | None,
            report_config: object | None,
            resume: bool,
            stop_on_failure: bool,
            console: object,
            granularity: str,
        ) -> int:
            del (
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                stop_on_failure,
                console,
            )
            called["units"] = units
            called["resume"] = resume
            called["granularity"] = granularity
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "load_run_state",
            lambda path: SimpleNamespace(units=["saved.py", "saved.py::test_case"]),  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file: pytest.fail(  # type: ignore[arg-type]
                "auto discovery should not run for resume with saved state"
            ),
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}"),
                CapabilityManifest(
                    status="ok",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version="3.2",
                    slot_index=slot,
                    slot_count=1,
                    mechanisms=[],
                ),
            )[1],
        )

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "auto",
                "--resume",
                "--state-file",
                str(state_file),
            ],
        )

        assert result.exit_code == 0
        assert called["units"] == ["saved.py", "saved.py::test_case"]
        assert called["resume"] is True
        assert called["granularity"] == "mixed"

    @pytest.mark.parametrize(
        ("mode", "output_name", "expected_name"),
        [
            ("auto", "json", "p11test-results.json"),
            ("file", "junit", "p11test-results.xml"),
            ("test", "json", "p11test-results.json"),
        ],
    )
    def test_test_isolation_builds_report_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mode: str,
        output_name: str,
        expected_name: str,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        called: dict[str, object] = {}

        def fake_run(
            units: list[str],
            pytest_args: list[str],
            *,
            timeout: int,
            state_file: Path,
            policy_file: Path | None,
            report_config: object | None,
            resume: bool,
            stop_on_failure: bool,
            console: object,
            granularity: str,
        ) -> int:
            del (
                units,
                pytest_args,
                timeout,
                state_file,
                policy_file,
                resume,
                stop_on_failure,
                console,
                granularity,
            )
            called["report_config"] = report_config
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file: [
                str(default_root / "test_alpha.py")
            ],  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
                str(default_root / "test_alpha.py")
            ],  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}"),
                CapabilityManifest(
                    status="ok",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version="3.2",
                    slot_index=slot,
                    slot_count=1,
                    mechanisms=[],
                ),
            )[1],
        )

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", mode, "--output", output_name],
        )

        assert result.exit_code == 0
        report_config = called["report_config"]
        assert report_config is not None
        assert getattr(report_config, "output_format") == output_name
        assert Path(getattr(report_config, "output_path")).name == expected_name

    def test_test_file_isolation_resume_mismatch_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        state_file = tmp_path / "state.json"
        state_file.write_text('{"fingerprint":"old","results":[],"units":["a.py"]}\n')
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}"),
                CapabilityManifest(
                    status="ok",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version="3.2",
                    slot_index=slot,
                    slot_count=1,
                    mechanisms=[],
                ),
            )[1],
        )

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

    def test_test_preflight_failure_is_reported(self, tmp_path: Path, monkeypatch: object) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: CapabilityManifest(
                status="error",
                module_path=str(module),
                requested_interface=interface,
                interface_version=None,
                slot_index=slot,
                slot_count=None,
                mechanisms=[],
                error="RuntimeError: boom",
            ),
        )

        result = runner.invoke(app, ["test", "--module", str(module)])

        assert result.exit_code == 2
        assert "PKCS#11 preflight error" in result.output


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
