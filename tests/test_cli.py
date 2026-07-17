"""Tests for pkcs11-check CLI commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from pkcs11_check import __version__
from pkcs11_check.cli import test_cmd
from pkcs11_check.cli.app import app
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.preflight import CapabilityManifest
from pkcs11_check.core.test_selection import DisabledBaseline

runner = CliRunner()


class TestVersionCommand:
    def test_version_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert f"pkcs11-check {__version__}" in result.output


class TestCompareCoverageCommand:
    def test_compare_coverage_reports_loss_and_can_fail(self, tmp_path: Path) -> None:
        baseline_dir = tmp_path / "baseline"
        candidate_dir = tmp_path / "candidate"
        baseline_dir.mkdir()
        candidate_dir.mkdir()
        (baseline_dir / "coverage.json").write_text(
            json.dumps(
                {
                    "mechanism_coverage": {
                        "accepted_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
                        "attempted_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
                    }
                }
            )
            + "\n"
        )
        (candidate_dir / "coverage.json").write_text(
            json.dumps(
                {
                    "mechanism_coverage": {
                        "accepted_names": ["CKM_AES_CBC"],
                        "attempted_names": ["CKM_AES_CBC"],
                    }
                }
            )
            + "\n"
        )

        result = runner.invoke(
            app,
            [
                "compare-coverage",
                str(baseline_dir),
                str(candidate_dir),
                "--output",
                "json",
                "--fail-on-loss",
            ],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["has_loss"] is True
        assert payload["lost_by_state"] == {
            "accepted": ["CKM_AES_GCM"],
            "attempted": ["CKM_AES_GCM"],
        }


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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
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
            called["max_crashes_per_file"] = max_crashes_per_file
            called["deselect_by_file"] = deselect_by_file
            called["baseline_fingerprint"] = baseline_fingerprint
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
                "--max-crashes-per-file",
                "5",
                "--state-file",
                str(state_file),
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 7
        assert called["units"] == [str(Path(test_cmd._TESTCASES_DIR) / "test_alpha.py")]
        assert called["timeout"] == 33
        assert called["state_file"] == state_file
        assert called["policy_file"] == Path(".pkcs11-check-isolation-policy.json")
        assert called["resume"] is True
        assert called["stop_on_failure"] is True
        assert called["granularity"] == "file"
        assert called["max_crashes_per_file"] == 5
        assert "--p11-pin" not in called["pytest_args"]
        assert "--p11-manifest" in called["pytest_args"]

    def test_test_restores_pin_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        monkeypatch.setenv("P11TEST_PIN", "outer-secret")

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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
        ) -> int:
            del (
                units,
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                resume,
                stop_on_failure,
                console,
                granularity,
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
            )
            assert os.environ["P11TEST_PIN"] == "1234"
            return 0

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
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 0
        assert os.environ["P11TEST_PIN"] == "outer-secret"

    def test_test_restores_so_pin_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        monkeypatch.setenv("P11TEST_SO_PIN", "outer-so")

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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
        ) -> int:
            del (
                units,
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                resume,
                stop_on_failure,
                console,
                granularity,
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
            )
            assert os.environ["P11TEST_SO_PIN"] == "9999"
            return 0

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
                "--so-pin",
                "9999",
                "--isolation",
                "file",
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 0
        assert os.environ["P11TEST_SO_PIN"] == "outer-so"

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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
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
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
            )
            called["units"] = units
            called["granularity"] = granularity
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [  # type: ignore[arg-type]
                "src/pkcs11_check/testcases/test_demo.py::test_case"
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
            ["test", "--module", str(module), "--isolation", "test", "src/pkcs11_check/testcases"],
        )

        assert result.exit_code == 0
        assert called["units"] == ["src/pkcs11_check/testcases/test_demo.py::test_case"]
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
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
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
            )
            called["units"] = units
            called["granularity"] = granularity
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file, collected_out=None: [  # type: ignore[arg-type]
                "src/pkcs11_check/testcases/test_demo.py",
                "src/pkcs11_check/testcases/test_marked.py::test_case",
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
                "--isolation",
                "auto",
                "src/pkcs11_check/testcases",
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 0
        assert called["units"] == [
            "src/pkcs11_check/testcases/test_demo.py",
            "src/pkcs11_check/testcases/test_marked.py::test_case",
        ]
        assert called["granularity"] == "mixed"

    def test_test_defaults_to_auto_isolation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
        ) -> int:
            del (
                units,
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                resume,
                stop_on_failure,
                console,
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
            )
            called["granularity"] = granularity
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file, collected_out=None: [  # type: ignore[arg-type]
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

        result = runner.invoke(app, ["test", "--module", str(module), "--ignore-disabled-tests"])

        assert result.exit_code == 0
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
        ) -> int:
            del (
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                stop_on_failure,
                console,
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
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
            lambda *_a, **_k: pytest.fail(  # type: ignore[arg-type]
                "auto discovery should not run for resume with saved state"
            ),
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_item_metadata",
            lambda targets, pytest_args: [],  # type: ignore[arg-type]
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
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 0
        assert called["units"] == ["saved.py", "saved.py::test_case"]
        assert called["resume"] is True
        assert called["granularity"] == "mixed"

    def test_test_auto_resume_rejects_unexpanded_subprocess_per_test_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        state_file = tmp_path / "state.json"
        marked_file = tmp_path / "test_marked.py"
        marked_file.write_text("def test_one():\n    assert True\n")

        monkeypatch.setattr(
            test_cmd,
            "load_run_state",
            lambda path: SimpleNamespace(units=[str(marked_file)]),  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_item_metadata",
            lambda targets, pytest_args: [  # type: ignore[arg-type]
                CollectedPytestItem(
                    nodeid=f"{marked_file}::test_one",
                    file_path=str(marked_file),
                    markers=["subprocess_per_test"],
                )
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
        monkeypatch.setattr(
            test_cmd,
            "run_isolated_pytest_units",
            lambda *_a, **_k: pytest.fail("stale unexpanded state must not run"),  # type: ignore[arg-type]
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
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 2
        assert "subprocess_per_test file was not expanded" in result.output

    @pytest.mark.parametrize(
        ("mode", "output_name", "expected_name"),
        [
            ("auto", "json", "pkcs11-check-results.json"),
            ("file", "junit", "pkcs11-check-results.xml"),
            ("test", "json", "pkcs11-check-results.json"),
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
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
                max_crashes_per_file,
                deselect_by_file,
                baseline_fingerprint,
            )
            called["report_config"] = report_config
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file, collected_out=None: [
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
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                mode,
                "--output",
                output_name,
                "--ignore-disabled-tests",
            ],
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
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 2
        assert "belongs to a different isolated run" in " ".join(result.output.split())

    def test_test_none_json_writes_quality_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        results_path = tmp_path / "artifacts" / "results.json"

        def fake_main(args: list[str]) -> int:
            del args
            report_log = os.environ["PKCS11_CHECK_REPORT_LOG"]
            Path(report_log).write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": "test_demo.py::test_ok",
                                "when": "call",
                                "outcome": "passed",
                                "duration": 0.1,
                            }
                        ),
                        json.dumps(
                            {
                                "$report_type": "SelectionReport",
                                "selection_coverage": {
                                    "encrypt_roundtrip": {
                                        "selected_mechanisms": [
                                            "CKM_AES_CBC",
                                            "CKM_AES_GCM",
                                        ],
                                        "rejected_mechanisms": [],
                                        "rejected_reason_counts": {},
                                    }
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "$report_type": "CoverageReport",
                                "function_coverage": {
                                    "available": 1,
                                    "called_names": ["C_Encrypt"],
                                    "uncalled_names": [],
                                    "called_counts": {"C_Encrypt": 1},
                                    "bootstrap_counts": {},
                                },
                                "mechanism_coverage": {
                                    "available": 2,
                                    "available_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
                                    "invoked": 1,
                                    "invoked_names": ["CKM_AES_CBC"],
                                    "invoked_counts": {"CKM_AES_CBC": 1},
                                    "not_invoked": 1,
                                    "not_invoked_names": ["CKM_AES_GCM"],
                                    "invoked_detail": ["encrypt_roundtrip"],
                                    "invoked_detail_counts": {"encrypt_roundtrip": 1},
                                },
                            }
                        ),
                    ]
                )
                + "\n"
            )
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
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
                "--output",
                "json",
                "--output-file",
                str(results_path),
                "--isolation",
                "none",
            ],
        )

        assert result.exit_code == 0
        assert results_path.exists()
        assert results_path.parent.joinpath("coverage.json").exists()
        quality_path = results_path.parent / "quality.json"
        assert quality_path.exists()
        report = json.loads(quality_path.read_text())
        assert report["schema_version"] == "1"
        assert report["selection_findings"][0]["selected_but_not_invoked"] == ["CKM_AES_GCM"]

    def test_test_none_json_writes_quality_report_when_jsonl_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        results_path = tmp_path / "artifacts" / "results.json"

        def fake_main(args: list[str]) -> int:
            del args
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
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
                "--output",
                "json",
                "--output-file",
                str(results_path),
                "--isolation",
                "none",
            ],
        )

        assert result.exit_code == 0
        quality_path = results_path.parent / "quality.json"
        assert quality_path.exists()
        report = json.loads(quality_path.read_text())
        assert report["schema_version"] == "1"
        assert "selection telemetry not provided" in report["data_quality_warnings"]

    def test_test_none_honors_disabled_baseline_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        called: dict[str, object] = {}

        def fake_main(args: list[str]) -> int:
            del args
            deselect_path = Path(os.environ["PKCS11_CHECK_DESELECT_FILE"])
            called["path"] = deselect_path
            called["text"] = deselect_path.read_text()
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(
            test_cmd,
            "load_disabled_baseline",
            lambda path: DisabledBaseline(
                source_path=Path("config/disabled-tests.txt"),
                disabled_nodeids=frozenset({"test_demo.py::test_disabled"}),
                fingerprint="baseline-fp",
            ),
            raising=False,
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

        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "none"])

        assert result.exit_code == 0
        assert called["text"] == "test_demo.py::test_disabled\n"
        assert "PKCS11_CHECK_DESELECT_FILE" not in os.environ

    def test_test_none_ignore_disabled_tests_skips_baseline_loading(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")

        def fake_main(args: list[str]) -> int:
            del args
            assert "PKCS11_CHECK_DESELECT_FILE" not in os.environ
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(
            test_cmd,
            "load_disabled_baseline",
            lambda path: pytest.fail("disabled baseline should be ignored"),
            raising=False,
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
            ["test", "--module", str(module), "--isolation", "none", "--ignore-disabled-tests"],
        )

        assert result.exit_code == 0

    def test_test_none_missing_disabled_baseline_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")

        monkeypatch.setattr(
            test_cmd,
            "load_disabled_baseline",
            lambda path: (_ for _ in ()).throw(
                FileNotFoundError("disabled baseline file not found: broken")
            ),
            raising=False,
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

        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "none"])

        assert result.exit_code == 2
        assert "disabled baseline file not found" in result.output

    def test_test_isolation_filters_disabled_test_units_before_runner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        file_path = tmp_path / "test_demo.py"
        file_path.write_text("")
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
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
                max_crashes_per_file,
            )
            called["units"] = units
            called["granularity"] = granularity
            called["deselect_by_file"] = deselect_by_file
            called["baseline_fingerprint"] = baseline_fingerprint
            return 0

        unit_a = f"{file_path}::test_a"
        unit_b = f"{file_path}::test_b"
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [unit_a, unit_b],  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "load_disabled_baseline",
            lambda path: DisabledBaseline(
                source_path=Path("config/disabled-tests.txt"),
                disabled_nodeids=frozenset({unit_b}),
                fingerprint="baseline-fp-test",
            ),
            raising=False,
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

        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "test"])

        assert result.exit_code == 0
        assert called["units"] == [unit_a]
        assert called["granularity"] == "test"
        assert called["deselect_by_file"] == {}
        assert called["baseline_fingerprint"] == "baseline-fp-test"

    def test_file_isolation_drops_fully_disabled_files_and_passes_mixed_deselects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("")
        file_a = tmp_path / "test_a.py"
        file_b = tmp_path / "test_b.py"
        file_a.write_text("")
        file_b.write_text("")
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
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
                max_crashes_per_file,
                baseline_fingerprint,
            )
            called["units"] = units
            called["granularity"] = granularity
            called["deselect_by_file"] = deselect_by_file
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [str(file_a), str(file_b)],  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_item_metadata",
            lambda targets, pytest_args, *, env=None: [  # type: ignore[arg-type]
                CollectedPytestItem(
                    nodeid=f"{file_a}::test_keep",
                    file_path=str(file_a),
                    markers=[],
                ),
                CollectedPytestItem(
                    nodeid=f"{file_a}::test_drop",
                    file_path=str(file_a),
                    markers=[],
                ),
                CollectedPytestItem(
                    nodeid=f"{file_b}::test_only",
                    file_path=str(file_b),
                    markers=[],
                ),
            ],
            raising=False,
        )
        monkeypatch.setattr(
            test_cmd,
            "load_disabled_baseline",
            lambda path: DisabledBaseline(
                source_path=Path("config/disabled-tests.txt"),
                disabled_nodeids=frozenset({f"{file_a}::test_drop", f"{file_b}::test_only"}),
                fingerprint="baseline-fp-file",
            ),
            raising=False,
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

        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "file"])

        assert result.exit_code == 0
        assert called["units"] == [str(file_a)]
        assert called["granularity"] == "file"
        assert called["deselect_by_file"] == {str(file_a): {f"{file_a}::test_drop"}}

    def test_max_crashes_per_file_defaults_to_ten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
            max_crashes_per_file: int,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
        ) -> int:
            del (
                units,
                pytest_args,
                timeout,
                state_file,
                policy_file,
                report_config,
                resume,
                stop_on_failure,
                console,
                granularity,
                deselect_by_file,
                baseline_fingerprint,
            )
            called["max_crashes_per_file"] = max_crashes_per_file
            return 0

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
                "--isolation",
                "file",
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 0
        assert called["max_crashes_per_file"] == 10

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


class TestFetchDisabledCommand:
    """`fetch-disabled` downloads the disabled-tests baseline."""

    def test_accepts_empty_baseline(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A comments-only / no-entries baseline is valid ("no disabled tests")
        and MUST succeed -- an empty baseline is the normal state, not an error.
        """
        import io

        from pkcs11_check.cli import fetch_cmd

        baseline = (
            "# Global production disabled baseline.\n"
            "# One exact pytest nodeid per line.\n"
            "#src/pkcs11_check/testcases/acvp/aes/test_cfb128.py::test_x[tc1]\n"
        )
        monkeypatch.setattr(fetch_cmd, "urlopen", lambda _url: io.BytesIO(baseline.encode()))

        result = runner.invoke(app, ["fetch-disabled", "--data-dir", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert (tmp_path / "disabled-tests.txt").read_text() == baseline

    def test_accepts_real_entries(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import io

        from pkcs11_check.cli import fetch_cmd

        baseline = (
            "# header\n"
            "src/pkcs11_check/testcases/test_x.py::test_a\n"
            "src/pkcs11_check/testcases/test_x.py::test_b\n"
        )
        monkeypatch.setattr(fetch_cmd, "urlopen", lambda _url: io.BytesIO(baseline.encode()))

        result = runner.invoke(app, ["fetch-disabled", "--data-dir", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert (tmp_path / "disabled-tests.txt").read_text() == baseline

    def test_rejects_non_baseline(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-empty file that is not a baseline (e.g. an HTML 404 page) must
        still fail -- allowing an empty baseline must not allow garbage.
        """
        import io

        from pkcs11_check.cli import fetch_cmd

        html = "<html><body>404: Not Found</body></html>\n"
        monkeypatch.setattr(fetch_cmd, "urlopen", lambda _url: io.BytesIO(html.encode()))

        result = runner.invoke(app, ["fetch-disabled", "--data-dir", str(tmp_path)])

        assert result.exit_code == 1
