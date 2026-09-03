"""Tests for pkcs11-check CLI commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pkcs11_check import __version__
from pkcs11_check.cli import test_cmd
from pkcs11_check.cli.app import app
from pkcs11_check.core import disabled_baseline as disabled_baseline_mod
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.file_runner import (
    FileRunResult,
    FileRunState,
    IsolatedReportConfig,
    run_isolated_pytest_units,
    save_run_state,
)
from pkcs11_check.core.preflight import CapabilityManifest
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.core.test_selection import DisabledBaseline
from tests._plain_cli_runner import PlainCliRunner

# Strips ANSI so assertions on message content hold regardless of the caller's
# terminal environment (FORCE_COLOR/TERM). See tests/_plain_cli_runner.py.
runner = PlainCliRunner()


def _ok_preflight(
    module: Path, *, interface: str, slot: int, timeout: int, output_path: Path
) -> CapabilityManifest:
    del timeout
    output_path.write_text("{}", encoding="utf-8")
    return CapabilityManifest(
        status="ok",
        module_path=str(module),
        requested_interface=interface,
        interface_version="3.2",
        slot_index=slot,
        slot_count=1,
        mechanisms=[],
    )


def _persist_failure(
    state_file: Path,
    diagnostic: str,
    *,
    report_config: IsolatedReportConfig | None = None,
    resume: bool = False,
) -> None:
    test_cmd._persist_collection_failure(
        diagnostic=diagnostic,
        state_file=state_file,
        report_config=report_config,
        resume=resume,
        provenance={},
    )


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
            + "\n",
            encoding="utf-8",
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
            + "\n",
            encoding="utf-8",
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
        module.write_text("", encoding="utf-8")
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
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "1234",
                "--so-pin",
                "9876",
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
        assert "--p11-so-pin" not in called["pytest_args"]
        assert "--p11-manifest" in called["pytest_args"]

    def test_test_restores_pin_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
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
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

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
        module.write_text("", encoding="utf-8")
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
        collected = [
            CollectedPytestItem(
                nodeid="src/pkcs11_check/testcases/test_demo.py::test_case",
                file_path="src/pkcs11_check/testcases/test_demo.py",
                markers=[],
            )
        ]
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
            collected_items: list[CollectedPytestItem] | None = None,
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
            called["collected_items"] = collected_items
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, *, pytest_args, policy_file, collected_out=None: (
                (collected_out.extend(collected) if collected_out is not None else None)
                or [
                    "src/pkcs11_check/testcases/test_demo.py",
                    "src/pkcs11_check/testcases/test_marked.py::test_case",
                ]
            ),  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}", encoding="utf-8"),
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
        assert called["collected_items"] == collected

    def test_test_auto_collection_failure_json_preserves_diagnostic_and_replaces_stale_artifacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "artifacts" / "results.json"
        state_path = tmp_path / "state.json"
        report_path = output_path.parent / "report.jsonl"
        output_path.parent.mkdir()
        output_path.write_text("stale results", encoding="utf-8")
        report_path.write_text("stale report", encoding="utf-8")
        for name in ("quality.json", "coverage.json", "provisioning.json"):
            (output_path.parent / name).write_text("stale", encoding="utf-8")
        state_path.write_text('{"stale": true}\n', encoding="utf-8")
        cache_dir = state_path.parent / f".{state_path.name}.report-records"
        cache_dir.mkdir()
        (cache_dir / "stale.jsonl").write_text("stale\n", encoding="utf-8")
        collection_sidecar = state_path.with_name(f"{state_path.name}.collection.jsonl")
        collection_sidecar.write_text("stale\n", encoding="utf-8")

        diagnostic = "ImportError: Error importing plugin benchmark"

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        def fail_collection(*_args: object, **_kwargs: object) -> list[str]:
            assert not output_path.exists()
            assert not report_path.exists()
            assert not state_path.exists()
            raise ValueError(diagnostic)

        monkeypatch.setattr(test_cmd, "discover_auto_isolation_units", fail_collection)

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "auto",
                "--output",
                "json",
                "--output-file",
                str(output_path),
                "--state-file",
                str(state_path),
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 2
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["error"] >= 1
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["incomplete"] is True
        records = [
            json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [record["$report_type"] for record in records] == ["CollectReport"]
        collects = [record for record in records if record["$report_type"] == "CollectReport"]
        assert len(collects) == 1
        assert diagnostic in collects[0]["longrepr"]
        assert payload["provenance"]
        assert not state_path.exists()
        assert not (cache_dir / "stale.jsonl").exists()
        assert "stale" not in collection_sidecar.read_text(encoding="utf-8")
        assert "stale" not in report_path.read_text(encoding="utf-8")
        for name in ("quality.json", "coverage.json", "provisioning.json"):
            artifact = output_path.parent / name
            assert not artifact.exists() or "stale" not in artifact.read_text(encoding="utf-8")

    def test_test_auto_collection_failure_junit_is_an_error_with_diagnostic(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "artifacts" / "results.xml"
        state_path = tmp_path / "state.json"
        diagnostic = "ImportError: Error importing plugin benchmark"

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        def fail_collection(*_args: object, **_kwargs: object) -> list[str]:
            raise ValueError(diagnostic)

        monkeypatch.setattr(test_cmd, "discover_auto_isolation_units", fail_collection)

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "auto",
                "--output",
                "junit",
                "--output-file",
                str(output_path),
                "--state-file",
                str(state_path),
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 2
        junit = output_path.read_text(encoding="utf-8")
        assert 'errors="1"' in junit
        assert "<error" in junit
        assert diagnostic in junit

    def test_test_auto_collection_failure_resume_preserves_prior_report_evidence(
        self, tmp_path: Path
    ) -> None:
        state_path = tmp_path / "state.json"
        output_path = tmp_path / "results.json"
        report_path = tmp_path / "report.jsonl"
        save_run_state(
            state_path,
            FileRunState(
                units=["old.py"],
                fingerprint="old-fingerprint",
                results=[FileRunResult("old.py", "passed", 0, 0.1)],
            ),
        )
        report_path.write_text(
            "\n".join(
                [
                    json.dumps({"$report_type": "SessionStart"}),
                    json.dumps(
                        {
                            "$report_type": "TestReport",
                            "nodeid": "old.py::test_ok",
                            "when": "call",
                            "outcome": "passed",
                        }
                    ),
                    json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        _persist_failure(
            state_path,
            "ImportError: current collection failed",
            report_config=IsolatedReportConfig("json", output_path, jsonl_path=report_path),
            resume=True,
        )

        merged = report_path.read_text(encoding="utf-8")
        assert "old.py::test_ok" in merged
        assert "ImportError: current collection failed" in merged
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["passed"] == 1
        assert payload["summary"]["error"] == 1
        assert payload["summary"]["incomplete"] is True
        saved = json.loads(state_path.read_text(encoding="utf-8"))
        assert saved["units"] == ["old.py"]
        assert saved["fingerprint"] == "old-fingerprint"
        assert {result["target"] for result in saved["results"]} == {"old.py"}

        _persist_failure(
            state_path,
            "ImportError: current collection failed",
            report_config=IsolatedReportConfig("json", output_path, jsonl_path=report_path),
            resume=True,
        )
        records = [
            json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()
        ]
        assert sum(record["$report_type"] == "CollectReport" for record in records) == 1

        _persist_failure(
            state_path,
            "ImportError: changed collection failure",
            report_config=IsolatedReportConfig("json", output_path, jsonl_path=report_path),
            resume=True,
        )
        records = [
            json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()
        ]
        collects = [record for record in records if record["$report_type"] == "CollectReport"]
        assert len(collects) == 2
        assert "changed collection failure" in collects[-1]["longrepr"]

    @pytest.mark.parametrize(
        ("status", "returncode"),
        [("failed", 1), ("crashed", -11)],
        ids=["provider-failure", "provider-crash"],
    )
    def test_collection_failure_json_keeps_prior_result_without_raw_report(
        self, tmp_path: Path, status: str, returncode: int
    ) -> None:
        state_path = tmp_path / "state.json"
        output_path = tmp_path / "results.json"
        target = "provider/test_backend.py"
        save_run_state(
            state_path,
            FileRunState(
                units=[target],
                fingerprint="prior-fingerprint",
                results=[FileRunResult(target, status, returncode, 0.1)],
            ),
        )

        _persist_failure(
            state_path,
            "current collection failed",
            report_config=IsolatedReportConfig(
                "json", output_path, jsonl_path=tmp_path / "report.jsonl"
            ),
            resume=True,
        )

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        units = {unit["target"]: unit for unit in payload["units"]}
        provider = units[target]
        assert provider["status"] == status
        assert provider["counts"][status] == 1
        assert "incomplete" not in provider
        assert payload["summary"][status] == 1
        assert payload["summary"]["error"] == 1
        assert payload["summary"]["incomplete"] is True

    def test_collection_failure_json_keeps_prior_xfail_details(self, tmp_path: Path) -> None:
        state_path = tmp_path / "state.json"
        output_path = tmp_path / "results.json"
        target = "provider/test_backend.py"
        xfail_record = {
            "$report_type": "TestReport",
            "nodeid": f"{target}::test_expected_refusal",
            "when": "call",
            "outcome": "skipped",
            "wasxfail": "provider limitation",
        }
        report_path = tmp_path / "report.jsonl"
        report_path.write_text(json.dumps(xfail_record) + "\n", encoding="utf-8")
        save_run_state(
            state_path,
            FileRunState(
                units=[target],
                fingerprint="prior-fingerprint",
                results=[FileRunResult(target, "passed", 0, 0.1)],
                report_records_by_unit={target: [xfail_record]},
            ),
        )

        _persist_failure(
            state_path,
            "current collection failed",
            report_config=IsolatedReportConfig("json", output_path, jsonl_path=report_path),
            resume=True,
        )

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        provider = next(unit for unit in payload["units"] if unit["target"] == target)
        assert provider["status"] == "passed"
        assert provider["counts"]["xfailed"] == 1
        assert provider["tests"][0]["outcome"] == "xfailed"
        assert payload["summary"]["xfailed"] == 1
        assert payload["summary"]["error"] == 1

    def test_global_collection_sidecar_survives_successful_resume(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path = tmp_path / "state.json"
        output_path = tmp_path / "results.json"
        report_path = tmp_path / "report.jsonl"
        target = tmp_path / "test_ok.py"
        target.write_text("def test_ok():\n    assert True\n", encoding="utf-8")

        _persist_failure(
            state_path,
            "global collection interrupted",
            report_config=IsolatedReportConfig("json", output_path, jsonl_path=report_path),
            resume=True,
        )
        assert not state_path.exists()

        def fake_run(cmd: list[str], **_: object) -> tuple[int, str, str]:
            report = Path(cmd[cmd.index("--report-log") + 1])
            report.write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": f"{target}::test_ok",
                                "when": "call",
                                "outcome": "passed",
                            }
                        ),
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return 0, "", ""

        monkeypatch.setattr(test_cmd, "_reset_fresh_run_artifacts", lambda *_: None)
        monkeypatch.setattr("pkcs11_check.core.file_runner._run_subprocess_tee", fake_run)
        run_isolated_pytest_units(
            [str(target)],
            [],
            timeout=12,
            state_file=state_path,
            policy_file=None,
            report_config=IsolatedReportConfig("json", output_path, jsonl_path=report_path),
            resume=True,
            stop_on_failure=False,
            console=SimpleNamespace(print=lambda *_args, **_kwargs: None),
            granularity="file",
        )
        merged = report_path.read_text(encoding="utf-8")
        assert "global collection interrupted" in merged
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["incomplete"] is True

    def test_global_collection_failure_without_output_keeps_sidecar(self, tmp_path: Path) -> None:
        state_path = tmp_path / "state.json"
        _persist_failure(state_path, "global collection failed")
        sidecar = state_path.with_name(f"{state_path.name}.collection.jsonl")
        assert sidecar.exists()
        assert "global collection failed" in sidecar.read_text(encoding="utf-8")
        assert not state_path.exists()

    def test_collection_skip_is_not_a_harness_error(self, tmp_path: Path) -> None:
        report_path = tmp_path / "report.jsonl"
        output_path = tmp_path / "results.json"
        report_path.write_text(
            "\n".join(
                [
                    json.dumps({"$report_type": "SessionStart"}),
                    json.dumps(
                        {
                            "$report_type": "CollectReport",
                            "nodeid": "test_empty.py",
                            "when": "collect",
                            "outcome": "skipped",
                        }
                    ),
                    json.dumps({"$report_type": "SessionFinish", "exitstatus": 5}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        payload = test_cmd.postprocess_jsonl_to_unified(report_path, output_path)
        assert payload["summary"]["error"] == 0
        assert payload["summary"]["incomplete"] is False

    def test_test_defaults_to_auto_isolation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        collected = [
            CollectedPytestItem(nodeid="saved.py::test_case", file_path="saved.py", markers=[])
        ]
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
            collected_items: list[CollectedPytestItem] | None = None,
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
            called["collected_items"] = collected_items
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
            lambda targets, pytest_args: collected,  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}", encoding="utf-8"),
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
        assert called["collected_items"] == collected

    def test_test_auto_resume_rejects_unexpanded_subprocess_per_test_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        marked_file = tmp_path / "test_marked.py"
        marked_file.write_text("def test_one():\n    assert True\n", encoding="utf-8")

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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        state_file.write_text(
            '{"fingerprint":"old","results":[],"units":["a.py"]}\n', encoding="utf-8"
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
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
                + "\n",
                encoding="utf-8",
            )
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}", encoding="utf-8"),
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
        assert results_path.parent.joinpath("report.jsonl").exists()
        assert results_path.parent.joinpath("coverage.json").exists()
        quality_path = results_path.parent / "quality.json"
        assert quality_path.exists()
        report = json.loads(quality_path.read_text(encoding="utf-8"))
        assert report["schema_version"] == "1"
        assert report["selection_findings"][0]["selected_but_not_invoked"] == ["CKM_AES_GCM"]

    def test_test_none_json_keeps_native_collection_error_in_report_and_results(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "artifacts" / "results.json"
        results_path.parent.mkdir()
        for name in ("coverage.json", "provisioning.json"):
            (results_path.parent / name).write_text("stale", encoding="utf-8")
        diagnostic = "SyntaxError: invalid syntax"

        def fake_main(args: list[str]) -> int:
            del args
            report_log = os.environ["PKCS11_CHECK_REPORT_LOG"]
            Path(report_log).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps(
                            {
                                "$report_type": "CollectReport",
                                "nodeid": "test_broken.py",
                                "when": "collect",
                                "outcome": "failed",
                                "longrepr": diagnostic,
                            }
                        ),
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": 2}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return 2

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

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

        assert result.exit_code == 2
        report_path = results_path.parent / "report.jsonl"
        assert diagnostic in report_path.read_text(encoding="utf-8")
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        assert payload["summary"]["error"] == 1
        assert payload["summary"]["failed"] == 0
        assert payload["summary"]["xfailed"] == 0
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["incomplete"] is True
        assert not (results_path.parent / "coverage.json").exists()
        assert not (results_path.parent / "provisioning.json").exists()

    def test_test_none_json_empty_reportlog_gets_collection_error_artifacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "artifacts" / "results.json"
        results_path.parent.mkdir()
        for name in ("coverage.json", "provisioning.json"):
            (results_path.parent / name).write_text("stale", encoding="utf-8")

        def fake_main(args: list[str]) -> int:
            del args
            Path(os.environ["PKCS11_CHECK_REPORT_LOG"]).write_text("", encoding="utf-8")
            return 2

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

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

        assert result.exit_code == 2
        report_path = results_path.parent / "report.jsonl"
        records = [
            json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()
        ]
        assert len(records) == 1
        assert records[0]["$report_type"] == "CollectReport"
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        assert payload["summary"]["error"] == 1
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["incomplete"] is True
        assert not (results_path.parent / "coverage.json").exists()
        assert not (results_path.parent / "provisioning.json").exists()

    def test_test_none_json_writes_quality_report_when_jsonl_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "artifacts" / "results.json"

        def fake_main(args: list[str]) -> int:
            del args
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}", encoding="utf-8"),
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
        report = json.loads(quality_path.read_text(encoding="utf-8"))
        assert report["schema_version"] == "1"
        assert "selection telemetry not provided" in report["data_quality_warnings"]

    def test_test_none_honors_disabled_baseline_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: dict[str, object] = {}

        def fake_main(args: list[str]) -> int:
            del args
            deselect_path = Path(os.environ["PKCS11_CHECK_DESELECT_FILE"])
            called["path"] = deselect_path
            called["text"] = deselect_path.read_text(encoding="utf-8")
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(
            disabled_baseline_mod,
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")

        def fake_main(args: list[str]) -> int:
            del args
            assert "PKCS11_CHECK_DESELECT_FILE" not in os.environ
            return 0

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(
            disabled_baseline_mod,
            "load_disabled_baseline",
            lambda path: pytest.fail("disabled baseline should be ignored"),
            raising=False,
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: (
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")

        monkeypatch.setattr(
            disabled_baseline_mod,
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
        file_path = tmp_path / "test_demo.py"
        file_path.write_text("", encoding="utf-8")
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
            disabled_baseline_mod,
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
        file_a = tmp_path / "test_a.py"
        file_b = tmp_path / "test_b.py"
        file_a.write_text("", encoding="utf-8")
        file_b.write_text("", encoding="utf-8")
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
            disabled_baseline_mod,
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
                output_path.write_text("{}", encoding="utf-8"),
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
        # Keys are scheduling units (native paths); node-id VALUES are canonical
        # forward-slash form so they match a disabled-tests file written on any platform.
        assert called["deselect_by_file"] == {str(file_a): {f"{file_a.as_posix()}::test_drop"}}

    def test_max_crashes_per_file_defaults_to_ten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
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
                output_path.write_text("{}", encoding="utf-8"),
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
        module.write_text("", encoding="utf-8")
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

    @pytest.mark.parametrize(
        ("status", "returncode", "timed_out"),
        [("crashed", -11, False), ("timeout", -9, True)],
    )
    def test_test_preflight_failure_json_writes_incomplete_artifact(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        status: str,
        returncode: int | None,
        timed_out: bool,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "results.json"
        observation = build_process_observation(
            str(module), "preflight", 0, returncode, timed_out=timed_out
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: CapabilityManifest(
                status=status,
                module_path=str(module),
                requested_interface=interface,
                interface_version=None,
                slot_index=slot,
                slot_count=None,
                mechanisms=[],
                process_observation=observation,
                error=f"preflight {status}",
            ),
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
                str(output_path),
            ],
        )

        assert result.exit_code == 1
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["incomplete"] is True
        assert len(payload["units"]) == 1
        unit = payload["units"][0]
        assert unit["target"] == str(module)
        assert unit["status"] == status
        assert unit["returncode"] == (124 if status == "timeout" else abs(returncode))
        assert unit["executions"] == [observation]

    def test_test_preflight_error_json_has_no_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "results.json"
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
                error="preflight error",
            ),
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
                str(output_path),
            ],
        )

        assert result.exit_code == 2
        assert not output_path.exists()

    def test_test_preflight_crash_non_json_has_no_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "results.xml"
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: CapabilityManifest(
                status="crashed",
                module_path=str(module),
                requested_interface=interface,
                interface_version=None,
                slot_index=slot,
                slot_count=None,
                mechanisms=[],
                process_observation=build_process_observation(str(module), "preflight", 0, -11),
                error="preflight crashed",
            ),
        )

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--output",
                "junit",
                "--output-file",
                str(output_path),
            ],
        )

        assert result.exit_code == 1
        assert not output_path.exists()

    def test_test_preflight_timeout_default_json_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        observation = build_process_observation(str(module), "preflight", 0, None, timed_out=True)
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path: CapabilityManifest(
                status="timeout",
                module_path=str(module),
                requested_interface=interface,
                interface_version=None,
                slot_index=slot,
                slot_count=None,
                mechanisms=[],
                process_observation=observation,
                error="preflight timed out",
            ),
        )

        result = runner.invoke(app, ["test", "--module", str(module), "--output", "json"])

        assert result.exit_code == 1
        assert (tmp_path / "pkcs11-check-results.json").exists()


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
        assert (tmp_path / "disabled-tests.txt").read_text(encoding="utf-8") == baseline

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
        assert (tmp_path / "disabled-tests.txt").read_text(encoding="utf-8") == baseline

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
