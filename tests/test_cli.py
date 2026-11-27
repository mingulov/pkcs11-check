"""Tests for pkcs11-check CLI commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from pkcs11_check import __version__
from pkcs11_check.cli import test_cmd
from pkcs11_check.cli.app import app
from pkcs11_check.core import collection_errors as collection_errors_mod
from pkcs11_check.core import disabled_baseline as disabled_baseline_mod
from pkcs11_check.core._report_records import _write_unit_report_record_cache
from pkcs11_check.core.collection import CollectedPytestItem, CollectedSkip
from pkcs11_check.core.doctor_probe import LoginProbe
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


def _auto_discover_with_collected(
    collected: list[CollectedPytestItem],
) -> object:
    """Fake auto discovery that fills collected_out and returns demo units."""

    def fake(
        targets: object,
        default_root: object,
        *,
        pytest_args: object,
        policy_file: object,
        collected_out: list[CollectedPytestItem] | None = None,
        skips_out: object = None,
    ) -> list[str]:
        del targets, default_root, pytest_args, policy_file, skips_out
        if collected_out is not None:
            collected_out.extend(collected)
        return [
            "src/pkcs11_check/testcases/test_demo.py",
            "src/pkcs11_check/testcases/test_marked.py::test_case",
        ]

    return fake


def _ok_preflight(
    module: Path,
    *,
    interface: str,
    slot: int,
    timeout: int,
    output_path: Path,
    counters: object = None,
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


def test_r44_c6r6_persist_collection_failure_reset_refusal_writes_nothing(
    tmp_path: Path,
) -> None:
    """#88R44-[C]r6: collection-failure persist stops when reset refuses.

    Codex R6: the persist helper called reset fire-and-forget, so a
    refused reset still ended with fresh state + reports over the
    old run's retry inputs. On refusal it must write nothing --
    the state file keeps its bytes and no failure sidecar lands
    (the caller still prints the diagnostic and exits 2).
    """
    from pkcs11_check.core._counters_durability import (
        release_barrier_lock,
        try_acquire_barrier_lock,
    )
    from pkcs11_check.core.file_runner import collection_failure_sidecar_path

    state_file = tmp_path / "state.json"
    state_file.write_text('{"old": true}', encoding="utf-8")
    candidate = tmp_path / "state.json.counters.aaaaaaaa"
    (candidate / "registrations").mkdir(parents=True)
    token = try_acquire_barrier_lock(candidate)
    assert token is not None, "the test holds the rival lock (premise)"
    try:
        _persist_failure(state_file, "boom", report_config=None, resume=False)
    finally:
        release_barrier_lock(token)
    assert state_file.read_text(encoding="utf-8") == '{"old": true}', "state untouched"
    assert not collection_failure_sidecar_path(state_file).exists(), "no sidecar lands"


class TestVersionCommand:
    def test_version_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert f"pkcs11-check {__version__}" in result.output

    def test_version_flag_matches_subcommand(self) -> None:
        """U3: pkcs11-check --version prints the same string, exit 0."""
        flag = runner.invoke(app, ["--version"])
        subcommand = runner.invoke(app, ["version"])
        assert flag.exit_code == 0, flag.output
        assert flag.output == subcommand.output


def test_test_none_json_uses_output_directory_for_report_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    results_path = tmp_path / "nested" / "artifacts" / "results.json"
    observed_dirs: list[Path | None] = []
    real_mkstemp = test_cmd.tempfile.mkstemp

    def observing_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        raw_dir = kwargs.get("dir")
        observed_dirs.append(Path(raw_dir) if isinstance(raw_dir, str) else raw_dir)
        return real_mkstemp(*args, **kwargs)

    def fake_main(args: list[str]) -> int:
        Path(args[args.index("--report-log") + 1]).write_text(
            "\n".join(
                [
                    json.dumps({"$report_type": "SessionStart"}),
                    json.dumps(
                        {
                            "$report_type": "TestReport",
                            "nodeid": "test_demo.py::test_ok",
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
        return 0

    monkeypatch.setattr(test_cmd.tempfile, "mkstemp", observing_mkstemp)
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

    assert result.exit_code == 0
    assert observed_dirs[-1] == results_path.parent
    assert results_path.parent.joinpath("report.jsonl").exists()


def test_test_none_non_json_detail_building_streams_report_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")

    def fake_main(args: list[str]) -> int:
        Path(args[args.index("--report-log") + 1]).write_text(
            "\n".join(
                [
                    '{"$report_type":"SessionStart"}',
                    '{"$report_type":"SessionFinish","exitstatus":0}',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return 0

    def assert_stream(records: object) -> dict[str, object]:
        assert not isinstance(records, list), "detail builder must receive the report stream"
        return {"counts": {}, "tests": []}

    monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
    monkeypatch.setattr(test_cmd, "_build_detail_from_report_records", assert_stream)

    result = runner.invoke(
        app,
        ["test", "--module", str(module), "--output", "rich", "--isolation", "none"],
    )

    assert result.exit_code == 0


@pytest.mark.parametrize("output", ["json", "junit", "rich"])
def test_test_none_passes_report_log_cli_arg_and_sets_no_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    """None path passes --report-log explicitly, like the isolated path.

    Regression: pytest-reportlog reads config.option.report_log eagerly in its
    own pytest_configure, which on the observed/default installation runs
    before ours (entry-point discovery order + pluggy LIFO hook execution),
    so the late env injection in plugin.py never activated the writer and
    every none+JSON run ended in a HarnessError. The fix passes a real
    --report-log CLI arg (the isolated path's exact spelling) and sets no
    PKCS11_CHECK_REPORT_LOG.
    """
    monkeypatch.delenv("PKCS11_CHECK_REPORT_LOG", raising=False)
    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    results_path = tmp_path / "nested" / "results.json"
    captured_args: dict[str, list[str]] = {}
    captured_env: dict[str, bool] = {}
    captured_report: dict[str, Path] = {}

    def fake_main(args: list[str]) -> int:
        captured_args["args"] = list(args)
        captured_env["report_log_set"] = "PKCS11_CHECK_REPORT_LOG" in os.environ
        if "--report-log" in args:
            report_path = Path(args[args.index("--report-log") + 1])
        else:  # pre-fix fallback so the test reaches its assertions
            report_path = Path(os.environ["PKCS11_CHECK_REPORT_LOG"])
        captured_report["path"] = report_path
        report_path.write_text(
            "\n".join(
                [
                    json.dumps({"$report_type": "SessionStart"}),
                    json.dumps(
                        {
                            "$report_type": "TestReport",
                            "nodeid": "test_demo.py::test_ok",
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
        return 0

    monkeypatch.setattr("pkcs11_check.cli.test_cmd.pytest.main", fake_main)
    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

    cli_args = [
        "test",
        "--module",
        str(module),
        "--output",
        output,
        "--isolation",
        "none",
    ]
    if output in {"json", "junit"}:
        cli_args.extend(["--output-file", str(results_path)])
    result = runner.invoke(app, cli_args)

    assert result.exit_code == 0
    seen_args = captured_args["args"]
    assert "--report-log" in seen_args
    log_index = seen_args.index("--report-log")
    assert Path(seen_args[log_index + 1]) == captured_report["path"]
    assert captured_report["path"].name.startswith("pkcs11-check-jsonl-")
    assert captured_env["report_log_set"] is False
    assert "PKCS11_CHECK_REPORT_LOG" not in os.environ


def test_test_none_json_real_pytest_main_produces_report_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E2E: none+JSON with a real in-process pytest.main writes report records.

    The stub test touches no fixtures, so no PKCS#11 module is needed beyond
    the existing dummy.so path. Pre-fix this ends in HarnessError (the report
    log stays empty); post-fix the SessionStart/TestReport/SessionFinish
    records flow and results.json assembles.

    In-process (not a subprocess) by design: the production none path calls
    pytest.main in-process, so only an in-process run exercises the real
    plugin-ordering interaction. Hermeticity holds because the stub lives in
    tmp_path (its own rootdir: no repo conftest/ini apply) and the none path
    already passes -p no:cacheprovider.
    """
    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    stub = tmp_path / "test_stub_ok.py"
    stub.write_text("def test_ok() -> None:\n    assert True\n", encoding="utf-8")
    results_path = tmp_path / "artifacts" / "results.json"

    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)

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
            "--ignore-disabled-tests",
            str(stub),
        ],
    )

    assert result.exit_code == 0
    report_path = results_path.parent / "report.jsonl"
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    types = [record.get("$report_type") for record in records]
    assert "SessionStart" in types
    assert "TestReport" in types
    assert "SessionFinish" in types
    assert "HarnessError" not in types
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    assert payload["summary"]["failed"] == 0


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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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

    def test_test_bad_pin_fails_fast_without_running_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U1: wrong PIN prints one message and exits 2; no units run."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def bad_pin_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("pin_incorrect")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", bad_pin_probe)
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "9999", "--isolation", "file"],
        )
        assert result.exit_code == 2, result.output
        assert result.output.count("PIN incorrect for slot 0") == 1, result.output
        assert "pkcs11-check doctor" in result.output
        assert called == []

    def test_r44_c6r6_fresh_reset_refusal_exits_2_everything_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R44-[C]r6: fresh CLI stops on reset refusal; state+evidence intact.

        Codex R6: the CLI called reset fire-and-forget, then ran
        the world over the refused inputs -- and it deleted the
        stale preflight evidence BEFORE reset, so even the retry
        inputs were gone. On refusal: exit 2, the runner never
        runs, the state file keeps its bytes, and the preflight
        evidence stays (its deletion moves after reset admission).
        """
        from pkcs11_check.core._counters_durability import (
            release_barrier_lock,
            try_acquire_barrier_lock,
        )
        from pkcs11_check.core.preflight import preflight_evidence_path_for_state

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        state_file.write_text('{"old": true}', encoding="utf-8")
        candidate = tmp_path / "state.json.counters.aaaaaaaa"
        (candidate / "registrations").mkdir(parents=True)
        evidence = preflight_evidence_path_for_state(state_file)
        evidence.write_text("stale-round", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def good_pin_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("ok")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", good_pin_probe)
        token = try_acquire_barrier_lock(candidate)
        assert token is not None, "the test holds the rival lock (premise)"
        try:
            result = runner.invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--state-file",
                    str(state_file),
                ],
            )
        finally:
            release_barrier_lock(token)
        assert result.exit_code == 2, result.output
        assert called == [], "the runner never runs"
        assert state_file.read_text(encoding="utf-8") == '{"old": true}', "state intact"
        assert evidence.read_text(encoding="utf-8") == "stale-round", "evidence intact"

    def test_r44_c6r6_fresh_reset_admission_clears_preflight_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R44-[C]r6 control: admitted reset still clears stale evidence.

        The preflight-evidence deletion moved after reset admission;
        a fresh run with no contention still deletes the stale
        evidence and proceeds to the runner.
        """
        from pkcs11_check.core.preflight import preflight_evidence_path_for_state

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        state_file.write_text('{"old": true}', encoding="utf-8")
        evidence = preflight_evidence_path_for_state(state_file)
        evidence.write_text("stale-round", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def good_pin_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("ok")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", good_pin_probe)
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0, result.output
        assert called == ["run"], "the runner proceeds"
        assert not evidence.exists(), "stale evidence cleared after admission"

    def test_r44_c6r6_resume_without_state_still_clears_preflight_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R44-[C]r6: resume-without-state keeps its evidence clearing.

        The early deletion now covers only resume-without-state
        (fresh runs delete after reset admission instead); a resume
        with no state file still drops the stale evidence and
        proceeds.
        """
        from pkcs11_check.core.preflight import preflight_evidence_path_for_state

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        evidence = preflight_evidence_path_for_state(state_file)
        evidence.write_text("stale-round", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
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
                "--isolation",
                "file",
                "--state-file",
                str(state_file),
                "--resume",
            ],
        )
        assert result.exit_code == 0, result.output
        assert called == ["run"], "the runner proceeds"
        assert not evidence.exists(), "stale evidence cleared without state"

    def test_test_good_pin_runs_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U1 control: a correct PIN proceeds to the runner unchanged."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def good_pin_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("ok")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", good_pin_probe)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [],
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert "PIN incorrect" not in result.output
        assert called == ["run"]

    def test_test_pin_probe_crashed_fails_fast(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-1b: a provider that dies on login refuses the suite (exit 1)."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def crashed_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("crashed", "login probe crashed (SIGSEGV)")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", crashed_probe)
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert result.exit_code == 1, result.output
        assert "refusing to run the suite" in " ".join(result.output.split())
        assert called == []

    def test_test_pin_probe_timeout_fails_fast(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-1b: a provider that hangs on login refuses the suite (exit 1)."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def hung_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("timeout", "login probe timed out after 10s")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", hung_probe)
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert result.exit_code == 1, result.output
        assert "refusing to run the suite" in " ".join(result.output.split())
        assert called == []

    def test_test_pin_probe_crashed_json_writes_results_and_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-1: a crashed probe in JSON mode leaves results + report.jsonl."""
        from pkcs11_check.core.preflight import append_preflight_evidence

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "out.json"

        def crashed_probe(*args: object, **kwargs: object) -> LoginProbe:
            append_preflight_evidence(kwargs["counters"].evidence_path, [{"probe": "evidence"}])
            return LoginProbe("crashed", "login probe crashed (SIGSEGV)", -11)

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", crashed_probe)
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
                "--output",
                "json",
                "--output-file",
                str(output_path),
            ],
        )
        assert result.exit_code == 1, result.output
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["status"] == "crashed"
        # The report writer abs-normalizes signal codes (shared with the
        # manifest path): raw -11 renders as 11.
        assert payload["units"][0]["returncode"] == 11
        report_jsonl = output_path.parent / "report.jsonl"
        assert "probe" in report_jsonl.read_text(encoding="utf-8")

    def test_test_pin_probe_timeout_json_uses_124(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-1: a hung probe in JSON mode reports timeout/124, incomplete."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "out.json"

        def hung_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("timeout", "login probe timed out after 10s", 1)

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", hung_probe)
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
                "--output",
                "json",
                "--output-file",
                str(output_path),
            ],
        )
        assert result.exit_code == 1, result.output
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["status"] == "timeout"
        assert payload["units"][0]["returncode"] == 124

    def test_test_pin_probe_crashed_none_json_writes_results(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-1: none-mode probe crash still leaves the requested report."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "out.json"

        def crashed_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("crashed", "login probe crashed (SIGSEGV)", -11)

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", crashed_probe)
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "1234",
                "--isolation",
                "none",
                "--output",
                "json",
                "--output-file",
                str(output_path),
            ],
        )
        assert result.exit_code == 1, result.output
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["status"] == "crashed"

    def test_test_pin_probe_crashed_text_writes_no_results(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-1 control: text mode keeps message-only refusal (no files)."""
        monkeypatch.chdir(tmp_path)
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def crashed_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("crashed", "login probe crashed (SIGSEGV)", -11)

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", crashed_probe)
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert result.exit_code == 1, result.output
        assert not (tmp_path / "pkcs11-check-results.json").exists()
        assert not (tmp_path / "report.jsonl").exists()

    def test_test_pin_incorrect_json_writes_no_results(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-1 control: usage errors (exit 2) write no report, as before."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        output_path = tmp_path / "out.json"

        def bad_pin_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("pin_incorrect")

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", bad_pin_probe)
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "9999",
                "--isolation",
                "file",
                "--output",
                "json",
                "--output-file",
                str(output_path),
            ],
        )
        assert result.exit_code == 2, result.output
        assert not output_path.exists()

    def test_test_pin_probe_error_warns_and_proceeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-1b control: an inconclusive probe warns loudly, suite runs."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def error_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("error", "no probe result")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", error_probe)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [],
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert result.exit_code == 0, result.output
        assert "login probe inconclusive" in result.output
        assert called == ["run"]

    def test_test_pin_probe_error_escapes_hostile_detail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-4: provider bytes in the probe detail render literally."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        def hostile_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("error", "[/red]")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", hostile_probe)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [],
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert result.exit_code == 0, result.output
        assert "Traceback" not in result.output
        assert "[/red]" in result.output
        assert called == ["run"]

    def test_test_resume_wrong_pin_preserves_prior_provider_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-1b: on resume the saved crash (exit 1) wins over fresh exit 2."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["provider.py"],
                fingerprint="prior",
                results=[FileRunResult("provider.py", "crashed", -11, 0.1)],
            ),
        )

        def bad_pin_probe(*args: object, **kwargs: object) -> LoginProbe:
            return LoginProbe("pin_incorrect")

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", bad_pin_probe)
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "9999",
                "--isolation",
                "file",
                "--resume",
                "--state-file",
                str(state_file),
                "--ignore-disabled-tests",
            ],
        )
        assert result.exit_code == 1, result.output
        assert "PIN incorrect for slot 0" in result.output

    def test_test_isolated_interrupt_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6: a user interrupt mid-run exits 2 (incomplete), not 130."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def interrupted_run(*args: object, **kwargs: object) -> int:
            raise KeyboardInterrupt

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", interrupted_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
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
                "--isolation",
                "file",
                "--ignore-disabled-tests",
            ],
        )
        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output

    def test_test_isolated_interrupt_keeps_prior_provider_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6: on resume, durable findings upgrade the interrupt exit to 1."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["provider.py"],
                fingerprint="prior",
                results=[FileRunResult("provider.py", "crashed", -11, 0.1)],
            ),
        )

        def interrupted_run(*args: object, **kwargs: object) -> int:
            raise KeyboardInterrupt

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", interrupted_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
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
        assert result.exit_code == 1, result.output

    def test_test_isolated_interrupt_sees_current_run_findings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6: a fresh run interrupted after a unit crashed exits 1.

        The run loop saves each completed unit before the next starts, so the
        interrupt arm reads current-run evidence -- the same precedence the
        non-isolated path applies to its captured report.
        """
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def crash_then_interrupt(*args: object, **kwargs: object) -> int:
            state_file = kwargs["state_file"]
            assert isinstance(state_file, Path)
            save_run_state(
                state_file,
                FileRunState(
                    units=["provider.py"],
                    fingerprint="fresh",
                    results=[FileRunResult("provider.py", "crashed", -11, 0.1)],
                ),
            )
            raise KeyboardInterrupt

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", crash_then_interrupt)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
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
                "--isolation",
                "file",
                "--state-file",
                str(tmp_path / "state.json"),
                "--ignore-disabled-tests",
            ],
        )
        assert result.exit_code == 1, result.output

    def test_test_preflight_interrupt_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6: an interrupt during preflight exits 2 (nothing ran)."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def interrupted_preflight(*args: object, **kwargs: object) -> CapabilityManifest:
            raise KeyboardInterrupt

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", interrupted_preflight)
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
        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output

    def test_test_login_probe_interrupt_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6: an interrupt during the login probe exits 2 (nothing ran)."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def interrupted_login(*args: object, **kwargs: object) -> LoginProbe:
            raise KeyboardInterrupt

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", interrupted_login)
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
        assert result.exit_code == 2, result.output
        assert "Traceback" not in result.output

    def test_test_empty_match_fails_fast_without_running_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U11: a selection matching nothing exits 2 before any unit runs."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
                str(default_root / "test_alpha.py")
            ],
        )
        monkeypatch.setattr(
            test_cmd, "collect_pytest_items_with_skips", lambda targets, args: ([], [])
        )
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--match",
                "zzz_no_such_test_zzz",
                "--isolation",
                "file",
            ],
        )
        assert result.exit_code == 2, result.output
        assert "0 tests matched" in result.output
        assert called == []

    def test_test_matched_but_all_units_excluded_names_exclusion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M3/M5: matched-but-excluded says so; does not claim 0 matched."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [],
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [CollectedPytestItem(nodeid="a.py::t", file_path="a.py", markers=[])],
                [],
            ),
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--match", "t", "--isolation", "file"],
        )
        assert result.exit_code == 2, result.output
        assert "1 tests matched but all units were excluded" in result.output
        assert "0 tests matched" not in result.output
        assert called == []

    def test_test_empty_match_reports_collection_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-2a: a skipped module's reason survives the empty-selection gate."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        target = tmp_path / "test_acvp_sha3.py"
        target.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [str(target)],
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [],
                [CollectedSkip(nodeid="test_acvp_sha3.py", reason="vectors not cloned")],
            ),
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), str(target), "--isolation", "file"],
        )
        assert result.exit_code == 2, result.output
        assert "0 tests matched" in result.output
        assert "skipped at collection: vectors not cloned" in result.output
        assert called == []

    def test_test_empty_match_caps_collection_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-2a: many collection skips render capped, with a remainder line."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        target = tmp_path / "test_many.py"
        target.write_text("", encoding="utf-8")

        def fake_run(*args: object, **kwargs: object) -> int:
            return 0

        skips = [
            CollectedSkip(nodeid=f"test_{index}.py", reason="vectors not cloned")
            for index in range(11)
        ]
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [str(target)],
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: ([], skips),
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), str(target), "--isolation", "file"],
        )
        assert result.exit_code == 2, result.output
        assert "test_9.py" in result.output
        assert "test_10.py" not in result.output
        assert "and 1 more skipped at collection" in result.output

    def test_test_matched_but_all_excluded_with_scheduled_file_exits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-2b (M3b): the only matched node disabled, a zero-match file
        scheduled -> fail fast instead of a vacuous run."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        seed_file = tmp_path / "test_seed.py"
        encrypt_file = tmp_path / "test_encrypt.py"
        seed_file.write_text("", encoding="utf-8")
        encrypt_file.write_text("", encoding="utf-8")
        matched = f"{seed_file}::test_seed_key_gen"
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
                str(seed_file),
                str(encrypt_file),
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [CollectedPytestItem(nodeid=matched, file_path=str(seed_file), markers=[])],
                [],
            ),
        )
        monkeypatch.setattr(
            disabled_baseline_mod,
            "load_disabled_baseline",
            lambda path: DisabledBaseline(
                source_path=Path("config/disabled-tests.txt"),
                disabled_nodeids=frozenset({matched}),
                fingerprint="baseline-fp-test",
            ),
            raising=False,
        )
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                str(seed_file),
                str(encrypt_file),
                "--match",
                "test_seed_key_gen",
                "--isolation",
                "file",
            ],
        )
        assert result.exit_code == 2, result.output
        assert "1 tests matched but every matched test was excluded" in result.output
        assert called == []

    def test_test_matched_disabled_unmatched_scheduled_file_runs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-2b control: baseline misses the match -> explicit targets run."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        seed_file = tmp_path / "test_seed.py"
        encrypt_file = tmp_path / "test_encrypt.py"
        seed_file.write_text("", encoding="utf-8")
        encrypt_file.write_text("", encoding="utf-8")
        matched = f"{seed_file}::test_seed_key_gen"
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
                str(seed_file),
                str(encrypt_file),
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [CollectedPytestItem(nodeid=matched, file_path=str(seed_file), markers=[])],
                [],
            ),
        )
        monkeypatch.setattr(
            disabled_baseline_mod,
            "load_disabled_baseline",
            lambda path: DisabledBaseline(
                source_path=Path("config/disabled-tests.txt"),
                disabled_nodeids=frozenset({f"{seed_file}::test_unrelated"}),
                fingerprint="baseline-fp-test",
            ),
            raising=False,
        )
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                str(seed_file),
                str(encrypt_file),
                "--match",
                "test_seed_key_gen",
                "--isolation",
                "file",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "were excluded" not in result.output
        assert called == ["run"]

    def test_test_no_selection_zero_units_skips_fast_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M5: without any selection, empty units never hit the U11 error."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [],
        )
        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "file"])
        assert "0 tests matched" not in result.output
        assert "were excluded" not in result.output
        assert called == ["run"]

    def test_test_nonempty_match_runs_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U11 control: a matching selection proceeds to the runner."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        called: list[str] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            called.append("run")
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [
                str(default_root / "test_alpha.py")
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [
                    CollectedPytestItem(
                        nodeid="test_alpha.py::test_hit", file_path="test_alpha.py", markers=[]
                    )
                ],
                [],
            ),
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--match", "test_hit", "--isolation", "file"],
        )
        assert "0 tests matched" not in result.output
        assert called == ["run"]

    def test_test_text_run_ends_with_unit_totals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U5: a text-mode run ends with a totals line."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"

        def fake_run(*args: object, **kwargs: object) -> int:
            assert isinstance(kwargs["state_file"], Path)
            save_run_state(
                kwargs["state_file"],
                FileRunState(
                    units=["a.py", "b.py"],
                    fingerprint="fp",
                    results=[
                        FileRunResult("a.py", "passed", 0, 0.1),
                        FileRunResult("b.py", "failed", 1, 0.2),
                    ],
                ),
            )
            return 1

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [CollectedPytestItem(nodeid="a.py::t", file_path="a.py", markers=[])],
                [],
            ),
        )
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 1, result.output
        assert "Totals: 1 failed, 1 passed (2 total)" in result.output

    def test_test_corrupt_state_skips_totals_without_masking_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M2: a malformed state file never masks the run's exit code."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"

        def fake_run(*args: object, **kwargs: object) -> int:
            assert isinstance(kwargs["state_file"], Path)
            kwargs["state_file"].write_text("[]", encoding="utf-8")
            return 3

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 3, result.output
        assert "Totals:" not in result.output
        assert "Traceback" not in result.output

    def test_test_totals_escapes_hostile_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R18-4: tampered statuses render literally, never crash the exit."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"

        def fake_run(*args: object, **kwargs: object) -> int:
            assert isinstance(kwargs["state_file"], Path)
            save_run_state(
                kwargs["state_file"],
                FileRunState(
                    units=["a.py"],
                    fingerprint="fp",
                    results=[FileRunResult("a.py", "[/red]", 0, 0.1)],
                ),
            )
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Traceback" not in result.output
        assert "[/red]" in result.output

    def test_test_json_run_prints_no_text_totals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U5 control: JSON mode keeps totals in the file, not on console."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"

        def fake_run(*args: object, **kwargs: object) -> int:
            assert isinstance(kwargs["state_file"], Path)
            save_run_state(
                kwargs["state_file"],
                FileRunState(
                    units=["a.py"],
                    fingerprint="fp",
                    results=[FileRunResult("a.py", "passed", 0, 0.1)],
                ),
            )
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            lambda targets, args: (
                [CollectedPytestItem(nodeid="a.py::t", file_path="a.py", markers=[])],
                [],
            ),
        )
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--state-file",
                str(state_file),
                "--output",
                "json",
                "--output-file",
                str(tmp_path / "results.json"),
            ],
        )
        assert "Totals:" not in result.output

    def test_unit_display_quiet_by_default_loud_when_verbose(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U6: chatter hidden by default, shown with --verbose or DEBUG."""
        assert test_cmd._unit_display_quiet(False) is True
        assert test_cmd._unit_display_quiet(True) is False
        import logging

        monkeypatch.setattr(logging.getLogger(), "level", logging.DEBUG)
        assert test_cmd._unit_display_quiet(False) is False

    def test_test_threads_quiet_display_to_runner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U6: default runs hide unit chatter; --verbose shows it."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        seen: list[object] = []

        def fake_run(*args: object, **kwargs: object) -> int:
            seen.append(kwargs.get("quiet_unit_display"))
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        runner.invoke(app, ["test", "--module", str(module), "--isolation", "file"])
        runner.invoke(app, ["test", "--module", str(module), "--isolation", "file", "--verbose"])
        assert seen == [True, False], seen

    def test_provenance_explains_dev_checkout_suffix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U4: a git-describe version says once that it is a dev checkout."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def fake_run(*args: object, **kwargs: object) -> int:
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "_build_run_provenance",
            lambda *a, **k: {
                "framework": {"version": "v0.3.0-71-gabc1234-dirty", "source": "git-describe"},
                "provider": {},
            },
        )
        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "file"])
        assert "v0.3.0-71-gabc1234-dirty (dev checkout)" in result.output

    def test_provenance_clean_for_package_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U4 control: a package version prints with no suffix clause."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def fake_run(*args: object, **kwargs: object) -> int:
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(
            test_cmd,
            "_build_run_provenance",
            lambda *a, **k: {
                "framework": {"version": "0.3.1", "source": "package"},
                "provider": {},
            },
        )
        result = runner.invoke(app, ["test", "--module", str(module), "--isolation", "file"])
        assert "pkcs11-check 0.3.1 |" in result.output
        assert "dev checkout" not in result.output

    def test_sessions_hidden_from_help_but_still_accepted(self) -> None:
        """U13: the dead --sessions knob is hidden, not removed."""
        help_text = runner.invoke(app, ["test", "--help"])
        assert help_text.exit_code == 0, help_text.output
        assert "--sessions" not in help_text.output
        parsed = runner.invoke(
            app, ["test", "--module", "m.so", "--sessions", "4", "--show-config"]
        )
        assert parsed.exit_code == 0, parsed.output

    def test_sessions_warning_fires_in_every_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        """N5: the dead --sessions warning fires in none mode too."""
        test_cmd._warn_ignored_sessions(4, "file")
        test_cmd._warn_ignored_sessions(4, "none")
        test_cmd._warn_ignored_sessions(1, "none")
        err = capsys.readouterr().err
        assert err.count("--sessions is ignored") == 2, err
        assert "--isolation none mode" in err

    def test_sessions_warns_in_isolated_modes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U13: passing --sessions warns that it is ignored."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def fake_run(*args: object, **kwargs: object) -> int:
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", "file", "--sessions", "4"],
        )
        assert "--sessions is ignored" in result.output

    def test_resume_barrier_refusal_names_fresh_run_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """S12: a failed resume barrier refuses loudly and names the way out."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "prepare_resume", lambda *a, **k: {"barrier_ok": False})
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
                str(tmp_path / "state.json"),
            ],
        )
        assert result.exit_code == 2, result.output
        assert "without proven quiescence" in result.output
        assert "without --resume" in result.output

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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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

    def test_test_exports_and_restores_wrap_key_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # F-002: the KEK travels by env only; the outer environment is restored.
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        monkeypatch.setenv("P11TEST_WRAP_KEY_VALUE", "outer-kek")

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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
        ) -> int:
            del (
                units,
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
            assert os.environ["P11TEST_WRAP_KEY_VALUE"] == "ab" * 16
            assert "--p11-wrap-key-value" not in pytest_args
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
                "--wrap-key-value",
                "ab" * 16,
                "--isolation",
                "file",
                "--ignore-disabled-tests",
            ],
        )

        assert result.exit_code == 0
        assert os.environ["P11TEST_WRAP_KEY_VALUE"] == "outer-kek"

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
            quiet_unit_display: bool = False,
            collected_items: object = None,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            "collect_pytest_items_with_skips",
            lambda targets, pytest_args: (
                [  # type: ignore[arg-type]
                    CollectedPytestItem(
                        nodeid="src/pkcs11_check/testcases/test_demo.py::test_case",
                        file_path="src/pkcs11_check/testcases/test_demo.py",
                        markers=[],
                    )
                ],
                [],
            ),
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            _auto_discover_with_collected(collected),  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
        assert records[0] == {
            "$report_type": "IsolatedUnitReport",
            "target": "<collection>",
            "attempt": 0,
        }
        assert [record["$report_type"] for record in records] == [
            "IsolatedUnitReport",
            "CollectReport",
        ]
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

        # Admit (the helper returns bool since R44-[C]r6; None would refuse).
        monkeypatch.setattr(test_cmd, "_reset_fresh_run_artifacts", lambda *_: True)
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            lambda targets, default_root, **_rest: [  # type: ignore[arg-type]
                str(default_root / "test_alpha.py")
            ],
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            lambda path: SimpleNamespace(  # type: ignore[arg-type]
                units=["saved.py", "saved.py::test_case"], results=[], fingerprint=""
            ),
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
            "collect_pytest_items_with_skips",
            lambda targets, pytest_args: (collected, []),  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            "collect_pytest_items_with_skips",
            lambda targets, pytest_args: (
                [  # type: ignore[arg-type]
                    CollectedPytestItem(
                        nodeid=f"{marked_file}::test_one",
                        file_path=str(marked_file),
                        markers=["subprocess_per_test"],
                    )
                ],
                [],
            ),
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
            collected_items: list[CollectedPytestItem] | None = None,
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
            called["collected_items"] = collected_items
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_auto_isolation_units",
            lambda targets, default_root, **_rest: [str(default_root / "test_alpha.py")],  # type: ignore[arg-type]
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
            "collect_pytest_items_with_skips",
            lambda *_args, **_kwargs: pytest.fail(  # type: ignore[arg-type]
                "ignored disabled baseline must not trigger metadata collection"
            ),
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
        if mode == "file":
            assert called["collected_items"] is None

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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            report_log = args[args.index("--report-log") + 1]
            Path(report_log).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
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
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}),
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            report_log = args[args.index("--report-log") + 1]
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
        assert payload["summary"]["error"] == 2
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
            Path(args[args.index("--report-log") + 1]).write_text("", encoding="utf-8")
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
        assert records[0]["$report_type"] == "HarnessError"
        assert records[0]["returncode"] == 2
        assert records[0]["completion_verified"] is False
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        assert payload["summary"]["error"] == 1
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["incomplete"] is True
        assert not (results_path.parent / "coverage.json").exists()
        assert not (results_path.parent / "provisioning.json").exists()

    @pytest.mark.parametrize("returncode", [2, 3, 4])
    def test_test_none_json_preserves_harness_returncode_and_public_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "nested" / "results.json"

        def fake_main(args: list[str]) -> int:
            Path(args[args.index("--report-log") + 1]).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": "test_demo.py::test_ok",
                                "when": "call",
                                "outcome": "passed",
                            }
                        ),
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": returncode}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return returncode

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
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        assert payload["units"][0]["returncode"] == returncode
        assert payload["units"][0]["completion_verified"] is False
        assert payload["units"][0]["incomplete"] is True
        assert payload["summary"]["failed"] == 0
        assert payload["summary"]["incomplete"] is True

    def test_test_none_json_provider_failure_wins_over_harness_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "nested" / "results.json"

        def fake_main(args: list[str]) -> int:
            Path(args[args.index("--report-log") + 1]).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": "test_demo.py::test_failed",
                                "when": "call",
                                "outcome": "failed",
                                "longrepr": "provider failure",
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

        assert result.exit_code == 1
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        assert payload["summary"]["failed"] == 1
        assert payload["summary"]["incomplete"] is True

    def test_test_none_interrupt_shape_without_finish_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6 pin: a none-path interrupt (no SessionFinish) exits 2.

        pytest catches the interrupt itself and returns INTERRUPTED; the CLI
        maps it to public 2 -- the parity anchor for the isolated arm.
        """
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "nested" / "results.json"

        def fake_main(args: list[str]) -> int:
            Path(args[args.index("--report-log") + 1]).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": "test_demo.py::test_ok",
                                "when": "call",
                                "outcome": "passed",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return int(pytest.ExitCode.INTERRUPTED)

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
        assert result.exit_code == 2, result.output
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        assert payload["summary"]["incomplete"] is True

    def test_test_none_interrupt_shape_with_failure_exits_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B6 pin: partial provider evidence upgrades the interrupt exit to 1."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "nested" / "results.json"

        def fake_main(args: list[str]) -> int:
            Path(args[args.index("--report-log") + 1]).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": "test_demo.py::test_failed",
                                "when": "call",
                                "outcome": "failed",
                                "longrepr": "provider failure",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return int(pytest.ExitCode.INTERRUPTED)

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
        assert result.exit_code == 1, result.output

    @pytest.mark.parametrize(
        ("output", "returncode", "finish", "expected_exit"),
        [
            ("rich", 0, None, 1),
            ("junit", 1, 0, 1),
            ("json", 1, 0, 1),
            ("json", 2, 2, 2),
            ("rich", 5, 5, 2),
        ],
        ids=[
            "missing-finish",
            "mismatched-finish",
            "harness-exit",
            "harness-exit-json",
            "empty-session",
        ],
    )
    def test_test_none_validates_report_completion_for_every_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        output: str,
        returncode: int,
        finish: int | None,
        expected_exit: int,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        results_path = tmp_path / "nested" / "results.json"

        def fake_main(args: list[str]) -> int:
            report_path = Path(args[args.index("--report-log") + 1])
            records = [json.dumps({"$report_type": "SessionStart"})]
            if returncode != 5:
                records.append(
                    json.dumps(
                        {
                            "$report_type": "TestReport",
                            "nodeid": "test_demo.py::test_ok",
                            "when": "call",
                            "outcome": "passed",
                        }
                    )
                )
            if finish is not None:
                records.append(json.dumps({"$report_type": "SessionFinish", "exitstatus": finish}))
            report_path.write_text("\n".join(records) + "\n", encoding="utf-8")
            return returncode

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        args = [
            "test",
            "--module",
            str(module),
            "--output",
            output,
            "--isolation",
            "none",
        ]
        if output in {"json", "junit"}:
            args.extend(["--output-file", str(results_path)])
        result = runner.invoke(app, args)

        assert result.exit_code == expected_exit
        if output == "json":
            payload = json.loads(results_path.read_text(encoding="utf-8"))
            assert payload["summary"]["incomplete"] is True
            assert payload["units"]
            assert payload["units"][0]["completion_verified"] is False
            assert payload["units"][0]["incomplete"] is True
            report_records = [
                json.loads(line)
                for line in (results_path.parent / "report.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            harness = [
                record for record in report_records if record["$report_type"] == "HarnessError"
            ]
            assert len(harness) == 1
            assert harness[0]["returncode"] == returncode
            assert harness[0]["completion_verified"] is False
        else:
            assert not (tmp_path / "pkcs11-check-results.json").exists()
            if output == "rich" and (finish is None or finish != returncode):
                assert "INCOMPLETE" in result.output
            if output == "junit":
                root = ET.parse(results_path).getroot()
                assert root.attrib["tests"] == "1"
                assert root.attrib["errors"] == "1"
                error = root.find("testcase/error")
                assert error is not None
                assert error.attrib["type"] == "incomplete"

    @pytest.mark.parametrize("output", ["rich", "junit"])
    @pytest.mark.parametrize("provider_failure", [False, True])
    def test_test_none_non_json_collects_report_log_and_provider_wins(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        output: str,
        provider_failure: bool,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, Path] = {}
        output_path = tmp_path / "nested" / "results.xml"

        def fake_main(args: list[str]) -> int:
            report_path = Path(args[args.index("--report-log") + 1])
            observed["path"] = report_path
            report_path.write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        *(
                            [
                                json.dumps(
                                    {
                                        "$report_type": "TestReport",
                                        "nodeid": "test_demo.py::test_failed",
                                        "when": "call",
                                        "outcome": "failed",
                                        "longrepr": "provider diagnostic",
                                    }
                                )
                            ]
                            if provider_failure
                            else []
                        ),
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": 2}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            assert report_path.exists()
            return 2

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        args = [
            "test",
            "--module",
            str(module),
            "--output",
            output,
            "--isolation",
            "none",
        ]
        if output == "junit":
            args.extend(["--output-file", str(output_path)])
        result = runner.invoke(
            app,
            args,
        )

        assert result.exit_code == (1 if provider_failure else 2)
        report_path = observed["path"]
        assert not report_path.exists()
        if output == "junit":
            root = ET.parse(output_path).getroot()
            assert root.attrib["tests"] == ("2" if provider_failure else "1")
            assert root.attrib["failures"] == ("1" if provider_failure else "0")
            assert root.attrib["errors"] == "1"
            if provider_failure:
                assert root.find("testcase/failure") is not None
                assert root.find("testcase/error") is not None

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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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

        assert result.exit_code == 1
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
        caller_deselect_file = tmp_path / "caller-deselect.txt"
        restored: dict[str, str | None] = {}

        def fake_main(args: list[str]) -> int:
            deselect_path = Path(os.environ["PKCS11_CHECK_DESELECT_FILE"])
            called["path"] = deselect_path
            called["text"] = deselect_path.read_text(encoding="utf-8")
            Path(args[args.index("--report-log") + 1]).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
        real_ensure_completion = test_cmd._ensure_nonisolated_completion_record

        def observe_restored_deselect_file(
            report_path: Path,
            *,
            returncode: int,
            stdout: str,
            stderr: str,
        ) -> bool:
            restored["value"] = os.environ.get("PKCS11_CHECK_DESELECT_FILE")
            return real_ensure_completion(
                report_path,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
            )

        monkeypatch.setattr(
            test_cmd,
            "_ensure_nonisolated_completion_record",
            observe_restored_deselect_file,
        )

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", "none"],
            env={"PKCS11_CHECK_DESELECT_FILE": str(caller_deselect_file)},
        )

        assert result.exit_code == 0
        assert called["text"] == "test_demo.py::test_disabled\n"
        assert restored["value"] == str(caller_deselect_file)

    def test_test_none_ignore_disabled_tests_skips_baseline_loading(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def fake_main(args: list[str]) -> int:
            assert "PKCS11_CHECK_DESELECT_FILE" not in os.environ
            Path(args[args.index("--report-log") + 1]).write_text(
                "\n".join(
                    [
                        json.dumps({"$report_type": "SessionStart"}),
                        json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            )
            called["units"] = units
            called["granularity"] = granularity
            called["deselect_by_file"] = deselect_by_file
            called["baseline_fingerprint"] = baseline_fingerprint
            return 0

        unit_a = f"{file_path.resolve()}::test_a"
        unit_b = f"{file_path.resolve()}::test_b"
        raw_a = "app/test_demo.py::test_a"
        raw_b = "app/test_demo.py::test_b"
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]

        def fake_discover(
            targets, default_root, *, granularity, pytest_args, collected_out=None, skips_out=None
        ):
            if collected_out is not None:
                collected_out.extend(
                    [
                        CollectedPytestItem(raw_a, str(file_path), []),
                        CollectedPytestItem(raw_b, str(file_path), []),
                    ]
                )
            return [unit_a, unit_b]

        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            fake_discover,
        )
        monkeypatch.setattr(
            disabled_baseline_mod,
            "load_disabled_baseline",
            lambda path: DisabledBaseline(
                source_path=Path("config/disabled-tests.txt"),
                disabled_nodeids=frozenset({raw_b}),
                fingerprint="baseline-fp-test",
            ),
            raising=False,
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
        collection_calls: list[None] = []

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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
                baseline_fingerprint,
            )
            called["units"] = units
            called["granularity"] = granularity
            called["deselect_by_file"] = deselect_by_file
            called["collected_items"] = collected_items
            return 0

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)  # type: ignore[arg-type]
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [str(file_a), str(file_b)],  # type: ignore[arg-type]
        )
        collected = [
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
        ]

        def fake_collect(
            targets: list[str], pytest_args: list[str], *, env: dict[str, str] | None = None
        ) -> tuple[list[CollectedPytestItem], list[CollectedSkip]]:
            del targets, pytest_args, env
            collection_calls.append(None)
            return collected, []

        monkeypatch.setattr(
            test_cmd,
            "collect_pytest_items_with_skips",
            fake_collect,
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
        assert called["collected_items"] == collected
        assert len(collection_calls) == 1
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
            quiet_unit_display: bool = False,
            deselect_by_file: dict[str, set[str]] | None = None,
            baseline_fingerprint: str | None = None,
            provenance: object = None,
            recovery_config: object = None,
            counters_barrier_plan: object = None,
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status="error",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    error="RuntimeError: boom",
                )
            ),
        )

        result = runner.invoke(app, ["test", "--module", str(module)])

        assert result.exit_code == 2
        assert "PKCS#11 preflight error" in result.output

    @pytest.mark.parametrize(
        ("reason", "expected_exit"),
        [("module_unloadable", 3), (None, 2)],
        ids=["module-unloadable", "later-config-error"],
    )
    def test_test_preflight_maps_only_module_load_failure_to_three(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        reason: str | None,
        expected_exit: int,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status="error",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    reason=reason,
                    error="preflight error",
                )
            ),
        )

        result = runner.invoke(app, ["test", "--module", str(module)])

        assert result.exit_code == expected_exit

    def test_test_preflight_exception_restores_overrides_and_manifest_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, Path] = {}
        monkeypatch.setenv("P11TEST_PIN", "caller-pin")
        monkeypatch.setenv("P11TEST_SO_PIN", "caller-so-pin")

        def fail_preflight(
            module: Path,
            *,
            interface: str,
            slot: int,
            timeout: int,
            output_path: Path,
            counters: object = None,
        ) -> CapabilityManifest:
            del module, interface, slot, timeout
            observed["manifest"] = output_path
            raise RuntimeError("preflight helper failed")

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fail_preflight)

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "override-pin",
                "--so-pin",
                "override-so-pin",
            ],
        )

        assert result.exception is not None
        assert result.exception.args == ("preflight helper failed",)
        assert os.environ["P11TEST_PIN"] == "caller-pin"
        assert os.environ["P11TEST_SO_PIN"] == "caller-so-pin"
        assert not observed["manifest"].exists()

    def test_test_build_args_exception_restores_overrides_and_manifest_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, Path] = {}
        monkeypatch.setenv("P11TEST_PIN", "caller-pin")
        monkeypatch.setenv("P11TEST_SO_PIN", "caller-so-pin")

        def ok_preflight(
            module: Path,
            *,
            interface: str,
            slot: int,
            timeout: int,
            output_path: Path,
            counters: object = None,
        ) -> CapabilityManifest:
            manifest = _ok_preflight(
                module,
                interface=interface,
                slot=slot,
                timeout=timeout,
                output_path=output_path,
            )
            observed["manifest"] = output_path
            return manifest

        def fail_build_args(**_kwargs: object) -> list[str]:
            raise RuntimeError("argument construction failed")

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", ok_preflight)
        monkeypatch.setattr(test_cmd, "_build_pytest_args", fail_build_args)

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "override-pin",
                "--so-pin",
                "override-so-pin",
            ],
        )

        assert result.exception is not None
        assert result.exception.args == ("argument construction failed",)
        assert os.environ["P11TEST_PIN"] == "caller-pin"
        assert os.environ["P11TEST_SO_PIN"] == "caller-so-pin"
        assert not observed["manifest"].exists()

    def test_test_manifest_close_failure_retries_close_and_preserves_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, Path] = {}
        real_mkstemp = test_cmd.tempfile.mkstemp
        real_close = test_cmd.os.close
        close_calls = 0

        def observing_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
            fd, raw_path = real_mkstemp(*args, **kwargs)
            observed["manifest"] = Path(raw_path)
            return fd, raw_path

        def fail_once_close(fd: int) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                raise OSError("manifest close failed")
            real_close(fd)

        monkeypatch.setattr(test_cmd.tempfile, "mkstemp", observing_mkstemp)
        monkeypatch.setattr(test_cmd.os, "close", fail_once_close)

        result = runner.invoke(app, ["test", "--module", str(module)])

        assert result.exception is not None
        assert result.exception.args == ("manifest close failed",)
        assert close_calls == 2
        assert not observed["manifest"].exists()

    def test_test_jsonl_close_failure_is_retried_and_fd_is_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, int | Path] = {}
        real_mkstemp = test_cmd.tempfile.mkstemp
        real_close = test_cmd.os.close
        injected = False

        def observing_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
            fd, raw_path = real_mkstemp(*args, **kwargs)
            if str(kwargs.get("prefix", "")).startswith("pkcs11-check-jsonl-"):
                observed["jsonl_fd"] = fd
                observed["jsonl"] = Path(raw_path)
            return fd, raw_path

        def fail_jsonl_close(fd: int) -> None:
            nonlocal injected
            if fd == observed.get("jsonl_fd") and not injected:
                injected = True
                raise OSError("jsonl close failed")
            real_close(fd)

        monkeypatch.setattr(test_cmd.tempfile, "mkstemp", observing_mkstemp)
        monkeypatch.setattr(test_cmd.os, "close", fail_jsonl_close)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--isolation", "none"],
        )

        assert result.exception is not None
        assert result.exception.args == ("jsonl close failed",)
        jsonl_fd = observed["jsonl_fd"]
        assert isinstance(jsonl_fd, int)
        with pytest.raises(OSError):
            os.fstat(jsonl_fd)
        jsonl_path = observed["jsonl"]
        assert isinstance(jsonl_path, Path)
        assert not jsonl_path.exists()

    def test_test_setup_error_survives_manifest_unlink_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, Path] = {}
        monkeypatch.setenv("P11TEST_PIN", "caller-pin")
        monkeypatch.setenv("P11TEST_SO_PIN", "caller-so-pin")
        real_unlink = Path.unlink

        def ok_preflight(
            module: Path,
            *,
            interface: str,
            slot: int,
            timeout: int,
            output_path: Path,
            counters: object = None,
        ) -> CapabilityManifest:
            manifest = _ok_preflight(
                module,
                interface=interface,
                slot=slot,
                timeout=timeout,
                output_path=output_path,
            )
            observed["manifest"] = output_path
            return manifest

        def fail_unlink(self: Path, *args: object, **kwargs: object) -> None:
            if self == observed.get("manifest"):
                raise OSError("manifest unlink failed")
            real_unlink(self, *args, **kwargs)

        def fail_build_args(**_kwargs: object) -> list[str]:
            raise RuntimeError("argument construction failed")

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", ok_preflight)
        monkeypatch.setattr(test_cmd, "_build_pytest_args", fail_build_args)
        monkeypatch.setattr(Path, "unlink", fail_unlink)

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--pin",
                "override-pin",
                "--so-pin",
                "override-so-pin",
            ],
        )

        assert result.exception is not None
        assert result.exception.args == ("argument construction failed",)
        assert os.environ["P11TEST_PIN"] == "caller-pin"
        assert os.environ["P11TEST_SO_PIN"] == "caller-so-pin"
        assert observed["manifest"].exists()

    def test_test_none_parse_failure_cleans_report_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        observed: dict[str, Path] = {}

        def fake_main(args: list[str]) -> int:
            path = Path(args[args.index("--report-log") + 1])
            observed["report"] = path
            path.write_text(
                '{"$report_type":"SessionStart"}\n'
                '{"$report_type":"SessionFinish","exitstatus":0}\n',
                encoding="utf-8",
            )
            return 0

        def fail_detail(_records: object) -> None:
            raise RuntimeError("post-run parse failed")

        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "_build_detail_from_report_records", fail_detail)

        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--output", "rich", "--isolation", "none"],
        )

        assert result.exception is not None
        assert result.exception.args == ("post-run parse failed",)
        assert not observed["report"].exists()

    def test_test_resume_preflight_failure_preserves_prior_provider_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["provider.py"],
                fingerprint="prior",
                results=[FileRunResult("provider.py", "failed", 1, 0.1)],
            ),
        )
        monkeypatch.setattr(
            test_cmd,
            "run_preflight_subprocess",
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status="error",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    error="collection/configuration failure",
                )
            ),
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

        assert result.exit_code == 1

    @pytest.mark.parametrize("preflight_reason", [None, "module_unloadable"])
    @pytest.mark.parametrize("returncode", [2, 3, 4])
    @pytest.mark.parametrize("evidence_storage", ["cached", "inline"])
    def test_test_resume_early_exit_uses_cached_provider_evidence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        preflight_reason: str | None,
        returncode: int,
        evidence_storage: str,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        target = "provider.py"
        save_run_state(
            state_file,
            FileRunState(
                units=[target],
                fingerprint="prior",
                results=[
                    FileRunResult(target, "failed", returncode, 0.1, completion_verified=False)
                ],
            ),
        )
        records = [
            {
                "$report_type": "TestReport",
                "nodeid": f"{target}::test_provider",
                "when": "call",
                "outcome": "failed",
                "longrepr": "provider failed",
            },
            {
                "$report_type": "HarnessError",
                "nodeid": target,
                "outcome": "error",
                "returncode": returncode,
                "completion_verified": False,
                "longrepr": "collection failed",
            },
        ]
        if evidence_storage == "cached":
            _write_unit_report_record_cache(state_file, target, records)
        else:
            state_payload = json.loads(state_file.read_text(encoding="utf-8"))
            state_payload["report_records_by_unit"] = {target: records}
            state_file.write_text(json.dumps(state_payload), encoding="utf-8")

        if preflight_reason is None:
            monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

            def fail_collection(*_args: object, **_kwargs: object) -> list[str]:
                raise ValueError("current collection failed")

            monkeypatch.setattr(test_cmd, "discover_pytest_units", fail_collection)
        else:
            monkeypatch.setattr(
                test_cmd,
                "run_preflight_subprocess",
                lambda module, *, interface, slot, timeout, output_path, counters=None: (
                    CapabilityManifest(
                        status="error",
                        module_path=str(module),
                        requested_interface=interface,
                        interface_version=None,
                        slot_index=slot,
                        slot_count=None,
                        mechanisms=[],
                        reason=preflight_reason,
                        error="module is unloadable",
                    )
                ),
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

        assert result.exit_code == 1

    def test_test_resume_missing_module_uses_cached_provider_evidence(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.json"
        target = "provider.py"
        save_run_state(
            state_file,
            FileRunState(
                units=[target],
                fingerprint="prior",
                results=[FileRunResult(target, "failed", 2, 0.1, completion_verified=False)],
            ),
        )
        _write_unit_report_record_cache(
            state_file,
            target,
            [
                {
                    "$report_type": "TestReport",
                    "nodeid": f"{target}::test_provider",
                    "when": "call",
                    "outcome": "failed",
                },
                {
                    "$report_type": "HarnessError",
                    "nodeid": target,
                    "outcome": "error",
                    "returncode": 2,
                    "completion_verified": False,
                },
            ],
        )

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(tmp_path / "missing.so"),
                "--resume",
                "--state-file",
                str(state_file),
            ],
        )

        assert result.exit_code == 1

    def test_test_resume_missing_module_preserves_prior_provider_failure(
        self, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["provider.py"],
                fingerprint="prior",
                results=[FileRunResult("provider.py", "failed", 1, 0.1)],
            ),
        )

        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                str(tmp_path / "missing.so"),
                "--resume",
                "--state-file",
                str(state_file),
            ],
        )

        assert result.exit_code == 1

    @pytest.mark.parametrize("provider_evidence", [False, True], ids=["harness-only", "provider"])
    @pytest.mark.parametrize(
        "early_exit", ["unsupported-isolation", "conflicting-flags"], ids=["isolation", "flags"]
    )
    def test_test_resume_configuration_exit_uses_prior_provider_evidence(
        self,
        tmp_path: Path,
        provider_evidence: bool,
        early_exit: str,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        target = "provider.py"
        save_run_state(
            state_file,
            FileRunState(
                units=[target],
                fingerprint="prior",
                results=[FileRunResult(target, "failed", 2, 0.1, completion_verified=False)],
            ),
        )
        if provider_evidence:
            _write_unit_report_record_cache(
                state_file,
                target,
                [
                    {
                        "$report_type": "TestReport",
                        "nodeid": f"{target}::test_provider",
                        "when": "call",
                        "outcome": "failed",
                    }
                ],
            )

        args = [
            "test",
            "--module",
            str(module),
            "--resume",
            "--state-file",
            str(state_file),
        ]
        if early_exit == "unsupported-isolation":
            args.extend(["--isolation", "invalid"])
        else:
            args.extend(["--skip-slow", "--only-slow"])

        result = runner.invoke(app, args)

        assert result.exit_code == (1 if provider_evidence else 2)

    @pytest.mark.parametrize("provider_evidence", [False, True], ids=["harness-only", "provider"])
    @pytest.mark.parametrize(
        "config_branch", ["disabled-baseline", "recovery"], ids=["disabled", "recovery"]
    )
    def test_test_resume_setup_exit_uses_prior_provider_evidence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        provider_evidence: bool,
        config_branch: str,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        target = "provider.py"
        save_run_state(
            state_file,
            FileRunState(
                units=[target],
                fingerprint="prior",
                results=[FileRunResult(target, "failed", 2, 0.1, completion_verified=False)],
            ),
        )
        if provider_evidence:
            _write_unit_report_record_cache(
                state_file,
                target,
                [
                    {
                        "$report_type": "TestReport",
                        "nodeid": f"{target}::test_provider",
                        "when": "call",
                        "outcome": "failed",
                    }
                ],
            )
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        if config_branch == "disabled-baseline":
            monkeypatch.setattr(
                test_cmd,
                "resolve_disabled_nodeids",
                lambda **_kwargs: (_ for _ in ()).throw(
                    FileNotFoundError("disabled baseline missing")
                ),
            )
        else:
            monkeypatch.setattr(
                test_cmd,
                "discover_pytest_units",
                lambda *_args, **_kwargs: [target],
            )
            monkeypatch.setattr(
                test_cmd,
                "build_recovery_config",
                lambda **_kwargs: (_ for _ in ()).throw(ValueError("bad recovery config")),
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

        assert result.exit_code == (1 if provider_evidence else 2)

    @pytest.mark.parametrize("returncode", [2, 3, 4])
    @pytest.mark.parametrize("early_exit", ["collection", "unloadable"])
    def test_test_resume_early_exit_without_provider_evidence_keeps_infra_code(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        early_exit: str,
        returncode: int,
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["provider.py"],
                fingerprint="prior",
                results=[FileRunResult("provider.py", "failed", returncode, 0.1)],
            ),
        )
        if early_exit == "collection":
            monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

            def fail_collection(*_args: object, **_kwargs: object) -> list[str]:
                raise ValueError("current collection failed")

            monkeypatch.setattr(test_cmd, "discover_pytest_units", fail_collection)
            expected_exit = 2
        else:
            monkeypatch.setattr(
                test_cmd,
                "run_preflight_subprocess",
                lambda module, *, interface, slot, timeout, output_path, counters=None: (
                    CapabilityManifest(
                        status="error",
                        module_path=str(module),
                        requested_interface=interface,
                        interface_version=None,
                        slot_index=slot,
                        slot_count=None,
                        mechanisms=[],
                        reason="module_unloadable",
                        error="module is unloadable",
                    )
                ),
            )
            expected_exit = 3

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

        assert result.exit_code == expected_exit

    def test_test_resume_collection_failure_preserves_prior_provider_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["provider.py"],
                fingerprint="prior",
                results=[FileRunResult("provider.py", "crashed", -11, 0.1)],
            ),
        )
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

        def fail_collection(*_args: object, **_kwargs: object) -> list[str]:
            raise ValueError("resumed collection failure")

        monkeypatch.setattr(test_cmd, "discover_pytest_units", fail_collection)
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

        assert result.exit_code == 1

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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status=status,
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    process_observation=observation,
                    error=f"preflight {status}",
                )
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status="error",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    error="preflight error",
                )
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status="crashed",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    process_observation=build_process_observation(str(module), "preflight", 0, -11),
                    error="preflight crashed",
                )
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
            lambda module, *, interface, slot, timeout, output_path, counters=None: (
                CapabilityManifest(
                    status="timeout",
                    module_path=str(module),
                    requested_interface=interface,
                    interface_version=None,
                    slot_index=slot,
                    slot_count=None,
                    mechanisms=[],
                    process_observation=observation,
                    error="preflight timed out",
                )
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
        monkeypatch.setattr(fetch_cmd, "urlopen", lambda _url, **_kw: io.BytesIO(baseline.encode()))

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
        monkeypatch.setattr(fetch_cmd, "urlopen", lambda _url, **_kw: io.BytesIO(baseline.encode()))

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
        monkeypatch.setattr(fetch_cmd, "urlopen", lambda _url, **_kw: io.BytesIO(html.encode()))

        result = runner.invoke(app, ["fetch-disabled", "--data-dir", str(tmp_path)])

        assert result.exit_code == 1


def test_completion_helpers_stream_report_logs_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class OnePassRecords:
        def __init__(self, records: list[dict[str, object]]) -> None:
            self._records = iter(records)

        def __iter__(self) -> OnePassRecords:
            return self

        def __next__(self) -> dict[str, object]:
            return next(self._records)

        def __length_hint__(self) -> int:
            raise AssertionError("report records must be consumed as a stream")

    records = [
        {"$report_type": "SessionStart"},
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]
    cli_calls = 0

    def cli_records(*_args: object, **_kwargs: object) -> OnePassRecords:
        nonlocal cli_calls
        cli_calls += 1
        return OnePassRecords(records)

    monkeypatch.setattr(test_cmd, "iter_report_log_records", cli_records)
    assert not test_cmd._ensure_nonisolated_completion_record(
        tmp_path / "cli.jsonl", returncode=1, stdout="", stderr=""
    )
    assert cli_calls == 1

    collection_open_count = 0
    original_open = Path.open

    def collection_open(path: Path, *args: object, **kwargs: object):
        nonlocal collection_open_count
        if path == tmp_path / "collection.jsonl":
            collection_open_count += 1
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", collection_open)
    assert not collection_errors_mod.ensure_failed_collection_report(
        tmp_path / "collection.jsonl",
        target="test_demo.py",
        status="failed",
        returncode=1,
        stdout="",
        stderr="",
    )
    assert collection_open_count == 1


# ---------------------------------------------------------------------------
# CLI tests for --selection-manifest
# ---------------------------------------------------------------------------


def test_cli_selection_manifest_requires_format_json(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(manifest),
            "--format",
            "junit",
            "--isolation",
            "file",
            "test_encrypt.py",
        ],
    )
    assert result.exit_code == 2
    assert "--selection-manifest requires --format json" in result.output


def test_cli_selection_manifest_requires_isolation_file(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    for iso in ["auto", "none", "test"]:
        result = runner.invoke(
            app,
            [
                "test",
                "--module",
                "/tmp/fake.so",
                "--selection-manifest",
                str(manifest),
                "--format",
                "json",
                "--isolation",
                iso,
                "test_encrypt.py",
            ],
        )
        assert result.exit_code == 2
        assert "--selection-manifest requires --isolation file" in result.output


def test_cli_selection_manifest_requires_single_bare_file_target(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    # No targets
    res1 = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(manifest),
            "--format",
            "json",
            "--isolation",
            "file",
        ],
    )
    assert res1.exit_code == 2
    assert "requires exactly one bare file target" in res1.output

    # Multiple targets
    res2 = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(manifest),
            "--format",
            "json",
            "--isolation",
            "file",
            "test_a.py",
            "test_b.py",
        ],
    )
    assert res2.exit_code == 2
    assert "requires exactly one bare file target" in res2.output

    # Node ID target with ::
    res3 = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(manifest),
            "--format",
            "json",
            "--isolation",
            "file",
            "test_encrypt.py::test_roundtrip",
        ],
    )
    assert res3.exit_code == 2
    assert "requires exactly one bare file target" in res3.output


def test_cli_selection_manifest_rejects_mismatched_target(tmp_path: Path) -> None:
    from pkcs11_check.core.test_selection import (
        compute_batch_id,
        compute_collection_sha256,
    )

    source = "test_encrypt.py"
    nodeids = [f"{source}::test_roundtrip"]
    col_sha = compute_collection_sha256(nodeids)
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=1,
        source_collection_sha256=col_sha,
        nodeids=nodeids,
    )
    manifest_data = {
        "schema": 1,
        "plan_id": "a" * 64,
        "batch_id": batch_id,
        "source": source,
        "source_collection_count": 1,
        "source_collection_sha256": col_sha,
        "nodeids": nodeids,
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(manifest_data), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(manifest),
            "--format",
            "json",
            "--isolation",
            "file",
            "test_reinitialize.py",
        ],
    )
    assert result.exit_code == 2
    assert "does not match manifest source" in result.output


def test_cli_selection_manifest_rejects_nonexistent_or_invalid_file(tmp_path: Path) -> None:
    # 1. Non-existent file
    nonexistent = tmp_path / "nonexistent.json"
    res1 = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(nonexistent),
            "--format",
            "json",
            "--isolation",
            "file",
            "test_encrypt.py",
        ],
    )
    assert res1.exit_code == 2
    assert "invalid selection manifest" in res1.output or "not found" in res1.output

    # 2. Malformed JSON
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    res2 = runner.invoke(
        app,
        [
            "test",
            "--module",
            "/tmp/fake.so",
            "--selection-manifest",
            str(bad_json),
            "--format",
            "json",
            "--isolation",
            "file",
            "test_encrypt.py",
        ],
    )
    assert res2.exit_code == 2
    assert "invalid selection manifest" in res2.output


def test_merge_shards_cli_includes_shard_with_only_selection_json(tmp_path: Path) -> None:
    from pkcs11_check.core.test_selection import CaseSelection, compute_batch_id

    source = "wycheproof/test_wycheproof_ecdsa.py"
    nodeids = (f"{source}::test_verify[c1]",)
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )
    sel = CaseSelection(
        schema=1,
        plan_id="b" * 64,
        batch_id=batch_id,
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )

    # Shard 0: complete shard
    s0 = tmp_path / "shard0"
    s0.mkdir()
    (s0 / "results.json").write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": {"passed": 1, "total": 1},
                "units": [{"target": "test_ok.py", "status": "passed"}],
            }
        ),
        encoding="utf-8",
    )
    (s0 / "report.jsonl").write_text(
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "test_ok.py::test_1",
                "when": "call",
                "outcome": "passed",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    # Shard 1: only selection.json (no results.json, no report.jsonl)
    s1 = tmp_path / "shard1"
    s1.mkdir()
    (s1 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2) + "\n", encoding="utf-8")

    out_dir = tmp_path / "merged"
    res = runner.invoke(app, ["merge-shards", str(s0), str(s1), "-o", str(out_dir)])
    assert res.exit_code == 0
    assert (out_dir / "results.json").exists()
    merged_data = json.loads((out_dir / "results.json").read_text(encoding="utf-8"))
    assert merged_data["summary"]["incomplete"] is True
    assert any(
        "shard1" in w and "LOST" in w for w in merged_data.get("shards", {}).get("warnings", [])
    )


def test_recorded_counters_dir_accepts_allocated_forms(tmp_path: Path) -> None:
    """M8: sibling canonical/nonce counters dirs are accepted for resume."""
    state = tmp_path / "run.json"
    state.touch()
    canonical = tmp_path / "run.json.counters"
    canonical.mkdir()
    nonced = tmp_path / "run.json.counters.abcdef12"
    nonced.mkdir()
    assert test_cmd._validated_recorded_counters_dir(state, str(canonical)) == canonical.resolve()
    assert test_cmd._validated_recorded_counters_dir(state, str(nonced)) == nonced.resolve()


def test_recorded_counters_dir_refuses_outside_and_lookalikes(tmp_path: Path) -> None:
    """M8: non-sibling dirs and hostile lookalikes are refused for resume."""
    state = tmp_path / "run.json"
    state.touch()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    outsider = elsewhere / "run.json.counters"
    outsider.mkdir()
    lookalike = tmp_path / "run.json.counters.evil"
    lookalike.mkdir()
    with pytest.raises(ValueError, match="not an allocated counters dir"):
        test_cmd._validated_recorded_counters_dir(state, str(outsider))
    with pytest.raises(ValueError, match="not an allocated counters dir"):
        test_cmd._validated_recorded_counters_dir(state, str(lookalike))


def test_recorded_counters_dir_refuses_symlink_escape(tmp_path: Path) -> None:
    """M8: a correctly-named link escaping the state dir is refused."""
    state = tmp_path / "run.json"
    state.touch()
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "run.json.counters"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="not an allocated counters dir"):
        test_cmd._validated_recorded_counters_dir(state, str(link))


def test_r44_c11r11_recorded_dir_loop_refuses_as_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R44-[C]r11: a looping recorded dir refuses (no raw escape).

    Codex R11: a self-referential recorded counters dir made resume
    exit with a raw RuntimeError (3.12) instead of the controlled
    refusal. Resolution faults at both resolve sites normalize into
    the existing ValueError refusal, preserving the path and the
    underlying error. Mocked: this interpreter tolerates loops
    lexically, so only fault injection reproduces 3.12 here.
    """
    state = tmp_path / "run.json"
    state.touch()
    recorded = tmp_path / "run.json.counters.aaaaaaaa"
    recorded.mkdir()
    real_resolve = Path.resolve

    def _looping_resolve(self: Path, strict: bool = False) -> Path:
        if self == recorded:
            raise RuntimeError("Symlink loop from 'run.json.counters.aaaaaaaa'")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _looping_resolve)
    with pytest.raises(ValueError, match="cannot be resolved") as exc_info:
        test_cmd._validated_recorded_counters_dir(state, str(recorded))
    assert str(recorded) in str(exc_info.value), "the path is named"
    assert "Symlink loop" in str(exc_info.value), "the cause is preserved"


# NOTE (#88R44-[C]r11 residual): a missing-but-well-named recorded dir is
# ACCEPTED (non-strict resolve never raises FileNotFoundError), so resume
# reuses a cleared dir silently. Whether that needs a refusal is an open
# product question -- deliberately unpinned until adjudicated.


def test_r44_c12r12_recorded_dir_state_resolve_fault_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R44-[C]r12: the state-file resolve is covered too (R12 Minor).

    The validator resolves two paths; the loop test pins the
    recorded dir, this one pins the state file itself.
    """
    state = tmp_path / "run.json"
    state.touch()
    recorded = tmp_path / "run.json.counters.aaaaaaaa"
    recorded.mkdir()
    real_resolve = Path.resolve

    def _looping_resolve(self: Path, strict: bool = False) -> Path:
        if self == state:
            raise RuntimeError("Symlink loop from 'run.json'")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _looping_resolve)
    with pytest.raises(ValueError, match="cannot be resolved") as exc_info:
        test_cmd._validated_recorded_counters_dir(state, str(recorded))
    assert str(state) in str(exc_info.value), "the path is named"
    assert "Symlink loop" in str(exc_info.value), "the cause is preserved"


def test_r44_c12r12_cli_resume_looped_recorded_dir_exits_2_before_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R44-[C]r12: CLI resume with a looping recorded dir exits 2 early.

    End-to-end pin for the R11 repro: a saved state naming a
    looping counters dir refuses with exit 2 before the barrier,
    preflight, or runner ever start (R12 Minor: the direct
    validator tests never drove the CLI exit path).
    """
    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    state_file = tmp_path / "state.json"
    recorded = tmp_path / "state.json.counters.aaaaaaaa"
    recorded.mkdir()
    save_run_state(
        state_file,
        FileRunState(units=["a.py"], fingerprint="fp", results=[], counters_dir=str(recorded)),
    )
    real_resolve = Path.resolve

    def _looping_resolve(self: Path, strict: bool = False) -> Path:
        if self == recorded:
            raise RuntimeError("Symlink loop from 'state.json.counters.aaaaaaaa'")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _looping_resolve)
    called: list[str] = []

    def _record(name: str):
        def _fake(*args: object, **kwargs: object) -> None:
            called.append(name)
            raise AssertionError(f"{name} must not run on refusal")

        return _fake

    monkeypatch.setattr(test_cmd, "prepare_resume", _record("barrier"))
    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _record("preflight"))
    monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", _record("runner"))  # type: ignore[arg-type]
    result = runner.invoke(
        app,
        [
            "test",
            "--module",
            str(module),
            "--isolation",
            "file",
            "--state-file",
            str(state_file),
            "--resume",
        ],
    )
    import textwrap

    assert result.exit_code == 2, result.output
    # Normalized: Rich may wrap the diagnostic across lines at narrow
    # widths (R13 Minor), so match on whitespace-folded output. The
    # width-10 adversarial fold proves the technique survives an
    # actual split (the 18-char phrase cannot fit on a 10-char line).
    adversarial = textwrap.fill(result.output, width=10)
    assert "cannot be resolved" not in adversarial, "premise: really split"
    output = " ".join(result.output.split())
    assert "refusing to resume" in output, result.output
    assert "cannot be resolved" in output, result.output
    assert "cannot be resolved" in " ".join(adversarial.split())
    assert called == [], "barrier, preflight, and runner never start"
