"""Tests for per-file isolated pytest running."""

from __future__ import annotations

import json
import subprocess
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console

from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.file_runner import (
    BackendIsolationPolicy,
    FileRunResult,
    FileRunState,
    IsolatedReportConfig,
    _collection_args,
    _identify_crash_culprit,
    _read_jsonl_results,
    build_policy_fingerprint,
    build_state_fingerprint,
    collect_pytest_nodeids,
    discover_auto_isolation_units,
    discover_pytest_units,
    file_forces_file_isolation,
    file_isolation_mode,
    load_isolation_policy,
    load_run_state,
    normalize_policy_file_key,
    postprocess_jsonl_to_unified,
    run_isolated_pytest_units,
    save_isolation_policy,
    save_run_state,
    units_remaining_for_resume,
    write_isolated_json_report,
    write_report_jsonl,
)


def test_discover_pytest_units_from_directory(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_b.py").write_text("")
    (tests_dir / "note.txt").write_text("")
    nested = tests_dir / "nested"
    nested.mkdir()
    (nested / "test_a.py").write_text("")

    units = discover_pytest_units([str(tests_dir)], tmp_path / "unused")

    assert units == [str(nested / "test_a.py"), str(tests_dir / "test_b.py")]


def test_discover_pytest_units_keeps_nodeid_target(tmp_path: Path) -> None:
    target = f"{tmp_path / 'test_demo.py'}::TestThing::test_case"
    (tmp_path / "test_demo.py").write_text("")

    units = discover_pytest_units([target], tmp_path / "unused")

    assert units == [target]


def test_collect_pytest_nodeids(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")

    def fake_run(
        cmd: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        env: dict[str, str],
    ) -> SimpleNamespace:
        del check, capture_output, text, env
        assert cmd[-2:] == ["--collect-only", "-qq"]
        return SimpleNamespace(
            returncode=0,
            stdout=(
                f"{target}::test_case\n{target}::test_other[param]\n\n2 tests collected in 0.03s\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]

    units = collect_pytest_nodeids([str(target)], ["--p11-module", "/tmp/module.so"])

    assert units == [f"{target}::test_case", f"{target}::test_other[param]"]


def test_discover_pytest_units_test_granularity_collects_nodeids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")

    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [f"{target}::test_case"],  # type: ignore[arg-type]
    )

    units = discover_pytest_units(
        [str(target)],
        tmp_path / "unused",
        granularity="test",
        pytest_args=["--p11-module", "/tmp/module.so"],
    )

    assert units == [f"{target}::test_case"]


def test_collect_pytest_nodeids_reports_collection_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")

    def fake_run(
        cmd: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        env: dict[str, str],
    ) -> SimpleNamespace:
        del cmd, check, capture_output, text, env
        return SimpleNamespace(returncode=4, stdout="", stderr="usage error")

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="pytest collection failed: usage error"):
        collect_pytest_nodeids([str(target)], ["--p11-module", "/tmp/module.so"])


def test_file_isolation_mode_defaults_to_file(tmp_path: Path) -> None:
    assert file_isolation_mode(set()) == "file"


def test_file_isolation_mode_promotes_subprocess_per_test(tmp_path: Path) -> None:
    del tmp_path
    assert file_isolation_mode({"subprocess_per_test"}) == "test"


def test_file_forces_file_isolation_for_subprocess_marker(tmp_path: Path) -> None:
    del tmp_path
    assert file_forces_file_isolation({"subprocess"}) is True


def test_discover_auto_isolation_units_keeps_regular_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_item_metadata",
        lambda targets, pytest_args, *, env=None: [  # type: ignore[arg-type]
            CollectedPytestItem(nodeid=f"{target}::test_case", file_path=str(target), markers=[])
        ],
    )

    units = discover_auto_isolation_units(
        [str(target)],
        tmp_path / "unused",
        pytest_args=["--p11-module", "/tmp/module.so"],
    )

    assert units == [str(target)]


def test_discover_auto_isolation_units_expands_per_test_marked_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_one():\n    assert True\n")
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_item_metadata",
        lambda targets, pytest_args, *, env=None: [  # type: ignore[arg-type]
            CollectedPytestItem(
                nodeid=f"{target}::test_one",
                file_path=str(target),
                markers=["subprocess_per_test"],
            ),
            CollectedPytestItem(
                nodeid=f"{target}::test_two",
                file_path=str(target),
                markers=["subprocess_per_test"],
            ),
        ],
    )

    units = discover_auto_isolation_units(
        [str(target)],
        tmp_path / "unused",
        pytest_args=["--p11-module", "/tmp/module.so"],
    )

    assert units == [f"{target}::test_one", f"{target}::test_two"]


def test_discover_auto_isolation_units_expands_policy_promoted_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_demo.py"
    target.write_text("def test_one():\n    assert True\n")
    policy_file = tmp_path / "policy.json"
    fingerprint = build_policy_fingerprint(["--p11-module", str(module)])
    save_isolation_policy(
        policy_file,
        {
            fingerprint: BackendIsolationPolicy(
                fingerprint=fingerprint,
                promoted_files=[normalize_policy_file_key(str(target))],
                crashed_tests=[],
            )
        },
    )

    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_item_metadata",
        lambda targets, pytest_args, *, env=None: [  # type: ignore[arg-type]
            CollectedPytestItem(nodeid=f"{target}::test_one", file_path=str(target), markers=[])
        ],
    )

    units = discover_auto_isolation_units(
        [str(target)],
        tmp_path / "unused",
        pytest_args=["--p11-module", str(module)],
        policy_file=policy_file,
    )

    assert units == [f"{target}::test_one"]


def test_discover_auto_isolation_units_collapses_nodeid_for_subprocess_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_item_metadata",
        lambda targets, pytest_args, *, env=None: [  # type: ignore[arg-type]
            CollectedPytestItem(
                nodeid=f"{target}::test_case",
                file_path=str(target),
                markers=["subprocess"],
            )
        ],
    )

    units = discover_auto_isolation_units(
        [f"{target}::test_case"],
        tmp_path / "unused",
        pytest_args=["--p11-module", "/tmp/module.so"],
    )

    assert units == [str(target)]


def test_discover_auto_isolation_units_falls_back_to_nodeid_collection_when_metadata_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    policy_file = tmp_path / "policy.json"
    fingerprint = build_policy_fingerprint(["--p11-module", str(module)])
    save_isolation_policy(
        policy_file,
        {
            fingerprint: BackendIsolationPolicy(
                fingerprint=fingerprint,
                promoted_files=[normalize_policy_file_key(str(target))],
                crashed_tests=[],
            )
        },
    )
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_item_metadata",
        lambda targets, pytest_args, *, env=None: [],  # type: ignore[arg-type]
    )
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.discover_pytest_units",
        lambda targets, default_root, *, granularity, pytest_args=None, env=None: (  # type: ignore[arg-type]
            [f"{target}::test_case"] if granularity == "test" else list(targets)
        ),
    )

    units = discover_auto_isolation_units(
        [str(target)],
        tmp_path / "unused",
        pytest_args=["--p11-module", str(module)],
        policy_file=policy_file,
    )

    assert units == [f"{target}::test_case"]


def test_state_round_trip(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state = FileRunState(
        units=["test_a.py", "test_b.py"],
        fingerprint="abc123",
        results=[FileRunResult("test_a.py", "passed", 0, 1.2)],
        report_records_by_unit={
            "test_a.py": [
                {
                    "$report_type": "TestReport",
                    "nodeid": "test_a.py::test_case",
                    "when": "call",
                    "outcome": "passed",
                    "duration": 0.1,
                }
            ]
        },
    )

    save_run_state(state_file, state)
    loaded = load_run_state(state_file)

    assert loaded == state


def test_save_run_state_creates_parent_directories(tmp_path: Path) -> None:
    state_file = tmp_path / "nested" / "state.json"
    state = FileRunState(units=["test_a.py"], fingerprint="abc123", results=[])

    save_run_state(state_file, state)

    assert state_file.exists()


def test_isolation_policy_round_trip(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy = BackendIsolationPolicy(
        fingerprint="abc123",
        promoted_files=["/tmp/test_demo.py"],
        crashed_tests=["/tmp/test_demo.py::test_case"],
    )

    save_isolation_policy(policy_file, {"abc123": policy})
    loaded = load_isolation_policy(policy_file)

    assert loaded == {"abc123": policy}


def test_units_remaining_for_resume_skips_passed_and_empty() -> None:
    units = ["test_a.py", "test_b.py", "test_c.py", "test_d.py"]
    state = FileRunState(
        units=units,
        fingerprint="abc123",
        results=[
            FileRunResult("test_a.py", "passed", 0, 0.1),
            FileRunResult("test_b.py", "empty", 5, 0.1),
            FileRunResult("test_c.py", "failed", 1, 0.1),
        ],
    )

    assert units_remaining_for_resume(units, state) == ["test_c.py", "test_d.py"]


def test_units_remaining_for_resume_skips_crash_limited() -> None:
    units = ["test_a.py::test_one", "test_a.py::test_two", "test_b.py"]
    state = FileRunState(
        units=units,
        fingerprint="abc123",
        results=[FileRunResult("test_a.py::test_two", "crash_limited", 0, 0.0)],
    )

    assert units_remaining_for_resume(units, state) == ["test_a.py::test_one", "test_b.py"]


def test_units_remaining_for_resume_skips_escalated() -> None:
    units = ["test_a.py", "test_a.py::test_case", "test_b.py"]
    state = FileRunState(
        units=units,
        fingerprint="abc123",
        results=[FileRunResult("test_a.py", "escalated", -11, 0.1)],
    )

    assert units_remaining_for_resume(units, state) == ["test_a.py::test_case", "test_b.py"]


def test_run_isolated_pytest_units_records_results_and_stops(
    monkeypatch: object, tmp_path: Path
) -> None:
    calls: list[list[str]] = []
    results = iter([0, 1, 0])

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        calls.append(cmd)
        return (next(results), "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    state_file = tmp_path / "state.json"
    console = Console(file=StringIO(), force_terminal=False)

    exit_code = run_isolated_pytest_units(
        ["test_a.py", "test_b.py", "test_c.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=True,
        console=console,
        granularity="file",
    )

    saved = load_run_state(state_file)
    assert exit_code == 1
    assert saved is not None
    assert saved.fingerprint == build_state_fingerprint(
        ["test_a.py", "test_b.py", "test_c.py"],
        ["--p11-module", "/tmp/module.so"],
    )
    assert [result.target for result in saved.results] == ["test_a.py", "test_b.py"]
    assert len(calls) == 2


def test_run_isolated_pytest_units_promotes_crashed_file_in_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    state_file = tmp_path / "state.json"
    policy_file = tmp_path / "policy.json"
    console = Console(file=StringIO(), force_terminal=False)

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> tuple[int, str, str]:
        del cmd, check, env, timeout, stdout, stderr
        return (-11, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        [str(target)],
        ["--p11-module", str(module)],
        timeout=12,
        state_file=state_file,
        policy_file=policy_file,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="file",
    )

    fingerprint = build_policy_fingerprint(["--p11-module", str(module)])
    policies = load_isolation_policy(policy_file)

    assert exit_code == 1
    assert policies[fingerprint].promoted_files == [normalize_policy_file_key(str(target))]


def test_run_isolated_pytest_units_escalates_crashed_file_in_same_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    state_file = tmp_path / "state.json"
    console = Console(file=StringIO(), force_terminal=False)
    calls: list[str] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        unit = cmd[3]
        calls.append(unit)
        return (-11 if unit == str(target) else 0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.discover_pytest_units",
        lambda targets, default_root, *, granularity, pytest_args, env=None: (
            [  # type: ignore[arg-type]
                f"{target}::test_one",
                f"{target}::test_two",
            ]
            if granularity == "test"
            else list(targets)
        ),
    )

    exit_code = run_isolated_pytest_units(
        [str(target), "test_after.py"],
        ["--p11-module", str(module)],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="mixed",
    )

    saved = load_run_state(state_file)
    assert exit_code == 1
    assert calls[:4] == [str(target), f"{target}::test_one", f"{target}::test_two", "test_after.py"]
    assert saved is not None
    assert saved.units == [
        str(target),
        f"{target}::test_one",
        f"{target}::test_two",
        "test_after.py",
    ]
    assert saved.fingerprint == build_state_fingerprint(saved.units, ["--p11-module", str(module)])
    assert saved.results[0].target == str(target)
    assert saved.results[0].status == "escalated"
    assert [result.target for result in saved.results[1:]] == [
        f"{target}::test_one",
        f"{target}::test_two",
        "test_after.py",
    ]


def test_run_isolated_pytest_units_limits_repeated_crashes_in_same_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    state_file = tmp_path / "state.json"
    console = Console(file=StringIO(), force_terminal=False)
    calls: list[str] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        unit = cmd[3]
        calls.append(unit)
        if unit == str(target):
            return (-11, "", "")
        if unit in {f"{target}::test_one", f"{target}::test_two"}:
            return (-11, "", "")
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.discover_pytest_units",
        lambda targets, default_root, *, granularity, pytest_args, env=None: (
            [  # type: ignore[arg-type]
                f"{target}::test_one",
                f"{target}::test_two",
                f"{target}::test_three",
            ]
            if granularity == "test"
            else list(targets)
        ),
    )

    exit_code = run_isolated_pytest_units(
        [str(target), "test_after.py"],
        ["--p11-module", str(module)],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="mixed",
        max_crashes_per_file=2,
    )

    saved = load_run_state(state_file)
    assert exit_code == 1
    assert calls == [str(target), f"{target}::test_one", f"{target}::test_two", "test_after.py"]
    assert saved is not None
    assert [result.target for result in saved.results] == [
        str(target),
        f"{target}::test_one",
        f"{target}::test_two",
        f"{target}::test_three",
        "test_after.py",
    ]
    assert [result.status for result in saved.results] == [
        "escalated",
        "crashed",
        "crashed",
        "crash_limited",
        "passed",
    ]


def test_build_state_fingerprint_changes_when_unit_file_changes(tmp_path: Path) -> None:
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")
    env = {"P11TEST_PIN": "1234"}

    first = build_state_fingerprint([str(unit)], ["--p11-module", "/tmp/module.so"], env)

    unit.write_text("def test_demo():\n    assert False\n")
    second = build_state_fingerprint([str(unit)], ["--p11-module", "/tmp/module.so"], env)

    assert first != second


def test_build_state_fingerprint_changes_when_module_changes(tmp_path: Path) -> None:
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")
    module = tmp_path / "module.so"
    module.write_text("v1")
    env = {"P11TEST_PIN": "1234"}

    first = build_state_fingerprint([str(unit)], ["--p11-module", str(module)], env)

    module.write_text("v2")
    second = build_state_fingerprint([str(unit)], ["--p11-module", str(module)], env)

    assert first != second


def test_build_state_fingerprint_changes_when_env_changes(tmp_path: Path) -> None:
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")
    module = tmp_path / "module.so"
    module.write_text("v1")

    first = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module)],
        {"BOUNCY_HSM_CFG_STRING": "Server=127.0.0.1;Port=8765;"},
    )
    second = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module)],
        {"BOUNCY_HSM_CFG_STRING": "Server=127.0.0.1;Port=9999;"},
    )

    assert first != second


def test_build_state_fingerprint_changes_when_disabled_baseline_changes(tmp_path: Path) -> None:
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")

    first = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", "/tmp/module.so"],
        baseline_fingerprint="baseline-a",
    )
    second = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", "/tmp/module.so"],
        baseline_fingerprint="baseline-b",
    )

    assert first != second


def test_build_policy_fingerprint_ignores_runner_control_env(tmp_path: Path) -> None:
    module = tmp_path / "module.so"
    module.write_text("v1")

    first = build_policy_fingerprint(
        ["--p11-module", str(module)],
        {
            "P11TEST_ISOLATION": "auto",
            "P11TEST_STATE_FILE": "/tmp/one.json",
            "P11TEST_PIN": "1234",
        },
    )
    second = build_policy_fingerprint(
        ["--p11-module", str(module)],
        {
            "P11TEST_ISOLATION": "test",
            "P11TEST_STATE_FILE": "/tmp/two.json",
            "P11TEST_PIN": "1234",
        },
    )

    assert first == second


def test_build_state_fingerprint_uses_manifest_content_not_manifest_path(tmp_path: Path) -> None:
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")
    module = tmp_path / "module.so"
    module.write_text("v1")
    manifest_a = tmp_path / "manifest-a.json"
    manifest_b = tmp_path / "manifest-b.json"
    manifest_a.write_text('{"status":"ok"}\n')
    manifest_b.write_text('{"status":"ok"}\n')

    first = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module), "--p11-manifest", str(manifest_a)],
    )
    second = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module), "--p11-manifest", str(manifest_b)],
    )

    assert first == second


def test_run_isolated_pytest_units_resume_skips_passed(monkeypatch: object, tmp_path: Path) -> None:
    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    state_file = tmp_path / "state.json"
    save_run_state(
        state_file,
        FileRunState(
            units=["test_a.py", "test_b.py"],
            fingerprint=build_state_fingerprint(
                ["test_a.py", "test_b.py"],
                ["--p11-module", "/tmp/module.so"],
            ),
            results=[FileRunResult("test_a.py", "passed", 0, 0.1)],
        ),
    )
    console = Console(file=StringIO(), force_terminal=False)

    exit_code = run_isolated_pytest_units(
        ["test_a.py", "test_b.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=True,
        stop_on_failure=False,
        console=console,
        granularity="file",
    )

    saved = load_run_state(state_file)
    assert exit_code == 0
    assert saved is not None
    assert [result.target for result in saved.results] == ["test_a.py", "test_b.py"]


def test_run_isolated_pytest_units_resume_rejects_changed_baseline_fingerprint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", lambda *args, **kwargs: (0, "", ""))
    state_file = tmp_path / "state.json"
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(
                units,
                pytest_args,
                baseline_fingerprint="baseline-old",
            ),
            results=[],
        ),
    )
    console = Console(file=StringIO(), force_terminal=False)

    with pytest.raises(ValueError, match="belongs to a different isolated run"):
        run_isolated_pytest_units(
            units,
            pytest_args,
            timeout=12,
            state_file=state_file,
            policy_file=None,
            report_config=None,
            resume=True,
            stop_on_failure=False,
            console=console,
            granularity="file",
            baseline_fingerprint="baseline-new",
        )


def test_run_isolated_pytest_units_resume_replaces_failed_result(
    monkeypatch: object, tmp_path: Path
) -> None:
    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> tuple[int, str, str]:
        del cmd, check, env, timeout, stdout, stderr
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    units = ["test_a.py", "test_b.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(units, pytest_args),
            results=[
                FileRunResult("test_a.py", "passed", 0, 0.1),
                FileRunResult("test_b.py", "failed", 1, 0.1),
            ],
            report_records_by_unit={
                "test_a.py": [
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_case",
                        "when": "call",
                        "outcome": "passed",
                        "duration": 0.1,
                    },
                    {
                        "$report_type": "SelectionReport",
                        "selection_coverage": {
                            "encrypt_roundtrip": {
                                "selected_mechanisms": ["CKM_AES_CBC"],
                                "rejected_mechanisms": [],
                                "rejected_reason_counts": {},
                            }
                        },
                    },
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
                    },
                ],
            },
        ),
    )
    console = Console(file=StringIO(), force_terminal=False)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=True,
        stop_on_failure=False,
        console=console,
        granularity="file",
    )

    saved = load_run_state(state_file)
    assert exit_code == 0
    assert saved is not None
    assert saved.results == [
        FileRunResult("test_a.py", "passed", 0, 0.1),
        FileRunResult("test_b.py", "passed", 0, saved.results[1].duration_s),
    ]


def test_run_isolated_pytest_units_resume_json_rebuilds_artifacts_when_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen_cmds: list[list[str]] = []
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(units, pytest_args),
            results=[FileRunResult("test_a.py", "passed", 0, 0.1)],
        ),
    )
    report_jsonl_path.write_text(
        "\n".join(
            [
                _jsonl_line(nodeid="test_a.py::test_case", when="call", outcome="passed"),
                json.dumps(
                    {
                        "$report_type": "SelectionReport",
                        "selection_coverage": {
                            "encrypt_roundtrip": {
                                "selected_mechanisms": ["CKM_AES_CBC"],
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
                            "available": 1,
                            "available_names": ["CKM_AES_CBC"],
                            "invoked": 1,
                            "invoked_names": ["CKM_AES_CBC"],
                            "invoked_counts": {"CKM_AES_CBC": 1},
                            "not_invoked": 0,
                            "not_invoked_names": [],
                            "invoked_detail": ["encrypt_roundtrip"],
                            "invoked_detail_counts": {"encrypt_roundtrip": 1},
                        },
                    }
                ),
            ]
        )
        + "\n"
    )

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=report_jsonl_path,
        ),
        resume=True,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    assert seen_cmds == []
    report = json.loads(results_path.read_text())
    assert report["units"][0]["counts"]["passed"] == 1
    coverage = json.loads((tmp_path / "coverage.json").read_text())
    assert coverage["mechanism_coverage"]["invoked_names"] == ["CKM_AES_CBC"]
    quality = json.loads((tmp_path / "quality.json").read_text())
    assert quality["summary"]["selection_scenarios"] == 1
    assert quality["selection_findings"][0]["scenario"] == "encrypt_roundtrip"


def test_run_isolated_pytest_units_resume_json_uses_state_records_without_coverage_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen_cmds: list[list[str]] = []
    units = ["test_a.py", "test_b.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                jsonl_path.write_text(
                    "\n".join(
                        [
                            _jsonl_line(
                                nodeid="test_b.py::test_case",
                                when="call",
                                outcome="passed",
                            ),
                            json.dumps(
                                {
                                    "$report_type": "SelectionReport",
                                    "selection_coverage": {
                                        "encrypt_roundtrip": {
                                            "selected_mechanisms": ["CKM_AES_GCM"],
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
                                        "invoked_names": ["CKM_AES_GCM"],
                                        "invoked_counts": {"CKM_AES_GCM": 1},
                                        "not_invoked": 1,
                                        "not_invoked_names": ["CKM_AES_CBC"],
                                        "invoked_detail": ["encrypt_roundtrip"],
                                        "invoked_detail_counts": {"encrypt_roundtrip": 1},
                                    },
                                }
                            ),
                        ]
                    )
                    + "\n"
                )
                break
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(units, pytest_args),
            results=[
                FileRunResult("test_a.py", "passed", 0, 0.1),
                FileRunResult("test_b.py", "failed", 1, 0.1),
            ],
            report_records_by_unit={
                "test_a.py": [
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_case",
                        "when": "call",
                        "outcome": "passed",
                        "duration": 0.1,
                    },
                    {
                        "$report_type": "SelectionReport",
                        "selection_coverage": {
                            "encrypt_roundtrip": {
                                "selected_mechanisms": ["CKM_AES_CBC"],
                                "rejected_mechanisms": [],
                                "rejected_reason_counts": {},
                            }
                        },
                    },
                ],
            },
        ),
    )

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=report_jsonl_path,
        ),
        resume=True,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    assert len(seen_cmds) == 1
    report = json.loads(results_path.read_text())
    units_by_target = {unit["target"]: unit for unit in report["units"]}
    assert units_by_target["test_a.py"]["counts"]["passed"] == 1
    assert units_by_target["test_b.py"]["counts"]["passed"] == 1
    merged_jsonl = report_jsonl_path.read_text()
    assert "test_a.py::test_case" in merged_jsonl
    assert "test_b.py::test_case" in merged_jsonl


def test_run_isolated_pytest_units_resume_json_rebuilds_multi_unit_log_without_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen_cmds: list[list[str]] = []
    units = ["test_a.py", "test_b.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(units, pytest_args),
            results=[
                FileRunResult("test_a.py", "passed", 0, 0.1),
                FileRunResult("test_b.py", "passed", 0, 0.1),
            ],
        ),
    )
    report_jsonl_path.write_text(
        "\n".join(
            [
                _jsonl_line(nodeid="test_a.py::test_case", when="call", outcome="passed"),
                _jsonl_line(nodeid="test_b.py::test_case", when="call", outcome="passed"),
            ]
        )
        + "\n"
    )

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=report_jsonl_path,
        ),
        resume=True,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    assert seen_cmds == []
    report = json.loads(results_path.read_text())
    units_by_target = {unit["target"]: unit for unit in report["units"]}
    assert units_by_target["test_a.py"]["counts"]["passed"] == 1
    assert units_by_target["test_b.py"]["counts"]["passed"] == 1
    quality = json.loads((tmp_path / "quality.json").read_text())
    assert quality["summary"]["test_records"] == 2


def test_run_isolated_pytest_units_resume_json_merges_existing_report_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen_cmds: list[list[str]] = []
    units = ["test_a.py", "test_b.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                jsonl_path.write_text(
                    "\n".join(
                        [
                            _jsonl_line(
                                nodeid="test_b.py::test_case",
                                when="call",
                                outcome="passed",
                            ),
                            json.dumps(
                                {
                                    "$report_type": "SelectionReport",
                                    "selection_coverage": {
                                        "encrypt_roundtrip": {
                                            "selected_mechanisms": ["CKM_AES_GCM"],
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
                                        "invoked_names": ["CKM_AES_GCM"],
                                        "invoked_counts": {"CKM_AES_GCM": 1},
                                        "not_invoked": 1,
                                        "not_invoked_names": ["CKM_AES_CBC"],
                                        "invoked_detail": ["encrypt_roundtrip"],
                                        "invoked_detail_counts": {"encrypt_roundtrip": 1},
                                    },
                                }
                            ),
                        ]
                    )
                    + "\n"
                )
                break
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(units, pytest_args),
            results=[
                FileRunResult("test_a.py", "passed", 0, 0.1),
                FileRunResult("test_b.py", "failed", 1, 0.1),
            ],
            report_records_by_unit={
                "test_a.py": [
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_case",
                        "when": "call",
                        "outcome": "passed",
                        "duration": 0.1,
                    },
                    {
                        "$report_type": "SelectionReport",
                        "selection_coverage": {
                            "encrypt_roundtrip": {
                                "selected_mechanisms": ["CKM_AES_CBC"],
                                "rejected_mechanisms": [],
                                "rejected_reason_counts": {},
                            }
                        },
                    },
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
                    },
                ],
            },
        ),
    )
    report_jsonl_path.write_text(
        "\n".join(
            [
                _jsonl_line(nodeid="test_a.py::test_case", when="call", outcome="passed"),
                json.dumps(
                    {
                        "$report_type": "SelectionReport",
                        "selection_coverage": {
                            "encrypt_roundtrip": {
                                "selected_mechanisms": ["CKM_AES_CBC"],
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

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=report_jsonl_path,
        ),
        resume=True,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    assert len(seen_cmds) == 1
    report = json.loads(results_path.read_text())
    units_by_target = {unit["target"]: unit for unit in report["units"]}
    assert units_by_target["test_a.py"]["counts"]["passed"] == 1
    assert units_by_target["test_b.py"]["counts"]["passed"] == 1
    merged_jsonl = report_jsonl_path.read_text()
    assert "test_a.py::test_case" in merged_jsonl
    assert "test_b.py::test_case" in merged_jsonl
    coverage = json.loads((tmp_path / "coverage.json").read_text())
    assert coverage["mechanism_coverage"]["invoked_names"] == ["CKM_AES_CBC", "CKM_AES_GCM"]
    quality = json.loads((tmp_path / "quality.json").read_text())
    assert quality["summary"]["test_records"] == 2
    assert quality["selection_findings"][0]["selected_mechanisms"] == [
        "CKM_AES_CBC",
        "CKM_AES_GCM",
    ]


def test_run_isolated_pytest_units_persists_report_records_into_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(
                    "\n".join(
                        [
                            _jsonl_line(
                                nodeid="test_a.py::test_case",
                                when="call",
                                outcome="passed",
                            ),
                            json.dumps(
                                {
                                    "$report_type": "SelectionReport",
                                    "selection_coverage": {
                                        "encrypt_roundtrip": {
                                            "selected_mechanisms": ["CKM_AES_CBC"],
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
                                        "available": 1,
                                        "available_names": ["CKM_AES_CBC"],
                                        "invoked": 1,
                                        "invoked_names": ["CKM_AES_CBC"],
                                        "invoked_counts": {"CKM_AES_CBC": 1},
                                        "not_invoked": 0,
                                        "not_invoked_names": [],
                                        "invoked_detail": ["encrypt_roundtrip"],
                                        "invoked_detail_counts": {"encrypt_roundtrip": 1},
                                    },
                                }
                            ),
                        ]
                    )
                    + "\n"
                )
                break
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=report_jsonl_path,
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    saved = load_run_state(state_file)
    assert exit_code == 0
    assert saved is not None
    assert list(saved.report_records_by_unit) == ["test_a.py"]
    assert [record["$report_type"] for record in saved.report_records_by_unit["test_a.py"]] == [
        "TestReport",
        "SelectionReport",
        "CoverageReport",
    ]


def test_run_isolated_pytest_units_timeout_persists_partial_report_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(
                    "\n".join(
                        [
                            _jsonl_line(
                                nodeid="test_a.py::test_case",
                                when="setup",
                                outcome="passed",
                            ),
                            json.dumps(
                                {
                                    "$report_type": "SelectionReport",
                                    "selection_coverage": {
                                        "encrypt_roundtrip": {
                                            "selected_mechanisms": ["CKM_AES_CBC"],
                                            "rejected_mechanisms": [],
                                            "rejected_reason_counts": {},
                                        }
                                    },
                                }
                            ),
                        ]
                    )
                    + "\n"
                )
                break
        raise subprocess.TimeoutExpired(cmd, timeout=12)

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=report_jsonl_path,
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    saved = load_run_state(state_file)
    assert exit_code == 1
    assert saved is not None
    assert saved.results[0].status == "timeout"
    assert list(saved.report_records_by_unit) == ["test_a.py"]
    assert [record["$report_type"] for record in saved.report_records_by_unit["test_a.py"]] == [
        "TestReport",
        "SelectionReport",
    ]


def test_run_isolated_pytest_units_iterative_deselect_persists_aggregated_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    calls: list[tuple[str, list[str]]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del timeout
        target = cmd[3]
        calls.append((target, list(cmd)))
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break

        if target == "test_a.py" and (
            env is None or "PKCS11_CHECK_DESELECT_FILE" not in env
        ):
            assert report_log_path is not None
            report_log_path.write_text(
                "\n".join(
                    [
                        _jsonl_line(
                            nodeid="test_a.py::test_done",
                            when="setup",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_done",
                            when="call",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_done",
                            when="teardown",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_culprit",
                            when="setup",
                            outcome="passed",
                        ),
                        json.dumps(
                            {
                                "$report_type": "SelectionReport",
                                "selection_coverage": {
                                    "encrypt_roundtrip": {
                                        "selected_mechanisms": ["CKM_AES_CBC"],
                                        "rejected_mechanisms": [],
                                        "rejected_reason_counts": {},
                                    }
                                },
                            }
                        ),
                    ]
                )
                + "\n"
            )
            return (-11, "", "")

        if target == "test_a.py::test_culprit":
            return (0, "", "")

        if target == "test_a.py" and env is not None and "PKCS11_CHECK_DESELECT_FILE" in env:
            assert report_log_path is not None
            report_log_path.write_text(
                "\n".join(
                    [
                        _jsonl_line(
                            nodeid="test_a.py::test_remaining",
                            when="call",
                            outcome="passed",
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
                                    "available": 1,
                                    "available_names": ["CKM_AES_CBC"],
                                    "invoked": 1,
                                    "invoked_names": ["CKM_AES_CBC"],
                                    "invoked_counts": {"CKM_AES_CBC": 1},
                                    "not_invoked": 0,
                                    "not_invoked_names": [],
                                    "invoked_detail": ["encrypt_roundtrip"],
                                    "invoked_detail_counts": {"encrypt_roundtrip": 1},
                                },
                            }
                        ),
                    ]
                )
                + "\n"
            )
            return (0, "", "")

        raise AssertionError(f"unexpected subprocess invocation: {cmd!r} env={env!r}")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            results_path,
            jsonl_path=tmp_path / "report.jsonl",
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    saved = load_run_state(state_file)
    assert exit_code == 0
    assert saved is not None
    assert calls[0][0] == "test_a.py"
    assert calls[1][0] == "test_a.py::test_culprit"
    assert calls[2][0] == "test_a.py"
    assert [record.get("nodeid") for record in saved.report_records_by_unit["test_a.py"]] == [
        "test_a.py::test_done",
        "test_a.py::test_done",
        "test_a.py::test_done",
        "test_a.py::test_culprit",
        None,
        "test_a.py::test_remaining",
        None,
    ]
    assert [
        record.get("$report_type", "TestReport")
        for record in saved.report_records_by_unit["test_a.py"]
    ] == [
        "TestReport",
        "TestReport",
        "TestReport",
        "TestReport",
        "SelectionReport",
        "TestReport",
        "CoverageReport",
    ]


def test_run_isolated_pytest_units_applies_baseline_deselects_on_initial_file_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_file = tmp_path / "state.json"
    console = Console(file=StringIO(), force_terminal=False)
    seen: dict[str, str] = {}

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del cmd, timeout
        assert env is not None
        deselect_path = Path(env["PKCS11_CHECK_DESELECT_FILE"])
        seen["text"] = deselect_path.read_text()
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        deselect_by_file={"test_a.py": {"test_a.py::test_disabled"}},
        baseline_fingerprint="baseline-initial",
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="file",
    )

    assert exit_code == 0
    assert seen["text"] == "test_a.py::test_disabled\n"


def test_run_isolated_pytest_units_merges_baseline_deselects_into_retry_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_file = tmp_path / "state.json"
    console = Console(file=StringIO(), force_terminal=False)
    calls: list[tuple[str, str | None]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del timeout
        target = cmd[3]
        deselect_text = None
        if env is not None and "PKCS11_CHECK_DESELECT_FILE" in env:
            deselect_text = Path(env["PKCS11_CHECK_DESELECT_FILE"]).read_text()
        calls.append((target, deselect_text))
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break

        if target == "test_a.py" and len(calls) == 1:
            assert report_log_path is not None
            report_log_path.write_text(
                "\n".join(
                    [
                        _jsonl_line(nodeid="test_a.py::test_done", when="setup", outcome="passed"),
                        _jsonl_line(nodeid="test_a.py::test_done", when="call", outcome="passed"),
                        _jsonl_line(
                            nodeid="test_a.py::test_done", when="teardown", outcome="passed"
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_culprit", when="setup", outcome="passed"
                        ),
                    ]
                )
                + "\n"
            )
            return (-11, "", "")

        if target == "test_a.py::test_culprit":
            return (-11, "", "")

        if target == "test_a.py":
            return (0, "", "")

        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        deselect_by_file={"test_a.py": {"test_a.py::baseline_disabled"}},
        baseline_fingerprint="baseline-retry",
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="mixed",
    )

    assert exit_code == 0
    assert calls[0] == ("test_a.py", "test_a.py::baseline_disabled\n")
    assert calls[2][0] == "test_a.py"
    assert calls[2][1] == (
        "test_a.py::baseline_disabled\n"
        "test_a.py::test_culprit\n"
        "test_a.py::test_done\n"
    )


def test_run_isolated_pytest_units_filters_disabled_tests_when_escalating_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    state_file = tmp_path / "state.json"
    console = Console(file=StringIO(), force_terminal=False)
    calls: list[str] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        unit = cmd[3]
        calls.append(unit)
        return (-11 if unit == str(target) else 0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.discover_pytest_units",
        lambda targets, default_root, *, granularity, pytest_args, env=None: (
            [  # type: ignore[arg-type]
                f"{target}::test_one",
                f"{target}::test_two",
            ]
            if granularity == "test"
            else list(targets)
        ),
    )

    exit_code = run_isolated_pytest_units(
        [str(target), "test_after.py"],
        ["--p11-module", "/tmp/module.so"],
        deselect_by_file={str(target): {f"{target}::test_two"}},
        baseline_fingerprint="baseline-escalate",
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="mixed",
    )

    assert exit_code == 1
    assert calls == [str(target), f"{target}::test_one", "test_after.py"]


def test_run_isolated_pytest_units_preserves_confirmed_crash_in_json_report_after_retry_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"
    seen_file_runs = 0

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        target = cmd[3]
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break

        if target == "test_a.py":
            if report_log_path is None:
                raise AssertionError("expected report-log path for file run")
            nonlocal seen_file_runs
            seen_file_runs += 1
            if seen_file_runs == 1:
                report_log_path.write_text(
                    "\n".join(
                        [
                            _jsonl_line(
                                nodeid="test_a.py::test_done", when="setup", outcome="passed"
                            ),
                            _jsonl_line(
                                nodeid="test_a.py::test_done", when="call", outcome="passed"
                            ),
                            _jsonl_line(
                                nodeid="test_a.py::test_done", when="teardown", outcome="passed"
                            ),
                            _jsonl_line(
                                nodeid="test_a.py::test_culprit", when="setup", outcome="passed"
                            ),
                        ]
                    )
                    + "\n"
                )
                return (-11, "", "")

            report_log_path.write_text(
                _jsonl_line(
                    nodeid="test_a.py::test_other",
                    when="call",
                    outcome="failed",
                    longrepr="assert False",
                )
                + "\n"
            )
            return (1, "retry failure", "")

        if target == "test_a.py::test_culprit":
            return (-11, "", "segmentation fault")

        raise AssertionError(f"unexpected target {target}")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig("json", results_path, jsonl_path=report_jsonl_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    assert exit_code == 1
    report = json.loads(results_path.read_text())
    unit = report["units"][0]
    assert unit["target"] == "test_a.py"
    assert unit["status"] == "failed"
    assert unit["counts"]["failed"] == 1
    assert unit["counts"]["crashed"] == 1
    assert unit["counts"]["error"] == 0
    by_nodeid = {entry["nodeid"]: entry for entry in unit["tests"]}
    assert by_nodeid["test_a.py::test_culprit"]["outcome"] == "crashed"
    assert by_nodeid["test_a.py::test_other"]["outcome"] == "failed"
    assert report["summary"]["failed"] == 1
    assert report["summary"]["crashed"] == 1
    assert report["summary"]["error"] == 0


def test_run_isolated_pytest_units_resume_rejects_mismatched_state(
    tmp_path: Path,
) -> None:
    state_file = tmp_path / "state.json"
    save_run_state(
        state_file,
        FileRunState(
            units=["test_a.py"],
            fingerprint="old-fingerprint",
            results=[],
        ),
    )
    console = Console(file=StringIO(), force_terminal=False)

    with pytest.raises(ValueError, match="belongs to a different isolated run"):
        run_isolated_pytest_units(
            ["test_b.py"],
            ["--p11-module", "/tmp/module.so"],
            timeout=12,
            state_file=state_file,
            policy_file=None,
            report_config=None,
            resume=True,
            stop_on_failure=False,
            console=console,
            granularity="file",
        )


def test_run_isolated_pytest_units_test_granularity_uses_shorter_outer_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, object] = {}

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> tuple[int, str, str]:
        del cmd, check, env, stdout, stderr
        seen["timeout"] = timeout
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    console = Console(file=StringIO(), force_terminal=False)

    exit_code = run_isolated_pytest_units(
        ["tests/test_demo.py::test_case"],
        ["--p11-module", "/tmp/module.so"],
        timeout=30,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=console,
        granularity="test",
    )

    assert exit_code == 0
    assert seen["timeout"] == 120


def test_run_isolated_pytest_units_writes_json_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> tuple[int, str, str]:
        del cmd, check, env, timeout, stdout, stderr
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_path = tmp_path / "results.json"
    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    payload = report_path.read_text()
    assert '"kind": "test-run"' in payload
    assert '"status": "passed"' in payload


def test_run_isolated_pytest_units_writes_junit_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    results = iter([1, -11])

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> tuple[int, str, str]:
        del cmd, check, env, timeout, stdout, stderr
        return (next(results), "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_path = tmp_path / "results.xml"
    exit_code = run_isolated_pytest_units(
        ["test_a.py", "test_b.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("junit", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 1
    payload = report_path.read_text()
    assert '<testsuite name="pkcs11-check-isolated"' in payload
    assert 'type="failure"' in payload
    assert 'type="crashed"' in payload


def test_run_isolated_pytest_units_writes_junit_skipped_for_crash_limited(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    results = iter([-11, -11, 0])
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> tuple[int, str, str]:
        del cmd, check, env, timeout, stdout, stderr
        return (next(results), "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_path = tmp_path / "results.xml"
    exit_code = run_isolated_pytest_units(
        [
            f"{target}::test_one",
            f"{target}::test_two",
            f"{target}::test_three",
        ],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("junit", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="test",
        max_crashes_per_file=2,
    )

    assert exit_code == 1
    payload = report_path.read_text()
    assert 'message="skipped after per-file crash limit was reached"' in payload


def test_run_isolated_pytest_units_extracts_per_unit_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify file-level subprocess gets --report-log and detail is extracted."""
    seen_cmds: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        # Write a fake JSONL report-log to the temp file
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                jsonl_path.write_text(
                    json.dumps(
                        {
                            "nodeid": "test_a.py::test_ok",
                            "when": "call",
                            "outcome": "passed",
                            "duration": 0.1,
                        }
                    )
                    + "\n"
                )
                break
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_path = tmp_path / "results.json"

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    # Verify --report-log was injected into the subprocess command
    cmd = seen_cmds[0]
    assert "--report-log" in cmd
    report_log_idx = cmd.index("--report-log")
    jsonl_temp_path = Path(cmd[report_log_idx + 1])
    # Verify the temp file was cleaned up
    assert not jsonl_temp_path.exists()
    # Verify the report has per-unit counts
    report = json.loads(report_path.read_text())
    assert report["units"][0].get("counts") is not None
    assert report["units"][0]["counts"]["passed"] == 1


def test_run_isolated_pytest_units_writes_quality_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                jsonl_path.write_text(
                    "\n".join(
                        [
                            json.dumps(
                                {
                                    "$report_type": "TestReport",
                                    "nodeid": "test_a.py::test_ok",
                                    "when": "call",
                                    "outcome": "passed",
                                    "duration": 0.1,
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
                break
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_path = tmp_path / "results.json"

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            report_path,
            jsonl_path=tmp_path / "report.jsonl",
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    assert (tmp_path / "coverage.json").exists()
    quality_path = tmp_path / "quality.json"
    assert quality_path.exists()
    report = json.loads(quality_path.read_text())
    assert report["schema_version"] == "1"
    assert report["selection_findings"] == []
    assert "selection telemetry not provided" in report["data_quality_warnings"]


def test_run_isolated_pytest_units_keeps_output_for_xfailed_unit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """stdout/stderr must be kept when a passing unit has xfailed tests."""

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        # Write JSONL with a passed test and an xfailed test
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                lines = [
                    json.dumps(
                        {
                            "nodeid": "test_a.py::test_ok",
                            "when": "call",
                            "outcome": "passed",
                            "duration": 0.1,
                        }
                    ),
                    json.dumps(
                        {
                            "nodeid": "test_a.py::test_xf",
                            "when": "call",
                            "outcome": "skipped",
                            "duration": 0.05,
                            "wasxfail": "known bug",
                        }
                    ),
                ]
                jsonl_path.write_text("\n".join(lines) + "\n")
                break
        return (0, "xfail output here\n", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    state_file = tmp_path / "state.json"

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    saved = load_run_state(state_file)
    assert saved is not None
    result = saved.results[0]
    assert result.status == "passed"
    assert result.stdout == "xfail output here\n"


def test_run_isolated_pytest_units_skips_report_log_for_test_level(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Performance guard: plain test-level runs must not create temp JSONL files."""
    seen_cmds: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        ["test_a.py::test_case"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="test",
    )

    assert exit_code == 0
    cmd = seen_cmds[0]
    assert "--report-log" not in cmd


def test_run_isolated_pytest_units_uses_report_log_for_test_level_when_merging_jsonl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen_cmds: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        seen_cmds.append(list(cmd))
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                jsonl_path.write_text(
                    "\n".join(
                        [
                            json.dumps(
                                {
                                    "$report_type": "TestReport",
                                    "nodeid": "test_a.py::test_case",
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
                                            "selected_mechanisms": ["CKM_AES_GCM"],
                                            "rejected_mechanisms": ["CKM_AES_XTS"],
                                            "rejected_reason_counts": {
                                                "unsupported_multi_part": 1,
                                            },
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
                                        "available_names": ["CKM_AES_GCM", "CKM_AES_XTS"],
                                        "invoked": 1,
                                        "invoked_names": ["CKM_AES_XTS"],
                                        "invoked_counts": {"CKM_AES_XTS": 1},
                                        "not_invoked": 1,
                                        "not_invoked_names": ["CKM_AES_GCM"],
                                        "invoked_detail": ["wrap_roundtrip"],
                                        "invoked_detail_counts": {"wrap_roundtrip": 1},
                                    },
                                }
                            ),
                        ]
                    )
                    + "\n"
                )
                break
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_path = tmp_path / "results.json"

    exit_code = run_isolated_pytest_units(
        ["test_a.py::test_case"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json",
            report_path,
            jsonl_path=tmp_path / "report.jsonl",
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="test",
    )

    assert exit_code == 0
    cmd = seen_cmds[0]
    assert "--report-log" in cmd
    report_log_idx = cmd.index("--report-log")
    jsonl_temp_path = Path(cmd[report_log_idx + 1])
    assert not jsonl_temp_path.exists()

    report = json.loads(report_path.read_text())
    assert report["units"][0]["target"] == "test_a.py"
    assert report["units"][0]["counts"]["passed"] == 1

    quality_report = json.loads((tmp_path / "quality.json").read_text())
    assert quality_report["summary"]["selection_scenarios"] == 1
    assert quality_report["selection_findings"][0]["scenario"] == "encrypt_roundtrip"
    assert quality_report["selection_findings"][0]["selected_but_not_invoked"] == [
        "CKM_AES_GCM"
    ]


def test_write_isolated_json_report_unified_format(tmp_path: Path) -> None:
    state = FileRunState(
        units=["test_a.py", "test_b.py"],
        fingerprint="abc123",
        results=[
            FileRunResult("test_a.py", "passed", 0, 1.0),
            FileRunResult("test_b.py", "failed", 1, 2.0, stdout="FAILED test", stderr=""),
        ],
    )
    per_unit_details = {
        "test_a.py": {
            "counts": {
                "passed": 3,
                "failed": 0,
                "skipped": 1,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
            },
            "tests": [],
        },
        "test_b.py": {
            "counts": {
                "passed": 1,
                "failed": 1,
                "skipped": 0,
                "xfailed": 1,
                "xpassed": 0,
                "error": 0,
            },
            "tests": [
                {
                    "nodeid": "test_b.py::test_bad",
                    "outcome": "failed",
                    "duration": 0.5,
                    "longrepr": "assert False",
                },
                {
                    "nodeid": "test_b.py::test_xf",
                    "outcome": "xfailed",
                    "duration": 0.1,
                    "wasxfail": "known",
                },
            ],
        },
    }
    report_path = tmp_path / "results.json"
    write_isolated_json_report(
        report_path,
        state,
        per_unit_details=per_unit_details,
    )

    report = json.loads(report_path.read_text())
    assert report["tool"] == "pkcs11-check"
    assert report["kind"] == "test-run"
    # Summary: (3+1)=4 passed, 1 failed, 1 skipped, 1 xfailed = total 7
    assert report["summary"]["passed"] == 4
    assert report["summary"]["failed"] == 1
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["xfailed"] == 1
    assert report["summary"]["total"] == 7
    assert len(report["units"]) == 2
    unit_a = report["units"][0]
    assert unit_a["target"] == "test_a.py"
    assert unit_a["counts"]["passed"] == 3
    assert "tests" not in unit_a  # no non-passing tests
    unit_b = report["units"][1]
    assert unit_b["target"] == "test_b.py"
    assert len(unit_b["tests"]) == 2
    assert unit_b["stdout"] == "FAILED test"


def test_write_isolated_json_report_groups_test_units_by_file(tmp_path: Path) -> None:
    state = FileRunState(
        units=[
            "test_a.py::test_one",
            "test_a.py::test_two",
            "test_b.py::test_only",
        ],
        fingerprint="abc123",
        results=[
            FileRunResult("test_a.py::test_one", "passed", 0, 0.5),
            FileRunResult("test_a.py::test_two", "failed", 1, 0.3, stdout="fail output"),
            FileRunResult("test_b.py::test_only", "passed", 0, 0.2),
        ],
    )
    per_unit_details = {
        "test_a.py::test_one": {
            "counts": {
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
            },
            "tests": [],
        },
        "test_a.py::test_two": {
            "counts": {
                "passed": 0,
                "failed": 1,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
            },
            "tests": [
                {
                    "nodeid": "test_a.py::test_two",
                    "outcome": "failed",
                    "duration": 0.3,
                    "longrepr": "bad",
                },
            ],
        },
        "test_b.py::test_only": {
            "counts": {
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
            },
            "tests": [],
        },
    }
    report_path = tmp_path / "results.json"
    write_isolated_json_report(
        report_path,
        state,
        per_unit_details=per_unit_details,
    )

    report = json.loads(report_path.read_text())
    # Should be grouped into 2 file-level units, not 3 test-level units
    assert len(report["units"]) == 2
    unit_a = next(u for u in report["units"] if u["target"] == "test_a.py")
    assert unit_a["counts"]["passed"] == 1
    assert unit_a["counts"]["failed"] == 1
    assert unit_a["status"] == "failed"
    assert len(unit_a["tests"]) == 1
    assert unit_a["stdout"] == "fail output"
    unit_b = next(u for u in report["units"] if u["target"] == "test_b.py")
    assert unit_b["counts"]["passed"] == 1
    assert unit_b["status"] == "passed"


def test_write_isolated_json_report_preserves_crashed_test_unit(tmp_path: Path) -> None:
    state = FileRunState(
        units=["test_a.py::test_case"],
        fingerprint="abc123",
        results=[
            FileRunResult(
                "test_a.py::test_case",
                "crashed",
                -11,
                0.4,
                stdout="partial stdout",
                stderr="segmentation fault",
            )
        ],
    )
    report_path = tmp_path / "results.json"

    write_isolated_json_report(report_path, state, per_unit_details={})

    report = json.loads(report_path.read_text())
    assert report["summary"]["crashed"] == 1
    assert report["summary"]["error"] == 0
    assert report["summary"]["total"] == 1
    unit = report["units"][0]
    assert unit["target"] == "test_a.py"
    assert unit["status"] == "crashed"
    assert unit["counts"]["crashed"] == 1
    assert unit["counts"]["error"] == 0
    assert unit["tests"][0]["nodeid"] == "test_a.py::test_case"
    assert unit["tests"][0]["outcome"] == "crashed"
    assert unit["tests"][0]["stderr"] == "segmentation fault"


# ---------------------------------------------------------------------------
# _read_jsonl_results / _map_outcome / _flatten_longrepr
# ---------------------------------------------------------------------------


def _jsonl_line(
    *,
    nodeid: str = "test_mod.py::test_x",
    when: str = "call",
    outcome: str = "passed",
    duration: float = 0.1,
    longrepr: Any = None,
    wasxfail: str | None = None,
    sections: list[list[str]] | None = None,
    location: list[Any] | None = None,
    start: float | None = None,
    report_type: str = "TestReport",
) -> str:
    """Build one JSONL line mimicking pytest-reportlog output."""
    rec: dict[str, Any] = {
        "$report_type": report_type,
        "nodeid": nodeid,
        "when": when,
        "outcome": outcome,
        "duration": duration,
    }
    if longrepr is not None:
        rec["longrepr"] = longrepr
    if wasxfail is not None:
        rec["wasxfail"] = wasxfail
    if sections is not None:
        rec["sections"] = sections
    if location is not None:
        rec["location"] = location
    if start is not None:
        rec["start"] = start
    return json.dumps(rec)


def test_read_jsonl_results_maps_outcomes(tmp_path: Path) -> None:
    """All 6 outcome mappings are correctly applied."""

    lines = [
        # 1. passed (no wasxfail) -> passed
        _jsonl_line(nodeid="t::a", outcome="passed"),
        # 2. passed + wasxfail -> xpassed
        _jsonl_line(nodeid="t::b", outcome="passed", wasxfail="expected fail"),
        # 3. failed (no wasxfail) -> failed
        _jsonl_line(nodeid="t::c", outcome="failed", longrepr="assert False"),
        # 4. failed + wasxfail (strict xfail) -> failed
        _jsonl_line(
            nodeid="t::d", outcome="failed", wasxfail="strict xfail", longrepr="strict xfail"
        ),
        # 5. skipped (no wasxfail) -> skipped
        _jsonl_line(nodeid="t::e", outcome="skipped", longrepr="reason"),
        # 6. skipped + wasxfail -> xfailed
        _jsonl_line(nodeid="t::f", outcome="skipped", wasxfail="known bug", longrepr="known bug"),
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    counts = result["counts"]
    assert counts["passed"] == 1
    assert counts["xpassed"] == 1
    assert counts["failed"] == 2  # failed + strict xfail both map to failed
    assert counts["skipped"] == 1
    assert counts["xfailed"] == 1

    # Check non-passing entries are present
    nodeids_in_tests = {t["nodeid"] for t in result["tests"]}
    assert "t::a" not in nodeids_in_tests  # passed is excluded
    assert "t::b" in nodeids_in_tests  # xpassed included
    assert "t::c" in nodeids_in_tests  # failed included
    assert "t::d" in nodeids_in_tests  # failed (strict xfail) included
    assert "t::e" not in nodeids_in_tests  # skipped excluded
    assert "t::f" in nodeids_in_tests  # xfailed included

    # Verify mapped outcome values
    by_nodeid = {t["nodeid"]: t for t in result["tests"]}
    assert by_nodeid["t::b"]["outcome"] == "xpassed"
    assert by_nodeid["t::c"]["outcome"] == "failed"
    assert by_nodeid["t::d"]["outcome"] == "failed"
    assert by_nodeid["t::f"]["outcome"] == "xfailed"


def test_read_jsonl_results_flattens_longrepr(tmp_path: Path) -> None:
    """Dict longrepr is flattened; string kept; None/absent handled."""

    dict_longrepr: dict[str, Any] = {
        "reprcrash": {"message": "AssertionError: bad", "path": "test.py", "lineno": 42},
        "reprtraceback": {
            "reprentries": [
                {
                    "lines": ["def test_x():", "    assert False"],
                    "reprfileloc": {"path": "t.py", "lineno": 10},
                },
                {"lines": ["E   AssertionError"], "reprfileloc": {"path": "t.py", "lineno": 11}},
            ],
        },
    }
    lines = [
        # dict longrepr
        _jsonl_line(nodeid="t::a", outcome="failed", longrepr=dict_longrepr),
        # string longrepr
        _jsonl_line(nodeid="t::b", outcome="failed", longrepr="simple failure msg"),
        # no longrepr (passed)
        _jsonl_line(nodeid="t::c", outcome="passed"),
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    by_nodeid = {t["nodeid"]: t for t in result["tests"]}

    # Dict longrepr should be flattened to string containing the crash message
    a_repr = by_nodeid["t::a"]["longrepr"]
    assert isinstance(a_repr, str)
    assert "AssertionError: bad" in a_repr

    # String longrepr preserved
    assert by_nodeid["t::b"]["longrepr"] == "simple failure msg"

    # Passed test not in non-passing list
    assert "t::c" not in by_nodeid


def test_read_jsonl_results_handles_setup_skip(tmp_path: Path) -> None:
    """A test skipped during setup (no call phase) is counted as skipped."""

    lines = [
        _jsonl_line(
            nodeid="t::skip_in_fixture",
            when="setup",
            outcome="skipped",
            longrepr="fixture skip reason",
        ),
        # No when=call line follows for this test
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    assert result["counts"]["skipped"] == 1
    assert result["counts"]["passed"] == 0


def test_read_jsonl_results_handles_collect_error(tmp_path: Path) -> None:
    """CollectReport with outcome=error is recorded as an error."""

    lines = [
        _jsonl_line(
            nodeid="test_broken.py",
            when="collect",
            outcome="failed",
            report_type="CollectReport",
            longrepr="SyntaxError: invalid syntax",
        ),
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    assert result["counts"]["error"] == 1
    assert len(result["tests"]) == 1
    assert result["tests"][0]["outcome"] == "error"


def test_read_jsonl_results_returns_none_for_missing(tmp_path: Path) -> None:
    """Missing file returns None."""

    result = _read_jsonl_results(tmp_path / "does_not_exist.jsonl")
    assert result is None


def test_read_jsonl_results_skips_truncated_lines(tmp_path: Path) -> None:
    """Truncated/invalid JSON lines are skipped without error."""

    lines = [
        _jsonl_line(nodeid="t::good", outcome="passed"),
        '{"nodeid": "t::truncated", "when": "call", "outcome":',  # truncated
        _jsonl_line(nodeid="t::also_good", outcome="failed", longrepr="fail"),
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    assert result["counts"]["passed"] == 1
    assert result["counts"]["failed"] == 1
    # Truncated line should be silently skipped
    total = sum(result["counts"].values())
    assert total == 2


# ---------------------------------------------------------------------------
# _identify_crash_culprit
# ---------------------------------------------------------------------------


def test_identify_crash_culprit_from_jsonl(tmp_path: Path) -> None:
    """Crash culprit is the test with setup but no teardown."""
    jsonl = tmp_path / "report.jsonl"
    lines = [
        _jsonl_line(nodeid="t.py::test_a", when="setup"),
        _jsonl_line(nodeid="t.py::test_a", when="call"),
        _jsonl_line(nodeid="t.py::test_a", when="teardown"),
        _jsonl_line(nodeid="t.py::test_b", when="setup"),
        # crash — no call or teardown for test_b
    ]
    jsonl.write_text("\n".join(lines) + "\n")
    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit == "t.py::test_b"
    assert completed == ["t.py::test_a"]


def test_identify_crash_culprit_mid_call(tmp_path: Path) -> None:
    """Crash during call phase — has setup+call but no teardown."""
    jsonl = tmp_path / "report.jsonl"
    lines = [
        _jsonl_line(nodeid="t.py::test_a", when="setup"),
        _jsonl_line(nodeid="t.py::test_a", when="call"),
        _jsonl_line(nodeid="t.py::test_a", when="teardown"),
        _jsonl_line(nodeid="t.py::test_b", when="setup"),
        _jsonl_line(nodeid="t.py::test_b", when="call"),
        # crash during call — no teardown
    ]
    jsonl.write_text("\n".join(lines) + "\n")
    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit == "t.py::test_b"
    assert completed == ["t.py::test_a"]


def test_identify_crash_culprit_empty_jsonl(tmp_path: Path) -> None:
    """Empty JSONL — no culprit, no completed."""
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("")
    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit is None
    assert completed == []


def test_identify_crash_culprit_all_completed(tmp_path: Path) -> None:
    """All tests completed — no culprit."""
    jsonl = tmp_path / "report.jsonl"
    lines = [
        _jsonl_line(nodeid="t.py::test_a", when="setup"),
        _jsonl_line(nodeid="t.py::test_a", when="call"),
        _jsonl_line(nodeid="t.py::test_a", when="teardown"),
    ]
    jsonl.write_text("\n".join(lines) + "\n")
    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit is None
    assert completed == ["t.py::test_a"]


def test_identify_crash_culprit_missing_file(tmp_path: Path) -> None:
    """Missing JSONL file — no culprit, no completed."""
    culprit, completed = _identify_crash_culprit(tmp_path / "nope.jsonl")
    assert culprit is None
    assert completed == []


# ---------------------------------------------------------------------------
# Integration tests — fixture dedup, postprocess, write_report_jsonl, etc.
# ---------------------------------------------------------------------------


def test_read_jsonl_results_deduplicates_fixture_errors(tmp_path: Path) -> None:
    """Session fixture failure: N identical setup/error entries -> 1 detail + N count."""
    shared_longrepr = "fixture 'db_session' raised RuntimeError: connection failed"
    lines = [
        _jsonl_line(
            nodeid="tests/test_a.py::test_one",
            when="setup",
            outcome="error",
            longrepr=shared_longrepr,
        ),
        _jsonl_line(
            nodeid="tests/test_a.py::test_two",
            when="setup",
            outcome="error",
            longrepr=shared_longrepr,
        ),
        _jsonl_line(
            nodeid="tests/test_a.py::test_three",
            when="setup",
            outcome="error",
            longrepr=shared_longrepr,
        ),
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    assert result["counts"]["error"] == 3
    error_entries = [t for t in result["tests"] if t["outcome"] == "error"]
    assert len(error_entries) == 1  # deduplicated to single detail entry


def test_identify_crash_culprit_with_completed_and_partial(tmp_path: Path) -> None:
    """Multiple completed tests + one partial = correct culprit + completed list."""
    lines = [
        # test_a: fully completed (setup + call + teardown)
        _jsonl_line(nodeid="t.py::test_a", when="setup"),
        _jsonl_line(nodeid="t.py::test_a", when="call"),
        _jsonl_line(nodeid="t.py::test_a", when="teardown"),
        # test_b: fully completed
        _jsonl_line(nodeid="t.py::test_b", when="setup"),
        _jsonl_line(nodeid="t.py::test_b", when="call"),
        _jsonl_line(nodeid="t.py::test_b", when="teardown"),
        # test_c: fully completed
        _jsonl_line(nodeid="t.py::test_c", when="setup"),
        _jsonl_line(nodeid="t.py::test_c", when="call"),
        _jsonl_line(nodeid="t.py::test_c", when="teardown"),
        # test_d: setup + call but no teardown (crash during teardown)
        _jsonl_line(nodeid="t.py::test_d", when="setup"),
        _jsonl_line(nodeid="t.py::test_d", when="call"),
        # test_e: only setup (never reached call)
        _jsonl_line(nodeid="t.py::test_e", when="setup"),
    ]
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("\n".join(lines) + "\n")

    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit == "t.py::test_d"
    assert sorted(completed) == ["t.py::test_a", "t.py::test_b", "t.py::test_c"]


def test_postprocess_jsonl_to_unified_groups_by_file(tmp_path: Path) -> None:
    """JSONL from --isolation none is grouped by file into unified format."""
    lines = [
        # a.py::test_1 — passed
        _jsonl_line(nodeid="a.py::test_1", when="setup"),
        _jsonl_line(nodeid="a.py::test_1", when="call", outcome="passed"),
        _jsonl_line(nodeid="a.py::test_1", when="teardown"),
        # a.py::test_2 — xfailed
        _jsonl_line(nodeid="a.py::test_2", when="setup"),
        _jsonl_line(
            nodeid="a.py::test_2",
            when="call",
            outcome="skipped",
            wasxfail="known issue",
            longrepr="known issue",
        ),
        _jsonl_line(nodeid="a.py::test_2", when="teardown"),
        # b.py::test_3 — failed
        _jsonl_line(nodeid="b.py::test_3", when="setup"),
        _jsonl_line(
            nodeid="b.py::test_3",
            when="call",
            outcome="failed",
            longrepr="AssertionError: expected 1 got 2",
        ),
        _jsonl_line(nodeid="b.py::test_3", when="teardown"),
    ]
    jsonl = tmp_path / "input.jsonl"
    jsonl.write_text("\n".join(lines) + "\n")
    output = tmp_path / "results.json"

    postprocess_jsonl_to_unified(jsonl, output)

    report = json.loads(output.read_text())
    assert report["tool"] == "pkcs11-check"
    assert report["kind"] == "test-run"
    assert len(report["units"]) == 2

    units_by_target = {u["target"]: u for u in report["units"]}
    assert "a.py" in units_by_target
    assert "b.py" in units_by_target

    # a.py: 1 passed + 1 xfailed
    a_counts = units_by_target["a.py"]["counts"]
    assert a_counts["passed"] == 1
    assert a_counts["xfailed"] == 1

    # b.py: 1 failed
    b_counts = units_by_target["b.py"]["counts"]
    assert b_counts["failed"] == 1

    # xfailed test should have wasxfail field
    a_tests = units_by_target["a.py"].get("tests", [])
    xfailed_entries = [t for t in a_tests if t.get("outcome") == "xfailed"]
    assert len(xfailed_entries) == 1
    assert "wasxfail" in xfailed_entries[0]


def test_read_jsonl_results_strict_xfail_stays_failed(tmp_path: Path) -> None:
    """Strict xfail: outcome=failed + wasxfail -> still failed (not xpassed)."""
    lines = [
        _jsonl_line(
            nodeid="t.py::test_strict",
            when="call",
            outcome="failed",
            wasxfail="strict: should not pass yet",
            longrepr="strict xfail unexpectedly passed",
        ),
    ]
    p = tmp_path / "report.jsonl"
    p.write_text("\n".join(lines) + "\n")

    result = _read_jsonl_results(p)
    assert result is not None
    assert result["counts"]["failed"] == 1
    assert result["counts"].get("xpassed", 0) == 0

    failed_entries = [t for t in result["tests"] if t["outcome"] == "failed"]
    assert len(failed_entries) == 1
    assert failed_entries[0]["nodeid"] == "t.py::test_strict"


def test_write_report_jsonl_streaming_concat(tmp_path: Path) -> None:
    """write_report_jsonl concatenates multiple JSONL files atomically."""
    src_a = tmp_path / "a.jsonl"
    src_b = tmp_path / "b.jsonl"
    src_c = tmp_path / "c.jsonl"
    src_a.write_text('{"line": "a1"}\n{"line": "a2"}\n')
    src_b.write_text('{"line": "b1"}\n')
    src_c.write_text('{"line": "c1"}\n{"line": "c2"}\n{"line": "c3"}\n')

    output = tmp_path / "out" / "combined.jsonl"
    write_report_jsonl([src_a, src_b, src_c], output)

    assert output.exists()
    lines = output.read_text().strip().split("\n")
    assert len(lines) == 6
    # Verify order: a lines, then b, then c
    assert json.loads(lines[0])["line"] == "a1"
    assert json.loads(lines[1])["line"] == "a2"
    assert json.loads(lines[2])["line"] == "b1"
    assert json.loads(lines[3])["line"] == "c1"
    assert json.loads(lines[4])["line"] == "c2"
    assert json.loads(lines[5])["line"] == "c3"

    # Source files should be deleted
    assert not src_a.exists()
    assert not src_b.exists()
    assert not src_c.exists()


def test_collection_args_strips_report_log(tmp_path: Path) -> None:
    """_collection_args strips --report-log and --report-log=path from args."""
    args = [
        "--p11-module",
        "/usr/lib/softhsm2.so",
        "--report-log=/tmp/bar.jsonl",
        "-v",
        "--tb=short",
        "--p11-pin",
        "1234",
    ]
    result = _collection_args(args)

    # --report-log=path (equals form) stripped
    assert "--report-log=/tmp/bar.jsonl" not in result

    # -v and --tb=short also stripped by _collection_args
    assert "-v" not in result
    assert "--tb=short" not in result

    # Real args are preserved
    assert "--p11-module" in result
    assert "/usr/lib/softhsm2.so" in result
    assert "--p11-pin" in result
    assert "1234" in result

    # Always ends with --collect-only -qq
    assert result[-2:] == ["--collect-only", "-qq"]


def test_unit_timeout_seconds_with_num_tests() -> None:
    from pkcs11_check.core.file_runner import _unit_timeout_seconds

    # Per-test granularity ignores num_tests
    assert _unit_timeout_seconds(120, "test", num_tests=100) == 180

    # Per-file with num_tests uses scaled formula
    assert _unit_timeout_seconds(120, "file", num_tests=100) == 560  # 100*5+60
    assert _unit_timeout_seconds(120, "file", num_tests=10) == 300   # floor
    assert _unit_timeout_seconds(120, "file", num_tests=30000) == 14400  # cap

    # Per-file without num_tests uses legacy formula
    assert _unit_timeout_seconds(120, "file") == 3600  # 120*30
    assert _unit_timeout_seconds(120, "file", num_tests=0) == 3600  # same as no num_tests
