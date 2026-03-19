"""Tests for per-file isolated pytest running."""

from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from pkcs11_check.core.file_runner import (
    BackendIsolationPolicy,
    FileRunResult,
    FileRunState,
    IsolatedReportConfig,
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
    run_isolated_pytest_units,
    save_isolation_policy,
    save_run_state,
    units_remaining_for_resume,
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
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")

    assert file_isolation_mode(target) == "file"


def test_file_isolation_mode_promotes_subprocess_per_test(tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("import pytest\npytestmark = [pytest.mark.subprocess_per_test]\n")

    assert file_isolation_mode(target) == "test"


def test_file_forces_file_isolation_for_subprocess_marker(tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("import pytest\npytestmark = [pytest.mark.subprocess]\n")

    assert file_forces_file_isolation(target) is True


def test_discover_auto_isolation_units_keeps_regular_files(tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")

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
    target.write_text("import pytest\npytestmark = [pytest.mark.subprocess_per_test]\n")

    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [f"{target}::test_one", f"{target}::test_two"],  # type: ignore[arg-type]
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
        "pkcs11_check.core.file_runner.collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [f"{target}::test_one"],  # type: ignore[arg-type]
    )

    units = discover_auto_isolation_units(
        [str(target)],
        tmp_path / "unused",
        pytest_args=["--p11-module", str(module)],
        policy_file=policy_file,
    )

    assert units == [f"{target}::test_one"]


def test_discover_auto_isolation_units_collapses_nodeid_for_subprocess_file(tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("import pytest\npytestmark = [pytest.mark.subprocess]\n")

    units = discover_auto_isolation_units(
        [f"{target}::test_case"],
        tmp_path / "unused",
        pytest_args=["--p11-module", "/tmp/module.so"],
    )

    assert units == [str(target)]


def test_state_round_trip(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state = FileRunState(
        units=["test_a.py", "test_b.py"],
        fingerprint="abc123",
        results=[FileRunResult("test_a.py", "passed", 0, 1.2)],
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del check, env, timeout
        calls.append(cmd)
        return SimpleNamespace(returncode=next(results))

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del cmd, check, env, timeout
        return SimpleNamespace(returncode=-11)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]

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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del check, env, timeout
        unit = cmd[3]
        calls.append(unit)
        return SimpleNamespace(returncode=-11 if unit == str(target) else 0)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del check, env, timeout
        unit = cmd[3]
        calls.append(unit)
        if unit == str(target):
            return SimpleNamespace(returncode=-11)
        if unit in {f"{target}::test_one", f"{target}::test_two"}:
            return SimpleNamespace(returncode=-11)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del check, env, timeout
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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


def test_run_isolated_pytest_units_resume_replaces_failed_result(
    monkeypatch: object, tmp_path: Path
) -> None:
    def fake_run(
        cmd: list[str],
        *,
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del cmd, check, env, timeout
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del cmd, check, env
        seen["timeout"] = timeout
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del cmd, check, env, timeout
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
    assert '"kind": "isolated-run"' in payload
    assert '"status": "passed"' in payload


def test_run_isolated_pytest_units_writes_junit_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    results = iter([1, -11])

    def fake_run(
        cmd: list[str],
        *,
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del cmd, check, env, timeout
        return SimpleNamespace(returncode=next(results))

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
        check: bool,
        env: dict[str, str],
        timeout: int,
    ) -> SimpleNamespace:
        del cmd, check, env, timeout
        return SimpleNamespace(returncode=next(results))

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
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
