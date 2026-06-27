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
    UNIT_STATUS_PRIORITY,
    BackendIsolationPolicy,
    FileRunResult,
    FileRunState,
    IsolatedReportConfig,
    _absolute_nodeid,
    _build_isolated_json_payload,
    _collection_args,
    _identify_crash_culprit,
    _load_available_mechanisms,
    _load_cached_report_records_by_unit,
    _read_jsonl_results,
    _write_unit_report_record_cache,
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
    validate_subprocess_per_test_expansion,
    write_isolated_json_report,
    write_report_jsonl,
)


def test_unit_status_priority_is_the_overall_status_set() -> None:
    assert UNIT_STATUS_PRIORITY == (
        "timeout",
        "crashed",
        "failed",
        "crash_limited",
        "passed",
        "empty",
        "escalated",
    )


def test_status_from_returncode_classifies_timeout_sentinel() -> None:
    assert (
        file_runner_mod._status_from_returncode(file_runner_mod._TIMEOUT_RETURN_CODE) == "timeout"
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


def test_absolute_nodeid_pins_path_part_to_file_key() -> None:
    # rootdir-relative / slash-less path part is replaced by the absolute file key;
    # the test part (after ::) is preserved verbatim.
    assert (
        _absolute_nodeid("/abs/test_x.py", "rel/test_x.py::TestC::test_m")
        == "/abs/test_x.py::TestC::test_m"
    )
    assert _absolute_nodeid("/abs/test_x.py", "home/u/test_x.py") == "/abs/test_x.py"


def test_discover_auto_isolation_units_pins_absolute_nodeid_for_rootdir_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Regression: when an installed package is run with a stray absolute path on
    # the pytest command line, pytest's rootdir can settle on '/', so collected
    # nodeids come out slash-less (e.g. 'home/user/.../test_demo.py::test_one')
    # while file_path stays absolute. The per-test expansion must pin the unit to
    # the absolute file path so it is runnable and passes the expansion guard
    # (previously this raised "subprocess_per_test file was not expanded").
    target = tmp_path / "test_demo.py"
    target.write_text("def test_one():\n    assert True\n")
    rootdir_relative_nodeid = f"{str(target).lstrip('/')}::test_one"
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.collect_pytest_item_metadata",
        lambda targets, pytest_args, *, env=None: [  # type: ignore[arg-type]
            CollectedPytestItem(
                nodeid=rootdir_relative_nodeid,
                file_path=str(target),
                markers=["subprocess_per_test"],
            ),
        ],
    )

    # Must not raise (validate runs inside) and must pin to the absolute path.
    units = discover_auto_isolation_units(
        [str(target)],
        tmp_path / "unused",
        pytest_args=["--p11-module", "/tmp/module.so", "--p11-manifest", "/tmp/m.json"],
    )

    assert units == [f"{normalize_policy_file_key(str(target))}::test_one"]


def test_validate_subprocess_per_test_expansion_rejects_file_unit(tmp_path: Path) -> None:
    target = tmp_path / "test_marked.py"
    target.write_text("def test_one():\n    assert True\n")
    collected = [
        CollectedPytestItem(
            nodeid=f"{target}::test_one",
            file_path=str(target),
            markers=["subprocess_per_test"],
        )
    ]

    with pytest.raises(ValueError, match="subprocess_per_test file was not expanded"):
        validate_subprocess_per_test_expansion([str(target)], collected)


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
    # The durable resume state is units + fingerprint + results. Report records
    # are NOT round-tripped through state.json (they are persisted as per-unit
    # shards); see test_save_run_state_does_not_embed_report_records.
    state = FileRunState(
        units=["test_a.py", "test_b.py"],
        fingerprint="abc123",
        results=[FileRunResult("test_a.py", "passed", 0, 1.2)],
    )

    save_run_state(state_file, state)
    loaded = load_run_state(state_file)

    assert loaded == state


def test_save_run_state_does_not_embed_report_records(tmp_path: Path) -> None:
    """Report records live in per-unit shards, never inline in state.json.

    Embedding ``report_records_by_unit`` in state.json previously made the
    per-unit ``save_run_state`` call O(n^2): the payload grew to hundreds of MB
    and was re-serialized once per completed unit (~14 min on a full bouncyhsm
    round) for data the end-of-run merge always reloads from the shards. Guard
    against regressing back to persisting the records inline.
    """
    state_file = tmp_path / "state.json"
    # A large in-memory record set that would balloon state.json if persisted.
    big_records = {
        f"unit_{i}.py": [
            {
                "$report_type": "TestReport",
                "nodeid": f"unit_{i}.py::t{j}",
                "when": "call",
                "outcome": "passed",
                "duration": 0.01,
            }
            for j in range(200)
        ]
        for i in range(50)
    }
    state = FileRunState(
        units=sorted(big_records),
        fingerprint="abc123",
        results=[FileRunResult(unit, "passed", 0, 0.1) for unit in sorted(big_records)],
        report_records_by_unit=big_records,
    )

    save_run_state(state_file, state)

    raw = json.loads(state_file.read_text())
    assert "report_records_by_unit" not in raw
    # The persisted file stays tiny even though the in-memory records are large.
    assert state_file.stat().st_size < 200_000

    # Durable resume fields still round-trip; records load back empty.
    loaded = load_run_state(state_file)
    assert loaded is not None
    assert loaded.units == state.units
    assert loaded.fingerprint == state.fingerprint
    assert loaded.results == state.results
    assert loaded.report_records_by_unit == {}


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
        {"P11TEST_TOKEN_DIR": "/run/tokens/a"},
    )
    second = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module)],
        {"P11TEST_TOKEN_DIR": "/run/tokens/b"},
    )

    assert first != second


def test_build_state_fingerprint_ignores_unregistered_provider_env(tmp_path: Path) -> None:
    """A provider env var outside the framework namespaces is ignored by default."""
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")
    module = tmp_path / "module.so"
    module.write_text("v1")

    first = build_state_fingerprint(
        [str(unit)], ["--p11-module", str(module)], {"MYHSM_CONF": "/etc/a.conf"}
    )
    second = build_state_fingerprint(
        [str(unit)], ["--p11-module", str(module)], {"MYHSM_CONF": "/etc/b.conf"}
    )

    assert first == second


def test_build_state_fingerprint_honors_extension_env_prefixes(tmp_path: Path) -> None:
    """Registering a provider prefix via PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES
    makes that provider's configuration part of the fingerprint."""
    unit = tmp_path / "test_demo.py"
    unit.write_text("def test_demo():\n    assert True\n")
    module = tmp_path / "module.so"
    module.write_text("v1")

    first = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module)],
        {"PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES": "MYHSM_", "MYHSM_CONF": "/etc/a.conf"},
    )
    second = build_state_fingerprint(
        [str(unit)],
        ["--p11-module", str(module)],
        {"PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES": "MYHSM_", "MYHSM_CONF": "/etc/b.conf"},
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


def test_run_isolated_pytest_units_resume_json_streams_complete_cache(
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

    def load_all_forbidden(
        _state_file: Path, _units: list[str]
    ) -> dict[str, list[dict[str, object]]]:
        pytest.fail("complete resume finalization must stream cached report-record shards")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        file_runner_mod,
        "_load_cached_report_records_by_unit",
        load_all_forbidden,
    )
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=build_state_fingerprint(units, pytest_args),
            results=[FileRunResult("test_a.py", "passed", 0, 0.1)],
        ),
    )
    _write_unit_report_record_cache(
        state_file,
        "test_a.py",
        [
            {
                "$report_type": "TestReport",
                "nodeid": "test_a.py::test_case",
                "when": "call",
                "outcome": "passed",
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
            },
        ],
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
    assert "test_a.py::test_case" in report_jsonl_path.read_text()
    report = json.loads(results_path.read_text())
    assert report["units"][0]["counts"]["passed"] == 1
    coverage = json.loads((tmp_path / "coverage.json").read_text())
    assert coverage["mechanism_coverage"]["invoked_names"] == ["CKM_AES_CBC"]


def test_run_isolated_pytest_units_resume_json_streams_complete_existing_report(
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

    def extract_all_forbidden(
        _jsonl_path: Path, *, candidate_targets: set[str]
    ) -> dict[str, list[dict[str, object]]]:
        del candidate_targets
        pytest.fail("complete resume fallback must stream existing report records")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        file_runner_mod,
        "_extract_unit_report_records_from_jsonl",
        extract_all_forbidden,
    )
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


def test_run_isolated_pytest_units_resume_json_streams_partial_existing_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(
                    "\n".join(
                        [
                            _jsonl_line(
                                nodeid="test_b.py::test_new",
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

    def extract_all_forbidden(
        _jsonl_path: Path, *, candidate_targets: set[str]
    ) -> dict[str, list[dict[str, object]]]:
        del candidate_targets
        pytest.fail("partial resume fallback must stream existing report records")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        file_runner_mod,
        "_extract_unit_report_records_from_jsonl",
        extract_all_forbidden,
    )
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
                _jsonl_line(nodeid="test_a.py::test_old", when="call", outcome="passed"),
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
                _jsonl_line(nodeid="test_b.py::test_stale", when="call", outcome="failed"),
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
    merged_report = report_jsonl_path.read_text()
    assert "test_a.py::test_old" in merged_report
    assert "test_b.py::test_new" in merged_report
    assert "test_b.py::test_stale" not in merged_report
    results = json.loads(results_path.read_text())
    assert [unit["target"] for unit in results["units"]] == units
    assert [unit["counts"]["passed"] for unit in results["units"]] == [1, 1]
    coverage = json.loads((tmp_path / "coverage.json").read_text())
    assert coverage["mechanism_coverage"]["invoked_names"] == ["CKM_AES_CBC", "CKM_AES_GCM"]


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
        ),
    )
    # A completed unit persists its report records as a per-unit shard (this is
    # what the real runner writes on completion); the merge reloads them from
    # there on resume. state.json no longer carries an inline copy.
    _write_unit_report_record_cache(
        state_file,
        "test_a.py",
        [
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


def test_write_unit_report_record_cache_from_jsonl_paths_streams_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_file = tmp_path / "state.json"
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_one",
                        "when": "call",
                        "outcome": "passed",
                    }
                ),
                "not json",
            ]
        )
        + "\n"
    )
    second.write_text(
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
        )
        + "\n"
    )

    def load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("cache writes from JSONL paths must stream records")

    monkeypatch.setattr(file_runner_mod, "_load_report_log_records", load_all_forbidden)

    file_runner_mod._write_unit_report_record_cache_from_jsonl_paths(
        state_file,
        "test_a.py",
        [first, tmp_path / "missing.jsonl", second],
    )

    cache_text = file_runner_mod._report_record_cache_path(state_file, "test_a.py").read_text()
    assert [json.loads(line) for line in cache_text.splitlines()] == [
        {
            "$report_type": "TestReport",
            "nodeid": "test_a.py::test_one",
            "when": "call",
            "outcome": "passed",
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
    ]


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
    # Records are persisted as per-unit shards, not inline in state.json.
    records_by_unit = _load_cached_report_records_by_unit(state_file, units)
    assert list(records_by_unit) == ["test_a.py"]
    assert [record["$report_type"] for record in records_by_unit["test_a.py"]] == [
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
    # Partial records persist as a per-unit shard, not inline in state.json.
    records_by_unit = _load_cached_report_records_by_unit(state_file, units)
    assert list(records_by_unit) == ["test_a.py"]
    assert [record["$report_type"] for record in records_by_unit["test_a.py"]] == [
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

        if target == "test_a.py" and (env is None or "PKCS11_CHECK_DESELECT_FILE" not in env):
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
    assert exit_code == 1
    assert saved is not None
    report = json.loads(results_path.read_text())
    assert report["summary"]["crashed"] == 1
    assert report["units"][0]["status"] == "crashed"
    assert calls[0][0] == "test_a.py"
    assert calls[1][0] == "test_a.py::test_culprit"
    assert calls[2][0] == "test_a.py"
    # Aggregated records persist as a per-unit shard, not inline in state.json.
    records_by_unit = _load_cached_report_records_by_unit(state_file, units)
    assert [record.get("nodeid") for record in records_by_unit["test_a.py"]] == [
        "test_a.py::test_done",
        "test_a.py::test_done",
        "test_a.py::test_done",
        "test_a.py::test_culprit",
        None,
        "test_a.py::test_remaining",
        None,
    ]
    assert [
        record.get("$report_type", "TestReport") for record in records_by_unit["test_a.py"]
    ] == [
        "TestReport",
        "TestReport",
        "TestReport",
        "TestReport",
        "SelectionReport",
        "TestReport",
        "CoverageReport",
    ]


def test_run_isolated_pytest_units_caps_iterative_deselect_crashes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_a.py"
    target.write_text("def test_case():\n    assert True\n")
    after = tmp_path / "test_after.py"
    after.write_text("def test_after():\n    assert True\n")
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    calls: list[str] = []
    file_runs = 0

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        nonlocal file_runs
        unit = cmd[3]
        calls.append(unit)
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break

        if unit == str(target):
            assert report_log_path is not None
            file_runs += 1
            if file_runs <= 2:
                report_log_path.write_text(
                    _jsonl_line(nodeid=f"{target}::test_crash_{file_runs}", when="setup") + "\n"
                )
                return (-11, "", "")
            report_log_path.write_text(
                _jsonl_line(nodeid=f"{target}::test_remaining", when="call") + "\n"
            )
            return (0, "", "")

        if unit in {f"{target}::test_crash_1", f"{target}::test_crash_2"}:
            return (-11, "", "segmentation fault")

        if unit == str(after):
            return (0, "", "")

        raise AssertionError(f"unexpected subprocess invocation: {cmd!r}")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        [str(target), str(after)],
        ["--p11-module", str(module)],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig("json", results_path, jsonl_path=tmp_path / "run.jsonl"),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
        max_crashes_per_file=2,
    )

    assert exit_code == 1
    assert calls == [
        str(target),
        f"{target}::test_crash_1",
        str(target),
        f"{target}::test_crash_2",
        str(after),
    ]

    saved = load_run_state(state_file)
    assert saved is not None
    assert [(result.target, result.status) for result in saved.results] == [
        (str(target), "crashed"),
        (str(after), "passed"),
    ]

    report = json.loads(results_path.read_text())
    assert report["units"][0]["target"] == str(target)
    assert report["units"][0]["status"] == "crashed"
    assert report["units"][0]["counts"]["crashed"] == 2
    assert report["summary"]["crashed"] == 2


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

    assert exit_code == 1
    assert calls[0] == ("test_a.py", "test_a.py::baseline_disabled\n")
    assert calls[2][0] == "test_a.py"
    assert calls[2][1] == (
        "test_a.py::baseline_disabled\ntest_a.py::test_culprit\ntest_a.py::test_done\n"
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
    assert unit["status"] == "crashed"
    assert unit["counts"]["failed"] == 1
    assert unit["counts"]["crashed"] == 1
    assert unit["counts"]["error"] == 0
    by_nodeid = {entry["nodeid"]: entry for entry in unit["tests"]}
    assert by_nodeid["test_a.py::test_culprit"]["outcome"] == "crashed"
    assert by_nodeid["test_a.py::test_other"]["outcome"] == "failed"
    assert report["summary"]["failed"] == 1
    assert report["summary"]["crashed"] == 1
    assert report["summary"]["error"] == 0


def test_run_isolated_pytest_units_records_crash_confirmation_timeout(
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
        del timeout
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
                return (-11, "fatal python error", "")

            assert env is not None
            assert "PKCS11_CHECK_DESELECT_FILE" in env
            report_log_path.write_text(
                _jsonl_line(nodeid="test_a.py::test_remaining", when="call", outcome="passed")
                + "\n"
            )
            return (0, "", "")

        if target == "test_a.py::test_culprit":
            raise subprocess.TimeoutExpired(cmd, timeout=12)

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
    assert unit["status"] == "timeout"
    assert unit["counts"]["timeout"] == 1
    assert report["summary"]["timeout"] == 1
    by_nodeid = {entry["nodeid"]: entry for entry in unit["tests"]}
    culprit = by_nodeid["test_a.py::test_culprit"]
    assert culprit["outcome"] == "timeout"
    assert "confirmation timed out" in culprit["longrepr"]


def test_run_isolated_pytest_units_preserves_file_crash_after_successful_retry(
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
                return (-11, "fatal python error", "")

            report_log_path.write_text(
                "\n".join(
                    [
                        _jsonl_line(nodeid="test_a.py::test_other", when="setup", outcome="passed"),
                        _jsonl_line(nodeid="test_a.py::test_other", when="call", outcome="passed"),
                        _jsonl_line(
                            nodeid="test_a.py::test_other", when="teardown", outcome="passed"
                        ),
                    ]
                )
                + "\n"
            )
            return (0, "", "")

        if target == "test_a.py::test_culprit":
            return (0, "", "")

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
    assert unit["status"] == "crashed"
    assert unit["counts"]["crashed"] == 1
    assert report["summary"]["crashed"] == 1
    by_nodeid = {entry["nodeid"]: entry for entry in unit["tests"]}
    assert by_nodeid["test_a.py::test_culprit"]["outcome"] == "crashed"
    assert "passed in isolation" in by_nodeid["test_a.py::test_culprit"]["longrepr"]


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


def test_run_isolated_pytest_units_preserves_compliance_notes(
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
                    json.dumps(
                        {
                            "nodeid": "test_a.py::test_ok",
                            "when": "call",
                            "outcome": "passed",
                            "duration": 0.1,
                            "user_properties": [
                                [
                                    "pkcs11_compliance_notes",
                                    [
                                        {
                                            "description": "validation policy accepted",
                                            "level": "standard",
                                            "reference": "PKCS#11 v3.2",
                                            "test_id": "test_ok",
                                            "nodeid": "test_a.py::test_ok",
                                        }
                                    ],
                                ]
                            ],
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
    assert seen_cmds
    report = json.loads(report_path.read_text())
    assert report["units"][0]["compliance_notes"] == [
        {
            "description": "validation policy accepted",
            "level": "standard",
            "reference": "PKCS#11 v3.2",
            "test_id": "test_ok",
            "nodeid": "test_a.py::test_ok",
        }
    ]


def test_run_isolated_pytest_units_preserves_real_subprocess_compliance_notes(
    tmp_path: Path,
) -> None:
    testcases_dir = tmp_path / "src" / "pkcs11_check" / "testcases"
    testcases_dir.mkdir(parents=True)
    target = testcases_dir / "test_note.py"
    target.write_text(
        "\n".join(
            [
                "from pkcs11_check.compliance import ComplianceLevel, note",
                "",
                "def test_emits_note():",
                "    note(",
                "        'validation policy accepted',",
                "        ComplianceLevel.STANDARD,",
                "        reference='PKCS#11 v3.2',",
                "        test_id='test_emits_note',",
                "    )",
                "",
            ]
        )
    )
    report_path = tmp_path / "results.json"
    report_jsonl = tmp_path / "report.jsonl"

    exit_code = run_isolated_pytest_units(
        [str(target)],
        ["--p11-module", "/tmp/mock-module.so"],
        timeout=30,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path, jsonl_path=report_jsonl),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text())
    expected_fields = {
        "description": "validation policy accepted",
        "level": "standard",
        "reference": "PKCS#11 v3.2",
        "test_id": "test_emits_note",
    }
    assert len(report["units"][0]["compliance_notes"]) == 1
    unit_note = report["units"][0]["compliance_notes"][0]
    for key, value in expected_fields.items():
        assert unit_note[key] == value
    assert unit_note["nodeid"].endswith("src/pkcs11_check/testcases/test_note.py::test_emits_note")
    assert report_jsonl.exists()
    report_records = [json.loads(line) for line in report_jsonl.read_text().splitlines()]
    call_report = next(record for record in report_records if record.get("when") == "call")
    assert ["pkcs11_compliance_notes", [unit_note]] in call_report["user_properties"]


def test_run_isolated_pytest_units_does_not_retain_cached_report_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Large file-level report logs are cached on disk, not retained in state memory."""

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        unit = next((arg for arg in cmd if arg.startswith("test_")), "test_unknown.py")
        for index, arg in enumerate(cmd):
            if arg == "--report-log" and index + 1 < len(cmd):
                jsonl_path = Path(cmd[index + 1])
                jsonl_path.write_text(
                    "\n".join(
                        json.dumps(
                            {
                                "$report_type": "TestReport",
                                "nodeid": f"{unit}::test_{case}",
                                "when": "call",
                                "outcome": "passed",
                                "duration": 0.01,
                            }
                        )
                        for case in range(10)
                    )
                    + "\n"
                )
                break
        return (0, "", "")

    seen_record_sizes: list[int] = []
    real_save_run_state = file_runner_mod.save_run_state

    def observing_save_run_state(path: Path, state: FileRunState) -> None:
        seen_record_sizes.append(
            sum(len(records) for records in state.report_records_by_unit.values())
        )
        real_save_run_state(path, state)

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(file_runner_mod, "save_run_state", observing_save_run_state)

    report_path = tmp_path / "results.json"
    state_file = tmp_path / "state.json"

    exit_code = run_isolated_pytest_units(
        ["test_a.py", "test_b.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
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
    assert seen_record_sizes
    assert max(seen_record_sizes) == 0
    report = json.loads(report_path.read_text())
    assert report["summary"]["passed"] == 20
    assert len(_load_cached_report_records_by_unit(state_file, ["test_a.py", "test_b.py"])) == 2


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
    assert quality_report["selection_findings"][0]["selected_but_not_invoked"] == ["CKM_AES_GCM"]


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


def test_write_isolated_json_report_crash_status_wins_over_failed_count(
    tmp_path: Path,
) -> None:
    state = FileRunState(
        units=["test_a.py::test_bad", "test_a.py::test_crash"],
        fingerprint="abc123",
        results=[
            FileRunResult("test_a.py::test_bad", "failed", 1, 0.2),
            FileRunResult(
                "test_a.py::test_crash",
                "crashed",
                -11,
                0.4,
                stderr="segmentation fault",
            ),
        ],
    )
    per_unit_details = {
        "test_a.py::test_bad": {
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
                    "nodeid": "test_a.py::test_bad",
                    "outcome": "failed",
                    "duration": 0.2,
                    "longrepr": "assert False",
                }
            ],
        }
    }
    report_path = tmp_path / "results.json"

    write_isolated_json_report(report_path, state, per_unit_details=per_unit_details)

    report = json.loads(report_path.read_text())
    assert report["summary"]["failed"] == 1
    assert report["summary"]["crashed"] == 1
    unit = report["units"][0]
    assert unit["target"] == "test_a.py"
    assert unit["status"] == "crashed"
    assert unit["counts"]["failed"] == 1
    assert unit["counts"]["crashed"] == 1
    outcomes = {record["nodeid"]: record["outcome"] for record in unit["tests"]}
    assert outcomes == {
        "test_a.py::test_bad": "failed",
        "test_a.py::test_crash": "crashed",
    }


@pytest.mark.parametrize(
    ("special_outcome", "expected_status"),
    [("crashed", "crashed"), ("timeout", "timeout")],
)
def test_write_isolated_json_report_special_detail_status_wins_over_failed_file_result(
    tmp_path: Path,
    special_outcome: str,
    expected_status: str,
) -> None:
    state = FileRunState(
        units=["test_a.py"],
        fingerprint="abc123",
        results=[FileRunResult("test_a.py", "failed", 1, 0.2)],
    )
    counts = {
        "passed": 0,
        "failed": 1,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
    }
    counts[special_outcome] = 1
    per_unit_details = {
        "test_a.py": {
            "counts": counts,
            "tests": [
                {
                    "nodeid": "test_a.py::test_bad",
                    "outcome": "failed",
                    "duration": 0.1,
                    "longrepr": "assert False",
                },
                {
                    "nodeid": f"test_a.py::test_{special_outcome}",
                    "outcome": special_outcome,
                    "duration": 0.1,
                    "longrepr": special_outcome,
                },
            ],
        }
    }
    report_path = tmp_path / "results.json"

    write_isolated_json_report(report_path, state, per_unit_details=per_unit_details)

    report = json.loads(report_path.read_text())
    unit = report["units"][0]
    assert unit["status"] == expected_status
    assert unit["counts"]["failed"] == 1
    assert unit["counts"][special_outcome] == 1
    assert report["summary"]["failed"] == 1
    assert report["summary"][special_outcome] == 1


def test_crash_limited_results_surface_as_counted_outcome() -> None:
    state = FileRunState(
        units=["t.py"],
        fingerprint="abc123",
        results=[
            FileRunResult(target="t.py::test_a", status="crashed", returncode=-11, duration_s=0.1),
            FileRunResult(
                target="t.py::test_b", status="crash_limited", returncode=0, duration_s=0.0
            ),
            FileRunResult(
                target="t.py::test_c", status="crash_limited", returncode=0, duration_s=0.0
            ),
        ],
    )
    payload = _build_isolated_json_payload(state)
    s = payload["summary"]
    assert s["crash_limited"] == 2
    assert s["crashed"] == 1
    assert s["total"] == s["crashed"] + s["crash_limited"]
    unit = payload["units"][0]
    outcomes = sorted(t["outcome"] for t in unit["tests"])
    assert outcomes == ["crash_limited", "crash_limited", "crashed"]


def test_crash_limited_default_longrepr_when_no_output() -> None:
    state = FileRunState(
        units=["t.py"],
        fingerprint="abc123",
        results=[
            FileRunResult(
                target="t.py::test_abandoned", status="crash_limited", returncode=0, duration_s=0.0
            ),
        ],
    )
    payload = _build_isolated_json_payload(state)
    unit = payload["units"][0]
    test_entry = unit["tests"][0]
    assert test_entry["outcome"] == "crash_limited"
    assert test_entry["longrepr"] == "abandoned: per-file crash limit reached"


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
    assert _unit_timeout_seconds(120, "file", num_tests=10) == 300  # floor
    assert _unit_timeout_seconds(120, "file", num_tests=30000) == 14400  # cap

    # Per-file without num_tests uses legacy formula
    assert _unit_timeout_seconds(120, "file") == 3600  # 120*30
    assert _unit_timeout_seconds(120, "file", num_tests=0) == 3600  # same as no num_tests


# ---------------------------------------------------------------------------
# Progressive timeout retry tests
# ---------------------------------------------------------------------------


def test_progressive_timeout_retry_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When a file times out, progressive retry deselects completed + culprit
    and retries.  If the retry succeeds the file is NOT escalated."""
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    calls: list[tuple[str, list[str]]] = []
    call_count = 0

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        nonlocal call_count
        call_count += 1
        target = cmd[3]
        calls.append((target, list(cmd)))
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break

        # First call: file run that times out with partial JSONL
        if target == "test_a.py" and (env is None or "PKCS11_CHECK_DESELECT_FILE" not in env):
            assert report_log_path is not None
            report_log_path.write_text(
                "\n".join(
                    [
                        # test_done1 completed
                        _jsonl_line(
                            nodeid="test_a.py::test_done1",
                            when="setup",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_done1",
                            when="call",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_done1",
                            when="teardown",
                            outcome="passed",
                        ),
                        # test_done2 completed
                        _jsonl_line(
                            nodeid="test_a.py::test_done2",
                            when="setup",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_done2",
                            when="call",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid="test_a.py::test_done2",
                            when="teardown",
                            outcome="passed",
                        ),
                        # test_slow started but did not finish (culprit)
                        _jsonl_line(
                            nodeid="test_a.py::test_slow",
                            when="setup",
                            outcome="passed",
                        ),
                    ]
                )
                + "\n"
            )
            raise subprocess.TimeoutExpired(cmd, timeout=12)

        # Second call: culprit confirmation (test_slow alone) - passes
        if target == "test_a.py::test_slow":
            return (0, "", "")

        # Third call: retry file with deselect - succeeds
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
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    saved = load_run_state(state_file)
    assert saved is not None
    # File was NOT escalated - progressive retry handled it
    assert call_count == 3
    assert calls[0][0] == "test_a.py"
    assert calls[1][0] == "test_a.py::test_slow"
    assert calls[2][0] == "test_a.py"
    # No per-test units should appear in the state (no escalation)
    assert all("::" not in u for u in saved.units)
    # The result should reflect successful retry, not escalation
    statuses = [r.status for r in saved.results]
    assert "escalated" not in statuses
    assert exit_code == 0 or exit_code == 1  # depends on timeout record


def test_progressive_timeout_retry_exhausted_escalates_remaining(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When progressive timeout retries are exhausted, fall back to escalation
    but only for tests NOT already completed."""
    module = tmp_path / "module.so"
    module.write_text("")
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case():\n    assert True\n")
    units = [str(target)]
    pytest_args = ["--p11-module", str(module)]
    state_file = tmp_path / "state.json"
    calls: list[tuple[str, list[str]]] = []
    timeout_count = 0

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        nonlocal timeout_count
        t = cmd[3]
        calls.append((t, list(cmd)))
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break

        # File-level calls always timeout, with one completed + one culprit each time
        if t == str(target) and "::" not in t:
            timeout_count += 1
            assert report_log_path is not None
            # Each iteration: test_doneN completed, test_slowN is culprit
            report_log_path.write_text(
                "\n".join(
                    [
                        _jsonl_line(
                            nodeid=f"{target}::test_done{timeout_count}",
                            when="setup",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid=f"{target}::test_done{timeout_count}",
                            when="call",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid=f"{target}::test_done{timeout_count}",
                            when="teardown",
                            outcome="passed",
                        ),
                        _jsonl_line(
                            nodeid=f"{target}::test_slow{timeout_count}",
                            when="setup",
                            outcome="passed",
                        ),
                    ]
                )
                + "\n"
            )
            raise subprocess.TimeoutExpired(cmd, timeout=12)

        # Culprit confirmations pass
        if "::" in t and "test_slow" in t:
            return (0, "", "")

        # Escalated per-test units pass
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        "pkcs11_check.core.file_runner.discover_pytest_units",
        lambda targets, default_root, *, granularity, pytest_args, env=None: (
            [  # type: ignore[arg-type]
                f"{target}::test_done1",
                f"{target}::test_done2",
                f"{target}::test_done3",
                f"{target}::test_slow1",
                f"{target}::test_slow2",
                f"{target}::test_slow3",
                f"{target}::test_remaining",
            ]
            if granularity == "test"
            else list(targets)
        ),
    )

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    saved = load_run_state(state_file)
    assert saved is not None
    assert exit_code == 1
    # File should be escalated
    file_results = [r for r in saved.results if r.target == str(target)]
    assert any(r.status == "escalated" for r in file_results)
    # Escalated units should NOT include completed tests (test_done1..3)
    # or confirmed culprits (test_slow1..3)
    escalated_targets = [u for u in saved.units if "::" in u]
    completed_and_culprits = {
        f"{target}::test_done1",
        f"{target}::test_done2",
        f"{target}::test_done3",
        f"{target}::test_slow1",
        f"{target}::test_slow2",
        f"{target}::test_slow3",
    }
    for nodeid in escalated_targets:
        assert nodeid not in completed_and_culprits, (
            f"Escalated unit {nodeid} should have been excluded"
        )


def test_timeout_does_not_promote_to_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Timeouts should NOT promote the file in the isolation policy.
    Only crashes should trigger policy promotion."""
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    policy_file = tmp_path / "policy.json"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        report_log_path: Path | None = None
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                report_log_path = Path(cmd[i + 1])
                break
        if report_log_path is not None:
            report_log_path.write_text("")
        raise subprocess.TimeoutExpired(cmd, timeout=12)

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=policy_file,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 1
    # Policy file should either not exist or have no promoted files.
    # _promote_crashing_unit normalises the key to an absolute path, so
    # check that NO policy has any promoted files at all.
    policies = load_isolation_policy(policy_file)
    for _fp, policy in policies.items():
        assert len(policy.promoted_files) == 0, (
            f"Timeout should not promote anything to policy, "
            f"but found promoted_files={policy.promoted_files}"
        )


def test_file_skip_for_missing_mechanism(tmp_path: Path) -> None:
    """File with REQUIRED_MECHANISMS absent from manifest gets file-skipped."""
    from pkcs11_check.core.test_selection import extract_required_mechanisms

    test_file = tmp_path / "test_example.py"
    test_file.write_text(
        'import pytest\nREQUIRED_MECHANISMS = ["AES_CCM"]\ndef test_dummy(): pass\n'
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "status": "ok",
                "module_path": "/lib/mod.so",
                "requested_interface": "PKCS11",
                "interface_version": "2.40",
                "slot_index": 0,
                "slot_count": 1,
                "mechanisms": ["CKM_AES_CBC", "CKM_AES_ECB"],
            }
        )
    )

    mechs = _load_available_mechanisms(["--p11-manifest", str(manifest)])
    required = extract_required_mechanisms(str(test_file))
    assert required is not None
    assert required == ["AES_CCM"]
    assert mechs is not None
    missing = [m for m in required if m not in mechs]
    assert missing == ["AES_CCM"]


def test_file_skip_counts_collected_tests_as_skipped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "test_example.py"
    test_file.write_text(
        'REQUIRED_MECHANISMS = ["AES_CCM"]\ndef test_a(): pass\ndef test_b(): pass\n'
    )
    report_path = tmp_path / "results.json"

    monkeypatch.setattr(file_runner_mod, "_load_available_mechanisms", lambda _args: {"AES_CBC"})
    monkeypatch.setattr(
        file_runner_mod,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [
            f"{test_file}::test_a",
            f"{test_file}::test_b",
        ],
    )

    def _unexpected_run(*_args: Any, **_kwargs: Any) -> tuple[int, str, str]:
        pytest.fail("file-skipped unit must not invoke pytest")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", _unexpected_run)

    exit_code = run_isolated_pytest_units(
        [str(test_file)],
        ["--p11-manifest", str(tmp_path / "manifest.json")],
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
    report = json.loads(report_path.read_text())
    assert report["summary"]["skipped"] == 2
    assert report["summary"]["total"] == 2
    unit = report["units"][0]
    assert unit["file_skip"] is True
    assert unit["counts"]["skipped"] == 2
    assert unit["skip_reasons"] == {"AES_CCM not supported by module": 2}
    quality = json.loads((tmp_path / "quality.json").read_text())
    assert quality["file_skipped_units"] == [
        {"target": str(test_file), "reason": "AES_CCM not supported by module"}
    ]


def test_mechanism_coverage_buckets_required_mechanisms_for_unit_outcomes(
    tmp_path: Path,
) -> None:
    skipped_file = tmp_path / "test_skip.py"
    skipped_file.write_text('REQUIRED_MECHANISMS = ["AES_CCM"]\ndef test_x(): pass\n')
    crashed_file = tmp_path / "test_crash.py"
    crashed_file.write_text('REQUIRED_MECHANISMS = ["HKDF_DERIVE"]\ndef test_x(): pass\n')
    timeout_file = tmp_path / "test_timeout.py"
    timeout_file.write_text('REQUIRED_MECHANISMS = ["CKM_ML_DSA"]\ndef test_x(): pass\n')
    coverage = {
        "mechanism_coverage": {
            "available_names": ["CKM_AES_CCM", "CKM_HKDF_DERIVE", "CKM_ML_DSA"],
            "invoked_names": [],
            "not_invoked_names": ["CKM_AES_CCM", "CKM_HKDF_DERIVE", "CKM_ML_DSA"],
            "skipped_by_capability_names": [],
            "crashed_names": [],
            "timeout_names": [],
        }
    }
    state = FileRunState(
        units=[str(skipped_file), str(crashed_file), str(timeout_file)],
        fingerprint="fp",
        results=[
            FileRunResult(str(skipped_file), "passed", 0, 0.0),
            FileRunResult(str(crashed_file), "crashed", -11, 1.0),
            FileRunResult(str(timeout_file), "timeout", file_runner_mod._TIMEOUT_RETURN_CODE, 1.0),
        ],
    )

    augmented = file_runner_mod._augment_mechanism_coverage_from_unit_outcomes(
        coverage,
        state,
        per_unit_details={str(skipped_file): {"file_skip": True}},
    )

    mechanism_coverage = augmented["mechanism_coverage"]
    assert mechanism_coverage["skipped_by_capability_names"] == ["CKM_AES_CCM"]
    assert mechanism_coverage["crashed_names"] == ["CKM_HKDF_DERIVE"]
    assert mechanism_coverage["timeout_names"] == ["CKM_ML_DSA"]


def test_nodeid_unit_with_missing_required_mechanism_is_skipped_before_pytest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "test_example.py"
    test_file.write_text('REQUIRED_MECHANISMS = ["HKDF_DERIVE"]\ndef test_a(): pass\n')
    nodeid = f"{test_file}::test_a"
    report_path = tmp_path / "results.json"

    monkeypatch.setattr(file_runner_mod, "_load_available_mechanisms", lambda _args: {"AES_CBC"})
    monkeypatch.setattr(
        file_runner_mod,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [nodeid],
    )

    def _unexpected_run(*_args: Any, **_kwargs: Any) -> tuple[int, str, str]:
        pytest.fail("missing REQUIRED_MECHANISMS nodeid unit must not invoke pytest")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", _unexpected_run)

    exit_code = run_isolated_pytest_units(
        [nodeid],
        ["--p11-manifest", str(tmp_path / "manifest.json")],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text())
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["total"] == 1
    unit = report["units"][0]
    assert unit["target"] == str(test_file)
    assert unit["file_skip"] is True
    assert unit["counts"]["skipped"] == 1
    assert unit["skip_reasons"] == {"HKDF_DERIVE not supported by module": 1}


def test_file_skip_for_any_missing_required_mechanism_counts_collected_tests(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "test_example.py"
    test_file.write_text(
        'REQUIRED_MECHANISMS = ["ML_DSA", "ML_DSA_KEY_PAIR_GEN"]\n'
        "def test_a(): pass\n"
        "def test_b(): pass\n"
    )
    report_path = tmp_path / "results.json"
    calls: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        calls.append(cmd)
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_load_available_mechanisms", lambda _args: {"ML_DSA"})
    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        file_runner_mod,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [
            f"{test_file}::test_a",
            f"{test_file}::test_b",
        ],
    )

    exit_code = run_isolated_pytest_units(
        [str(test_file)],
        ["--p11-module", "/tmp/module.so", "--p11-manifest", str(tmp_path / "manifest.json")],
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
    assert calls == []
    report = json.loads(report_path.read_text())
    unit = report["units"][0]
    assert unit["file_skip"] is True
    assert unit["counts"]["skipped"] == 2
    assert unit["skip_reasons"] == {"ML_DSA_KEY_PAIR_GEN not supported by module": 2}


def test_file_skip_counts_survive_report_jsonl_merge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    skipped_file = tmp_path / "test_skipped.py"
    skipped_file.write_text(
        'REQUIRED_MECHANISMS = ["EDDSA"]\ndef test_a(): pass\ndef test_b(): pass\n'
    )
    passed_file = tmp_path / "test_passed.py"
    passed_file.write_text("def test_ok(): pass\n")
    report_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    monkeypatch.setattr(file_runner_mod, "_load_available_mechanisms", lambda _args: {"AES_CBC"})
    monkeypatch.setattr(
        file_runner_mod,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [
            f"{skipped_file}::test_a",
            f"{skipped_file}::test_b",
        ],
    )

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        assert str(passed_file) in cmd
        report_log_idx = cmd.index("--report-log")
        unit_jsonl_path = Path(cmd[report_log_idx + 1])
        unit_jsonl_path.write_text(
            _jsonl_line(nodeid=f"{passed_file}::test_ok", outcome="passed") + "\n"
        )
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        [str(skipped_file), str(passed_file)],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path, jsonl_path=report_jsonl_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text())
    assert report["summary"]["passed"] == 1
    assert report["summary"]["skipped"] == 2
    assert report["summary"]["total"] == 3
    units = {unit["target"]: unit for unit in report["units"]}
    skipped_unit = units[str(skipped_file)]
    assert skipped_unit["file_skip"] is True
    assert skipped_unit["counts"]["skipped"] == 2
    assert skipped_unit["skip_reasons"] == {"EDDSA not supported by module": 2}
    assert units[str(passed_file)]["counts"]["passed"] == 1


def test_file_not_skipped_when_mechanism_present(tmp_path: Path) -> None:
    """File with REQUIRED_MECHANISMS present in manifest is NOT skipped."""
    from pkcs11_check.core.test_selection import extract_required_mechanisms

    test_file = tmp_path / "test_example.py"
    test_file.write_text('REQUIRED_MECHANISMS = ["AES_CBC"]\n')
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "status": "ok",
                "module_path": "/lib/mod.so",
                "requested_interface": "PKCS11",
                "interface_version": "2.40",
                "slot_index": 0,
                "slot_count": 1,
                "mechanisms": ["CKM_AES_CBC", "CKM_AES_ECB"],
            }
        )
    )
    mechs = _load_available_mechanisms(["--p11-manifest", str(manifest)])
    required = extract_required_mechanisms(str(test_file))
    assert required is not None
    assert required == ["AES_CBC"]
    assert mechs is not None
    missing = [m for m in required if m not in mechs]
    assert missing == []


def test_load_available_mechanisms_from_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "status": "ok",
                "module_path": "/lib/mod.so",
                "requested_interface": "PKCS11",
                "interface_version": "2.40",
                "slot_index": 0,
                "slot_count": 1,
                "mechanisms": ["CKM_AES_CBC", "CKM_AES_ECB", "CKM_RSA_PKCS"],
            }
        )
    )
    result = _load_available_mechanisms(["--p11-manifest", str(manifest)])
    assert result is not None
    assert "AES_CBC" in result
    assert "CKM_AES_CBC" in result
    assert "RSA_PKCS" in result


def test_load_available_mechanisms_no_manifest() -> None:
    result = _load_available_mechanisms(["--p11-module", "/lib/mod.so"])
    assert result is None


def test_child_metrics_and_incomplete_excluded_from_total() -> None:
    # Two test-level results so _group_results_by_file uses the test-level grouping
    # path (has_test_level=True): test_x ran and failed (child-crash marker),
    # test_b was abandoned as crash_limited (triggers incomplete=True).
    state = FileRunState(
        units=["t.py"],
        fingerprint="abc",
        results=[
            FileRunResult(target="t.py::test_x", status="failed", returncode=1, duration_s=0.1),
            FileRunResult(
                target="t.py::test_b", status="crash_limited", returncode=0, duration_s=0.0
            ),
        ],
    )
    # inject a failed test bearing a child-crash marker via per_unit_details;
    # key matches r.target in the per-result detail lookup
    details: dict[str, Any] = {
        "t.py::test_x": {
            "counts": {"failed": 1},
            "tests": [
                {
                    "nodeid": "t.py::test_x",
                    "outcome": "failed",
                    "longrepr": "module crashed with signal 11",
                },
            ],
        }
    }
    payload = _build_isolated_json_payload(state, per_unit_details=details)
    s = payload["summary"]
    assert s["child_crash"] == 1
    assert s["child_timeout"] == 0
    assert s["incomplete"] is True  # crash_limited > 0
    # child_* must NOT inflate total
    assert s["total"] == sum(
        s[k]
        for k in (
            "passed",
            "failed",
            "skipped",
            "xfailed",
            "xpassed",
            "error",
            "crashed",
            "timeout",
            "crash_limited",
        )
    )
