"""Tests for per-file isolated pytest running."""

from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from p11test.core.file_runner import (
    FileRunResult,
    FileRunState,
    build_state_fingerprint,
    discover_pytest_units,
    load_run_state,
    run_isolated_pytest_units,
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

    units = discover_pytest_units([target], tmp_path / "unused")

    assert units == [target]


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
        resume=False,
        stop_on_failure=True,
        console=console,
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
        resume=True,
        stop_on_failure=False,
        console=console,
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
        resume=True,
        stop_on_failure=False,
        console=console,
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
            resume=True,
            stop_on_failure=False,
            console=console,
        )
