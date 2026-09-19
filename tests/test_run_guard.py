"""Run-artifact guards: overlapping runs must fail loudly, never destroy (F-038).

Two `test` runs sharing one directory used to delete each other's state and
outputs: fixed CWD defaults plus a fresh-run reset with no inter-process lock.
The guard holds an OS file lock per artifact path from the first reset to run
end; a second run sharing any artifact is refused before it can reset or
write anything. Resume across a foreign fingerprint stays rejected (pinned).
"""

from __future__ import annotations

import sys
import threading
import time
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from pkcs11_check.core._run_guard import RunArtifactsLockedError, run_artifact_guard


def test_guard_reacquires_after_release(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    with run_artifact_guard(target):
        pass
    with run_artifact_guard(target):
        pass


def test_guard_second_holder_refused(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    with run_artifact_guard(target):
        with pytest.raises(RunArtifactsLockedError):
            with run_artifact_guard(target):
                pass  # pragma: no cover - must not acquire


def test_guard_releases_first_path_when_second_contended(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    with run_artifact_guard(second):
        with pytest.raises(RunArtifactsLockedError):
            with run_artifact_guard(first, second):
                pass  # pragma: no cover - must not acquire
    # The failed multi-path acquisition unwound `first`: it acquires cleanly.
    with run_artifact_guard(first):
        pass


def test_guard_timeout_waits_then_raises(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    with run_artifact_guard(target):
        start = time.monotonic()
        with pytest.raises(RunArtifactsLockedError):
            with run_artifact_guard(target, timeout=0.3):
                pass  # pragma: no cover - must not acquire
        assert time.monotonic() - start >= 0.25


def test_guard_timeout_acquires_once_released(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    entered = threading.Event()
    release = threading.Event()

    def _holder() -> None:
        with run_artifact_guard(target):
            entered.set()
            assert release.wait(timeout=10)

    thread = threading.Thread(target=_holder, daemon=True)
    thread.start()
    assert entered.wait(timeout=10)
    timer = threading.Timer(0.4, release.set)
    timer.start()
    try:
        start = time.monotonic()
        with run_artifact_guard(target, timeout=10):
            waited = time.monotonic() - start
        assert waited >= 0.3
    finally:
        timer.cancel()
        release.set()
        thread.join(timeout=10)
        assert not thread.is_alive()


def test_guard_unifies_spelling_aliases(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    with run_artifact_guard(tmp_path / "x.json"):
        with pytest.raises(RunArtifactsLockedError):
            with run_artifact_guard(tmp_path / "sub" / ".." / "x.json"):
                pass  # pragma: no cover - same file, must not acquire


def test_guard_skips_none_paths(tmp_path: Path) -> None:
    with run_artifact_guard(None, tmp_path / "state.json", None):
        with pytest.raises(RunArtifactsLockedError):
            with run_artifact_guard(tmp_path / "state.json"):
                pass  # pragma: no cover - must not acquire


def test_guard_creates_missing_parent_dirs(tmp_path: Path) -> None:
    """Guards work when the run has not created its output dirs yet."""
    target = tmp_path / "nested" / "dir" / "state.json"
    with run_artifact_guard(target):
        assert (tmp_path / "nested" / "dir" / "state.json.lock").exists()
    with run_artifact_guard(target):
        pass


def test_guard_error_names_remedy(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    with run_artifact_guard(target):
        with pytest.raises(RunArtifactsLockedError) as exc_info:
            with run_artifact_guard(target):
                pass  # pragma: no cover - must not acquire
    message = str(exc_info.value)
    assert "state.json" in message
    assert "--state-file" in message


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock contention probe")
def test_cli_second_run_refused_before_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run whose artifacts are guarded refuses with exit 2, touching nothing."""
    import fcntl

    from pkcs11_check.cli import test_cmd
    from pkcs11_check.cli.app import app
    from tests._plain_cli_runner import PlainCliRunner

    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    state_file = tmp_path / "state.json"
    results_file = tmp_path / "results.json"
    state_file.write_text('{"sentinel": "state"}', encoding="utf-8")
    results_file.write_text('{"sentinel": "results"}', encoding="utf-8")

    def _ok_preflight(
        module: Path,
        *,
        interface: str,
        slot: int,
        timeout: int,
        output_path: Path,
    ) -> object:
        from pkcs11_check.core.preflight import CapabilityManifest

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

    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)

    guard_path = tmp_path / "state.json.lock"
    with guard_path.open("a+b") as guard_fh:
        fcntl.flock(guard_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = PlainCliRunner().invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--state-file",
                str(state_file),
                "--output-file",
                str(results_file),
                "--isolation",
                "file",
                "--ignore-disabled-tests",
            ],
        )
        fcntl.flock(guard_fh.fileno(), fcntl.LOCK_UN)

    assert result.exit_code == 2
    assert "another run" in result.output
    assert state_file.read_text(encoding="utf-8") == '{"sentinel": "state"}'
    assert results_file.read_text(encoding="utf-8") == '{"sentinel": "results"}'


def test_resume_rejects_foreign_fingerprint(tmp_path: Path) -> None:
    """Resume identifies the right run: a foreign state fingerprint refuses."""
    from pkcs11_check.core.file_runner import (
        FileRunState,
        load_run_state,
        run_isolated_pytest_units,
        save_run_state,
    )

    state_file = tmp_path / "state.json"
    save_run_state(state_file, FileRunState(units=["test_a.py"], fingerprint="WRONG", results=[]))
    assert load_run_state(state_file) is not None

    with pytest.raises(ValueError, match="different isolated run"):
        run_isolated_pytest_units(
            ["test_a.py"],
            ["--p11-module", "/tmp/module.so"],
            timeout=12,
            state_file=state_file,
            policy_file=None,
            report_config=None,
            resume=True,
            stop_on_failure=False,
            console=Console(file=StringIO(), force_terminal=False),
            granularity="file",
        )


def test_policy_promote_waits_for_guard(tmp_path: Path) -> None:
    """Policy updates serialize on the policy guard instead of losing updates."""
    from pkcs11_check.core._escalation import _promote_crashing_unit
    from pkcs11_check.core._unit_discovery import load_isolation_policy

    policy_file = tmp_path / "policy.json"
    console = Console(file=StringIO(), force_terminal=False)
    done: list[bool] = []

    def _promote() -> None:
        _promote_crashing_unit(
            policy_file,
            ["--p11-module", "/tmp/module.so"],
            {},
            "test_a.py::test_boom",
            "test",
            "crashed",
            console,
        )
        done.append(True)

    with run_artifact_guard(policy_file):
        thread = threading.Thread(target=_promote, daemon=True)
        thread.start()
        time.sleep(0.3)
        assert done == [], "the promote must wait while the policy guard is held"
    thread.join(timeout=30)
    assert done == [True]

    policies = load_isolation_policy(policy_file)
    assert len(policies) == 1
    policy = next(iter(policies.values()))
    assert "test_a.py::test_boom" in policy.crashed_tests


def test_concurrent_policy_promotes_keep_both_updates(tmp_path: Path) -> None:
    """Racing promotes keep every update (guard serializes the RMW)."""
    from pkcs11_check.core._escalation import _promote_crashing_unit
    from pkcs11_check.core._unit_discovery import load_isolation_policy

    policy_file = tmp_path / "policy.json"
    console = Console(file=StringIO(), force_terminal=False)

    def _promote(unit: str) -> None:
        _promote_crashing_unit(
            policy_file,
            ["--p11-module", "/tmp/module.so"],
            {},
            unit,
            "test",
            "crashed",
            console,
        )

    threads = [
        threading.Thread(target=_promote, args=(f"test_{i}.py::test_boom",), daemon=True)
        for i in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    policies = load_isolation_policy(policy_file)
    assert len(policies) == 1
    policy = next(iter(policies.values()))
    assert len(policy.crashed_tests) == 8
