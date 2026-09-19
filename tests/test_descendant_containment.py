"""Descendant containment: abnormal child exits leave no live stragglers (F-022).

Unit children launch in their own process group (POSIX) and any abnormal exit
-- file-deadline kill, crash, or abrupt self-exit -- kills the whole group, so
orphaned probe grandchildren cannot hold sessions or token state across units.
Windows walks the process tree via taskkill (mock-covered here; real coverage
needs a Windows host).
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core.file_runner import _kill_process_tree, _run_subprocess_tee

needs_posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")

_SLEEPER = (
    "import time, sys; open(sys.argv[1], 'w').write(str(__import__('os').getpid())); time.sleep(60)"
)

# Poll until the sleeper proves it is alive; spawners run this before hanging
# or dying so the test never races spawn against containment.
_SPAWN_WAIT = (
    "import time, os\n"
    "deadline = time.monotonic() + 10\n"
    "while not os.path.exists({pidfile!r}) and time.monotonic() < deadline:\n"
    "    time.sleep(0.02)\n"
)


def _pid_dead(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _reap_safety_net(pid: int) -> None:
    """Best-effort kill for a leaked test sleeper (red runs, flakes)."""
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


@needs_posix
def test_child_runs_in_own_process_group(tmp_path: Path) -> None:
    """The unit child is a group leader: pgid == pid (the owned group)."""
    probe = tmp_path / "ids.txt"
    script = f"import os; open({str(probe)!r}, 'w').write(f'{{os.getpid()}} {{os.getpgrp()}}')"
    rc, _, _, _ = _run_subprocess_tee(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    assert rc == 0
    pid, pgid = (int(part) for part in probe.read_text(encoding="utf-8").split())
    assert pgid == pid


@needs_posix
def test_file_deadline_kill_reaps_grandchild(tmp_path: Path) -> None:
    """A file-deadline kill takes the whole group, not just the child."""
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {_SLEEPER!r}, {str(pid_file)!r}]); "
        + _SPAWN_WAIT.format(pidfile=str(pid_file))
        + "time.sleep(60)"
    )
    rc, _, _, observation = _run_subprocess_tee(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        timeout=2,
    )
    assert rc != 0
    assert pid_file.exists(), "the child must have spawned before hanging"
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    try:
        deadline = time.monotonic() + 10
        while not _pid_dead(grandchild) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert _pid_dead(grandchild), "timed-out descendant still alive"
    finally:
        _reap_safety_net(grandchild)


@needs_posix
def test_abrupt_exit_reaps_grandchild(tmp_path: Path) -> None:
    """A self-exiting child (rc 7) still gets its group contained."""
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import os, subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {_SLEEPER!r}, {str(pid_file)!r}]); "
        + _SPAWN_WAIT.format(pidfile=str(pid_file))
        + "os._exit(7)"
    )
    rc, _, _, _ = _run_subprocess_tee(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    assert rc == 7
    # The sleeper may need a moment to write its pid file; poll briefly.
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pid_file.exists(), "the child must have spawned before exiting"
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    try:
        deadline = time.monotonic() + 10
        while not _pid_dead(grandchild) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert _pid_dead(grandchild), "abrupt-exit descendant still alive"
    finally:
        _reap_safety_net(grandchild)


@needs_posix
def test_crash_reaps_grandchild_and_preserves_signal(tmp_path: Path) -> None:
    """A SIGSEGV child keeps its crash evidence (rc -11) minus the straggler."""
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import os, signal, subprocess, sys, time; "
        f"child = subprocess.Popen([sys.executable, '-c', {_SLEEPER!r}, {str(pid_file)!r}]); "
        + _SPAWN_WAIT.format(pidfile=str(pid_file))
        + "os.kill(os.getpid(), signal.SIGSEGV)"
    )
    rc, _, _, _ = _run_subprocess_tee(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    assert rc == -signal.SIGSEGV
    assert pid_file.exists(), "the child must have spawned before crashing"
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    try:
        deadline = time.monotonic() + 10
        while not _pid_dead(grandchild) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert _pid_dead(grandchild), "crash descendant still alive"
    finally:
        _reap_safety_net(grandchild)


@needs_posix
def test_clean_exit_leaves_group_alone(tmp_path: Path) -> None:
    """Clean exits (rc 0) do not trigger group containment."""
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {_SLEEPER!r}, {str(pid_file)!r}])"
    )
    rc, _, _, _ = _run_subprocess_tee(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    assert rc == 0
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pid_file.exists()
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    try:
        assert not _pid_dead(grandchild), "clean-exit descendant must survive"
    finally:
        _reap_safety_net(grandchild)


def test_kill_tree_windows_uses_taskkill(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows containment walks the tree via taskkill /T (mock dispatch)."""
    calls: list[list[str]] = []
    killed: list[bool] = []

    def _fake_run(argv: list[str], **kwargs: Any) -> object:
        del kwargs
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(file_runner_mod.sys, "platform", "win32")
    monkeypatch.setattr(file_runner_mod.subprocess, "run", _fake_run)
    proc = SimpleNamespace(pid=12345, kill=lambda: killed.append(True))

    _kill_process_tree(proc)  # type: ignore[arg-type]

    assert calls == [["taskkill", "/PID", "12345", "/T", "/F"]]
    assert killed == []


def test_kill_tree_windows_falls_back_to_direct_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If taskkill itself is unavailable, the direct child is still killed."""

    def _missing(argv: list[str], **kwargs: Any) -> object:
        del argv, kwargs
        raise FileNotFoundError("taskkill")

    killed: list[bool] = []
    monkeypatch.setattr(file_runner_mod.sys, "platform", "win32")
    monkeypatch.setattr(file_runner_mod.subprocess, "run", _missing)
    proc = SimpleNamespace(pid=12345, kill=lambda: killed.append(True))

    _kill_process_tree(proc)  # type: ignore[arg-type]

    assert killed == [True]


def test_kill_tree_posix_never_shells_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """POSIX containment is a single killpg; no subprocess is spawned."""
    calls: list[list[str]] = []

    def _boom(argv: list[str], **kwargs: Any) -> object:
        del kwargs
        calls.append(argv)
        raise AssertionError("must not shell out on POSIX")

    groups: list[tuple[int, int]] = []
    monkeypatch.setattr(file_runner_mod.sys, "platform", "linux")
    monkeypatch.setattr(file_runner_mod.subprocess, "run", _boom)
    monkeypatch.setattr(file_runner_mod.os, "killpg", lambda pg, sig: groups.append((pg, sig)))
    proc = SimpleNamespace(pid=4242, kill=lambda: None)

    _kill_process_tree(proc)  # type: ignore[arg-type]

    assert calls == []
    assert groups == [(4242, signal.SIGKILL)]


def test_kill_tree_tolerates_already_gone_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """ESRCH from a reaped group is silence, not an error."""

    def _gone(pg: int, sig: int) -> None:
        del pg, sig
        raise ProcessLookupError("gone")

    monkeypatch.setattr(file_runner_mod.sys, "platform", "linux")
    monkeypatch.setattr(file_runner_mod.os, "killpg", _gone)
    proc = SimpleNamespace(pid=4242, kill=lambda: None)

    _kill_process_tree(proc)  # type: ignore[arg-type]
