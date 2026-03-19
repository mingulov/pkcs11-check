"""Subprocess-based test isolation for segfault survival."""

from __future__ import annotations

import multiprocessing
import time
from collections.abc import Callable
from dataclasses import dataclass
from multiprocessing.queues import Queue


@dataclass
class TestResult:
    """Result from an isolated test run."""

    __test__ = False  # prevent pytest collection

    name: str
    outcome: str  # "passed", "failed", "skipped", "crashed", "timeout"
    duration_s: float = 0.0
    signal: int | None = None
    error_message: str | None = None
    pkcs11_rc: int | None = None
    stdout: str = ""
    stderr: str = ""


def _run_in_subprocess(
    queue: Queue[TestResult],
    name: str,
    fn: Callable[[], None],
) -> None:
    """Target function for subprocess. Runs fn and puts result in queue."""
    start = time.monotonic()
    try:
        fn()
        duration = time.monotonic() - start
        queue.put(TestResult(name=name, outcome="passed", duration_s=duration))
    except Exception as exc:
        duration = time.monotonic() - start
        queue.put(
            TestResult(
                name=name,
                outcome="failed",
                duration_s=duration,
                error_message=str(exc),
            )
        )


class IsolatedRunner:
    """Runs test functions in isolated subprocesses."""

    def __init__(self, timeout: float = 120) -> None:
        self.timeout = timeout

    def run(self, name: str, fn: Callable[[], None]) -> TestResult:
        """Run fn in a subprocess. Returns TestResult regardless of crash/timeout."""
        ctx = multiprocessing.get_context("spawn")
        queue: Queue[TestResult] = ctx.Queue()
        proc = ctx.Process(target=_run_in_subprocess, args=(queue, name, fn))

        start = time.monotonic()
        proc.start()
        proc.join(timeout=self.timeout)
        duration = time.monotonic() - start

        if proc.is_alive():
            proc.kill()
            proc.join(timeout=5)
            return TestResult(
                name=name,
                outcome="timeout",
                duration_s=duration,
                error_message=f"timeout after {self.timeout}s",
            )

        if proc.exitcode is not None and proc.exitcode < 0:
            sig = -proc.exitcode
            return TestResult(
                name=name,
                outcome="crashed",
                duration_s=duration,
                signal=sig,
                error_message=f"module crashed (signal {sig})",
            )

        if not queue.empty():
            return queue.get_nowait()

        return TestResult(
            name=name,
            outcome="failed",
            duration_s=duration,
            error_message=f"subprocess exited with code {proc.exitcode}",
        )
