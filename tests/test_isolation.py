"""Tests for subprocess-based test isolation."""

from __future__ import annotations

import os
import signal
import sys
import time

import pytest

from p11test.core.isolation import IsolatedRunner, TestResult


# Module-level functions required for multiprocessing pickling
def _passing_fn() -> None:
    pass


def _failing_fn() -> None:
    msg = "deliberate failure"
    raise AssertionError(msg)


def _crashing_fn() -> None:
    os.kill(os.getpid(), signal.SIGSEGV)


def _hanging_fn() -> None:
    time.sleep(60)


class TestTestResultDataclass:
    def test_passed_result(self) -> None:
        r = TestResult(name="test_foo", outcome="passed", duration_s=0.1)
        assert r.outcome == "passed"
        assert r.signal is None

    def test_crashed_result(self) -> None:
        r = TestResult(name="test_foo", outcome="crashed", duration_s=0.0, signal=11)
        assert r.outcome == "crashed"


class TestIsolatedRunner:
    def test_successful_function(self) -> None:
        runner = IsolatedRunner(timeout=10)
        result = runner.run("test_pass", _passing_fn)
        assert result.outcome == "passed"

    def test_failing_function(self) -> None:
        runner = IsolatedRunner(timeout=10)
        result = runner.run("test_fail", _failing_fn)
        assert result.outcome == "failed"
        assert "deliberate failure" in (result.error_message or "")

    @pytest.mark.skipif(sys.platform == "win32", reason="No SIGSEGV on Windows")
    def test_crashing_function(self) -> None:
        runner = IsolatedRunner(timeout=10)
        result = runner.run("test_crash", _crashing_fn)
        assert result.outcome == "crashed"
        assert result.signal == signal.SIGSEGV

    def test_timeout_function(self) -> None:
        runner = IsolatedRunner(timeout=1)
        result = runner.run("test_hang", _hanging_fn)
        assert result.outcome == "timeout"
