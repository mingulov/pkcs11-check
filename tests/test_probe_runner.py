"""Meta-tests for the parent-side run_probe launcher (runner.py).

Covers: env injection (PIN via _P11CHECK_PIN only), PIN-in-params rejection,
timeout -> rc 124 + marker, and coverage routing to the correct accumulator (I6).
"""

from __future__ import annotations

import signal
import subprocess
import tempfile
from pathlib import Path

import pytest

from pkcs11_check.core import process_observation
from pkcs11_check.core.process_observation import drain_process_observations
from pkcs11_check.testcases._probes.runner import ProbeResult, run_probe
from pkcs11_check.testcases._raw_subprocess import get_raw_subprocess_coverage
from pkcs11_check.testcases._subprocess_preamble import get_preamble_subprocess_coverage

# ---------------------------------------------------------------------------
# Env injection & basic echo
# ---------------------------------------------------------------------------


def test_run_probe_passes_extra_and_injects_pin_via_env() -> None:
    """PIN travels only via _P11CHECK_PIN env; probe params carry the marker only."""
    result = run_probe(
        "_echo",
        {"module_path": "/nonexistent.so", "marker": "hello"},
        pin="1234",
        timeout=30,
    )
    assert isinstance(result, ProbeResult)
    assert result.returncode == 0, result.stderr
    assert "ECHO_MARKER:hello" in result.stdout
    assert "ECHO_PIN_PRESENT:True" in result.stdout  # PIN reached child via env only


def _fake_completed(returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, "", "")


def _assert_probe_observation(result: ProbeResult, *, returncode: int, kind: str) -> None:
    observation = result.observation
    assert observation is not None
    assert observation["parent_nodeid"] is None
    assert observation["role"] == "probe"
    assert observation["target"] == "_echo"
    assert observation["termination"] == {
        "kind": kind,
        "raw_code": returncode,
        "signal_name": "SIGKILL" if returncode == -9 else None,
        "windows_status": 0xC0000005 if returncode == -1073741819 else None,
    }


def test_run_probe_records_passing_process_observation() -> None:
    drain_process_observations()
    result = run_probe("_echo", {"module_path": "/nonexistent.so"}, timeout=30)

    _assert_probe_observation(result, returncode=0, kind="exit")
    assert drain_process_observations() == [result.observation]


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="SIGKILL is POSIX-only")
def test_run_probe_records_sigkill_process_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drain_process_observations()
    monkeypatch.setattr(
        "pkcs11_check.testcases._probes.runner.subprocess.run",
        lambda *a, **k: _fake_completed(-9),
    )

    result = run_probe("_echo", {"module_path": "/x.so"})

    _assert_probe_observation(result, returncode=-9, kind="signal")
    assert drain_process_observations() == [result.observation]


def test_run_probe_records_timeout_process_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drain_process_observations()

    def raise_timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(args[0] if args else [], 1)

    monkeypatch.setattr("pkcs11_check.testcases._probes.runner.subprocess.run", raise_timeout)
    result = run_probe("_echo", {"module_path": "/x.so"}, timeout=1)

    assert result.returncode == 124
    _assert_probe_observation(result, returncode=124, kind="timeout")
    assert drain_process_observations() == [result.observation]


def test_run_probe_records_windows_access_violation_process_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drain_process_observations()
    monkeypatch.setattr(process_observation.sys, "platform", "win32")
    monkeypatch.setattr(
        "pkcs11_check.testcases._probes.runner.subprocess.run",
        lambda *a, **k: _fake_completed(-1073741819),
    )

    result = run_probe("_echo", {"module_path": "/x.so"})

    _assert_probe_observation(result, returncode=-1073741819, kind="exception")
    assert drain_process_observations() == [result.observation]


def test_run_probe_records_ctypes_windows_access_violation_from_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drain_process_observations()
    monkeypatch.setattr(process_observation.sys, "platform", "win32")
    monkeypatch.setattr(
        "pkcs11_check.testcases._probes.runner.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(
            [],
            1,
            "",
            "Traceback (most recent call last):\nOSError: exception: access violation reading 0",
        ),
    )

    result = run_probe("_echo", {"module_path": "/x.so"})

    assert result.observation is not None
    assert result.observation["termination"] == {
        "kind": "exception",
        "raw_code": 1,
        "signal_name": None,
        "windows_status": 0xC0000005,
    }
    assert drain_process_observations() == [result.observation]


# ---------------------------------------------------------------------------
# PIN-in-params rejection (Invariant I3)
# ---------------------------------------------------------------------------


def test_run_probe_rejects_pin_in_params() -> None:
    """PinInParamsError is raised before the subprocess is launched."""
    from pkcs11_check.testcases._probes.params import PinInParamsError

    with pytest.raises(PinInParamsError):
        run_probe("_echo", {"module_path": "/x.so", "pin": "1234"})


# ---------------------------------------------------------------------------
# Timeout handling (Invariant I8)
# ---------------------------------------------------------------------------


def test_run_probe_timeout_marks_rc_124() -> None:
    """A hanging probe gets rc=124 and the timeout marker on stderr (I8)."""
    result = run_probe("_echo", {"module_path": "/x.so", "sleep": 5}, timeout=1)
    assert result.returncode == 124
    assert "_P11CHECK_SUBPROCESS_TIMEOUT" in result.stderr


# ---------------------------------------------------------------------------
# Coverage routing (Invariant I6)
# ---------------------------------------------------------------------------


def test_run_probe_coverage_session_routes_to_preamble_accumulator() -> None:
    """coverage='session' ingests into preamble accumulators, not raw ones."""
    # Drain both accumulators before the test to avoid bleed from earlier tests.
    get_preamble_subprocess_coverage()
    get_raw_subprocess_coverage()

    run_probe(
        "_echo",
        {"module_path": "/nonexistent.so"},
        coverage="session",
        timeout=30,
    )

    preamble_call, _, _, _ = get_preamble_subprocess_coverage()
    raw_call, _, _, _ = get_raw_subprocess_coverage()

    assert preamble_call.get("C_Echo") == 1, f"preamble counter: {dict(preamble_call)}"
    assert not raw_call, f"raw counter should be empty but got: {dict(raw_call)}"


def test_run_probe_coverage_raw_routes_to_raw_accumulator() -> None:
    """coverage='raw' ingests into raw accumulators, not preamble ones."""
    # Drain both accumulators before the test to avoid bleed from earlier tests.
    get_preamble_subprocess_coverage()
    get_raw_subprocess_coverage()

    run_probe(
        "_echo",
        {"module_path": "/nonexistent.so"},
        coverage="raw",
        timeout=30,
    )

    raw_call, _, _, _ = get_raw_subprocess_coverage()
    preamble_call, _, _, _ = get_preamble_subprocess_coverage()

    assert raw_call.get("C_Echo") == 1, f"raw counter: {dict(raw_call)}"
    assert not preamble_call, f"preamble counter should be empty but got: {dict(preamble_call)}"


# ---------------------------------------------------------------------------
# Params temp-file retention (deferred minor #5)
# ---------------------------------------------------------------------------


def _run_failing_probe() -> None:
    """Drive a failed probe (rc 124) via the _echo sleep+timeout path."""
    result = run_probe("_echo", {"module_path": "/nonexistent.so", "sleep": 3}, timeout=1)
    assert result.returncode == 124, result.stderr


def test_run_probe_deletes_params_temp_file_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """By default the params temp file is removed even when the probe fails, so
    expected crash/timeout outcomes do not accumulate p11probe-*.json in TMPDIR."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.delenv("PKCS11_CHECK_KEEP_PROBE_PARAMS", raising=False)

    _run_failing_probe()

    assert not list(tmp_path.glob("p11probe-*.json")), "params temp file not deleted by default"
    assert not list(tmp_path.glob("p11cov-*.json")), "coverage temp file leaked"


def test_run_probe_retains_params_temp_file_when_debug_env_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With PKCS11_CHECK_KEEP_PROBE_PARAMS set, a failed probe keeps its params
    temp file for standalone repro; the coverage temp is still removed."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("PKCS11_CHECK_KEEP_PROBE_PARAMS", "1")

    _run_failing_probe()

    retained = list(tmp_path.glob("p11probe-*.json"))
    assert len(retained) == 1, f"expected exactly one retained params file, got {retained}"
    assert not list(tmp_path.glob("p11cov-*.json")), "coverage temp file must still be removed"
