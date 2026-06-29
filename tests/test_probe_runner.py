"""Meta-tests for the parent-side run_probe launcher (runner.py).

Covers: env injection (PIN via _P11CHECK_PIN only), PIN-in-params rejection,
timeout -> rc 124 + marker, and coverage routing to the correct accumulator (I6).
"""

from __future__ import annotations

import pytest

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

    preamble_call, _ = get_preamble_subprocess_coverage()
    raw_call, _ = get_raw_subprocess_coverage()

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

    raw_call, _ = get_raw_subprocess_coverage()
    preamble_call, _ = get_preamble_subprocess_coverage()

    assert raw_call.get("C_Echo") == 1, f"raw counter: {dict(raw_call)}"
    assert not preamble_call, f"preamble counter should be empty but got: {dict(preamble_call)}"
