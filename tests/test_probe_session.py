"""Meta-tests for _probes/session.py: the RawPKCS11 child entry point.

The test drives probe_main end-to-end via a real subprocess so that the
session-setup path (load -> C_Initialize -> C_OpenSession -> C_Login) is exercised
against a real PKCS#11 shared library, not a Python mock.

Mock module requirements: pkcs11-mock (https://github.com/Pkcs11Interop/pkcs11-mock)
is a minimal C stub that returns CKR_OK for all operations and accepts any PIN.
Build from upstream (https://github.com/Pkcs11Interop/pkcs11-mock) and set
P11TEST_MOCK_MODULE=/path/to/pkcs11-mock.so.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path


def _write_probe(tmp_path: Path) -> Path:
    """Write a tiny child module that calls probe_main and reports session state."""
    probe = tmp_path / "probe_under_test.py"
    probe.write_text(
        textwrap.dedent(
            """
            from pkcs11_check.testcases._probes.session import probe_main, ProbeContext

            def run(ctx: ProbeContext, extra: dict) -> None:
                print("SESSION_OK:" + str(ctx.sh is not None))

            if __name__ == "__main__":
                probe_main(run)
            """
        )
    )
    return probe


def test_session_probe_opens_session_and_runs(tmp_path: Path, mock_module_path: str) -> None:
    """probe_main at Level.LOGIN opens a session and delivers a non-None sh to run_fn."""
    params = tmp_path / "params.json"
    # Do NOT hard-code slot_id: pkcs11-mock exposes slot 1, not 0. Omitting lets
    # probe_main discover the first available slot via get_slot_ids().
    params.write_text(json.dumps({"module_path": mock_module_path}))

    probe = _write_probe(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_PIN": "1234"},  # PIN only via env (I3)
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "SESSION_OK:True" in proc.stdout


def test_session_probe_writes_coverage(tmp_path: Path, mock_module_path: str) -> None:
    """I6 round-trip: _P11CHECK_SUBPROCESS_COVERAGE produces a parseable JSON file.

    The call_log must contain "C_Initialize" (probe_main always calls it at Level.LOGIN).
    A future rename of call_log / mechanism_counts fields would be caught here.
    """
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}))

    probe = _write_probe(tmp_path)
    cov_path = tmp_path / "cov.json"

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_PIN": "1234", "_P11CHECK_SUBPROCESS_COVERAGE": str(cov_path)},
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr

    assert cov_path.exists(), "coverage file was not written"
    data = json.loads(cov_path.read_text())

    assert "call_log" in data, f"missing 'call_log' key; got: {list(data)}"
    assert "mechanism_counts" in data, f"missing 'mechanism_counts' key; got: {list(data)}"

    call_log = data["call_log"]
    assert isinstance(call_log, dict) and call_log, f"call_log is empty or not a dict: {call_log!r}"
    # C_Initialize is always called by probe_main at Level.LOGIN — assert the real key.
    assert "C_Initialize" in call_log, (
        f"expected 'C_Initialize' in call_log; got keys: {list(call_log)}"
    )


def test_session_probe_emits_rv_trace(tmp_path: Path, mock_module_path: str) -> None:
    """I7 round-trip: PKCS11_CHECK_RV_TRACE=1 causes P11_RV_TRACE_JSON: to appear in stdout."""
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}))

    probe = _write_probe(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_PIN": "1234", "PKCS11_CHECK_RV_TRACE": "1"},
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr

    marker = "P11_RV_TRACE_JSON:"
    assert marker in proc.stdout, f"marker {marker!r} not found in stdout: {proc.stdout!r}"

    # Extract the JSON after the LAST occurrence of the marker on its line.
    last_json_str = next(
        line.split(marker, 1)[1] for line in reversed(proc.stdout.splitlines()) if marker in line
    )
    trace = json.loads(last_json_str)
    assert isinstance(trace, list), f"rv_trace is not a list: {trace!r}"
