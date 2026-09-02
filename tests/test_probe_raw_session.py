"""Meta-tests for _probes/raw_session.py: the ctypes.CDLL child entry point.

Exercises probe_main_raw end-to-end via subprocess against the pkcs11-mock shared
library.  The raw CDLL path drives the module through ctypes without RawPKCS11, so:

  - call_log is always empty (no automatic call interceptor).
  - mechanism_counts is always empty.
  - rv-trace is always empty unless the probe explicitly records calls itself.

I6 and I7 tests assert the correct *shape* of the emitted data, not the content.

Mock module requirements: pkcs11-mock (https://github.com/Pkcs11Interop/pkcs11-mock)
is a minimal C stub that returns CKR_OK for all operations.
Build from upstream and set P11TEST_MOCK_MODULE=/path/to/pkcs11-mock.so.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path


def _write_raw_probe(tmp_path: Path) -> Path:
    """Write a tiny child script that calls probe_main_raw and reports ctx state."""
    probe = tmp_path / "raw_probe.py"
    probe.write_text(
        textwrap.dedent(
            """
            from pkcs11_check.testcases._probes.raw_session import (
                probe_main_raw,
                RawCtypesContext,
            )

            def run(ctx: RawCtypesContext, extra: dict) -> None:
                print("RAW_OK:" + str(ctx.func_list is not None))

            if __name__ == "__main__":
                probe_main_raw(run)
            """
        ),
        encoding="utf-8",
    )
    return probe


def test_raw_session_probe_loads_and_runs(tmp_path: Path, mock_module_path: str) -> None:
    """probe_main_raw loads the CDLL, bootstraps the function list, and runs run_fn."""
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}), encoding="utf-8")
    probe = _write_raw_probe(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": ""},
        timeout=30,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr
    assert "RAW_OK:True" in proc.stdout


def test_raw_session_probe_writes_coverage(tmp_path: Path, mock_module_path: str) -> None:
    """I6 round-trip: _P11CHECK_SUBPROCESS_COVERAGE is written with the correct shape.

    The raw CDLL path has no automatic call interceptor, so call_log is empty.
    The test asserts the *shape* (both keys present, correct types) rather than
    the content — an empty call_log is the legitimate, expected value for this path.
    """
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}), encoding="utf-8")
    probe = _write_raw_probe(tmp_path)
    cov_path = tmp_path / "cov.json"

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_SUBPROCESS_COVERAGE": str(cov_path)},
        timeout=30,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr

    assert cov_path.exists(), "coverage file was not written by probe_main_raw"
    data = json.loads(cov_path.read_text(encoding="utf-8"))

    # Shape check (I6): both keys must be present.
    assert "call_log" in data, f"missing 'call_log' key; got: {list(data)}"
    assert "mechanism_counts" in data, f"missing 'mechanism_counts' key; got: {list(data)}"

    # Type check: both values must be dicts (even if empty).
    assert isinstance(data["call_log"], dict), (
        f"'call_log' must be a dict; got {type(data['call_log'])!r}: {data['call_log']!r}"
    )
    assert isinstance(data["mechanism_counts"], dict), (
        f"'mechanism_counts' must be a dict; got {type(data['mechanism_counts'])!r}"
    )
    # Note: call_log IS empty for the raw CDLL path — this is correct behaviour.
    # The parent's get_raw_subprocess_coverage() accumulates zero counts from it.


def test_raw_session_probe_emits_rv_trace(tmp_path: Path, mock_module_path: str) -> None:
    """I7 round-trip: PKCS11_CHECK_RV_TRACE=1 causes P11_RV_TRACE_JSON: in stdout.

    The raw CDLL path emits an empty list because there is no automatic RV interceptor.
    The test verifies the marker is present and the JSON payload is a list.
    """
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}), encoding="utf-8")
    probe = _write_raw_probe(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "PKCS11_CHECK_RV_TRACE": "1"},
        timeout=30,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr

    marker = "P11_RV_TRACE_JSON:"
    assert marker in proc.stdout, f"marker {marker!r} not found in stdout: {proc.stdout!r}"

    # Extract the JSON after the last occurrence of the marker.
    last_json_str = next(
        line.split(marker, 1)[1] for line in reversed(proc.stdout.splitlines()) if marker in line
    )
    trace = json.loads(last_json_str)
    assert isinstance(trace, list), f"rv_trace payload must be a list; got: {trace!r}"
    # Note: trace IS empty for the raw CDLL path — this is correct behaviour.
    # Probes that need RV recording must implement their own interceptor.
