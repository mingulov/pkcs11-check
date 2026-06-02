"""Shared subprocess runner for raw ctypes PKCS#11 tests.

Used by test_operation_state.py, test_sign_recover.py, test_dual_function.py
and any future tests that need to call C_* functions via ctypes subprocess
(for crash safety or to test wrapper-blocked conditions).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter

from pkcs11_check.testcases._subprocess_trace import record_subprocess_rv_trace

_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[str] = Counter()

_RV_TRACE_EMITTER = r"""
import atexit as _p11check_atexit
import json as _p11check_json
import os as _p11check_os


def _p11check_rv_trace_enabled():
    _value = _p11check_os.environ.get("PKCS11_CHECK_RV_TRACE", "")
    if _value.strip().lower() in ("1", "true", "yes", "on"):
        return True
    return bool(_p11check_os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT"))


def _p11check_rv_trace_maxlen():
    _value = _p11check_os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT")
    if not _value:
        return None
    try:
        _maxlen = int(_value)
    except ValueError:
        return None
    return _maxlen if _maxlen > 0 else None


_p11check_raw = globals().get("raw")
if _p11check_raw is not None and _p11check_rv_trace_enabled():
    _p11check_raw.enable_rv_trace(maxlen=_p11check_rv_trace_maxlen())

    def _p11check_emit_rv_trace():
        try:
            print(
                "P11_RV_TRACE_JSON:"
                + _p11check_json.dumps(
                    _p11check_raw.rv_trace,
                    separators=(",", ":"),
                ),
                flush=True,
            )
        except (OSError, TypeError, ValueError):
            pass

    _p11check_atexit.register(_p11check_emit_rv_trace)
"""


def run_raw_script(
    boilerplate: str,
    script_body: str,
    cleanup: str = "",
    timeout: int = 15,
    *,
    pin: str | None = None,
) -> tuple[int, str, str]:
    """Run a ctypes PKCS#11 script in a subprocess.

    Args:
        boilerplate: Pre-formatted setup code (module load, session open, login).
        script_body: Test-specific code appended after boilerplate.
        cleanup: Code appended after script_body (e.g., session close, finalize).
        timeout: Subprocess timeout in seconds.
        pin: User PIN to forward to the child. Injected into the child env under
            ``_P11CHECK_PIN`` (never embedded in the script source), matching the
            login path emitted by ``subprocess_session_preamble``.

    Returns:
        (returncode, stdout, stderr) - returncode < 0 means signal (segfault).
    """
    full_script = boilerplate + textwrap.dedent(_RV_TRACE_EMITTER) + textwrap.dedent(script_body)
    if cleanup:
        full_script += textwrap.dedent(cleanup)

    # Create temp file for subprocess coverage data
    cov_fd, cov_path = tempfile.mkstemp(suffix=".json", prefix="p11cov_")
    os.close(cov_fd)
    env = {**os.environ, "_P11CHECK_SUBPROCESS_COVERAGE": cov_path}
    if pin is not None:
        # Pass the PIN via the child env, never via the script text/argv.
        env["_P11CHECK_PIN"] = pin

    result = subprocess.run(
        [sys.executable, "-c", full_script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    # Read subprocess coverage (may not exist if subprocess crashed)
    try:
        with open(cov_path) as f:
            data = json.load(f)
        _subprocess_call_counts.update(data.get("call_log", {}))
        for k, v in data.get("mechanism_counts", {}).items():
            _subprocess_mechanism_counts[k] += v
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    finally:
        try:
            os.unlink(cov_path)
        except OSError:
            pass

    record_subprocess_rv_trace(result.stdout, result.stderr)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def get_raw_subprocess_coverage() -> tuple[Counter[str], Counter[str]]:
    """Return accumulated subprocess coverage and clear it."""
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    return func, mech


def parse_output(stdout: str) -> dict[str, str]:
    """Parse ``KEY:value`` lines from subprocess stdout into a dict.

    Lines without a colon or starting with FATAL/DEBUG are ignored.
    Multiple values for the same key: last wins.
    """
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key and not key.startswith(("FATAL", "DEBUG", "#")):
            result[key] = value.strip()
    return result
