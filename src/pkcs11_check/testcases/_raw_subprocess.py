"""Shared subprocess runner for raw ctypes PKCS#11 tests.

Used by test_operation_state.py, test_sign_recover.py, test_dual_function.py
and any future tests that need to call C_* functions via ctypes subprocess
(for crash safety or to test wrapper-blocked conditions).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap


def run_raw_script(
    boilerplate: str,
    script_body: str,
    cleanup: str = "",
    timeout: int = 15,
) -> tuple[int, str, str]:
    """Run a ctypes PKCS#11 script in a subprocess.

    Args:
        boilerplate: Pre-formatted setup code (module load, session open, login).
        script_body: Test-specific code appended after boilerplate.
        cleanup: Code appended after script_body (e.g., session close, finalize).
        timeout: Subprocess timeout in seconds.

    Returns:
        (returncode, stdout, stderr) — returncode < 0 means signal (segfault).
    """
    full_script = boilerplate + textwrap.dedent(script_body)
    if cleanup:
        full_script += textwrap.dedent(cleanup)

    result = subprocess.run(
        [sys.executable, "-c", full_script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


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
