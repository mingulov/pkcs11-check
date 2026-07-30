"""``python -m pkcs11_check`` entry point.

Needed where the ``pkcs11-check`` console-script shim is not on PATH -- notably the
Windows/Wine docker target, which runs the framework with ``wine python -m pkcs11_check``.
"""

from __future__ import annotations

import subprocess
import sys


def test_python_dash_m_runs_cli_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pkcs11_check", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stderr
    assert "Usage" in result.stdout or "usage" in result.stdout
