"""Meta-tests for _probes/session.py: the RawPKCS11 child entry point.

The test drives probe_main end-to-end via a real subprocess so that the
session-setup path (load -> C_Initialize -> C_OpenSession -> C_Login) is exercised
against a real PKCS#11 shared library, not a Python mock.

Mock module requirements: pkcs11-mock (https://github.com/Pkcs11Interop/pkcs11-mock)
is a minimal C stub that returns CKR_OK for all operations and accepts any PIN.
Build with: bash local-builds/build.sh pkcs11-mock
or override with the P11TEST_MOCK_MODULE environment variable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


def _find_mock_module() -> str | None:
    """Return the path to pkcs11-mock.so if discoverable, otherwise None."""
    candidates = [
        os.environ.get("P11TEST_MOCK_MODULE"),
        str(Path.home() / ".cache" / "pkcs11-check-test" / "pkcs11-mock.so"),
        "/tmp/pkcs11-mock-build/pkcs11-mock.so",  # noqa: S108 -- test temp path only
        "/usr/lib/pkcs11/pkcs11-mock.so",
        "/usr/lib64/libpkcs11-mock.so",
        "/opt/pkcs11_mock/libpkcs11_mock.so",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def _get_mock_module_path() -> str:
    """Return path to pkcs11-mock.so, or pytest.skip if not available."""
    path = _find_mock_module()
    if path is None:
        pytest.skip(
            "pkcs11-mock.so not found; build with"
            " 'bash local-builds/build.sh pkcs11-mock'"
            " or set P11TEST_MOCK_MODULE to its path"
        )
    return path


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


def test_session_probe_opens_session_and_runs(tmp_path: Path) -> None:
    """probe_main at Level.LOGIN opens a session and delivers a non-None sh to run_fn."""
    mock_path = _get_mock_module_path()

    params = tmp_path / "params.json"
    # Do NOT hard-code slot_id: pkcs11-mock exposes slot 1, not 0. Omitting lets
    # probe_main discover the first available slot via get_slot_ids().
    params.write_text(json.dumps({"module_path": mock_path}))

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
