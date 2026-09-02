"""A Windows crash (positive NTSTATUS) must classify as 'crashed', like a POSIX signal."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from pkcs11_check.core import doctor_probe, preflight


def _fake_completed(returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout="", stderr="")


def test_preflight_windows_crash_is_crashed(tmp_path):
    with patch.object(preflight.subprocess, "Popen") as popen:
        popen.return_value.wait.return_value = 0xC0000005
        manifest = preflight.run_preflight_subprocess(
            tmp_path / "m.dll",
            interface="auto",
            slot=0,
            timeout=5,
            output_path=tmp_path / "manifest.json",
        )
    assert manifest.status == "crashed"
    assert "EXCEPTION_ACCESS_VIOLATION" in manifest.error


def test_doctor_windows_crash_is_crashed(tmp_path):
    with patch.object(doctor_probe.subprocess, "run", return_value=_fake_completed(0xC0000005)):
        probe = doctor_probe.run_login_probe_subprocess(
            tmp_path / "m.dll",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
        )
    assert probe.status == "crashed"
    assert "EXCEPTION_ACCESS_VIOLATION" in probe.detail
