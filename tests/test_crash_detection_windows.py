"""A Windows crash (positive NTSTATUS) must classify as 'crashed', like a POSIX signal."""

from __future__ import annotations

from unittest.mock import patch

from pkcs11_check.core import doctor_probe, preflight


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
    with patch.object(doctor_probe.subprocess, "Popen") as popen:
        popen.return_value.communicate.return_value = ("", "")
        popen.return_value.returncode = 0xC0000005
        probe = doctor_probe.run_login_probe_subprocess(
            tmp_path / "m.dll",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
        )
    assert probe.status == "crashed"
    assert "EXCEPTION_ACCESS_VIOLATION" in probe.detail
