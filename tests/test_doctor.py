"""Tests for `pkcs11-check doctor` — the setup-diagnosis checklist.

The probes (preflight, login) are monkeypatched so these run with no real module.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from pkcs11_check.cli import doctor_cmd
from pkcs11_check.core.doctor_probe import LoginProbe, run_login_probe_subprocess
from pkcs11_check.core.preflight import CapabilityManifest


def _manifest(
    status: str, *, error: str | None = None, slot_count: int | None = 2
) -> CapabilityManifest:
    return CapabilityManifest(
        status=status,
        module_path="m.so",
        requested_interface="auto",
        interface_version="3.0" if status == "ok" else None,
        slot_index=0,
        slot_count=slot_count if status == "ok" else None,
        mechanisms=["CKM_AES_CBC"] if status == "ok" else [],
        error=error,
    )


def _patch(
    monkeypatch: pytest.MonkeyPatch, manifest: CapabilityManifest, login: LoginProbe
) -> None:
    monkeypatch.setattr(doctor_cmd, "run_preflight_subprocess", lambda *a, **k: manifest)
    monkeypatch.setattr(doctor_cmd, "run_login_probe_subprocess", lambda *a, **k: login)


def test_missing_module_exits_3(tmp_path: Path) -> None:
    with pytest.raises(typer.Exit) as exc:
        doctor_cmd.doctor_command(
            module=tmp_path / "nope.so", interface="auto", slot=0, pin=None, timeout=10
        )
    assert exc.value.exit_code == 3


def test_all_ok_with_pin_exits_0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = tmp_path / "m.so"
    mod.write_bytes(b"\x7fELF")
    _patch(monkeypatch, _manifest("ok"), LoginProbe("ok"))
    # exit 0 means no typer.Exit raised
    doctor_cmd.doctor_command(module=mod, interface="auto", slot=0, pin="1234", timeout=10)


def test_wrong_pin_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = tmp_path / "m.so"
    mod.write_bytes(b"\x7fELF")
    _patch(monkeypatch, _manifest("ok"), LoginProbe("pin_incorrect"))
    with pytest.raises(typer.Exit) as exc:
        doctor_cmd.doctor_command(module=mod, interface="auto", slot=0, pin="9999", timeout=10)
    assert exc.value.exit_code == 1


def test_slot_out_of_range_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = tmp_path / "m.so"
    mod.write_bytes(b"\x7fELF")
    _patch(
        monkeypatch,
        _manifest("error", error="IndexError: slot 9 not found (token-present slots: 2)"),
        LoginProbe("ok"),
    )
    with pytest.raises(typer.Exit) as exc:
        doctor_cmd.doctor_command(module=mod, interface="auto", slot=9, pin=None, timeout=10)
    assert exc.value.exit_code == 1


def test_crash_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = tmp_path / "m.so"
    mod.write_bytes(b"\x7fELF")
    _patch(
        monkeypatch, _manifest("crashed", error="preflight crashed (signal 11)"), LoginProbe("ok")
    )
    with pytest.raises(typer.Exit) as exc:
        doctor_cmd.doctor_command(module=mod, interface="auto", slot=0, pin=None, timeout=10)
    assert exc.value.exit_code == 1


def test_login_probe_subprocess_handles_bad_module(tmp_path: Path) -> None:
    # A module that cannot load -> the probe must return a non-crashing status, not raise.
    bad = tmp_path / "bad.so"
    bad.write_bytes(b"not a library")
    result = run_login_probe_subprocess(bad, interface="auto", slot=0, pin=b"1234", timeout=15)
    assert result.status in {"error", "crashed", "timeout"}
