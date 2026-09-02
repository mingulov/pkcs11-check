"""Tests for collection-safe capability probing."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkcs11_check.core.preflight import (
    CapabilityManifest,
    load_manifest,
    probe_capabilities,
    run_preflight_subprocess,
    save_manifest,
)


def test_probe_capabilities_returns_manifest(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()

    mock_slot = MagicMock()
    mock_mech1 = MagicMock()
    mock_mech1.name = "CKM_AES_ECB"
    mock_mech2 = MagicMock()
    mock_mech2.name = "CKM_RSA_PKCS"
    mock_slot.get_mechanisms.return_value = [mock_mech2, mock_mech1]

    mock_module = MagicMock()
    mock_module.interface_version = "3.2"
    mock_module.get_slots.return_value = [mock_slot]

    with patch("pkcs11_check.core.preflight.load_module", return_value=mock_module):
        manifest = probe_capabilities(module_path, interface="auto", slot=0)

    assert manifest.status == "ok"
    assert manifest.module_path == str(module_path)
    assert manifest.requested_interface == "auto"
    assert manifest.interface_version == "3.2"
    assert manifest.slot_index == 0
    assert manifest.slot_count == 1
    assert manifest.mechanisms == ["CKM_AES_ECB", "CKM_RSA_PKCS"]
    assert set(manifest.mechanism_info.keys()) == {"CKM_AES_ECB", "CKM_RSA_PKCS"}
    for info in manifest.mechanism_info.values():
        assert "flags" in info
        assert "min_key_size" in info
        assert "max_key_size" in info


def test_probe_capabilities_returns_error_manifest(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()

    with patch("pkcs11_check.core.preflight.load_module", side_effect=RuntimeError("boom")):
        manifest = probe_capabilities(module_path, interface="3.2", slot=0)

    assert manifest.status == "error"
    assert manifest.module_path == str(module_path)
    assert manifest.requested_interface == "3.2"
    assert manifest.error == "RuntimeError: boom"


def test_probe_capabilities_marks_module_load_failure(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()

    with patch("pkcs11_check.core.preflight.load_module", side_effect=RuntimeError("boom")):
        manifest = probe_capabilities(module_path, interface="3.2", slot=0)

    assert manifest.status == "error"
    assert manifest.reason == "module_unloadable"


def test_probe_capabilities_does_not_mark_later_slot_failure_as_unloadable(
    tmp_path: Path,
) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()
    mock_module = MagicMock(interface_version="3.2")
    mock_module.get_slots.side_effect = RuntimeError("C_GetSlotList failed")

    with patch("pkcs11_check.core.preflight.load_module", return_value=mock_module):
        manifest = probe_capabilities(module_path, interface="auto", slot=0)

    assert manifest.status == "error"
    assert manifest.reason is None


def test_advertised_mechanism_info_failure_makes_preflight_non_green(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()
    mock_mech = MagicMock()
    mock_mech.name = "CKM_AES_ECB"
    mock_slot = MagicMock()
    mock_slot.get_mechanisms.return_value = [mock_mech]
    mock_slot.get_mechanism_info.side_effect = RuntimeError(
        "C_GetMechanismInfo(CKM_AES_ECB): CKR_FUNCTION_FAILED"
    )
    mock_module = MagicMock(interface_version="3.2")
    mock_module.get_slots.return_value = [mock_slot]

    with patch("pkcs11_check.core.preflight.load_module", return_value=mock_module):
        manifest = probe_capabilities(module_path, interface="auto", slot=0)

    assert manifest.status == "error"
    assert manifest.error is not None
    assert "CKM_AES_ECB" in manifest.error
    assert "CKR_FUNCTION_FAILED" in manifest.error


def test_preflight_classifies_translated_access_violation_as_crash(tmp_path: Path) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()

    with patch(
        "pkcs11_check.core.preflight.load_module",
        side_effect=OSError("exception: access violation reading 0x0"),
    ):
        manifest = probe_capabilities(module_path, interface="auto", slot=0)

    assert manifest.status == "crashed"
    assert manifest.error is not None
    assert "EXCEPTION_ACCESS_VIOLATION" in manifest.error


def test_manifest_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    manifest = CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version="3.0",
        slot_index=1,
        slot_count=2,
        mechanisms=["CKM_AES_ECB"],
    )

    save_manifest(path, manifest)

    assert load_manifest(path) == manifest


def test_probe_capabilities_records_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe_capabilities populates manifest.functions from available_function_names()."""
    import pkcs11_check.core.preflight as preflight_mod

    class _FakeSlot:
        def get_mechanisms(self) -> list[object]:
            return []

        def get_mechanism_info(self, mech: object) -> None:
            return None

    class _FakeRaw:
        def available_function_names(self) -> set[str]:
            return {"C_Sign", "C_Verify", "C_GenerateKeyPair"}

    class _FakeP11:
        interface_version = "2.40"
        raw = _FakeRaw()

        def get_slots(self, token_present: bool = True) -> list[_FakeSlot]:
            return [_FakeSlot()]

    monkeypatch.setattr(preflight_mod, "load_module", lambda module, interface: _FakeP11())

    manifest = preflight_mod.probe_capabilities(Path("/tmp/m.so"), interface="auto", slot=0)

    assert manifest.status == "ok"
    assert manifest.functions == ["C_GenerateKeyPair", "C_Sign", "C_Verify"]  # sorted


def test_manifest_serialization_roundtrip_with_and_without_functions(tmp_path: Path) -> None:
    """Old manifests (no functions key) deserialize to []; new ones round-trip."""
    import json

    # Forward: a manifest WITH functions survives asdict->json->load
    m = CapabilityManifest(
        status="ok",
        module_path="/tmp/m.so",
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_KEM"],
        functions=["C_EncapsulateKey"],
    )
    path = tmp_path / "m.json"
    save_manifest(path, m)
    assert load_manifest(path).functions == ["C_EncapsulateKey"]

    # Backward: a manifest file lacking "functions" loads with [] default
    legacy = {
        "status": "ok",
        "module_path": "/tmp/m.so",
        "requested_interface": "auto",
        "interface_version": "2.40",
        "slot_index": 0,
        "slot_count": 1,
        "mechanisms": [],
    }
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    loaded = load_manifest(legacy_path)
    assert loaded.functions == []
    assert loaded.process_observation is None


def test_preflight_timeout_returns_structured_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "module.so"
    wait_calls: list[int | None] = []

    class FakeProcess:
        returncode: int | None = None
        killed = False

        def wait(self, timeout: int | None = None) -> int:
            wait_calls.append(timeout)
            if len(wait_calls) == 1:
                raise subprocess.TimeoutExpired(cmd="preflight", timeout=timeout or 0)
            self.returncode = -9
            return self.returncode

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()

    monkeypatch.setattr("pkcs11_check.core.preflight.subprocess.Popen", lambda command: process)
    monkeypatch.setattr(
        "pkcs11_check.core.preflight.subprocess.run",
        lambda *args, **kwargs: pytest.fail("subprocess.run should not handle preflight timeouts"),
    )

    manifest = run_preflight_subprocess(
        module,
        interface="auto",
        slot=0,
        timeout=1,
        output_path=tmp_path / "manifest.json",
    )

    assert manifest.status == "timeout"
    assert wait_calls == [1, None]
    assert process.killed is True
    assert manifest.process_observation == {
        "target": str(module),
        "parent_nodeid": None,
        "role": "preflight",
        "attempt": 0,
        "termination": {
            "kind": "timeout",
            "raw_code": -9,
            "signal_name": None,
            "windows_status": None,
        },
        "memory": {"peak_rss_bytes": None, "limit_bytes": None},
        "oom": {"status": "unknown", "sources": []},
    }


def test_preflight_keyboard_interrupt_kills_and_reaps_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "module.so"
    wait_calls: list[int | None] = []
    interrupt = KeyboardInterrupt()

    class FakeProcess:
        killed = False

        def wait(self, timeout: int | None = None) -> int:
            wait_calls.append(timeout)
            if len(wait_calls) == 1:
                raise interrupt
            return -2

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()
    monkeypatch.setattr("pkcs11_check.core.preflight.subprocess.Popen", lambda command: process)

    with pytest.raises(KeyboardInterrupt) as exc_info:
        run_preflight_subprocess(
            module,
            interface="auto",
            slot=0,
            timeout=1,
            output_path=tmp_path / "manifest.json",
        )

    assert exc_info.value is interrupt
    assert process.killed is True
    assert wait_calls == [1, None]


def test_preflight_interrupt_preserved_when_cleanup_kill_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "module.so"
    wait_calls: list[int | None] = []
    kill_calls = 0
    interrupt = KeyboardInterrupt()

    class FakeProcess:
        def wait(self, timeout: int | None = None) -> int:
            wait_calls.append(timeout)
            if len(wait_calls) == 1:
                raise interrupt
            if timeout is None:
                raise AssertionError("must not reap after cleanup kill fails")
            return -2

        def kill(self) -> None:
            nonlocal kill_calls
            kill_calls += 1
            raise RuntimeError("cleanup failed")

    process = FakeProcess()
    monkeypatch.setattr("pkcs11_check.core.preflight.subprocess.Popen", lambda command: process)

    with pytest.raises(KeyboardInterrupt) as exc_info:
        run_preflight_subprocess(
            module,
            interface="auto",
            slot=0,
            timeout=1,
            output_path=tmp_path / "manifest.json",
        )

    assert exc_info.value is interrupt
    assert kill_calls == 1
    assert wait_calls == [1]


def test_preflight_interrupt_during_timeout_reap_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "module.so"
    wait_calls: list[int | None] = []
    kill_calls = 0
    interrupt = KeyboardInterrupt()

    class FakeProcess:
        def wait(self, timeout: int | None = None) -> int:
            wait_calls.append(timeout)
            if len(wait_calls) == 1:
                raise subprocess.TimeoutExpired(cmd="preflight", timeout=timeout or 0)
            if len(wait_calls) == 2:
                raise interrupt
            return -9

        def kill(self) -> None:
            nonlocal kill_calls
            kill_calls += 1

    process = FakeProcess()
    monkeypatch.setattr("pkcs11_check.core.preflight.subprocess.Popen", lambda command: process)

    with pytest.raises(KeyboardInterrupt) as exc_info:
        run_preflight_subprocess(
            module,
            interface="auto",
            slot=0,
            timeout=1,
            output_path=tmp_path / "manifest.json",
        )

    assert exc_info.value is interrupt
    assert kill_calls == 2
    assert wait_calls == [1, None, None]


def test_preflight_crash_returns_exact_structured_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "module.so"

    class FakeProcess:
        def wait(self, timeout: int | None = None) -> int:
            return -11

    monkeypatch.setattr(
        "pkcs11_check.core.preflight.subprocess.Popen", lambda command: FakeProcess()
    )

    manifest = run_preflight_subprocess(
        module,
        interface="auto",
        slot=0,
        timeout=1,
        output_path=tmp_path / "manifest.json",
    )

    assert manifest.status == "crashed"
    assert manifest.process_observation is not None
    assert manifest.process_observation["role"] == "preflight"
    assert manifest.process_observation["target"] == str(module)
    assert manifest.process_observation["attempt"] == 0
    termination = manifest.process_observation["termination"]
    assert isinstance(termination, dict)
    assert termination["raw_code"] == -11
