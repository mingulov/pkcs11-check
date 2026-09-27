from __future__ import annotations

import ctypes
from types import SimpleNamespace

from pkcs11_check.testcases import (
    test_interface_negotiation,
    test_reinitialize,
    test_threading,
)
from pkcs11_check.testcases._probes import subprocess_safety
from pkcs11_check.testcases._probes.session import ProbeContext


def test_doctor_login_forwards_exact_interface(monkeypatch) -> None:
    from pkcs11_check.core import doctor_probe
    from pkcs11_check.raw.api import RawPKCS11

    captured: list[tuple[str, str]] = []

    class _Raw:
        def C_Initialize(self, _reserved: object) -> int:  # noqa: N802
            return 0

        def C_OpenSession(self, *_args: object) -> int:  # noqa: N802
            output = _args[-1]
            ctypes.cast(output, ctypes.POINTER(ctypes.c_ulong))[0] = 7
            return 0

        def C_Login(self, *_args: object) -> int:  # noqa: N802
            return 0

        def C_Logout(self, _session: int) -> int:  # noqa: N802
            return 0

        def C_CloseSession(self, _session: int) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _reserved: object) -> int:  # noqa: N802
            return 0

    def load_raw(_cls: type[RawPKCS11], path: str, *, interface: str) -> _Raw:
        captured.append((path, interface))
        return _Raw()

    monkeypatch.setattr(RawPKCS11, "from_lib", classmethod(load_raw))
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.get_slot_ids", lambda *_args, **_kwargs: [9])

    result = doctor_probe.probe_login(
        module=doctor_probe.Path("provider.so"), interface="3.1", slot=0, pin=b"1234"
    )

    assert result.status == "ok"
    assert captured == [("provider.so", "3.1")]


def test_reload_cycle_reuses_context_interface_for_each_nested_load(monkeypatch) -> None:
    captured: list[tuple[str, str]] = []

    class _Raw:
        def C_Initialize(self, _reserved: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _reserved: object) -> int:  # noqa: N802
            return 0

        def C_CloseSession(self, _session: int) -> int:  # noqa: N802
            return 0

    def load_raw(path: str, *, interface: str) -> _Raw:
        captured.append((path, interface))
        return _Raw()

    monkeypatch.setattr(subprocess_safety.RawPKCS11, "from_lib", load_raw)
    monkeypatch.setattr(subprocess_safety, "get_slot_ids", lambda *_args, **_kwargs: [9])
    monkeypatch.setattr(subprocess_safety, "open_session", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(subprocess_safety, "gen_aes_key", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(subprocess_safety, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.delenv("_P11CHECK_PIN", raising=False)

    ctx = ProbeContext(
        raw=object(),
        sh=None,
        slot_id=None,
        cleanup=lambda: None,
        module_path="provider.so",
        interface="3.1",
    )
    subprocess_safety._reload_cycle_5x(ctx, {})

    assert captured == [("provider.so", "3.1")] * 5


def test_reinitialize_forwards_exact_interface(monkeypatch) -> None:
    captured: list[tuple[str, str]] = []

    class _Raw:
        def C_Initialize(self, _reserved: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _reserved: object) -> int:  # noqa: N802
            return 0

    def load_raw(path: str, *, interface: str) -> _Raw:
        captured.append((path, interface))
        return _Raw()

    monkeypatch.setattr(test_reinitialize.RawPKCS11, "from_lib", load_raw)
    monkeypatch.setattr(test_reinitialize, "get_slot_ids", lambda _raw: [9])
    monkeypatch.setattr(test_reinitialize, "raw_open_session", lambda *_args: 7)
    monkeypatch.setattr(test_reinitialize, "gen_aes_key", lambda *_args: 11)
    monkeypatch.setattr(test_reinitialize, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_reinitialize, "close_session_quietly", lambda *_args: None)

    config = SimpleNamespace(module="provider.so", interface="3.1", slot=0, pin=None)
    test_reinitialize.TestReinitialize().test_reinitialize_and_use(config)

    assert captured == [("provider.so", "3.1")]


def test_interface_negotiation_load_only_forwards_config_interface(monkeypatch) -> None:
    captured: list[tuple[str, str]] = []
    raw = object()

    def load_raw(path: str, *, interface: str) -> object:
        captured.append((path, interface))
        return raw

    monkeypatch.setattr(test_interface_negotiation.RawPKCS11, "from_lib", load_raw)
    assert (
        test_interface_negotiation._load_only_raw(
            SimpleNamespace(module="provider.so", interface="3.1")
        )
        is raw
    )

    assert captured == [("provider.so", "3.1")]


def test_threading_workload_transports_interface_in_environment(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def run(_cmd: object, *, env: dict[str, str], **_kwargs: object) -> SimpleNamespace:
        captured["env"] = env
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(test_threading.subprocess, "run", run)
    config = SimpleNamespace(module="provider.so", interface="3.1", slot=0, pin=None)

    result = test_threading._run_threaded_workload(config, workload="digest", threads=1, iters=1)

    assert result == (0, "OK", "")
    assert captured["env"]["P11_THREAD_INTERFACE"] == "3.1"
