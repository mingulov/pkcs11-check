from __future__ import annotations

import signal
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases import test_subprocess_safety
from pkcs11_check.testcases._subprocess_trace import drain_subprocess_rv_trace


def test_cross_process_setup_create_object_reject_is_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "_run_script",
        lambda *_args, **_kwargs: (
            1,
            "FATAL:Parent_CreateObject:0x00000013\nERROR: CKA_PRIVATE cannot be CK_FALSE\n",
        ),
    )
    config = SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)

    with pytest.raises(pytest.xfail.Exception, match="session-object setup rejected"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            config,
        )


def test_fork_after_initialize_rejects_nonzero_child_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "_run_script",
        lambda *_args, **_kwargs: (0, "OK: child exit 1\n"),
    )
    config = SimpleNamespace(module="/tmp/provider.so")

    with pytest.raises(pytest.fail.Exception, match="child"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(config)


def test_fork_after_initialize_rejects_child_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "_run_script",
        lambda *_args, **_kwargs: (0, "OK: child exit -1\n"),
    )
    config = SimpleNamespace(module="/tmp/provider.so")

    with pytest.raises(pytest.fail.Exception, match="child"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(config)


def test_run_script_records_rv_trace_before_timeout_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = 'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","rv":0,"rv_name":"CKR_OK"}]'
    signals: list[int] = []

    class _Process:
        pid = 12345
        args = ["python", "-c", "script"]
        returncode = 124
        calls = 0

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(self.args, float(timeout or 0))
            return marker, ""

    def _fake_popen(*_args: Any, **_kwargs: Any) -> _Process:
        return _Process()

    def _fake_killpg(_pid: int, sig: int) -> None:
        signals.append(sig)

    monkeypatch.setattr(getattr(test_subprocess_safety, "subprocess"), "Popen", _fake_popen)
    monkeypatch.setattr(getattr(test_subprocess_safety, "os"), "killpg", _fake_killpg)

    with pytest.raises(subprocess.TimeoutExpired):
        test_subprocess_safety._run_script(
            "from pkcs11_check.raw.api import RawPKCS11\n"
            "raw = RawPKCS11.from_lib('/tmp/provider.so')\n"
            "raw.C_Initialize(None)\n",
            timeout=15,
        )

    assert signals == [signal.SIGTERM]
    assert drain_subprocess_rv_trace() == [
        {"i": 0, "fn": "C_Initialize", "rv": 0, "rv_name": "CKR_OK"}
    ]


def test_rv_trace_injection_preserves_indented_raw_assignment() -> None:
    script = test_subprocess_safety._inject_rv_trace_emitter(
        "for _i in range(1):\n"
        '    raw = RawPKCS11.from_lib("/tmp/provider.so")\n'
        "    raw.C_Initialize(None)\n"
    )

    compile(script, "<rv-trace-subprocess-safety>", "exec")
    assert "    _p11check_enable_rv_trace()" in script
