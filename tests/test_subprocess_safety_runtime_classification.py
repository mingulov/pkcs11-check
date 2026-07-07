from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases import test_subprocess_safety
from pkcs11_check.testcases._probes.runner import ProbeResult


def test_cross_process_setup_create_object_reject_is_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=1,
            stdout="FATAL:Parent_CreateObject:0x00000013\nERROR: CKA_PRIVATE cannot be CK_FALSE\n",
            stderr="",
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
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout="OK: child exit 1\n", stderr=""),
    )
    config = SimpleNamespace(module="/tmp/provider.so")

    with pytest.raises(pytest.fail.Exception, match="child"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(config)


def test_fork_after_initialize_rejects_child_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0, stdout="OK: child exit -1\n", stderr=""
        ),
    )
    config = SimpleNamespace(module="/tmp/provider.so")

    with pytest.raises(pytest.fail.Exception, match="child"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(config)
