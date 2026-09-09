from __future__ import annotations

import os
from types import SimpleNamespace
from typing import cast

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.testcases import test_subprocess_safety
from pkcs11_check.testcases._probes import subprocess_safety as subprocess_safety_probe
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER


def test_cross_process_setup_create_object_reject_is_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_CreateObject:0x00000013\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)

    with pytest.raises(pytest.xfail.Exception, match="session-object setup rejected"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            config,
        )


def test_cross_process_setup_evidence_survives_outer_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="SETUP_XFAIL:Parent_CreateObject:0x00000013\n",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )

    assert [item.reason for item in get_records()] == ["not_operational", "crash"]


def test_cross_process_setup_evidence_survives_outer_windows_seh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=1,
            stdout="SETUP_XFAIL:Parent_CreateObject:0x00000013\n",
            stderr="OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
        ),
    )
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match="Windows exception"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )

    assert [item.reason for item in get_records()] == ["not_operational", "crash"]


def test_cross_process_duplicate_setup_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=(
                "SETUP_XFAIL:Parent_CreateObject:0x00000013\n"
                "SETUP_XFAIL:Parent_CreateObject:0x00000013\n"
            ),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate setup"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_cross_process_duplicate_setup_preserves_outer_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout=(
                "SETUP_XFAIL:Parent_CreateObject:0x00000013\n"
                "SETUP_XFAIL:Parent_CreateObject:0x00000013\n"
            ),
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )

    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


@pytest.mark.parametrize(
    ("stdout", "match"),
    [
        ("PARENT_LABEL:parent\n", "missing child status"),
        ("PARENT_LABEL:parent\nCHILD_EXIT:1\n", "status 1"),
    ],
)
def test_cross_process_incomplete_child_status_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    match: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match=match):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_cross_process_child_signal_is_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_SIGNAL:11\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["crash"]


def test_cross_process_child_fatal_is_provider_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FATAL:Init:0x00000005\nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception, match="child refused"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["not_operational"]


def test_cross_process_duplicate_child_fatal_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=(
                "PARENT_LABEL:parent\n"
                "CHILD_FATAL:Init:0x00000005\n"
                "CHILD_FATAL:Init:0x00000005\n"
                "CHILD_EXIT:2\n"
            ),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate child refusal"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_cross_process_child_exception_is_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_EXC:RuntimeError:broken\nCHILD_EXIT:5\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="child reported"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_cross_process_duplicate_parent_label_is_one_harness_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=("PARENT_LABEL:first\nPARENT_LABEL:second\nCHILD_EXIT:0\nCHILD_FOUND:0\n"),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate parent label"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    records = get_records()
    assert [item.reason for item in records] == ["harness_error"]


@pytest.mark.parametrize("label", [" parent", "parent "])
def test_cross_process_noncanonical_parent_label_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
    label: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=f"PARENT_LABEL:{label}\nCHILD_FOUND:1\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="parent label"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_cross_process_duplicate_child_status_is_one_harness_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=("PARENT_LABEL:parent\nCHILD_EXIT:0\nCHILD_EXIT:0\n"),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate child exit"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    records = get_records()
    assert [item.reason for item in records] == ["harness_error"]


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


def test_fork_positive_child_exit_is_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXIT:1\nOK:fork\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="incomplete"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert get_records()[-1].reason == "harness_error"


def test_fork_child_exception_with_success_exit_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXC:RuntimeError:broken\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="child exception|incomplete"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_fork_parent_init_refusal_is_provider_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_Init:0x00000005\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception, match="Parent_Init"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["not_operational"]


def test_fork_impossible_parent_setup_phase_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_GetSlotList:0x00000005\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_fork_duplicate_child_fatal_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=("CHILD_FATAL:Init:0x00000005\nCHILD_FATAL:Init:0x00000005\nCHILD_EXIT:0\n"),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate child refusal"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_fork_duplicate_child_exception_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=("CHILD_EXC:RuntimeError:broken\nCHILD_EXC:RuntimeError:broken\nCHILD_EXIT:0\n"),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate child exception"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    ("stdout", "match"),
    [
        ("SETUP_XFAIL:Parent_Init:0x00000000\n", "malformed setup"),
        ("CHILD_FATAL:Init:0x00000000\nCHILD_EXIT:2\n", "malformed or unknown"),
    ],
)
def test_fork_zero_rv_marker_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    match: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match=match):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_child_refusal_wrong_exit_pair_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=("PARENT_LABEL:parent\nCHILD_FATAL:Init:0x00000005\nCHILD_EXIT:9\n"),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="pair|status 9|incomplete"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_parent_open_refusal_is_provider_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_OpenSession:0x000000b5\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception, match="OpenSession"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["not_operational"]


def test_session_invalid_parent_slot_range_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_Slot:0>=1\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    ("stdout", "match"),
    [
        ("SETUP_XFAIL:Parent_Init:0x00000000\n", "malformed setup"),
        (
            "PARENT_LABEL:parent\nCHILD_FATAL:Init:0x00000000\nCHILD_EXIT:2\n",
            "malformed or unknown",
        ),
    ],
)
def test_session_zero_rv_marker_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    match: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match=match):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize("rv_text", ["0x0000005", "0x0000000A", "0x000000005"])
def test_session_noncanonical_setup_ckr_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    rv_text: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=f"SETUP_XFAIL:Parent_Init:{rv_text}\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize("found_text", ["01", "+1", "1_0"])
def test_session_noncanonical_found_decimal_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    found_text: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=f"PARENT_LABEL:parent\nCHILD_FOUND:{found_text}\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed child-found"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_missing_parent_label_with_child_signal_records_harness_and_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_SIGNAL:11\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


@pytest.mark.parametrize(
    ("phase", "exit_code", "operation"),
    [
        ("Init", 2, "C_Initialize"),
        ("Slot", 7, "C_GetSlotList"),
        ("Open", 8, "C_OpenSession"),
        ("Login", 6, "C_Login"),
        ("FindInit", 3, "C_FindObjectsInit"),
        ("Find", 4, "C_FindObjects"),
        ("FindFinal", 9, "C_FindObjectsFinal"),
    ],
)
def test_session_child_refusal_phase_requires_exact_exit_pair(
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    exit_code: int,
    operation: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=(
                f"PARENT_LABEL:parent\nCHILD_FATAL:{phase}:0x00000005\nCHILD_EXIT:{exit_code}\n"
            ),
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception, match="child refused"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    records = get_records()
    assert [item.reason for item in records] == ["not_operational"]
    assert records[0].operation == operation


def test_session_child_found_zero_is_exact_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:0\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
        SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
    )
    assert get_records() == []


def test_session_child_found_one_is_policy_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="child found 1"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction"]


def test_session_child_found_without_exit_is_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="missing child status"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "harness_error"]


def test_session_found_then_cleanup_signal_preserves_policy_and_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_SIGNAL:11\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "crash"]


def test_session_found_then_cleanup_exception_preserves_policy_and_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=(
                "PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXC:BufferError:cleanup\nCHILD_EXIT:5\n"
            ),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="child reported"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "harness_error"]


@pytest.mark.parametrize(
    "stdout",
    [
        "PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXC:RuntimeError:cleanup\n",
        ("PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXC:RuntimeError:cleanup\nCHILD_EXIT:4\n"),
        "PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXC:broken\nCHILD_EXIT:5\n",
        "PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXIT:4\n",
    ],
)
def test_session_found_policy_survives_cleanup_exception_protocol_errors(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="incomplete|pair|malformed|status"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    reasons = [item.reason for item in get_records()]
    assert reasons[0] == "self_contradiction"
    assert "harness_error" in reasons


def test_session_found_zero_then_cleanup_signal_is_crash_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:0\nCHILD_SIGNAL:11\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["crash"]


def test_session_found_zero_then_cleanup_exception_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=(
                "PARENT_LABEL:parent\nCHILD_FOUND:0\nCHILD_EXC:BufferError:cleanup\nCHILD_EXIT:5\n"
            ),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="child reported"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_found_policy_survives_outer_crash_without_child_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\n",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "crash"]


def test_session_found_policy_survives_outer_timeout_without_child_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=124,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\n",
            stderr=f"{SUBPROCESS_TIMEOUT_MARKER}:90s\n",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "crash"]


def test_fork_fatal_marker_whitespace_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_FATAL:Init:0x00000005 \nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_setup_marker_trailing_whitespace_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_Init:0x00000005 \n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    "stdout",
    [
        "CHILD_SIGNAL:+11\n",
        "CHILD_SIGNAL:011\n",
        "CHILD_SIGNAL:1_1\n",
        "CHILD_EXIT:01\n",
    ],
)
def test_fork_noncanonical_decimal_marker_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed|incomplete"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_fork_overpadded_ckr_marker_is_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_FATAL:Init:0x000000005\nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed or unknown"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_oversized_child_found_preserves_outer_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = "1" * 5000
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout=f"PARENT_LABEL:parent\nCHILD_FOUND:{oversized}\n",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


def test_oversized_slot_marker_preserves_outer_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = "1" * 5000
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=124,
            stdout=f"SETUP_EXC:Parent_Slot:{oversized}>=1\n",
            stderr=f"{SUBPROCESS_TIMEOUT_MARKER}:90s\n",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


@pytest.mark.parametrize("detail", ["01>=1", "1>=01", "+1>=1", "1_0>=1", "1>=1 "])
def test_session_noncanonical_setup_slot_range_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    detail: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=f"SETUP_EXC:Parent_Slot:{detail}\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup exception"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=1, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_noncanonical_exception_slot_range_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXC:SlotRange:01>=1\nCHILD_EXIT:5\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="parent label|malformed"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_child_exception_requires_exception_exit_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_EXC:RuntimeError:broken\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="exception|pair|incomplete"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_setup_refusal_excludes_nested_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=(
                "SETUP_XFAIL:Parent_GetSlotList:0x00000005\n"
                "PARENT_LABEL:parent\nCHILD_FOUND:0\nCHILD_EXIT:0\n"
            ),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="mixed|nested"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_signal_and_exit_conflict_is_harness_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_SIGNAL:11\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal and exit|conflicting"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_child_success_without_parent_label_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_FOUND:0\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="parent label"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_setup_and_child_signal_is_harness_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:Parent_Init:0x00000005\nCHILD_SIGNAL:11\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="mixed|nested"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_found_effect_survives_outer_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_EXIT:0\n",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "crash"]


def test_fork_child_refusal_requires_exact_exit_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_FATAL:Init:0x00000005\nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception, match="child refused"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["not_operational"]


def test_fork_reversed_refusal_transcript_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXIT:2\nCHILD_FATAL:Init:0x00000005\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="order"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize("rv_text", ["0x0000005", "0x0000000A"])
def test_fork_nonproducer_ckr_shape_is_harness(
    monkeypatch: pytest.MonkeyPatch,
    rv_text: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=f"CHILD_FATAL:Init:{rv_text}\nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed or unknown"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_undefined_high_width_ckr_is_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FATAL:Init:0x100000000\nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    records = get_records()
    assert [item.reason for item in records] == ["self_contradiction"]
    assert records[0].kind == "metadata"
    assert records[0].actual_ckr == "0x100000000"
    assert records[0].expected_ckr == ["CKR_OK"]


def test_fork_emits_child_disposition_before_parent_finalize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            events.append("initialize")
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            events.append("finalize")
            return 0

    monkeypatch.setattr(os, "fork", lambda: 1)

    def waitpid(_pid: int, _options: int) -> tuple[int, int]:
        events.append("waitpid")
        return 1, 0

    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(os, "WIFSIGNALED", lambda _status: False)
    monkeypatch.setattr(os, "WEXITSTATUS", lambda _status: 0)

    def emit(*args: object, **_kwargs: object) -> None:
        events.append(f"emit:{args[0]}")

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    subprocess_safety_probe._fork_after_initialize(
        cast(
            ProbeContext,
            SimpleNamespace(
                raw=_Raw(), sh=None, slot_id=None, cleanup=lambda: None, module_path=""
            ),
        ),
        {},
    )
    assert events == ["initialize", "waitpid", "emit:CHILD_EXIT:0", "finalize"]


def test_session_parent_slot_configuration_marker_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="SETUP_EXC:Parent_Slot:1>=1\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="slot configuration"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=1, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_session_reversed_result_transcript_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXIT:0\nCHILD_FOUND:0\nPARENT_LABEL:parent\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="order"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_fork_child_exit_harness_is_preserved_before_outer_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="CHILD_EXIT:1\n",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )

    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


def test_fork_child_signal_crash_is_preserved_before_cleanup_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_SIGNAL:11\n",
            stderr="HARNESS_ERROR:cleanup failed\n",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )

    assert [item.reason for item in get_records()] == ["crash", "harness_error"]


def test_fork_child_signal_and_outer_signal_are_both_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="CHILD_SIGNAL:11\n",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )

    assert [item.reason for item in get_records()] == ["crash", "crash"]


def test_fork_missing_status_with_outer_signal_is_crash_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="",
            stderr="segmentation fault",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )

    assert [item.reason for item in get_records()] == ["crash"]


def test_fork_outer_windows_seh_is_crash_without_missing_status_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=1,
            stdout="",
            stderr="OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
        ),
    )
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match="Windows exception"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )

    assert [item.reason for item in get_records()] == ["crash"]


@pytest.mark.parametrize("output", ["OK:fork\n", "CHILD_EXIT:not-an-int\nOK:fork\n"])
def test_fork_missing_or_malformed_status_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    output: str,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout=output, stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="incomplete"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert get_records()[-1].reason == "harness_error"


def test_fork_timeout_marker_is_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=124,
            stdout="CHILD_EXIT:0\n",
            stderr=f"{SUBPROCESS_TIMEOUT_MARKER}:15s\n",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert get_records()[-1].reason == "crash"
