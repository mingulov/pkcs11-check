from __future__ import annotations

import os
import signal
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.compliance import get_notes
from pkcs11_check.testcases import test_subprocess_safety
from pkcs11_check.testcases._probes import subprocess_safety as subprocess_safety_probe
from pkcs11_check.testcases._probes.params import ProbeParams
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER
from tests._skip_assert import assert_skips


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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
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
def test_cross_process_incomplete_child_status_is_probe_incomplete(
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
    assert [item.reason for item in get_records()] == ["probe_incomplete"]


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


def test_cross_process_child_exception_is_probe_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    assert [item.reason for item in get_records()] == ["probe_incomplete"]


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
    assert get_records()[-1].reason == "probe_incomplete"


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


def test_session_missing_parent_label_with_child_signal_records_incomplete_and_crash(
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
    assert [item.reason for item in get_records()] == ["probe_incomplete", "crash"]


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


def test_session_child_found_without_exit_is_probe_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    assert [item.reason for item in get_records()] == ["self_contradiction", "probe_incomplete"]


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


def test_session_found_then_cleanup_exception_preserves_policy_and_incomplete(
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
    assert [item.reason for item in get_records()] == ["self_contradiction", "probe_incomplete"]


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
    assert reasons[1:] and all(
        reason in ("harness_error", "probe_incomplete") for reason in reasons[1:]
    )


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


def test_session_found_zero_then_cleanup_exception_is_incomplete_only(
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
    assert [item.reason for item in get_records()] == ["probe_incomplete"]


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


def test_session_child_success_without_parent_label_is_probe_incomplete(
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
    assert [item.reason for item in get_records()] == ["probe_incomplete"]


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
    # F13 (P11C-0198-017): a matched inherited-child refusal is an observation
    # (skip + note), not a provider xfail; the exact exit pair is still required
    # (a mismatch stays harness-loud).
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_FATAL:Init:0x00000005\nCHILD_EXIT:2\n",
            stderr="",
        ),
    )
    before = _fork_notes_before()
    assert_skips(
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize,
        SimpleNamespace(module="/tmp/provider.so"),
        match="refused",
    )
    assert get_records() == []
    assert "Init" in _latest_fork_note_text(before)


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


@pytest.mark.skipif(sys.platform == "win32", reason="no os.fork on Windows")
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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_fork_child_exit_incomplete_is_preserved_before_outer_signal(
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

    assert [item.reason for item in get_records()] == ["probe_incomplete", "crash"]


def test_fork_nested_signal_with_cleanup_harness_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # F13 (P11C-0198-017): the nested signal is an observation (note), not a crash
    # record; the explicit outer harness error is the only record. The report hook
    # upgrades the recorded fail onto the returned outcome.
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_SIGNAL:11\n",
            stderr="HARNESS_ERROR:cleanup failed\n",
        ),
    )
    before = _fork_notes_before()
    test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
        SimpleNamespace(module="/tmp/provider.so")
    )

    assert [item.reason for item in get_records()] == ["harness_error"]
    assert "signal 11" in _latest_fork_note_text(before)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_fork_nested_signal_with_outer_crash_is_outer_crash_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # F13 (P11C-0198-017): the nested signal is an observation (note), not a crash
    # record; only the genuine outer crash is recorded.
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=-11,
            stdout="CHILD_SIGNAL:11\n",
            stderr="segmentation fault",
        ),
    )
    before = _fork_notes_before()
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )

    assert [item.reason for item in get_records()] == ["crash"]
    assert "signal 11" in _latest_fork_note_text(before)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
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


@pytest.mark.parametrize(
    ("output", "reason"),
    [
        ("OK:fork\n", "probe_incomplete"),
        ("CHILD_EXIT:not-an-int\nOK:fork\n", "harness_error"),
    ],
)
def test_fork_missing_or_malformed_status_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    output: str,
    reason: str,
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
    assert get_records()[-1].reason == reason


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


# ---------------------------------------------------------------------------
# F13 (P11C-0198-017): fork robustness is an observation; isolation is spawn.
# ---------------------------------------------------------------------------


def _posix_fork_gates(fn: object) -> list[Any]:
    """Return the POSIX-only fork skip marks applied to a test function."""
    marks = getattr(fn, "pytestmark", [])
    return [
        mark
        for mark in marks
        if mark.name == "skipif" and "fork" in str(mark.kwargs.get("reason", ""))
    ]


def _fork_notes_before() -> int:
    return len(get_notes())


def _latest_fork_note_text(before: int) -> str:
    notes = get_notes()[before:]
    assert len(notes) == 1
    return notes[0].description


def test_f13_fork_child_signal_is_observation_skip_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout="CHILD_SIGNAL:11\n", stderr=""),
    )
    before = _fork_notes_before()
    assert_skips(
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize,
        SimpleNamespace(module="/tmp/provider.so"),
        match="signal 11",
    )
    assert get_records() == []
    assert "signal 11" in _latest_fork_note_text(before)


def test_f13_fork_child_exception_is_observation_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXC:RuntimeError:broken\nCHILD_EXIT:1\n",
            stderr="",
        ),
    )
    before = _fork_notes_before()
    assert_skips(
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize,
        SimpleNamespace(module="/tmp/provider.so"),
        match="exception",
    )
    assert get_records() == []
    assert "RuntimeError" in _latest_fork_note_text(before)


def _assert_fork_fails_missing_child_status() -> None:
    """Assert the fork test fails loud with missing child status.

    A bare ``pytest.raises(pytest.fail.Exception)`` would let an escaping
    ``pytest.skip()`` through as a silent "skipped" (see ``assert_xfails``), so
    every non-fail outcome is converted to a hard failure here.
    """
    try:
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    except pytest.skip.Exception as exc:
        pytest.fail(f"expected a loud probe_incomplete fail, got pytest.skip() instead: {exc}")
    except pytest.xfail.Exception as exc:
        pytest.fail(f"expected a loud probe_incomplete fail, got pytest.xfail() instead: {exc}")
    except pytest.fail.Exception as exc:
        assert "missing child status" in str(exc), f"unexpected fail message: {exc}"
    else:
        pytest.fail("expected a loud probe_incomplete fail, but the test returned normally")
    records = get_records()
    assert [item.reason for item in records] == ["probe_incomplete"]
    assert records[0].detail is not None
    assert records[0].detail.get("protocol") == "missing_child_status"


def test_f13_fork_bare_child_fatal_is_probe_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_FATAL:Init:0x00000005\n",
            stderr="",
        ),
    )
    _assert_fork_fails_missing_child_status()


def test_f13_fork_bare_child_exception_is_probe_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_EXC:RuntimeError:broken\n",
            stderr="",
        ),
    )
    _assert_fork_fails_missing_child_status()


def test_f13_fork_child_timeout_is_phase_aware_observation_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="CHILD_PHASE:Init\nCHILD_TIMEOUT\n",
            stderr="",
        ),
    )
    before = _fork_notes_before()
    assert_skips(
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize,
        SimpleNamespace(module="/tmp/provider.so"),
        match="timed out during Init",
    )
    assert get_records() == []
    assert "Init" in _latest_fork_note_text(before)


def test_f13_fork_clean_child_is_observation_skip_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(returncode=0, stdout="CHILD_EXIT:0\n", stderr=""),
    )
    before = _fork_notes_before()
    assert_skips(
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize,
        SimpleNamespace(module="/tmp/provider.so"),
        match="survived",
    )
    assert get_records() == []
    assert "survived" in _latest_fork_note_text(before)


def test_f13_fork_timeout_with_exit_status_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0, stdout="CHILD_TIMEOUT\nCHILD_EXIT:0\n", stderr=""
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="conflicting"):
        test_subprocess_safety.TestForkSafety().test_fork_after_initialize(
            SimpleNamespace(module="/tmp/provider.so")
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_f13_fork_keeps_posix_only_gate() -> None:
    assert _posix_fork_gates(test_subprocess_safety.TestForkSafety.test_fork_after_initialize) != []


def test_f13_isolation_child_timeout_is_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_PHASE:Find\nCHILD_TIMEOUT\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["crash"]


def test_f13_isolation_found_then_timeout_preserves_policy_and_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_FOUND:1\nCHILD_TIMEOUT\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction", "crash"]


def test_f13_isolation_no_longer_requires_fork() -> None:
    assert (
        _posix_fork_gates(
            test_subprocess_safety.TestSessionObjectProcessIsolation.test_session_object_not_visible_to_other_process
        )
        == []
    )


def test_f13_isolation_timeout_with_exit_status_is_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_subprocess_safety,
        "run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout="PARENT_LABEL:parent\nCHILD_TIMEOUT\nCHILD_EXIT:0\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="conflicting"):
        test_subprocess_safety.TestSessionObjectProcessIsolation().test_session_object_not_visible_to_other_process(
            SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_f13_isolation_child_params_carry_label_slot_interface_without_pin() -> None:
    params = subprocess_safety_probe._isolation_child_params(
        "/tmp/provider.so", "pkcs11-3.0", 2, "crossproc-abc"
    )
    assert params["module_path"] == "/tmp/provider.so"
    assert params["interface"] == "pkcs11-3.0"
    assert params["slot_id"] == 2
    assert params["extra"]["probe"] == "session_object_isolation_child"
    assert params["extra"]["label"] == "crossproc-abc"
    ProbeParams.dump(params)


def test_f13_isolation_child_argv_executes_probe_module_without_shell() -> None:
    argv = subprocess_safety_probe._isolation_child_argv("/tmp/p11probe-child.json")
    assert argv == [
        sys.executable,
        "-u",
        "-m",
        "pkcs11_check.testcases._probes.subprocess_safety",
        "/tmp/p11probe-child.json",
    ]


def test_f13_isolation_child_env_inherits_pin_drops_coverage_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("_P11CHECK_PIN", "s3cret-pin")
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", "/tmp/p11cov-x.json")
    env = subprocess_safety_probe._isolation_child_env()
    assert env["_P11CHECK_PIN"] == "s3cret-pin"
    assert "_P11CHECK_SUBPROCESS_COVERAGE" not in env


def test_f13_isolation_child_probe_registered() -> None:
    assert "session_object_isolation_child" in subprocess_safety_probe._PROBES


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX waitpid semantics")
def test_f13_fork_probe_kills_hung_child_with_timeout_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    kills: list[tuple[int, int]] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            events.append("initialize")
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            events.append("finalize")
            return 0

    monkeypatch.setattr(os, "fork", lambda: 1)

    def waitpid(pid: int, options: int) -> tuple[int, int]:
        if options == 0:
            events.append("reap")
            # A SIGKILLed child reaps as signaled-by-SIGKILL (POSIX wait status).
            return pid, signal.SIGKILL
        return 0, 0

    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(os, "kill", lambda pid, sig: kills.append((pid, sig)))
    ticks = iter([1000.0, 1060.0])
    monkeypatch.setattr(
        subprocess_safety_probe,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _s: None),
    )

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
    assert kills == [(1, signal.SIGKILL)]
    assert "emit:CHILD_TIMEOUT" in events
    assert "emit:CHILD_EXIT:0" not in events
    assert "finalize" in events


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX waitpid semantics")
def test_f13_wait_child_bounded_keeps_race_exit_disposition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that exits between the last poll and SIGKILL keeps its real exit."""

    def waitpid(pid: int, options: int) -> tuple[int, int]:
        if options == 0:
            return pid, 0  # reaped a clean exit: the SIGKILL hit a zombie
        return 0, 0

    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(os, "kill", lambda _pid, _sig: None)
    ticks = iter([1000.0, 1060.0])
    monkeypatch.setattr(
        subprocess_safety_probe,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _s: None),
    )
    assert subprocess_safety_probe._wait_child_bounded(1, 10.0) == ("exit", 0)


def test_f13_fork_probe_child_reports_phases(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            return 0

    if hasattr(os, "fork"):
        monkeypatch.setattr(os, "fork", lambda: 0)

    def fake_exit(code: int) -> None:
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    monkeypatch.setattr(subprocess_safety_probe, "get_slot_ids", lambda _raw: [7])

    def emit(*args: object, **_kwargs: object) -> None:
        events.append(str(args[0]))

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    with pytest.raises(SystemExit) as exc_info:
        subprocess_safety_probe._fork_after_initialize(
            cast(
                ProbeContext,
                SimpleNamespace(
                    raw=_Raw(), sh=None, slot_id=None, cleanup=lambda: None, module_path=""
                ),
            ),
            {},
        )
    assert exc_info.value.code == 0
    assert events == [
        "CHILD_PHASE:FinalizeInherited",
        "CHILD_PHASE:Init",
        "CHILD_PHASE:Slot",
        "CHILD_PHASE:Finalize",
    ]


def test_f13_isolation_child_handler_reports_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            return 0

        def C_FindObjectsInit(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_FindObjects(self, *args: object) -> int:  # noqa: N802
            count_ptr = args[3]
            count_ptr._obj.value = 0  # type: ignore[attr-defined]
            return 0

        def C_FindObjectsFinal(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_CloseSession(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            return 0

    monkeypatch.delenv("_P11CHECK_PIN", raising=False)
    monkeypatch.setattr(subprocess_safety_probe, "get_slot_ids", lambda _raw: [7])
    monkeypatch.setattr(subprocess_safety_probe, "open_session", lambda *_a: 11)

    def emit(*args: object, **_kwargs: object) -> None:
        events.append(str(args[0]))

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    with pytest.raises(SystemExit) as exc_info:
        subprocess_safety_probe._session_object_isolation_child(
            cast(
                ProbeContext,
                SimpleNamespace(
                    raw=_Raw(),
                    sh=None,
                    slot_id=0,
                    cleanup=lambda: None,
                    module_path="/tmp/provider.so",
                    interface="auto",
                ),
            ),
            {"label": "crossproc-test"},
        )
    assert exc_info.value.code == 0
    assert events[-1] == "CHILD_FOUND:0"
    assert "CHILD_PHASE:Init" in events
    assert "CHILD_PHASE:Find" in events


def test_f13_isolation_child_handler_init_refusal_exit_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            return 5

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            return 0

    monkeypatch.delenv("_P11CHECK_PIN", raising=False)

    def emit(*args: object, **_kwargs: object) -> None:
        events.append(str(args[0]))

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    with pytest.raises(SystemExit) as exc_info:
        subprocess_safety_probe._session_object_isolation_child(
            cast(
                ProbeContext,
                SimpleNamespace(
                    raw=_Raw(),
                    sh=None,
                    slot_id=0,
                    cleanup=lambda: None,
                    module_path="/tmp/provider.so",
                    interface="auto",
                ),
            ),
            {"label": "crossproc-test"},
        )
    assert exc_info.value.code == 2
    assert "CHILD_FATAL:Init:0x00000005" in events


def test_f13_isolation_parent_relays_spawned_child_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str]] = []
    popen_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    cleaned: list[str] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            return 0

        def C_CreateObject(self, *args: object) -> int:  # noqa: N802
            handle_ptr = args[3]
            handle_ptr._obj.value = 42  # type: ignore[attr-defined]
            return 0

        def C_DestroyObject(self, *args: object) -> int:  # noqa: N802
            cleaned.append("destroy")
            return 0

        def C_CloseSession(self, *args: object) -> int:  # noqa: N802
            cleaned.append("close")
            return 0

        def C_Login(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            cleaned.append("finalize")
            return 0

    def boom() -> int:
        raise AssertionError("isolation must spawn, never fork")

    monkeypatch.setattr(os, "fork", boom, raising=False)
    monkeypatch.setenv("_P11CHECK_PIN", "s3cret-pin")
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", "/tmp/p11cov-parent.json")
    monkeypatch.setattr(subprocess_safety_probe, "get_slot_ids", lambda _raw: [7])
    monkeypatch.setattr(subprocess_safety_probe, "open_session", lambda *_a: 11)

    child_stdout = "CHILD_PHASE:Init\nCHILD_PHASE:Slot\nCHILD_FOUND:0\n"

    class _Proc:
        returncode = 0

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            return child_stdout, ""

    def fake_popen(*args: Any, **kwargs: Any) -> _Proc:
        popen_calls.append((args, kwargs))
        return _Proc()

    monkeypatch.setattr(
        subprocess_safety_probe,
        "subprocess",
        SimpleNamespace(
            Popen=fake_popen,
            TimeoutExpired=subprocess.TimeoutExpired,
            PIPE=subprocess.PIPE,
        ),
    )

    def emit(*args: object, **_kwargs: object) -> None:
        if "file" in _kwargs:
            events.append(("stderr", str(args[0])))
        else:
            events.append(("stdout", str(args[0])))

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    subprocess_safety_probe._session_object_isolation(
        cast(
            ProbeContext,
            SimpleNamespace(
                raw=_Raw(),
                sh=None,
                slot_id=0,
                cleanup=lambda: None,
                module_path="/tmp/provider.so",
                interface="auto",
            ),
        ),
        {},
    )
    assert len(popen_calls) == 1
    argv = popen_calls[0][0][0]
    assert argv[:4] == [
        sys.executable,
        "-u",
        "-m",
        "pkcs11_check.testcases._probes.subprocess_safety",
    ]
    assert argv[4].endswith(".json")
    child_env = popen_calls[0][1]["env"]
    assert child_env["_P11CHECK_PIN"] == "s3cret-pin"
    assert "_P11CHECK_SUBPROCESS_COVERAGE" not in child_env
    assert "s3cret-pin" not in " ".join(argv)
    assert not os.path.exists(argv[4])
    stdout_lines = [text for stream, text in events if stream == "stdout"]
    assert stdout_lines[0].startswith("PARENT_LABEL:crossproc-")
    assert stdout_lines[1:] == [
        "CHILD_PHASE:Init",
        "CHILD_PHASE:Slot",
        "CHILD_FOUND:0",
        "CHILD_EXIT:0",
    ]
    assert cleaned == ["destroy", "close", "finalize"]


def test_f13_isolation_parent_kills_timed_out_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    kills: list[bool] = []
    finalized: list[bool] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            return 0

        def C_CreateObject(self, *args: object) -> int:  # noqa: N802
            handle_ptr = args[3]
            handle_ptr._obj.value = 42  # type: ignore[attr-defined]
            return 0

        def C_DestroyObject(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_CloseSession(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            finalized.append(True)
            return 0

    def boom() -> int:
        raise AssertionError("isolation must spawn, never fork")

    monkeypatch.setattr(os, "fork", boom, raising=False)
    monkeypatch.delenv("_P11CHECK_PIN", raising=False)
    monkeypatch.setattr(subprocess_safety_probe, "get_slot_ids", lambda _raw: [7])
    monkeypatch.setattr(subprocess_safety_probe, "open_session", lambda *_a: 11)

    class _Proc:
        returncode: int | None = None
        calls = 0

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            type(self).calls += 1
            if timeout is not None:
                raise subprocess.TimeoutExpired(
                    "child", timeout, output="CHILD_PHASE:Init\n", stderr=""
                )
            return "", ""

        def kill(self) -> None:
            kills.append(True)
            self.returncode = -9

    monkeypatch.setattr(
        subprocess_safety_probe,
        "subprocess",
        SimpleNamespace(
            Popen=lambda *a, **k: _Proc(),
            TimeoutExpired=subprocess.TimeoutExpired,
            PIPE=subprocess.PIPE,
        ),
    )

    def emit(*args: object, **_kwargs: object) -> None:
        events.append(str(args[0]))

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    subprocess_safety_probe._session_object_isolation(
        cast(
            ProbeContext,
            SimpleNamespace(
                raw=_Raw(),
                sh=None,
                slot_id=0,
                cleanup=lambda: None,
                module_path="/tmp/provider.so",
                interface="auto",
            ),
        ),
        {},
    )
    assert kills == [True]
    assert "CHILD_PHASE:Init" in events
    assert events[-1] == "CHILD_TIMEOUT"
    assert finalized == [True]


def test_f13_isolation_parent_omits_terminal_marker_for_unrepresentable_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Windows AV exit code (>255) emits no terminal marker (loud missing status)."""
    events: list[str] = []
    finalized: list[bool] = []

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802
            return 0

        def C_CreateObject(self, *args: object) -> int:  # noqa: N802
            handle_ptr = args[3]
            handle_ptr._obj.value = 42  # type: ignore[attr-defined]
            return 0

        def C_DestroyObject(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_CloseSession(self, *args: object) -> int:  # noqa: N802
            return 0

        def C_Finalize(self, _args: object) -> int:  # noqa: N802
            finalized.append(True)
            return 0

    def boom() -> int:
        raise AssertionError("isolation must spawn, never fork")

    monkeypatch.setattr(os, "fork", boom, raising=False)
    monkeypatch.delenv("_P11CHECK_PIN", raising=False)
    monkeypatch.setattr(subprocess_safety_probe, "get_slot_ids", lambda _raw: [7])
    monkeypatch.setattr(subprocess_safety_probe, "open_session", lambda *_a: 11)

    child_stdout = "CHILD_PHASE:Find\nCHILD_FOUND:0\n"

    class _Proc:
        returncode: int | None = 0xC0000005

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            return child_stdout, ""

    monkeypatch.setattr(
        subprocess_safety_probe,
        "subprocess",
        SimpleNamespace(
            Popen=lambda *a, **k: _Proc(),
            TimeoutExpired=subprocess.TimeoutExpired,
            PIPE=subprocess.PIPE,
        ),
    )

    def emit(*args: object, **_kwargs: object) -> None:
        events.append(str(args[0]))

    monkeypatch.setattr(subprocess_safety_probe, "print", emit, raising=False)
    subprocess_safety_probe._session_object_isolation(
        cast(
            ProbeContext,
            SimpleNamespace(
                raw=_Raw(),
                sh=None,
                slot_id=0,
                cleanup=lambda: None,
                module_path="/tmp/provider.so",
                interface="auto",
            ),
        ),
        {},
    )
    assert "CHILD_PHASE:Find" in events
    assert "CHILD_FOUND:0" in events
    assert not [line for line in events if line.startswith(("CHILD_EXIT:", "CHILD_SIGNAL:"))]
    assert finalized == [True]
