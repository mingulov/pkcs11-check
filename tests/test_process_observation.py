from __future__ import annotations

import signal
from contextvars import copy_context

import pytest

from pkcs11_check.core.process_observation import (
    build_process_observation,
    drain_process_observations,
    record_process_observation,
    termination_from_returncode,
)


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="SIGKILL is POSIX-only")
def test_sigkill_is_not_called_oom() -> None:
    observation = build_process_observation(
        target="probe", role="probe", attempt=0, returncode=-9, platform="linux"
    )
    assert observation["termination"] == {
        "kind": "signal",
        "raw_code": -9,
        "signal_name": "SIGKILL",
        "windows_status": None,
    }
    assert observation["oom"] == {"status": "unknown", "sources": []}


def test_windows_exception_keeps_signed_and_unsigned_codes() -> None:
    termination = termination_from_returncode(-1073741819, platform="win32")
    assert termination["kind"] == "exception"
    assert termination["raw_code"] == -1073741819
    assert termination["windows_status"] == 0xC0000005


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [
        (
            0,
            {"kind": "exit", "raw_code": 0, "signal_name": None, "windows_status": None},
        ),
        (
            7,
            {"kind": "exit", "raw_code": 7, "signal_name": None, "windows_status": None},
        ),
        (
            -15,
            {"kind": "signal", "raw_code": -15, "signal_name": "SIGTERM", "windows_status": None},
        ),
        (
            None,
            {"kind": "unknown", "raw_code": None, "signal_name": None, "windows_status": None},
        ),
        (
            -999,
            {"kind": "unknown", "raw_code": -999, "signal_name": None, "windows_status": None},
        ),
    ],
)
def test_termination_preserves_exit_signal_and_unknown_values(
    returncode: int | None, expected: dict[str, object]
) -> None:
    assert termination_from_returncode(returncode, platform="linux") == expected


def test_timeout_owns_termination_kind_but_keeps_raw_code() -> None:
    assert termination_from_returncode(-9, platform="linux", timed_out=True) == {
        "kind": "timeout",
        "raw_code": -9,
        "signal_name": None,
        "windows_status": None,
    }


def test_external_kill_owns_termination_kind_but_keeps_raw_code() -> None:
    assert termination_from_returncode(-9, platform="linux", external_kill=True) == {
        "kind": "external-kill",
        "raw_code": -9,
        "signal_name": None,
        "windows_status": None,
    }


def test_record_and_drain_process_observations_is_context_local() -> None:
    observation = build_process_observation(
        target="probe", role="probe", attempt=0, returncode=0, platform="linux"
    )
    record_process_observation(observation)
    assert drain_process_observations() == [observation]
    assert drain_process_observations() == []


def test_record_in_child_context_does_not_mutate_parent_observations() -> None:
    drain_process_observations()
    observation = build_process_observation(
        target="child", role="probe", attempt=0, returncode=0, platform="linux"
    )
    child_context = copy_context()
    child_context.run(record_process_observation, observation)
    assert drain_process_observations() == []
    assert child_context.run(drain_process_observations) == [observation]
