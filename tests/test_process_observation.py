from __future__ import annotations

import signal
from contextvars import copy_context

import pytest

from pkcs11_check.core.process_observation import (
    SUBPROCESS_ABRUPT_EXIT_MARKER,
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


def test_windows_ctypes_access_violation_in_child_stderr_is_an_exception() -> None:
    termination = termination_from_returncode(
        1,
        platform="win32",
        stderr="Traceback (most recent call last):\nOSError: exception: access violation reading 0",
    )

    assert termination["kind"] == "exception"
    assert termination["raw_code"] == 1
    assert termination["windows_status"] == 0xC0000005


@pytest.mark.parametrize(
    "stderr",
    [
        "OSError: generic provider error",
        "a note mentions access violation but is not a traceback line",
        "Traceback: OSError: exception: access violation reading 0",
    ],
)
def test_windows_stderr_parser_does_not_promote_generic_exit(
    stderr: str,
) -> None:
    termination = termination_from_returncode(1, platform="win32", stderr=stderr)

    assert termination["kind"] == "exit"
    assert termination["windows_status"] is None


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


@pytest.mark.parametrize("returncode", [0, 1, 17])
def test_abrupt_exit_marker_classifies_non_negative_exit_as_abrupt(returncode: int) -> None:
    """A C exit(0) from inside a PKCS#11 call skips finalization like exit(n).

    The launcher appends the abrupt marker only when the child's own finalizer
    never ran, so the marker plus any non-negative code is an abrupt exit --
    including a clean-looking 0.
    """
    stderr = f"noise\n{SUBPROCESS_ABRUPT_EXIT_MARKER}:{returncode}\n"
    assert termination_from_returncode(returncode, platform="linux", stderr=stderr) == {
        "kind": "abrupt_exit",
        "raw_code": returncode,
        "signal_name": None,
        "windows_status": None,
    }


def test_zero_exit_without_abrupt_marker_is_a_plain_exit() -> None:
    """The marker is the only evidence of abruptness; a bare 0 is not."""
    assert termination_from_returncode(0, platform="linux", stderr="") == {
        "kind": "exit",
        "raw_code": 0,
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
