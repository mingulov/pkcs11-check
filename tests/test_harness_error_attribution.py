"""Meta-tests: a harness-side failure must never be recorded as a provider finding.

Background (GH #9 / #11): the output_length probe measured correctly, printed its
verdict, then raised BufferError in its own cleanup. The child exited 1 and the parent
recorded a ``crash`` finding -- a *fail* attributed to a conforming module. The whole
class is "our Python broke, the provider gets blamed".

The seam is an explicit ``HARNESS_ERROR:`` marker: only the harness itself emits it,
from known harness-side cleanup. Anything without the marker keeps the previous
behaviour, so a genuine module fault (notably a Windows SEH fault, which surfaces as a
catchable OSError and a *positive* exit code, not a signal) can never be hidden by it.
"""

from __future__ import annotations

import pytest

from pkcs11_check.classification import clear, derive_verdict, get_records
from pkcs11_check.testcases._probes._emit import (
    HARNESS_ERROR_MARKER,
    cleanup_guard,
    emit_harness_error,
)
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed


@pytest.fixture(autouse=True)
def _clean_records() -> None:
    clear()


def test_harness_error_is_a_fail_but_its_own_reason() -> None:
    """It must be loud (fail), and distinguishable from a provider crash."""
    assert derive_verdict("harness_error", None) == ("fail", "HIGH")
    assert derive_verdict("crash", None)[0] == "fail"


def test_marked_child_failure_is_not_blamed_on_the_provider() -> None:
    stderr = 'File "output_length.py", line 220, in _run_oracle\nBufferError: cannot close'
    with pytest.raises(pytest.fail.Exception):
        assert_subprocess_completed(
            1,
            f"TARGET_RV:0x00000021\n{HARNESS_ERROR_MARKER}BufferError: cannot close",
            stderr,
            context="C_Encrypt(AES_CTR, oversize)",
        )

    reasons = [r.reason for r in get_records()]
    assert reasons == ["harness_error"], reasons
    assert "crash" not in reasons
    clear()


def test_cleanup_failure_after_a_measurement_keeps_the_verdict() -> None:
    """Exit 0 + marker: the measurement is valid, the harness bug is still recorded."""
    assert_subprocess_completed(
        0,
        f"TARGET_RV:0x00000021\n{HARNESS_ERROR_MARKER}BufferError: cannot close",
        "",
        context="C_Encrypt(AES_CTR, oversize)",
    )

    records = get_records()
    assert [r.reason for r in records] == ["harness_error"]
    assert records[0].outcome == "fail"
    clear()


def test_unmarked_positive_exit_is_still_a_provider_crash() -> None:
    """Windows SEH: a real module fault arrives as OSError + rc=1, never a signal.

    It carries no marker, so it must keep classifying as a provider crash finding.
    """
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        assert_subprocess_completed(
            1,
            "",
            "OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
            context="C_Sign boundary probe",
        )

    assert [r.reason for r in get_records()] == ["crash"]


def test_signal_crash_is_never_reattributed() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        assert_subprocess_completed(
            -11,
            "",
            f"{HARNESS_ERROR_MARKER}irrelevant",
            context="C_Sign boundary probe",
        )

    assert [r.reason for r in get_records()] == ["crash"]


def test_windows_crash_is_never_reattributed() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        assert_subprocess_completed(
            0xC0000005,
            f"{HARNESS_ERROR_MARKER}earlier cleanup defect",
            "OSError: access violation",
            context="C_Sign boundary probe",
        )

    assert [r.reason for r in get_records()] == ["crash"]


def test_timeout_is_never_reattributed() -> None:
    with pytest.raises(pytest.fail.Exception, match="module hung"):
        assert_subprocess_completed(
            124,
            f"{HARNESS_ERROR_MARKER}earlier cleanup defect",
            SUBPROCESS_TIMEOUT_MARKER,
            context="C_Sign boundary probe",
        )

    assert [r.reason for r in get_records()] == ["crash"]


def test_emit_harness_error_prints_the_marker(capsys: pytest.CaptureFixture[str]) -> None:
    emit_harness_error(BufferError("cannot close exported pointers exist"), phase="mmap release")

    out = capsys.readouterr().out
    assert out.startswith(HARNESS_ERROR_MARKER)
    assert "mmap release" in out
    assert "BufferError" in out
    assert "cannot close exported pointers exist" in out


def test_cleanup_guard_swallows_so_a_printed_measurement_survives(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print("TARGET_RV:0x00000021")
    with cleanup_guard("mmap release"):
        raise BufferError("cannot close exported pointers exist")

    out = capsys.readouterr().out
    assert "TARGET_RV:0x00000021" in out
    assert HARNESS_ERROR_MARKER in out


def test_cleanup_guard_never_swallows_a_module_fault() -> None:
    """OSError at the FFI boundary is the module's doing; it must propagate."""
    with pytest.raises(OSError, match="access violation"):
        with cleanup_guard("mmap release"):
            raise OSError("exception: access violation reading 0xFFFFFFFFFFFFFFFF")
