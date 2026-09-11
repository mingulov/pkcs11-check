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

from pkcs11_check.classification import (
    HARNESS_REASONS,
    Classification,
    clear,
    derive_verdict,
    get_records,
    record,
)
from pkcs11_check.core.process_observation import SUBPROCESS_ABRUPT_EXIT_MARKER
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


def test_windows_seh_positive_exit_is_still_a_provider_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows SEH: a real module fault arrives as OSError + rc=1, never a signal."""
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        assert_subprocess_completed(
            1,
            "",
            "OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
            context="C_Sign boundary probe",
        )

    assert [r.reason for r in get_records()] == ["crash"]


def test_ordinary_oserror_is_not_windows_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        assert_subprocess_completed(
            1,
            "",
            "OSError: ordinary cleanup failure",
            context="C_Sign boundary probe",
        )

    records = get_records()
    assert [r.reason for r in records] == ["probe_incomplete"]
    assert records[0].detail is not None
    assert records[0].detail["termination"]["kind"] == "exit"


def test_unknown_positive_exit_remains_visible() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 7"):
        assert_subprocess_completed(7, "", "", context="C_Test probe")

    record = get_records()[-1]
    assert record.reason == "probe_incomplete"
    assert record.detail is not None
    assert record.detail["probe_incomplete"] is True
    assert record.detail["termination"] == {
        "kind": "exit",
        "raw_code": 7,
        "signal_name": None,
        "windows_status": None,
    }


def test_provider_measurement_survives_cleanup_error() -> None:
    record(
        Classification(
            reason="oracle",
            outcome="fail",
            severity="HIGH",
            label="C_Test measurement",
            summary="provider returned a measured result",
        )
    )
    assert_subprocess_completed(
        0,
        f"TARGET_RV:0x00000021\n{HARNESS_ERROR_MARKER}BufferError: cannot close",
        "",
        context="C_Test probe",
    )

    assert [r.reason for r in get_records()] == ["oracle", "harness_error"]


def test_signal_crash_is_never_reattributed() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        assert_subprocess_completed(
            -11,
            "",
            f"{HARNESS_ERROR_MARKER}irrelevant",
            context="C_Sign boundary probe",
        )

    assert [r.reason for r in get_records()] == ["crash"]


def test_windows_crash_is_never_reattributed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
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

    records = get_records()
    assert [r.reason for r in records] == ["crash"]
    assert records[0].detail is not None
    assert records[0].detail["termination"]["kind"] == "timeout"
    assert records[0].detail["termination"]["raw_code"] == 124


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


def test_probe_incomplete_is_not_a_harness_reason() -> None:
    """An unresolved attribution must keep counting against the provider.

    ``HARNESS_REASONS`` is a report-level exclusion filter, not a label: membership drops
    a record from the provider fail total and severity sections (report/render.py), from
    the fail buckets (report/health.py), and from cross-provider correlation
    (report/correlate.py). Inferring membership from an exit code we do not recognize
    erased real provider findings -- a module that wrote past a caller-declared output
    length was published as "a defect in this tool, not in the module under test".
    """
    assert "probe_incomplete" not in HARNESS_REASONS
    assert derive_verdict("probe_incomplete", None) == ("fail", "HIGH")


def test_unrecognized_exit_does_not_claim_the_harness_failed() -> None:
    """The inference path may state what is missing, never whose fault it is."""
    with pytest.raises(pytest.fail.Exception, match="Attribution unresolved"):
        assert_subprocess_completed(
            1,
            "",
            "Traceback (most recent call last):\nAssertionError: module wrote past the guard",
            context="C_Decrypt guard probe",
        )

    record = get_records()[-1]
    assert record.reason == "probe_incomplete"
    assert "NOT the module under test" not in (record.summary or "")
    # The child's own evidence has to survive: it is where the answer actually is.
    assert "module wrote past the guard" in (record.summary or "")


def test_explicit_harness_marker_still_earns_the_harness_reason() -> None:
    """Only the harness announcing its own defect may be excluded from provider counts."""
    with pytest.raises(pytest.fail.Exception, match="pkcs11-check itself failed"):
        assert_subprocess_completed(
            1,
            "",
            "HARNESS_ERROR:probe could not build its template",
            context="C_Sign boundary probe",
        )

    record = get_records()[-1]
    assert record.reason == "harness_error"
    assert record.reason in HARNESS_REASONS


def test_module_terminated_process_is_a_crash_not_a_harness_error() -> None:
    """A module that exit()s its host never returned a CK_RV -- that is a crash finding.

    Observed with SoftHSM2: C_Digest with an un-honorable length builds a ByteString,
    SecureAllocator::allocate throws std::bad_alloc, and SoftHSM's own catch(...) calls
    FatalException() -> exit(5). stdout and stderr are both empty because its only
    logging path is syslog and CPython finalization never runs.
    """
    with pytest.raises(pytest.fail.Exception, match="terminated the calling process"):
        assert_subprocess_completed(
            5,
            "",
            f"\n{SUBPROCESS_ABRUPT_EXIT_MARKER}:5\n",
            context="C_Digest(ulDataLen=0x7fffffffffffffff)",
        )

    record = get_records()[-1]
    assert record.reason == "crash"
    assert record.reason not in HARNESS_REASONS
    assert record.detail is not None
    assert record.detail["termination"]["kind"] == "abrupt_exit"


def test_positive_exit_without_the_marker_is_never_a_crash() -> None:
    """The marker is the only evidence of abruptness; a bare exit code is not."""
    with pytest.raises(pytest.fail.Exception, match="Attribution unresolved"):
        assert_subprocess_completed(5, "", "", context="C_Digest probe")

    assert get_records()[-1].reason == "probe_incomplete"
