"""S6: Windows NTSTATUS crash-code interpretation in the isolated file runner.

A module crash under Windows kills the unit subprocess with an NTSTATUS exit code
(e.g. 0xC0000005 access violation), not a negative POSIX signal. The runner must
classify those as crashes and name them, or real findings would be mislabeled
"failed". No effect on Linux (signal convention).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.core import _crash_classify, file_runner
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.report.__main__ import crashes_from_results


def test_is_windows_crash_code_recognises_ntstatus_errors() -> None:
    assert _crash_classify._is_windows_crash_code(0xC0000005)  # access violation
    assert _crash_classify._is_windows_crash_code(0xC00000FD)  # stack overflow
    assert _crash_classify._is_windows_crash_code(0xC0000409)  # stack buffer overrun
    assert not _crash_classify._is_windows_crash_code(0)
    assert not _crash_classify._is_windows_crash_code(1)  # ordinary pytest failure
    assert not _crash_classify._is_windows_crash_code(5)


def test_status_from_returncode_windows_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_runner.sys, "platform", "win32")
    assert file_runner._status_from_returncode(0xC0000005) == "crashed"
    assert file_runner._status_from_returncode(1) == "failed"
    assert file_runner._status_from_returncode(0) == "passed"
    assert file_runner._status_from_returncode(124) == "timeout"


def test_status_from_returncode_posix_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_runner.sys, "platform", "linux")
    assert file_runner._status_from_returncode(-11) == "crashed"
    # A Windows NTSTATUS value is just an ordinary nonzero exit on POSIX.
    assert file_runner._status_from_returncode(0xC0000005) == "failed"


def test_crash_classification_names_windows_exception() -> None:
    c = file_runner.crash_classification(returncode=0xC0000005, target="t")
    assert c["detail"]["signal"] == "EXCEPTION_ACCESS_VIOLATION"  # type: ignore[index]


def test_crash_classification_names_posix_signal() -> None:
    c = file_runner.crash_classification(returncode=-11, target="t")
    assert c["detail"]["signal"] == "SIGSEGV"  # type: ignore[index]


def test_report_crash_prefers_structured_windows_execution(tmp_path: Path) -> None:
    observation = build_process_observation("t", "unit", 0, -1073741819, platform="win32")
    path = tmp_path / "results.json"
    path.write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "t",
                        "status": "crashed",
                        "returncode": 1073741824,
                        "executions": [observation],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    crashes = crashes_from_results(path)

    assert crashes[0]["detail"] == {"observation": observation}
