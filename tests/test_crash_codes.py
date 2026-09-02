"""Unit tests for the shared, Windows-aware crash classifier (core/crash_codes.py)."""

from __future__ import annotations

import pytest

from pkcs11_check.core.crash_codes import (
    crash_detail_name,
    ctypes_access_violation_code,
    is_crash_returncode,
)


@pytest.mark.parametrize(
    ("rc", "expected"),
    [
        (None, False),
        (0, False),
        (1, False),  # pytest: tests failed
        (2, False),  # pytest: usage / collection error
        (5, False),  # pytest: no tests collected
        (-11, True),  # SIGSEGV
        (-6, True),  # SIGABRT
        (-9, True),  # SIGKILL
        (0xC0000005, True),  # EXCEPTION_ACCESS_VIOLATION
        (0xC0000374, True),  # STATUS_HEAP_CORRUPTION
        (0xC0000409, True),  # STATUS_STACK_BUFFER_OVERRUN
        (0x40000000, False),  # NTSTATUS with only the top bit set (not error-severity)
    ],
)
def test_is_crash_returncode(rc: int | None, expected: bool) -> None:
    assert is_crash_returncode(rc) is expected


def test_ntstatus_recognized_regardless_of_host() -> None:
    """A positive NTSTATUS crash code is a crash on ANY host (a POSIX exit code can
    never have the top two bits set), so recognition must not gate on sys.platform."""
    assert is_crash_returncode(0xC0000005) is True


def test_crash_detail_name() -> None:
    assert crash_detail_name(-11) == "SIGSEGV"
    assert crash_detail_name(-9) == "signal9"
    assert crash_detail_name(0xC0000005) == "EXCEPTION_ACCESS_VIOLATION"
    assert crash_detail_name(0xC0000005 & 0xFFFFFFFF) == "EXCEPTION_ACCESS_VIOLATION"
    assert crash_detail_name(0xC0DEAD01) == "0xC0DEAD01"
    assert crash_detail_name(3) == "exit3"
    assert crash_detail_name(None) == "unknown"


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (OSError("exception: access violation reading 0xFFFFFFFFFFFFFFFF"), 0xC0000005),
        (OSError("EXCEPTION: ACCESS VIOLATION writing 0"), 0xC0000005),
        (OSError("provider returned an error"), None),
        (RuntimeError("exception: access violation reading 0"), None),
        (None, None),
    ],
)
def test_ctypes_access_violation_parser_is_narrow(
    exc: BaseException | None, expected: int | None
) -> None:
    assert ctypes_access_violation_code(exc) == expected
