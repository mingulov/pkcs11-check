"""Shared, platform-aware classification of a subprocess exit code as a crash.

A crashing child terminates with a negative POSIX signal on Unix, or a large
positive NTSTATUS exception code (top two bits set, e.g. 0xC0000005 access
violation) on Windows. A POSIX exit code can never have the top two bits set,
so recognizing NTSTATUS crash codes unconditionally is sound on every host and
lets any detector classify a recorded returncode correctly.
"""

from __future__ import annotations

CRASH_SIGNALS: dict[int, str] = {
    -11: "SIGSEGV",
    -6: "SIGABRT",
    -5: "SIGTRAP",
    -4: "SIGILL",
    -8: "SIGFPE",
    -7: "SIGBUS",
}

# Windows NTSTATUS exception codes (the process exit code when a child dies on an
# unhandled exception); the Windows-ABI counterpart of CRASH_SIGNALS.
WINDOWS_EXCEPTION_NAMES: dict[int, str] = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
}


def is_windows_crash_code(returncode: int) -> bool:
    """True for an NTSTATUS exit code with error severity (top two bits set), e.g.
    0xC0000005 (access violation). On Windows an unhandled exception terminates the
    process with such a code instead of a negative POSIX signal."""
    return (returncode & 0xFFFFFFFF) & 0xC0000000 == 0xC0000000


def is_crash_returncode(returncode: int | None) -> bool:
    """True if a subprocess exit code denotes a crash (POSIX signal or Windows NTSTATUS).

    Recognizes NTSTATUS crash codes on any host: a legitimate POSIX exit code is 0..255
    and can never have the top two bits set, so there is no ambiguity to gate on
    sys.platform.
    """
    if returncode is None:
        return False
    if returncode < 0:
        return True
    return is_windows_crash_code(returncode)


def crash_detail_name(returncode: int | None) -> str:
    """Name a crash exit code: POSIX signal (negative) or Windows NTSTATUS (positive)."""
    if returncode is None:
        return "unknown"
    if returncode < 0:
        return CRASH_SIGNALS.get(returncode, f"signal{abs(returncode)}")
    if is_windows_crash_code(returncode):
        u = returncode & 0xFFFFFFFF
        return WINDOWS_EXCEPTION_NAMES.get(u, f"0x{u:08X}")
    return f"exit{returncode}"
