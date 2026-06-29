"""The single demand-zero honeypot buffer (Invariant I2).

A buffer-honest backing for oversized-length probes: a probe that claims a length
larger than any heap buffer must, to separate a real overflow from a module correctly
honoring a large-but-valid length, be backed by a demand-zero mapping (docs/probe-
soundness.md). This is the one guarded implementation; all former inline copies call it.
"""

from __future__ import annotations

import ctypes
import mmap

SETUP_XFAIL_PREFIX = "SETUP_XFAIL:"

# Demand-zero mmap sizes: try 1 TiB down to 1 GiB. MAP_NORESERVE (Linux) reserves no
# swap; the mapping outlasts the returned pointer (the OS reclaims it at process exit).
_HONEYPOT_SIZES = (1 << 40, 1 << 38, 1 << 36, 1 << 34, 1 << 32, 1 << 30)

# Module-level ref keeps the mapping alive for the process lifetime (ctypes pointer
# does not own it).
_honeypot_mapping: mmap.mmap | None = None


class HoneypotUnavailable(RuntimeError):  # noqa: N818
    """The demand-zero buffer cannot be allocated on this platform/run.

    str(self) is suitable to print after SETUP_XFAIL_PREFIX.
    """


def demand_zero_buffer() -> ctypes.POINTER(ctypes.c_ubyte):  # type: ignore[valid-type]
    """Return a pointer into a large demand-zero mapping (reads as 0 far past any heap).

    Raises HoneypotUnavailable on non-POSIX (no MAP_ANONYMOUS) or if every size fails.
    """
    global _honeypot_mapping
    if not hasattr(mmap, "MAP_ANONYMOUS"):
        raise HoneypotUnavailable(
            "demand-zero honeypot needs POSIX mmap (unavailable on this platform)"
        )
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    flags |= getattr(mmap, "MAP_NORESERVE", 0)
    last_exc: OSError | None = None
    for size in _HONEYPOT_SIZES:
        try:
            mm = mmap.mmap(-1, size, flags=flags)
        except (OSError, ValueError) as exc:  # ValueError: size too large for this build
            last_exc = exc if isinstance(exc, OSError) else last_exc
            continue
        _honeypot_mapping = mm
        one = (ctypes.c_ubyte * 1).from_buffer(mm)
        return ctypes.cast(one, ctypes.POINTER(ctypes.c_ubyte))
    raise HoneypotUnavailable(f"demand-zero honeypot allocation failed: {last_exc}")
