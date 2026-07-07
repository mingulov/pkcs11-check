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

# Cache the returned pointer to ensure idempotence: a second call returns the exact
# same pointer without re-allocating.
_honeypot_ptr: ctypes.POINTER(ctypes.c_ubyte) | None = None  # type: ignore[valid-type]


class HoneypotUnavailable(RuntimeError):  # noqa: N818
    """The demand-zero buffer cannot be allocated on this platform/run.

    str(self) is suitable to print after SETUP_XFAIL_PREFIX.
    """


def demand_zero_buffer() -> ctypes.POINTER(ctypes.c_ubyte):  # type: ignore[valid-type]
    """Return a pointer into a large demand-zero mapping (reads as 0 far past any heap).

    Raises HoneypotUnavailable on non-POSIX (no MAP_ANONYMOUS) or if every size fails.
    Idempotent: all calls return the exact same pointer (same process-lifetime mapping).
    """
    global _honeypot_mapping, _honeypot_ptr
    if not hasattr(mmap, "MAP_ANONYMOUS"):
        raise HoneypotUnavailable(
            "demand-zero honeypot needs POSIX mmap (unavailable on this platform)"
        )
    if _honeypot_ptr is not None:
        return _honeypot_ptr
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    flags |= getattr(mmap, "MAP_NORESERVE", 0)
    last_exc: OSError | ValueError | None = None
    for size in _HONEYPOT_SIZES:
        try:
            mm = mmap.mmap(-1, size, flags=flags)
        except (OSError, ValueError) as exc:  # ValueError: size too large for this build
            last_exc = exc
            continue
        _honeypot_mapping = mm
        one = (ctypes.c_ubyte * 1).from_buffer(mm)
        _honeypot_ptr = ctypes.cast(one, ctypes.POINTER(ctypes.c_ubyte))
        return _honeypot_ptr
    raise HoneypotUnavailable(f"demand-zero honeypot allocation failed: {last_exc}")
