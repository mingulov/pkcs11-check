"""The single demand-zero honeypot buffer (Invariant I2).

A buffer-honest backing for oversized-length probes: a probe that claims a length
larger than any heap buffer must, to separate a real overflow from a module correctly
honoring a large-but-valid length, be backed by a demand-zero mapping (docs/probe-
soundness.md). This is the one guarded implementation; all former inline copies call it.

A region carries its pointer together with its honestly mapped length, so a caller
can never advertise a readable/writable range larger than the backing it holds:
``demand_zero_region(minimum_length)`` never returns a cached or fallback mapping
smaller than the requested minimum. Explicitly unbacked hostile inputs are marked
``honest=0`` instead; they must never support a provider finding.
"""

from __future__ import annotations

import ctypes
import mmap
from dataclasses import dataclass

SETUP_XFAIL_PREFIX = "SETUP_XFAIL:"

# Demand-zero mmap sizes: try 1 TiB down to 1 GiB. MAP_NORESERVE (Linux) reserves no
# swap; the mapping outlasts the returned pointer (the OS reclaims it at process exit).
_HONEYPOT_SIZES = (1 << 40, 1 << 38, 1 << 36, 1 << 34, 1 << 32, 1 << 30)

# Module-level ref keeps the mapping alive for the process lifetime (ctypes pointer
# does not own it).
_honeypot_mapping: mmap.mmap | None = None

# Honestly mapped length of the cached mapping. Tracked alongside the pointer so a
# later request with a larger minimum can never receive this smaller mapping.
_honeypot_size: int = 0

# Cache the returned pointer to ensure idempotence: a repeat call with a satisfied
# minimum returns the exact same pointer without re-allocating.
_honeypot_ptr: ctypes.POINTER(ctypes.c_ubyte) | None = None  # type: ignore[valid-type]

# Superseded mappings are kept alive for the process lifetime: outstanding pointers
# into them must keep working after a larger minimum installs a new mapping.
_retired_mappings: list[mmap.mmap] = []


@dataclass(frozen=True)
class ZeroRegion:
    """A demand-zero mapping slice: pointer plus honestly mapped length.

    ``mapped_length`` is the number of readable/writable bytes starting at ``ptr``.
    ``honest`` is 1 when the mapping backs the caller's claimed range and 0 only
    for explicitly unbacked hostile inputs (see ``hostile_unbacked_region``),
    which must never support a provider memory-corruption conclusion.
    """

    ptr: ctypes.POINTER(ctypes.c_ubyte)  # type: ignore[valid-type]
    mapped_length: int
    honest: int = 1


class HoneypotUnavailable(RuntimeError):  # noqa: N818
    """The demand-zero buffer cannot be allocated on this platform/run.

    str(self) is suitable to print after SETUP_XFAIL_PREFIX.
    """


def hostile_unbacked_region(
    pointer: ctypes.POINTER(ctypes.c_ubyte),  # type: ignore[valid-type]
) -> ZeroRegion:
    """Mark an explicitly unbacked hostile input (``honest=0``).

    The returned region carries no honest backing (``mapped_length`` 0): the
    caller deliberately passes a pointer/length pair the harness does not back.
    Such an input is an out-of-contract hostile-caller observation only.
    """
    return ZeroRegion(ptr=pointer, mapped_length=0, honest=0)


def demand_zero_region(minimum_length: int = 0) -> ZeroRegion:
    """Return a demand-zero region mapped for at least ``minimum_length`` bytes.

    Reads within ``mapped_length`` return 0 far past any heap buffer. A cached
    mapping is returned only when it already satisfies the minimum; otherwise a
    larger candidate is allocated (the superseded mapping stays alive). Raises
    HoneypotUnavailable on non-POSIX (no MAP_ANONYMOUS), when every candidate
    fails, or when no candidate satisfies the minimum.
    """
    global _honeypot_mapping, _honeypot_size, _honeypot_ptr
    if minimum_length < 0:
        raise ValueError(f"minimum_length must be >= 0, got {minimum_length}")
    if not hasattr(mmap, "MAP_ANONYMOUS"):
        raise HoneypotUnavailable(
            "demand-zero honeypot needs POSIX mmap (unavailable on this platform)"
        )
    if (
        _honeypot_ptr is not None
        and _honeypot_mapping is not None
        and _honeypot_size >= minimum_length
    ):
        return ZeroRegion(ptr=_honeypot_ptr, mapped_length=_honeypot_size, honest=1)
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    flags |= getattr(mmap, "MAP_NORESERVE", 0)
    last_exc: OSError | ValueError | OverflowError | None = None
    for size in _HONEYPOT_SIZES:
        if size < minimum_length:
            continue
        try:
            mm = mmap.mmap(-1, size, flags=flags)
        except (OSError, ValueError, OverflowError) as exc:  # Size too large for this build
            last_exc = exc
            continue
        if _honeypot_mapping is not None:
            _retired_mappings.append(_honeypot_mapping)
        _honeypot_mapping = mm
        _honeypot_size = size
        one = (ctypes.c_ubyte * 1).from_buffer(mm)
        _honeypot_ptr = ctypes.cast(one, ctypes.POINTER(ctypes.c_ubyte))
        return ZeroRegion(ptr=_honeypot_ptr, mapped_length=size, honest=1)
    if last_exc is None:
        raise HoneypotUnavailable(
            f"demand-zero honeypot allocation failed: no candidate satisfies "
            f"minimum {minimum_length} bytes (largest candidate {_HONEYPOT_SIZES[0]} bytes)"
        )
    raise HoneypotUnavailable(f"demand-zero honeypot allocation failed: {last_exc}")


def demand_zero_buffer(
    min_size: int = 0,
) -> ctypes.POINTER(ctypes.c_ubyte):  # type: ignore[valid-type]
    """Return a pointer into a large demand-zero mapping (reads as 0 far past any heap).

    The mapping covers at least ``min_size`` bytes; callers must pass the length
    they are about to advertise to the module. Raises HoneypotUnavailable on
    non-POSIX (no MAP_ANONYMOUS), if every size fails, or if no candidate
    satisfies the minimum. Idempotent per minimum: repeat calls with a satisfied
    minimum return the exact same pointer (same process-lifetime mapping).
    """
    return demand_zero_region(min_size).ptr
