"""Probe: C_GenerateRandom / C_SeedRandom with oversized (untrusted) lengths.

Untrusted-caller probe: a length larger than the provided buffer must not cause a
memory-safety failure.  The demand-zero honeypot backs the claimed length so a crash is
unconditionally real (docs/probe-soundness.md).  Output protocol is preserved verbatim
for the parent classifier in security/test_random_length_truncation.py.

Dispatch on ``params.extra["which"]``:
  ``"generate"`` — C_GenerateRandom oversized-length probe (prints GENRAND_RV + UNDERFILL)
  ``"seed"``     — C_SeedRandom oversized-length probe (prints SEEDRAND_RV)

Required extra keys:
  ``"which"``   — "generate" or "seed"
  ``"length"``  — integer, the oversized length passed to the C_* function
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# 1 MiB past offset 0 — safely beyond any (int)/(word32) truncation of 0x100000008 (=8).
_PROBE_OFFSET = 1 << 20


def _run_generate_random(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateRandom oversized-length probe.

    Prints ``GENRAND_RV:0x%08x`` unconditionally, then ``UNDERFILL:%d`` (1 if the
    buffer past the 32-bit truncation offset is still zero, 0 if filled) when
    ``rv == CKR_OK``.
    """
    length = int(extra["length"])
    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    rv = ctx.raw.C_GenerateRandom(ctx.sh, buf, length)
    print(f"GENRAND_RV:0x{rv:08x}")

    if rv == CKR_OK:
        # Read 64 bytes at _PROBE_OFFSET via pointer arithmetic.  A truncating module
        # casts the length to 32 bits (low bits = 8), writes 8 bytes, and returns OK
        # — bytes at 1 MiB offset remain demand-zero.  A fully-honoring module fills
        # them with random data.
        addr = ctypes.cast(buf, ctypes.c_void_p).value
        assert addr is not None  # demand_zero_buffer always returns a non-NULL mapping
        sample = bytes((ctypes.c_ubyte * 64).from_address(addr + _PROBE_OFFSET))
        underfill = 1 if sample == b"\x00" * 64 else 0
        print(f"UNDERFILL:{underfill:d}")


def _run_seed_random(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SeedRandom oversized-length probe.

    Prints ``SEEDRAND_RV:0x%08x``.  No UNDERFILL check: seed input cannot be
    inspected post-call.
    """
    length = int(extra["length"])
    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    rv = ctx.raw.C_SeedRandom(ctx.sh, buf, length)
    print(f"SEEDRAND_RV:0x{rv:08x}")


_DISPATCH = {
    "generate": _run_generate_random,
    "seed": _run_seed_random,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"random_length probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
