"""Shared boundary length values for truncation / oversize probes (WS2+)."""

from __future__ import annotations

import ctypes

import pytest

# Whether the host CK_ULONG (= ctypes.c_ulong) is 64-bit. False on Win64 (LLP64, 32-bit
# long). The values below live in (2^32, 2^64): a 32-bit CK_ULONG caller cannot express
# them, and the module-side 64->32 truncation class they probe is only reachable from a
# 64-bit caller -- so gate those whole modules with the mark below. Never silently
# truncate to the low 32 bits (that turns an oversize probe vacuous, hiding findings).
CK_ULONG_IS_64BIT = ctypes.sizeof(ctypes.c_ulong) >= 8

requires_64bit_ck_ulong = pytest.mark.skipif(
    not CK_ULONG_IS_64BIT,
    reason="64->32 truncation/oversize probe needs a 64-bit CK_ULONG caller; the length "
    "is unrepresentable in a 32-bit CK_ULONG (truncating it would hide the finding)",
)

# Truncation-revealing 64-bit lengths: high 32 bits set, low 32 bits 0 or small.
# A 32-bit-truncating provider sees the small low word and proceeds on a tiny/zero
# length; a correct provider rejects the impossible 64-bit length or attempts it.
_2_32 = 1 << 32
TRUNCATION_LOW0 = _2_32  # 0x1_0000_0000 — truncates to 0
TRUNCATION_LOW8 = _2_32 + 8  # 0x1_0000_0008 — truncates to 8
TRUNCATION_HIGH_ALL_LOW16 = (0xFFFFFFFF << 32) | 16  # 0xFFFFFFFF_0000_0010 — truncates to 16
# Demand-zero oracle constant (Family B): full-size mmap, probe offset past 32-bit boundary.
OVERSIZE_WRITE_LEN = _2_32 + 8
PROBE_OFFSET = 1 << 20  # 1 MiB — past any 32-bit truncation, inside the full buffer

__all__ = [
    "CK_ULONG_IS_64BIT",
    "OVERSIZE_WRITE_LEN",
    "PROBE_OFFSET",
    "TRUNCATION_HIGH_ALL_LOW16",
    "TRUNCATION_LOW0",
    "TRUNCATION_LOW8",
    "requires_64bit_ck_ulong",
]
