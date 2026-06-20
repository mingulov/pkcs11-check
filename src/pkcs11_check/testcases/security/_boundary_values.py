"""Shared boundary length values for truncation / oversize probes (WS2+)."""

from __future__ import annotations

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
    "TRUNCATION_LOW0",
    "TRUNCATION_LOW8",
    "TRUNCATION_HIGH_ALL_LOW16",
    "OVERSIZE_WRITE_LEN",
    "PROBE_OFFSET",
]
