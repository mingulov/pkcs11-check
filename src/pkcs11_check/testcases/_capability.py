# src/pkcs11_check/testcases/_capability.py
"""Capability classifier: turn CK_MECHANISM_INFO into a single verdict.

One read-only source of truth used by both the in-range guardrail
(``skip_unless_capability``) and the over-delivery probe
(``test_capability_boundary``). No provider identity, no calibration.

Key-size comparison is in the mechanism's NATIVE CK_MECHANISM_INFO unit
(PKCS#11: RSA/EC report bits, AES/DES report bytes). The caller passes
``key_size`` in that native unit; no conversion happens here.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pkcs11_check.raw.api import ckm_name
from pkcs11_check.raw.recipes import get_mechanism_info
from pkcs11_check.raw.rv import CkrAssertionError


class Capability(Enum):
    """Verdict of an advertised-capability check for a (mechanism, size, op)."""

    NOT_ADVERTISED = "not_advertised"  # mechanism absent from C_GetMechanismList
    FLAG_UNSET = "flag_unset"  # advertised, but the operation flag is clear
    OUT_OF_RANGE = "out_of_range"  # key_size outside advertised [min, max]
    IN_RANGE = "in_range"  # advertised, flagged, and in range


# Module-level cache keyed (id(raw), slot_id, mechanism), mirroring fixtures._MECHANISM_CACHE.
_INFO_CACHE: dict[tuple[int, int, int], dict[str, int] | None] = {}


def reset_capability_cache() -> None:
    """Test hook: forget cached C_GetMechanismInfo reads."""
    _INFO_CACHE.clear()


def _cached_info(rs: Any, mechanism: int) -> dict[str, int] | None:
    key = (id(rs.raw), int(rs.slot_id), int(mechanism))
    if key not in _INFO_CACHE:
        try:
            _INFO_CACHE[key] = get_mechanism_info(rs.raw, rs.slot_id, mechanism)
        except CkrAssertionError:
            # Advertised but C_GetMechanismInfo errored: we cannot prove a range.
            _INFO_CACHE[key] = None
    return _INFO_CACHE[key]


def capability_for(
    rs: Any,
    mechanism: int,
    *,
    key_size: int | None = None,
    operation: int | None = None,
) -> Capability:
    """Classify a (mechanism, key_size, operation) against CK_MECHANISM_INFO.

    ``operation`` is a ``CKF_*`` flag. ``key_size`` is in the mechanism's native
    unit (RSA/EC bits, AES/DES bytes). Returns a :class:`Capability`.
    """
    if not rs.has_mechanism(ckm_name(int(mechanism))):
        return Capability.NOT_ADVERTISED
    info = _cached_info(rs, int(mechanism))
    if info is None:
        return Capability.IN_RANGE  # never gate out on missing info
    if operation is not None and (int(info["flags"]) & int(operation)) == 0:
        return Capability.FLAG_UNSET
    if key_size is not None:
        lo, hi = int(info["min_key_size"]), int(info["max_key_size"])
        if (lo, hi) != (0, 0) and not (lo <= int(key_size) <= hi):
            return Capability.OUT_OF_RANGE
    return Capability.IN_RANGE
