"""Shared routing for fixed and truncated Wycheproof HMAC vectors."""

from __future__ import annotations

from dataclasses import dataclass

from pkcs11_check.raw.pack import PackedMechanism, mech_ulong
from pkcs11_check.raw.types_std import CKM


@dataclass(frozen=True)
class HmacRoute:
    """The mechanism and optional parameter for one HMAC verification."""

    mechanism: CKM | int
    display_name: str
    mech_param: PackedMechanism | None


def hmac_tag_size_bytes(tag_size_bits: int, *, digest_size: int) -> int:
    """Validate a Wycheproof group tag size and return whole bytes."""
    if (
        isinstance(tag_size_bits, bool)
        or not isinstance(tag_size_bits, int)
        or tag_size_bits <= 0
        or tag_size_bits % 8
    ):
        raise ValueError("Wycheproof HMAC group tagSize must be a positive byte-aligned bit count")
    tag_size = tag_size_bits // 8
    if tag_size > digest_size:
        raise ValueError(
            f"expected HMAC tag size must be between 1 and {digest_size} bytes, got {tag_size}"
        )
    return tag_size


def route_hmac_mechanism(
    *,
    expected_tag_size: int,
    digest_size: int,
    fixed_mechanism: CKM | int,
    fixed_name: str,
    general_mechanism: CKM | int,
    general_name: str,
) -> HmacRoute:
    """Select fixed HMAC or HMAC_GENERAL from the vector group tag size.

    The supplied signature is intentionally not inspected here.  Wycheproof
    malformed-tag vectors must reach C_Verify unchanged, while the group
    ``tagSize`` determines whether the operation needs HMAC_GENERAL.
    """
    if not 1 <= expected_tag_size <= digest_size:
        raise ValueError(
            f"expected HMAC tag size must be between 1 and {digest_size} bytes, "
            f"got {expected_tag_size}"
        )
    if expected_tag_size == digest_size:
        return HmacRoute(fixed_mechanism, fixed_name, None)
    return HmacRoute(
        general_mechanism,
        general_name,
        mech_ulong(general_mechanism, expected_tag_size),
    )
