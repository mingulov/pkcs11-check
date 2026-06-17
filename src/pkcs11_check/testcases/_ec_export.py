"""EC public-key export and curve-aware raw-ECDSA split helpers."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT


class MalformedSignature(ValueError):  # noqa: N818
    """Raw ECDSA signature whose length does not equal 2 * coord_len."""


def coord_len_for_curve(curve: ec.EllipticCurve) -> int:
    """Return the byte length of one coordinate for *curve*."""
    return (curve.key_size + 7) // 8


def split_raw_ecdsa(sig: bytes, coord_len: int) -> tuple[int, int]:
    """Split a raw (r || s) ECDSA signature into (r, s) as big-endian integers.

    Raises MalformedSignature if len(sig) != 2 * coord_len.
    """
    if len(sig) != 2 * coord_len:
        raise MalformedSignature(
            f"Expected {2 * coord_len} bytes for raw ECDSA (coord_len={coord_len}), got {len(sig)}"
        )
    r = int.from_bytes(sig[:coord_len], "big")
    s = int.from_bytes(sig[coord_len:], "big")
    return r, s


def read_ec_public_key_or_xfail(
    rs: Any,
    handle: int,
    curve: ec.EllipticCurve,
    *,
    label: str = "EC public key",
) -> ec.EllipticCurvePublicKey:
    """Read CKA_EC_POINT from *handle* and construct a cryptography public key.

    xfails (not_operational / metadata) on any attribute-read or decoding failure.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    except AssertionError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: cannot read CKA_EC_POINT: {exc}",
        )

    ec_point = attrs[CKA_EC_POINT]
    if not isinstance(ec_point, bytes) or not ec_point:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: CKA_EC_POINT is missing or not bytes: {ec_point!r}",
        )

    try:
        point_bytes = decode_ec_point(ec_point)
    except ValueError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: cannot decode CKA_EC_POINT DER: {exc}",
        )

    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point_bytes)
    except Exception as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: cannot construct EC public key from point: {exc}",
        )
