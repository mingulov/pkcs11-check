"""EC public-key export and curve-aware raw-ECDSA split helpers."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr


class MalformedSignature(ValueError):  # noqa: N818
    """Raw ECDSA signature whose length does not equal 2 * coord_len."""


class ProviderECPointEncodingError(ValueError):
    """Provider CKA_EC_POINT is not a supported conventional encoding."""


class InvalidProviderECPointError(ValueError):
    """Provider CKA_EC_POINT does not identify a point on the expected curve."""


def coord_len_for_curve(curve: ec.EllipticCurve) -> int:
    """Return the byte length of one coordinate for *curve*."""
    return (curve.key_size + 7) // 8


def decode_provider_ec_point(
    data: bytes,
    curve: ec.EllipticCurve,
    *,
    label: str,
) -> bytes:
    """Decode a provider-returned conventional EC point for operational use.

    Exact-length uncompressed SEC1 is recognized before DER because a valid raw
    coordinate may also look like a DER length. Other inputs must be a strict DER
    OCTET STRING containing compressed or uncompressed SEC1. This helper does not
    classify the provider's representation; its caller owns that policy decision.
    """
    expected_raw_len = 1 + 2 * coord_len_for_curve(curve)
    if len(data) == expected_raw_len and data.startswith(b"\x04"):
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
        except ValueError as exc:
            raise InvalidProviderECPointError(
                f"{label}: raw CKA_EC_POINT is not on {curve.name}: {exc}"
            ) from exc
        return data

    try:
        point = decode_ec_point(data)
    except ValueError as exc:
        raise ProviderECPointEncodingError(
            f"{label}: CKA_EC_POINT is neither exact raw uncompressed SEC1 "
            f"nor canonical DER: {exc}"
        ) from exc

    try:
        ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
    except ValueError as exc:
        raise InvalidProviderECPointError(
            f"{label}: wrapped CKA_EC_POINT is not on {curve.name}: {exc}"
        ) from exc
    return point


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
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID),
            f"{label}: cannot read CKA_EC_POINT",
        )

    if CKA_EC_POINT not in attrs:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            summary=f"{label}: CKA_EC_POINT attribute unavailable",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
            },
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
        point_bytes = decode_provider_ec_point(ec_point, curve, label=label)
    except ProviderECPointEncodingError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: cannot decode CKA_EC_POINT: {exc}",
        )
    except InvalidProviderECPointError as exc:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            summary=f"{label}: provider returned an off-curve CKA_EC_POINT: {exc}",
        )

    return ec.EllipticCurvePublicKey.from_encoded_point(curve, point_bytes)
