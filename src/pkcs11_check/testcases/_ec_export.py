"""EC public-key export and curve-aware raw-ECDSA split helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, x448, x25519

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
)


class MalformedSignature(ValueError):  # noqa: N818
    """Raw ECDSA signature whose length does not equal 2 * coord_len."""


class ProviderECPointEncodingError(ValueError):
    """Provider CKA_EC_POINT is not a supported conventional encoding."""


class InvalidProviderECPointError(ValueError):
    """Provider CKA_EC_POINT does not identify a point on the expected curve."""


@dataclass(frozen=True)
class ConventionalECPoint:
    """A validated conventional provider point with both representation views."""

    provider_bytes: bytes
    sec1_bytes: bytes
    public_key: ec.EllipticCurvePublicKey


class RawECPointFamily(StrEnum):
    """Raw public-key family carried by CKA_EC_POINT."""

    X25519 = "x25519"
    X448 = "x448"
    ED25519 = "ed25519"
    ED448 = "ed448"


_RAW_EC_POINT_LENGTHS: dict[RawECPointFamily, int] = {
    RawECPointFamily.X25519: 32,
    RawECPointFamily.X448: 56,
    RawECPointFamily.ED25519: 32,
    RawECPointFamily.ED448: 57,
}

_RAW_EC_POINT_CONSTRUCTORS: dict[RawECPointFamily, Callable[[bytes], Any]] = {
    RawECPointFamily.X25519: x25519.X25519PublicKey.from_public_bytes,
    RawECPointFamily.X448: x448.X448PublicKey.from_public_bytes,
    RawECPointFamily.ED25519: ed25519.Ed25519PublicKey.from_public_bytes,
    RawECPointFamily.ED448: ed448.Ed448PublicKey.from_public_bytes,
}


_VALIDATABLE_CONVENTIONAL_CURVES: tuple[ec.EllipticCurve, ...] = (
    ec.SECP192R1(),
    ec.SECP224R1(),
    ec.SECP256K1(),
    ec.SECP256R1(),
    ec.SECP384R1(),
    ec.SECP521R1(),
    ec.BrainpoolP256R1(),
    ec.BrainpoolP384R1(),
    ec.BrainpoolP512R1(),
)


def coord_len_for_curve(curve: ec.EllipticCurve) -> int:
    """Return the byte length of one coordinate for *curve*."""
    return (curve.key_size + 7) // 8


def _has_sec1_shape_for_curve(point: bytes, curve: ec.EllipticCurve) -> bool:
    coord_len = coord_len_for_curve(curve)
    return (len(point) == 1 + 2 * coord_len and point.startswith(b"\x04")) or (
        len(point) == 1 + coord_len and point.startswith((b"\x02", b"\x03"))
    )


def _alternate_curve_for_point(
    point: bytes,
    expected_curve: ec.EllipticCurve,
) -> ec.EllipticCurve | None:
    """Return an alternate curve only when *point* actually validates on it."""
    for candidate in _VALIDATABLE_CONVENTIONAL_CURVES:
        if candidate.name == expected_curve.name or not _has_sec1_shape_for_curve(point, candidate):
            continue
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(candidate, point)
        except (ValueError, UnsupportedAlgorithm):
            continue
        return candidate
    return None


def parse_provider_ec_point(
    data: bytes,
    curve: ec.EllipticCurve,
    *,
    label: str,
) -> ConventionalECPoint:
    """Parse and validate a provider-returned conventional EC point.

    Exact-length uncompressed SEC1 is recognized before DER because a valid raw
    coordinate may also look like a DER length. Other inputs must be a strict DER
    OCTET STRING containing compressed or uncompressed SEC1. This pure helper does
    not classify the provider's representation; its caller owns that policy decision.
    """
    expected_raw_len = 1 + 2 * coord_len_for_curve(curve)
    if len(data) == expected_raw_len and data.startswith(b"\x04"):
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
        except ValueError as exc:
            raise InvalidProviderECPointError(
                f"{label}: raw CKA_EC_POINT is not on {curve.name}: {exc}"
            ) from exc
        return ConventionalECPoint(data, data, public_key)

    try:
        sec1_bytes = decode_ec_point(data)
    except ValueError as exc:
        raise ProviderECPointEncodingError(
            f"{label}: CKA_EC_POINT is neither exact raw uncompressed SEC1 nor canonical DER: {exc}"
        ) from exc

    if not _has_sec1_shape_for_curve(sec1_bytes, curve):
        alternate_curve = _alternate_curve_for_point(sec1_bytes, curve)
        if alternate_curve is not None:
            raise InvalidProviderECPointError(
                f"{label}: wrapped CKA_EC_POINT validates on {alternate_curve.name}, "
                f"not expected {curve.name}"
            )
        raise ProviderECPointEncodingError(
            f"{label}: canonical DER contains an invalid SEC1 point shape for {curve.name}"
        )

    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, sec1_bytes)
    except ValueError as exc:
        raise InvalidProviderECPointError(
            f"{label}: wrapped CKA_EC_POINT is not on {curve.name}: {exc}"
        ) from exc
    return ConventionalECPoint(data, sec1_bytes, public_key)


def decode_provider_ec_point(
    data: bytes,
    curve: ec.EllipticCurve,
    *,
    label: str,
) -> bytes:
    """Decode a provider point, preserving the historical SEC1-only result."""
    return parse_provider_ec_point(data, curve, label=label).sec1_bytes


def select_ecdh_point_form(
    point: ConventionalECPoint,
    *,
    supports_compressed: bool,
    supports_uncompressed: bool,
) -> bytes:
    """Choose raw SEC1 bytes for ECDH from the provider's validated point.

    If the provider's form is advertised, or capability is unavailable or
    ambiguous, retain the validated provider form. Only an advertised alternate
    form is serialized from the validated public key.
    """
    compressed = point.sec1_bytes.startswith((b"\x02", b"\x03"))
    current_supported = supports_compressed if compressed else supports_uncompressed
    if supports_compressed == supports_uncompressed or current_supported:
        return point.sec1_bytes

    form = (
        serialization.PublicFormat.CompressedPoint
        if supports_compressed
        else serialization.PublicFormat.UncompressedPoint
    )
    return point.public_key.public_bytes(serialization.Encoding.X962, form)


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


def read_conventional_ec_point_or_xfail(
    rs: Any,
    handle: int,
    curve: ec.EllipticCurve,
    *,
    label: str = "EC public key",
) -> ConventionalECPoint:
    """Read and validate a conventional CKA_EC_POINT for an operation.

    Unavailable or malformed representations xfail. A structurally valid point
    that is not on the expected curve is a hard cryptographic failure.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    except CkrAssertionError as exc:
        if exc.rv in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
            xfail_as(
                "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=f"{label}: cannot read CKA_EC_POINT: {exc}",
                detail={
                    "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                    "curve": curve.name,
                },
            )
        raise

    if CKA_EC_POINT in attrs:
        ec_point = attrs[CKA_EC_POINT]
    else:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: CKA_EC_POINT attribute unavailable",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )

    if not isinstance(ec_point, bytes) or not ec_point:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: CKA_EC_POINT is missing or not bytes: {ec_point!r}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )

    try:
        return parse_provider_ec_point(ec_point, curve, label=label)
    except ProviderECPointEncodingError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: cannot decode CKA_EC_POINT: {exc}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )
    except InvalidProviderECPointError as exc:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: provider returned an off-curve CKA_EC_POINT: {exc}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )


def read_ec_public_key_or_xfail(
    rs: Any,
    handle: int,
    curve: ec.EllipticCurve,
    *,
    label: str = "EC public key",
) -> ec.EllipticCurvePublicKey:
    """Read a conventional point and project it to its validated public key."""
    return read_conventional_ec_point_or_xfail(rs, handle, curve, label=label).public_key


def read_raw_ec_point_or_xfail(
    rs: Any,
    handle: int,
    family: RawECPointFamily,
    *,
    label: str,
) -> bytes:
    """Read and validate a raw Montgomery or Edwards public key.

    Raw-family public keys are not SEC1 points and must not be passed through the
    conventional SEC1-shape validation (``parse_provider_ec_point``). A provider may
    still return them DER-wrapped in an OCTET STRING (PKCS#11 v3.0; the tool's own
    importer emits this form) -- that generic unwrap is reused via ``decode_ec_point``
    before a length mismatch is treated as a deviation. The returned bytes are always
    the unwrapped raw point (never re-wrapped) so representation-sensitive callers can
    inspect them separately.
    """
    expected_length = _RAW_EC_POINT_LENGTHS[family]
    detail: dict[str, Any] = {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": expected_length, "actual": None},
    }

    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    except CkrAssertionError as exc:
        if exc.rv in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
            xfail_as(
                "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                actual=exc.rv,
                summary=f"{label}: cannot read CKA_EC_POINT: {exc}",
                detail=detail,
            )
        raise

    if CKA_EC_POINT in attrs:
        ec_point = attrs[CKA_EC_POINT]
    else:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            summary=f"{label}: CKA_EC_POINT attribute unavailable",
            detail=detail,
        )

    if not isinstance(ec_point, bytes):
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            summary=f"{label}: CKA_EC_POINT is not bytes: {ec_point!r}",
            detail=detail,
        )

    actual_length = len(ec_point)
    detail["length"] = {"expected": expected_length, "actual": actual_length}
    if not ec_point:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            summary=f"{label}: CKA_EC_POINT is empty",
            detail=detail,
        )

    representation = "raw"
    if actual_length != expected_length:
        # PKCS#11 v3.0 defines the Edwards/Montgomery CKA_EC_POINT as a DER-encoded
        # OCTET STRING wrapping the RFC 8032/7748 point (later text also sanctions the
        # bare raw form); the tool's own importer emits the DER-wrapped form. Try
        # unwrapping a well-formed OCTET STRING before treating a length mismatch as
        # a deviation -- reusing the same strict decoder as the conventional SEC1 path.
        try:
            unwrapped = decode_ec_point(ec_point)
        except ValueError:
            unwrapped = None
        if unwrapped is not None and len(unwrapped) == expected_length:
            ec_point = unwrapped
            actual_length = expected_length
            representation = "der"
            detail["length"] = {"expected": expected_length, "actual": actual_length}
        else:
            xfail_as(
                "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                summary=(
                    f"{label}: CKA_EC_POINT length {actual_length} does not match "
                    f"{family.value} length {expected_length}"
                ),
                detail=detail,
            )
    detail["representation"] = representation

    try:
        _RAW_EC_POINT_CONSTRUCTORS[family](ec_point)
    except ValueError as exc:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_GetAttributeValue",
            summary=f"{label}: invalid raw {family.value} public key: {exc}",
            detail=detail,
        )

    return ec_point
