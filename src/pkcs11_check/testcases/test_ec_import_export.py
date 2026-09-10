"""EC key import/export round-trip tests.

Tests importing raw EC public keys (CKA_EC_POINT + CKA_EC_PARAMS),
exporting EC points from generated keys, and verifying round-trip
functionality (generate -> export -> import -> use).
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    import_ec_public_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_VERIFY,
    CKM_ECDSA,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._ec_export import (
    InvalidProviderECPointError,
    ProviderECPointEncodingError,
    decode_provider_ec_point,
)
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_EC_PUBLIC_IMPORT_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_EC_POINT_SPEC_REF = "PKCS#11 v3.2"
_EC_POINT_EXPECTED_REPRESENTATION = "canonical DER OCTET STRING containing SEC1"
_EC_POINT_RAW_REPRESENTATION = "raw uncompressed SEC1"
_CURVES: dict[str, ec.EllipticCurve] = {
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}

_KIND_PRIORITY = {"metadata": 1, "crypto": 2}


@dataclass(frozen=True)
class _ECPointObservation:
    """A successfully decoded conventional-EC point and its provider bytes."""

    exported: bytes
    decoded: bytes
    strict_deviation: C.Classification | None = None


def _attribute_detail(attr: int, curve: ec.EllipticCurve) -> dict[str, Any]:
    names = {int(CKA_EC_POINT): "CKA_EC_POINT", int(CKA_EC_PARAMS): "CKA_EC_PARAMS"}
    return {
        "attribute": {"name": names[int(attr)], "id": int(attr)},
        "curve": curve.name,
    }


def _record_attribute_shape(
    value: object,
    *,
    attr: int,
    curve: ec.EllipticCurve,
    label: str,
    strict: bool = False,
) -> C.Classification | None:
    if value is MISSING_ATTRIBUTE:
        return None
    if isinstance(value, bytes) and value:
        return None
    return C.record_as(
        "wrong_result" if strict else "not_operational",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        summary=(
            f"{label}: expected a non-empty bytes value, got "
            f"{type(value).__name__ if not isinstance(value, bytes) else 'empty bytes'}"
        ),
        detail=_attribute_detail(attr, curve),
    )


def _read_export_attributes(
    rs: Any,
    handle: int,
    curve: ec.EllipticCurve,
    *,
    label: str,
) -> tuple[object, object, list[C.Classification]]:
    """Read point and parameters while retaining presence and exact bytes."""
    before = len(C.get_records())
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    except CkrAssertionError as exc:
        if exc.rv not in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
            raise
        record = C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            actual=exc.rv,
            summary=f"{label}: cannot read EC export attributes: {exc}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )
        return MISSING_ATTRIBUTE, MISSING_ATTRIBUTE, [record]

    point = attr_or_record(
        attrs,
        CKA_EC_POINT,
        label=f"{label}:CKA_EC_POINT",
        reason="not_operational",
    )
    params = attr_or_record(
        attrs,
        CKA_EC_PARAMS,
        label=f"{label}:CKA_EC_PARAMS",
        reason="not_operational",
    )
    records = C.get_records()[before:]
    _record_attribute_shape(
        point,
        attr=CKA_EC_POINT,
        curve=curve,
        label=f"{label}:CKA_EC_POINT",
    )
    _record_attribute_shape(
        params,
        attr=CKA_EC_PARAMS,
        curve=curve,
        label=f"{label}:CKA_EC_PARAMS",
    )
    # ``C.record_as`` has already retained each shape result in the global
    # collector; return the exact local slice without duplicating records.
    records = C.get_records()[before:]
    for record in records:
        if record.detail is None:
            continue
        attribute = record.detail.get("attribute")
        if isinstance(attribute, dict) and attribute.get("id") == int(CKA_EC_PARAMS):
            attribute["name"] = "CKA_EC_PARAMS"
    return point, params, records


def _read_point_attribute(
    rs: Any,
    handle: int,
    curve: ec.EllipticCurve,
    *,
    label: str,
    strict: bool = False,
) -> tuple[object, list[C.Classification]]:
    """Read one point with explicit refusal routing and presence semantics."""
    before = len(C.get_records())
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    except CkrAssertionError as exc:
        if exc.rv not in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
            raise
        C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            actual=exc.rv,
            summary=f"{label}: cannot read CKA_EC_POINT: {exc}",
            detail=_attribute_detail(CKA_EC_POINT, curve),
        )
        return MISSING_ATTRIBUTE, C.get_records()[before:]
    if CKA_EC_POINT not in attrs:
        C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            actual=None,
            mechanism=None,
            summary=f"{label}: attribute unavailable",
            detail=_attribute_detail(CKA_EC_POINT, curve),
        )
        return MISSING_ATTRIBUTE, C.get_records()[before:]
    value = attrs[CKA_EC_POINT]
    _record_attribute_shape(value, attr=CKA_EC_POINT, curve=curve, label=label, strict=strict)
    return value, C.get_records()[before:]


def _read_params_attribute(
    rs: Any,
    handle: int,
    curve: ec.EllipticCurve,
    *,
    label: str,
    strict: bool = False,
) -> tuple[object, list[C.Classification]]:
    """Read one CKA_EC_PARAMS value with explicit refusal routing and presence semantics."""
    before = len(C.get_records())
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_PARAMS])
    except CkrAssertionError as exc:
        if exc.rv not in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
            raise
        C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            actual=exc.rv,
            summary=f"{label}: cannot read CKA_EC_PARAMS: {exc}",
            detail=_attribute_detail(CKA_EC_PARAMS, curve),
        )
        return MISSING_ATTRIBUTE, C.get_records()[before:]
    if CKA_EC_PARAMS not in attrs:
        C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            actual=None,
            mechanism=None,
            summary=f"{label}: attribute unavailable",
            detail=_attribute_detail(CKA_EC_PARAMS, curve),
        )
        return MISSING_ATTRIBUTE, C.get_records()[before:]
    value = attrs[CKA_EC_PARAMS]
    _record_attribute_shape(value, attr=CKA_EC_PARAMS, curve=curve, label=label, strict=strict)
    return value, C.get_records()[before:]


def _decode_point(
    value: object,
    curve: ec.EllipticCurve,
    *,
    label: str,
    strict: bool,
) -> tuple[_ECPointObservation | None, C.Classification | None]:
    """Decode one conventional point, separating representation from validity."""
    if value is MISSING_ATTRIBUTE or not isinstance(value, bytes) or not value:
        return None, None
    try:
        decoded = decode_provider_ec_point(value, curve, label=label)
    except ProviderECPointEncodingError as exc:
        return (
            None,
            C.record_as(
                "wrong_result" if strict else "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                summary=f"{label}: cannot decode CKA_EC_POINT: {exc}",
                detail=_attribute_detail(CKA_EC_POINT, curve),
            ),
        )
    except InvalidProviderECPointError as exc:
        return (
            None,
            C.record_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation="C_GetAttributeValue",
                summary=f"{label}: provider returned an invalid CKA_EC_POINT: {exc}",
                detail=_attribute_detail(CKA_EC_POINT, curve),
            ),
        )

    deviation: C.Classification | None = None
    if strict and value == decoded:
        detail = _attribute_detail(CKA_EC_POINT, curve)
        detail.update(
            {
                "expected": _EC_POINT_EXPECTED_REPRESENTATION,
                "actual": _EC_POINT_RAW_REPRESENTATION,
                "spec_ref": _EC_POINT_SPEC_REF,
            }
        )
        deviation = C.record_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            spec_ref=_EC_POINT_SPEC_REF,
            summary=(
                f"{label}: CKA_EC_POINT uses raw uncompressed SEC1; "
                "PKCS#11 requires the canonical DER OCTET STRING representation"
            ),
            detail=detail,
        )
    return _ECPointObservation(value, decoded, deviation), None


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest retained classification after independent checks."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            1 if record.outcome == "fail" else 0,
            _KIND_PRIORITY.get(record.kind or "", 0),
        ),
    )
    C.raise_for_record(strongest)


def _destroy_handles(rs: Any, *handles: int) -> None:
    """Destroy all returned handles, preserving access violations and first error."""
    first_error: BaseException | None = None
    access_violation: BaseException | None = None
    for handle in handles:
        if not handle:
            continue
        try:
            destroy_quietly(rs.raw, rs.sh, handle)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
            if ctypes_access_violation_code(exc) is not None:
                access_violation = exc
    if access_violation is not None:
        raise access_violation
    if first_error is not None:
        raise first_error


def _make_ec_keypair(rs: Any, curve_name: str) -> tuple[int, int]:
    """Generate EC keypair, skip if curve unsupported."""
    curve_oid = encode_named_curve_parameters(curve_name)
    try:
        return gen_ec_keypair(rs.raw, rs.sh, curve_oid)
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip(f"Curve {curve_name} not supported")
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            f"EC key generation advertised but {curve_name} keygen is not operational",
        )
        raise


class TestECPublicKeyImport:
    """Test importing raw EC public keys."""

    @pytest.mark.parametrize("curve_name", ["secp256r1", "secp384r1", "secp521r1"])
    def test_generate_export_import_verify(self, p11_raw_session: Any, curve_name: str) -> None:
        """Generate EC key -> export public point -> import -> verify signature."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        curve = _CURVES[curve_name]
        pub, priv = _make_ec_keypair(rs, curve_name)
        imported_pub = 0
        try:
            # Export public point and params
            ec_point_value, ec_params_value, records = _read_export_attributes(
                rs, pub, curve, label=f"EC import/export {curve_name}"
            )
            point_observation, point_error = _decode_point(
                ec_point_value,
                curve,
                label=f"EC import/export {curve_name}",
                strict=False,
            )
            if point_error is not None:
                records.append(point_error)
            if point_observation is None:
                _raise_strongest(records)
                return
            if ec_point_value is MISSING_ATTRIBUTE:
                _raise_strongest(records)
                return
            if not isinstance(ec_point_value, bytes) or not ec_point_value:
                _raise_strongest(records)
                return
            if (
                ec_params_value is MISSING_ATTRIBUTE
                or not isinstance(ec_params_value, bytes)
                or not ec_params_value
            ):
                _raise_strongest(records)
                return

            # Sign with original private key
            data = b"round-trip test data for ECDSA"
            digest = hashlib.sha256(data).digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            if not isinstance(sig, bytes) or not sig:
                record = C.record_as(
                    "wrong_result",
                    kind="crypto",
                    label=f"EC import/export {curve_name}: signature",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                    summary="EC import/export: C_Sign returned an empty signature",
                )
                _raise_strongest([*records, record])
                return

            # Import the exported public key as a new object
            try:
                imported_pub = import_ec_public_key(
                    rs.raw,
                    rs.sh,
                    ec_params=ec_params_value,
                    ec_point=ec_point_value,
                    attrs={CKA_VERIFY: True},
                )
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _EC_PUBLIC_IMPORT_REJECT_RVS,
                    f"EC public key import not operational for {curve_name}",
                )

            # Verify signature with imported key
            verified = verify_single(rs.raw, rs.sh, imported_pub, CKM_ECDSA, digest, sig)
            if verified is not True:
                record = C.record_as(
                    "wrong_result",
                    kind="crypto",
                    label=f"EC import/export {curve_name}: verification",
                    operation="C_Verify",
                    mechanism="CKM_ECDSA",
                    summary="EC import/export: C_Verify rejected a signature from the paired key",
                )
                _raise_strongest([*records, record])
                return
            _raise_strongest(records)
        finally:
            _destroy_handles(rs, imported_pub, pub, priv)


class TestECPointExport:
    """Test EC point export consistency."""

    @pytest.mark.parametrize("curve_name", ["secp256r1", "secp384r1", "secp521r1"])
    def test_ec_point_has_canonical_provider_representation(
        self, p11_raw_session: Any, curve_name: str
    ) -> None:
        """Exported conventional EC point uses a legal SEC1 form and wrapper.

        This is a pure representation/shape check: it only needs
        C_GenerateKeyPair, not an operational ECDSA sign/verify mechanism.
        """
        rs = p11_raw_session
        curve = _CURVES[curve_name]
        pub, priv = _make_ec_keypair(rs, curve_name)
        try:
            value, records = _read_point_attribute(
                rs, pub, curve, label=f"EC point representation {curve_name}", strict=True
            )
            observation, error = _decode_point(
                value, curve, label=f"EC point representation {curve_name}", strict=True
            )
            if error is not None:
                records.append(error)
            if observation is not None and observation.strict_deviation is not None:
                records.append(observation.strict_deviation)
            _raise_strongest(records)
        finally:
            _destroy_handles(rs, pub, priv)

    @pytest.mark.parametrize("curve_name", ["secp256r1", "secp384r1", "secp521r1"])
    def test_ec_params_is_present(self, p11_raw_session: Any, curve_name: str) -> None:
        """CKA_EC_PARAMS is present and non-empty for the generated key.

        A separate node from ``test_ec_point_has_canonical_provider_representation`` so point and
        params representation checks are independent pytest items; this is a
        pure representation/shape check and needs no operational ECDSA
        mechanism.
        """
        rs = p11_raw_session
        curve = _CURVES[curve_name]
        pub, priv = _make_ec_keypair(rs, curve_name)
        try:
            _value, records = _read_params_attribute(
                rs, pub, curve, label=f"EC params representation {curve_name}", strict=True
            )
            _raise_strongest(records)
        finally:
            _destroy_handles(rs, pub, priv)

    def test_two_keypairs_different_points(self, p11_raw_session: Any) -> None:
        """Two independently generated keypairs have different public points."""
        rs = p11_raw_session
        pub1, priv1 = _make_ec_keypair(rs, "secp256r1")
        pub2 = priv2 = 0
        try:
            pub2, priv2 = _make_ec_keypair(rs, "secp256r1")
            curve = ec.SECP256R1()
            observations: list[_ECPointObservation] = []
            records: list[C.Classification] = []
            for handle in (pub1, pub2):
                value, read_records = _read_point_attribute(
                    rs, handle, curve, label="EC point uniqueness"
                )
                records.extend(read_records)
                observation, error = _decode_point(
                    value, curve, label="EC point uniqueness", strict=False
                )
                if observation is not None:
                    observations.append(observation)
                if error is not None:
                    records.append(error)
            if len(observations) == 2:
                first = ec.EllipticCurvePublicKey.from_encoded_point(curve, observations[0].decoded)
                second = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve, observations[1].decoded
                )
                if first.public_numbers() == second.public_numbers():
                    records.append(
                        C.record_as(
                            "wrong_result",
                            kind="crypto",
                            label="EC point uniqueness",
                            operation="C_GetAttributeValue",
                            summary=(
                                "EC point uniqueness: two keypairs returned the same public point"
                            ),
                        )
                    )
            _raise_strongest(records)
        finally:
            _destroy_handles(rs, pub1, priv1, pub2, priv2)
