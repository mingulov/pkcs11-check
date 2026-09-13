"""Strict RFC 5869 known-answer test for ``CKM_HKDF_DATA``."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.pack import mech_hkdf
from pkcs11_check.raw.recipes import derive_key, destroy_quietly, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_HKDF_DATA,
    CKM_SHA256,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    IMPORT_STORAGE_SHAPE_REJECTS,
    import_secret_key_negotiated,
)

pytestmark = [pytest.mark.kat, pytest.mark.keymgmt]
REQUIRED_MECHANISMS = ["HKDF_DATA"]

_HKDF_CREATE_REF = "PKCS#11 v3.2 · C_CreateObject"
_HKDF_DERIVE_REF = "PKCS#11 v3.2 · C_DeriveKey · CKM_HKDF_DATA"
_HKDF_READ_REF = "PKCS#11 v3.2 · C_GetAttributeValue"

_DERIVE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
}

# Fixed RFC 5869 HMAC-SHA-256 inputs.  The 32-byte IKM matches the OASIS
# requirement that a CKK_GENERIC_SECRET input equal the underlying hash size.
RFC5869_IKM = bytes(range(32))
RFC5869_SALT = bytes.fromhex("000102030405060708090a0b0c")
RFC5869_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
RFC5869_OKM = bytes.fromhex(
    "194109eabd17e0cb6c156d2bcbb8e54f9aa71ab5cdcf4a730b827c03ee4090f4f15a82b81a3b5856e57c"
)


def _rfc5869_sha256_okm() -> bytes:
    """Compute the fixed RFC5869 answer with an independent HMAC oracle."""
    prk = hmac.new(RFC5869_SALT, RFC5869_IKM, hashlib.sha256).digest()
    previous = b""
    okm = b""
    for counter in range(1, 3):
        previous = hmac.new(
            prk,
            previous + RFC5869_INFO + bytes([counter]),
            hashlib.sha256,
        ).digest()
        okm += previous
    return okm[: len(RFC5869_OKM)]


def _detail(
    *,
    producer_operation: str,
    producer_mechanism: str | None,
    consumer_operation: str,
    consumer_mechanism: str | None,
) -> dict[str, Any]:
    """Return operation provenance for a producer/readback boundary."""
    return {
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
        "consumer_operation": consumer_operation,
        "consumer_mechanism": consumer_mechanism,
    }


def _shape_record(
    *,
    label: str,
    attr: int,
    expected: object,
    actual: object,
    producer_operation: str,
    producer_mechanism: str | None,
    consumer_operation: str = "C_GetAttributeValue",
    consumer_mechanism: str | None = None,
) -> Any:
    """Record a hard metadata finding for malformed object readback."""
    attr_name = {
        int(CKA_CLASS): "CKA_CLASS",
        int(CKA_KEY_TYPE): "CKA_KEY_TYPE",
        int(CKA_VALUE): "CKA_VALUE",
    }.get(attr, f"0x{attr:08x}")
    if attr == int(CKA_VALUE):
        actual_length = len(actual) if hasattr(actual, "__len__") else None
        expected_detail: object = {"type": "bytes", "length": len(RFC5869_OKM)}
        actual_detail: object = {"type": type(actual).__name__, "length": actual_length}
    else:
        expected_detail = expected
        actual_detail = actual
    record = C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        spec_ref=_HKDF_READ_REF,
        summary=f"{label}: provider returned malformed derived-object metadata",
        detail={
            "attribute": {"name": attr_name, "id": int(attr)},
            "expected": expected_detail,
            "actual": actual_detail,
            **_detail(
                producer_operation=producer_operation,
                producer_mechanism=producer_mechanism,
                consumer_operation=consumer_operation,
                consumer_mechanism=consumer_mechanism,
            ),
        },
    )
    return record


def _required_attribute(
    attrs: dict[int, Any],
    attr: int,
    *,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None,
    consumer_operation: str = "C_GetAttributeValue",
    consumer_mechanism: str | None = None,
) -> Any:
    """Return a required attribute and retain missing-readback provenance."""
    value = attr_or_record(
        attrs,
        attr,
        label=label,
        reason="not_operational",
        mechanism=None,
        inherit_mechanism=False,
    )
    if value is not MISSING_ATTRIBUTE:
        return value
    record = C.get_records()[-1]
    if record.detail is None:
        record.detail = {}
    record.detail.update(
        _detail(
            producer_operation=producer_operation,
            producer_mechanism=producer_mechanism,
            consumer_operation=consumer_operation,
            consumer_mechanism=consumer_mechanism,
        )
    )
    return MISSING_ATTRIBUTE


def _raise_for_missing_attribute(values: list[Any], records_before: int) -> None:
    """Terminate on an unavailable attribute after preserving hard mismatches."""
    if not any(value is MISSING_ATTRIBUTE for value in values):
        return
    new_records = C.get_records()[records_before:]
    if not new_records:
        raise AssertionError("HKDF_DATA readback missing attribute produced no record")
    C.raise_for_record(new_records[-1])


def _wrong_value_record(
    actual: Any,
    *,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None,
    expected_value: bytes,
    consumer_operation: str = "C_GetAttributeValue",
    consumer_mechanism: str | None = None,
    reason: str = "wrong_result",
    kind: str = "crypto",
) -> Any:
    """Record a hard crypto finding for an exact expected-value mismatch."""
    record = C.record_as(
        reason,
        kind=kind,
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        spec_ref=_HKDF_READ_REF,
        summary=f"{label}: CKA_VALUE does not match the expected bytes",
        detail={
            "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
            "expected": {"type": "bytes", "length": len(expected_value)},
            "actual": {
                "type": type(actual).__name__,
                "length": len(actual) if hasattr(actual, "__len__") else None,
            },
            **_detail(
                producer_operation=producer_operation,
                producer_mechanism=producer_mechanism,
                consumer_operation=consumer_operation,
                consumer_mechanism=consumer_mechanism,
            ),
        },
    )
    return record


class TestHKDFDataKAT:
    """Strict RFC5869 SHA-256 vector for CKM_HKDF_DATA."""

    def test_rfc5869_sha256(self, p11_raw_session: Any) -> None:
        """CKM_HKDF_DATA returns the fixed RFC5869 OKM as CKO_DATA."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("HKDF_DATA not supported")

        expected = _rfc5869_sha256_okm()
        base_key = 0
        derived = 0
        try:
            try:
                base_key = import_secret_key_negotiated(
                    rs,
                    int(CKK_GENERIC_SECRET),
                    RFC5869_IKM,
                    attrs={
                        CKA_DERIVE: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                    purpose="CKM_HKDF_DATA base-key provisioning",
                )
            except CkrAssertionError as exc:
                if exc.rv not in IMPORT_STORAGE_SHAPE_REJECTS:
                    raise
                C.xfail_as(
                    "not_operational",
                    label="CKM_HKDF_DATA base-key provisioning",
                    operation="C_CreateObject",
                    mechanism=None,
                    inherit_mechanism=False,
                    spec_ref=_HKDF_CREATE_REF,
                    expected=CKR_OK,
                    actual=exc.rv,
                    summary=(
                        "CKM_HKDF_DATA base-key provisioning is not operational "
                        f"({ckr_name(exc.rv)})"
                    ),
                    detail=_detail(
                        producer_operation="C_CreateObject",
                        producer_mechanism=None,
                        consumer_operation="C_DeriveKey",
                        consumer_mechanism="CKM_HKDF_DATA",
                    ),
                )
            if base_key == 0:
                C.fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="CKM_HKDF_DATA base-key handle",
                    operation="C_CreateObject",
                    mechanism=None,
                    inherit_mechanism=False,
                    spec_ref=_HKDF_CREATE_REF,
                    expected="non-zero object handle",
                    actual=base_key,
                    summary="CKM_HKDF_DATA base-key provisioning returned a zero handle",
                    detail=_detail(
                        producer_operation="C_CreateObject",
                        producer_mechanism=None,
                        consumer_operation="C_DeriveKey",
                        consumer_mechanism="CKM_HKDF_DATA",
                    ),
                )

            base_attrs = read_attributes(
                rs.raw, rs.sh, base_key, [CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE]
            )
            base_readback_records_before = len(C.get_records())
            base_class = _required_attribute(
                base_attrs,
                CKA_CLASS,
                label="CKM_HKDF_DATA base-key CKA_CLASS readback",
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            )
            base_key_type = _required_attribute(
                base_attrs,
                CKA_KEY_TYPE,
                label="CKM_HKDF_DATA base-key CKA_KEY_TYPE readback",
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            )
            base_value = _required_attribute(
                base_attrs,
                CKA_VALUE,
                label="CKM_HKDF_DATA base-key CKA_VALUE readback",
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            )
            malformed_base: list[Any] = []
            if base_class is not MISSING_ATTRIBUTE and (
                not isinstance(base_class, int)
                or isinstance(base_class, bool)
                or int(base_class) != int(CKO_SECRET_KEY)
            ):
                malformed_base.append(
                    _shape_record(
                        label="CKM_HKDF_DATA base-key CKA_CLASS readback",
                        attr=int(CKA_CLASS),
                        expected=int(CKO_SECRET_KEY),
                        actual=base_class,
                        producer_operation="C_CreateObject",
                        producer_mechanism=None,
                        consumer_operation="C_DeriveKey",
                        consumer_mechanism="CKM_HKDF_DATA",
                    )
                )
            if base_key_type is not MISSING_ATTRIBUTE and (
                not isinstance(base_key_type, int)
                or isinstance(base_key_type, bool)
                or int(base_key_type) != int(CKK_GENERIC_SECRET)
            ):
                malformed_base.append(
                    _shape_record(
                        label="CKM_HKDF_DATA base-key CKA_KEY_TYPE readback",
                        attr=int(CKA_KEY_TYPE),
                        expected=int(CKK_GENERIC_SECRET),
                        actual=base_key_type,
                        producer_operation="C_CreateObject",
                        producer_mechanism=None,
                        consumer_operation="C_DeriveKey",
                        consumer_mechanism="CKM_HKDF_DATA",
                    )
                )
            if base_value is not MISSING_ATTRIBUTE and (
                type(base_value) is not bytes or base_value != RFC5869_IKM
            ):
                malformed_base.append(
                    _wrong_value_record(
                        base_value,
                        label="CKM_HKDF_DATA base-key CKA_VALUE readback",
                        producer_operation="C_CreateObject",
                        producer_mechanism=None,
                        expected_value=RFC5869_IKM,
                        consumer_operation="C_DeriveKey",
                        consumer_mechanism="CKM_HKDF_DATA",
                    )
                )
            if malformed_base:
                C.raise_for_record(malformed_base[-1])
            _raise_for_missing_attribute(
                [base_class, base_key_type, base_value],
                base_readback_records_before,
            )

            hkdf_param = mech_hkdf(
                CKM_HKDF_DATA,
                hash_mech=CKM_SHA256,
                extract=True,
                expand=True,
                salt=RFC5869_SALT,
                info=RFC5869_INFO,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_HKDF_DATA,
                    attrs={
                        CKA_CLASS: CKO_DATA,
                        CKA_VALUE_LEN: len(expected),
                        CKA_TOKEN: False,
                    },
                    mech_param=hkdf_param,
                )
            except CkrAssertionError as exc:
                if exc.rv not in _DERIVE_ERROR_RVS:
                    raise
                C.xfail_as(
                    "not_operational",
                    label="CKM_HKDF_DATA C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_HKDF_DATA",
                    inherit_mechanism=False,
                    spec_ref=_HKDF_DERIVE_REF,
                    expected=CKR_OK,
                    actual=exc.rv,
                    summary=f"CKM_HKDF_DATA C_DeriveKey refused ({ckr_name(exc.rv)})",
                    detail=_detail(
                        producer_operation="C_CreateObject",
                        producer_mechanism=None,
                        consumer_operation="C_DeriveKey",
                        consumer_mechanism="CKM_HKDF_DATA",
                    ),
                )
            if derived == 0:
                C.fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="CKM_HKDF_DATA derived-object handle",
                    operation="C_DeriveKey",
                    mechanism="CKM_HKDF_DATA",
                    inherit_mechanism=False,
                    spec_ref=_HKDF_DERIVE_REF,
                    expected="non-zero object handle",
                    actual=derived,
                    summary="CKM_HKDF_DATA C_DeriveKey returned a zero handle",
                    detail=_detail(
                        producer_operation="C_DeriveKey",
                        producer_mechanism="CKM_HKDF_DATA",
                        consumer_operation="C_GetAttributeValue",
                        consumer_mechanism=None,
                    ),
                )

            derived_attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_CLASS, CKA_VALUE])
            derived_readback_records_before = len(C.get_records())
            derived_class = _required_attribute(
                derived_attrs,
                CKA_CLASS,
                label="CKM_HKDF_DATA derived CKA_CLASS readback",
                producer_operation="C_DeriveKey",
                producer_mechanism="CKM_HKDF_DATA",
            )
            derived_value = _required_attribute(
                derived_attrs,
                CKA_VALUE,
                label="CKM_HKDF_DATA derived CKA_VALUE readback",
                producer_operation="C_DeriveKey",
                producer_mechanism="CKM_HKDF_DATA",
            )
            malformed_derived: list[Any] = []
            if derived_class is not MISSING_ATTRIBUTE and (
                not isinstance(derived_class, int)
                or isinstance(derived_class, bool)
                or int(derived_class) != int(CKO_DATA)
            ):
                malformed_derived.append(
                    _shape_record(
                        label="CKM_HKDF_DATA derived CKA_CLASS readback",
                        attr=int(CKA_CLASS),
                        expected=int(CKO_DATA),
                        actual=derived_class,
                        producer_operation="C_DeriveKey",
                        producer_mechanism="CKM_HKDF_DATA",
                    )
                )
            if derived_value is not MISSING_ATTRIBUTE and (
                type(derived_value) is not bytes
                or (type(derived_value) is bytes and len(derived_value) != len(expected))
            ):
                malformed_derived.append(
                    _shape_record(
                        label="CKM_HKDF_DATA derived CKA_VALUE readback",
                        attr=int(CKA_VALUE),
                        expected={"type": "bytes", "length": len(expected)},
                        actual=derived_value,
                        producer_operation="C_DeriveKey",
                        producer_mechanism="CKM_HKDF_DATA",
                    )
                )
            if malformed_derived:
                C.raise_for_record(malformed_derived[-1])
            _raise_for_missing_attribute(
                [derived_class, derived_value],
                derived_readback_records_before,
            )
            if derived_value != expected:
                C.raise_for_record(
                    _wrong_value_record(
                        derived_value,
                        label="CKM_HKDF_DATA RFC5869 CKA_VALUE readback",
                        producer_operation="C_DeriveKey",
                        producer_mechanism="CKM_HKDF_DATA",
                        expected_value=expected,
                        reason="oracle",
                    )
                )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)
