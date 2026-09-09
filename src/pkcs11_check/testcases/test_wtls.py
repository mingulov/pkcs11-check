"""Tests for WTLS protocol mechanisms.

Covers CKM_WTLS_PRE_MASTER_KEY_GEN, CKM_WTLS_MASTER_KEY_DERIVE,
CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC, CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE, and CKM_WTLS_PRF.

WTLS (Wireless Transport Layer Security) is a legacy protocol from the WAP
specification. These mechanisms are rarely supported by modern tokens and tests
will mostly skip. The raw packers in pkcs11_check.raw.pack provide proper
struct packing for WTLS parameter structures.

OASIS PKCS#11 v3.2 spec: WTLS.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
from collections.abc import Callable, Mapping
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_simple,
    mech_wtls_key_mat,
    mech_wtls_master_key_derive,
    mech_wtls_prf,
    template,
    template_ptr_count,
)
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_VENDOR_DEFINED,
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    CKM_WTLS_PRE_MASTER_KEY_GEN,
    CKM_WTLS_PRF,
    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    assert_correct,
    destroy_returned_handles,
    is_known_error,
    reject_or_classify,
)

pytestmark = pytest.mark.keymgmt

# Common CKR values for WTLS operations
_WTLS_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
}

_WTLS_INVALID_DIGEST_REJECT_RVS = (CKR_MECHANISM_PARAM_INVALID,)
_WTLS_TEMPLATE_CONFLICT_REJECT_RVS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

# WTLS client/server random values (16 bytes each)
_CLIENT_RANDOM = bytes(range(16))
_SERVER_RANDOM = bytes(range(16, 32))
_WTLS_PRF_SECRET = bytes(range(20))
_WTLS_PRF_LABEL = b"key expansion"
_WTLS_PRF_SEED = bytes(range(32))

_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class _ClassificationFailureError(Failed, AssertionError):
    """Keep migrated failures compatible with callers expecting AssertionError."""


def _read_attribute(attrs: Mapping[Any, Any], attr: Any, *, label: str, mechanism: str) -> Any:
    """Read an attribute while retaining a structured unavailable-value observation."""
    return attr_or_record(
        attrs,
        attr,
        label=label,
        reason="not_operational",
        kind="metadata",
        mechanism=mechanism,
    )


def _read_provider_attribute(
    raw: Any,
    session: int,
    handle: int,
    attr: Any,
    *,
    label: str,
    mechanism: str,
    error_rvs: set[Any] | frozenset[Any] | tuple[Any, ...],
) -> Any:
    """Read one provider attribute and classify typed readback errors accurately."""
    try:
        return _read_attribute(
            read_attributes(raw, session, handle, [attr]),
            attr,
            label=label,
            mechanism=mechanism,
        )
    except AssertionError as exc:
        if is_known_error(exc, error_rvs):
            C.record_as(
                "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                actual=getattr(exc, "rv", None),
                summary=f"{label}: C_GetAttributeValue not operational: {exc}",
            )
            return MISSING_ATTRIBUTE
        raise


def _record_wrong_attribute(
    *,
    attr: Any,
    label: str,
    expected: Any,
    actual: Any,
    kind: str,
    mechanism: str,
    operation: str,
) -> C.Classification:
    # Missing attributes are tracked as operability evidence, not interpreted
    # as a false-like provider value by this wrong-result helper.
    if actual is MISSING_ATTRIBUTE:
        attr_name = "CKA_KEY_TYPE" if attr == CKA_KEY_TYPE else "CKA_VALUE"
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            summary=f"{label}: provider did not return the requested attribute",
            detail={"attribute": {"name": attr_name, "id": int(attr)}},
        )
    attr_name = "CKA_KEY_TYPE" if attr == CKA_KEY_TYPE else "CKA_VALUE"
    return C.record_as(
        "wrong_result",
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual!r}; expected {expected!r}",
        detail={
            "attribute": {
                "name": attr_name,
                "id": int(attr),
                "expected": repr(expected),
                "actual": repr(actual),
            }
        },
    )


def _record_relation_mismatch(
    *,
    label: str,
    expected: str,
    left: Any,
    left_label: str,
    left_mechanism: str,
    right: Any,
    right_label: str,
    right_mechanism: str,
) -> C.Classification:
    """Record a relation over both WTLS derive legs without choosing one leg."""
    # The caller normally proves both values are present bytes.  Keep a
    # defensive absence branch here as well so relation evidence can never turn
    # a missing provider attribute into a wrong-result finding.
    if left is MISSING_ATTRIBUTE:
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=f"{label}:{left_label}",
            operation="C_GetAttributeValue",
            mechanism=left_mechanism,
            summary=f"{label}: {left_label} attribute was not returned",
            detail={"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}},
        )
    if right is MISSING_ATTRIBUTE:
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=f"{label}:{right_label}",
            operation="C_GetAttributeValue",
            mechanism=right_mechanism,
            summary=f"{label}: {right_label} attribute was not returned",
            detail={"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}},
        )
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        # This finding is about the relation, so neither leg is a truthful
        # single mechanism identity.  Both identities remain in detail.
        mechanism=None,
        summary=f"{label}: provider outputs violate the required relation",
        detail={
            "relation": {
                "operator": "must_differ",
                "expected": expected,
                "left": {
                    "label": left_label,
                    "mechanism": left_mechanism,
                    "actual": repr(left),
                },
                "right": {
                    "label": right_label,
                    "mechanism": right_mechanism,
                    "actual": repr(right),
                },
            }
        },
    )


def _validate_output(
    value: Any,
    *,
    label: str,
    mechanism: str,
    operation: str,
    expected_len: int | None = None,
) -> C.Classification | None:
    """Validate a present CKA_VALUE without terminating independent checks early."""
    if value is MISSING_ATTRIBUTE:
        return None
    if not isinstance(value, bytes):
        return _record_wrong_attribute(
            attr=CKA_VALUE,
            label=label,
            expected="bytes",
            actual=value,
            kind="crypto",
            mechanism=mechanism,
            operation=operation,
        )
    if not value:
        return _record_wrong_attribute(
            attr=CKA_VALUE,
            label=label,
            expected="non-empty bytes",
            actual=value,
            kind="crypto",
            mechanism=mechanism,
            operation=operation,
        )
    if expected_len is not None and len(value) != expected_len:
        return _record_wrong_attribute(
            attr=CKA_VALUE,
            label=label,
            expected=f"{expected_len}-byte bytes",
            actual=value,
            kind="crypto",
            mechanism=mechanism,
            operation=operation,
        )
    return None


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest hard output finding after all cleanup has completed."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            _KIND_PRIORITY.get(record.kind or "", 0),
            _SEVERITY_PRIORITY.get(record.severity, 0),
        ),
    )
    try:
        C.raise_for_record(strongest)
    except Failed as exc:
        failure = _ClassificationFailureError(str(exc))
        setattr(failure, "_pkcs11_check_classification", strongest)
        raise failure from exc


def _record_handle_mismatch(
    *,
    label: str,
    actual: Any,
    operation: str,
    mechanism: str,
) -> C.Classification:
    """Record CKR_OK producer success that returned the null object handle."""
    return C.record_as(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        operation=operation,
        mechanism=mechanism,
        actual=CKR_OK,
        summary=f"{label}: {operation} returned CKR_OK with handle {actual!r}",
        detail={"handle": {"actual": actual, "expected": "non-zero"}},
    )


def _record_parameter_mismatch(
    *, label: str, parameter: str, expected: Any, actual: Any, mechanism: str
) -> C.Classification:
    """Record provider-written mechanism output without inventing CKR data."""
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual!r}; expected {expected!r}",
        detail={
            "parameter": {
                "name": parameter,
                "expected": repr(expected),
                "actual": repr(actual),
            }
        },
    )


def _guard_producer_handle(
    handle: Any,
    *,
    label: str,
    operation: str,
    mechanism: str,
    records: list[C.Classification],
) -> bool:
    """Record a null successful output and tell callers to skip dependent reads."""
    if handle != 0:
        return True
    records.append(
        _record_handle_mismatch(
            label=label,
            actual=handle,
            operation=operation,
            mechanism=mechanism,
        )
    )
    return False


def _wtls_prf_sha256_reference(
    secret: bytes,
    label: bytes,
    seed: bytes,
    output_len: int,
) -> bytes:
    """Compute the WAP WTLS P_hash PRF using SHA-256 as the selected digest."""
    if output_len <= 0:
        raise ValueError("output_len must be positive")
    seed_data = label + seed
    output = b""
    a_value = seed_data
    while len(output) < output_len:
        a_value = hmac.new(secret, a_value, hashlib.sha256).digest()
        output += hmac.new(secret, a_value + seed_data, hashlib.sha256).digest()
    return output[:output_len]


def _create_generic_secret(rs: Any, size: int = 48) -> int:
    """Create a GENERIC_SECRET key for use as WTLS pre-master secret material."""
    value = bytes(range(size % 256)) * (size // 256 + 1)
    return create_object(
        rs.raw,
        rs.sh,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: value[:size],
            CKA_VALUE_LEN: size,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


def _wtls_derived_secret_attrs() -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }


def _derive_key_material_to_params(
    rs: Any,
    base_key: int,
    attrs: Mapping[Any, Any],
    mech: Any,
) -> None:
    """Run WTLS key-material derive, whose output handles live in mechanism params."""
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    rv = rs.raw.C_DeriveKey(
        rs.sh,
        mech.byref(),
        base_key,
        *template_ptr_count(tmpl),
        None,
    )
    expect_rv(rv, CKR_OK)


def _derive_wtls_prf_output(
    rs: Any,
    secret: int,
    *,
    seed: bytes,
    label: bytes = b"key expansion",
    output_len: int = 16,
    digest_mechanism: int = int(CKM_SHA256),
) -> bytes:
    """Run CKM_WTLS_PRF and return the bytes written to CK_WTLS_PRF_PARAMS.pOutput."""
    mech = mech_wtls_prf(
        CKM_WTLS_PRF,
        digest_mechanism=digest_mechanism,
        seed=seed,
        label=label,
        output_len=output_len,
    )
    rv = rs.raw.C_DeriveKey(rs.sh, mech.byref(), secret, None, 0, None)
    expect_rv(rv, CKR_OK)
    out_len = ctypes.cast(mech.params.pulOutputLen, ctypes.POINTER(CK_ULONG))[0]
    actual_len = int(out_len)
    if actual_len > output_len:
        classify(
            "self_contradiction",
            kind="metadata",
            label="CKM_WTLS_PRF:output-length",
            operation="C_DeriveKey",
            mechanism="CKM_WTLS_PRF",
            summary=(
                f"CKM_WTLS_PRF reported {actual_len} output bytes for a {output_len}-byte buffer"
            ),
        )
    return mech.buffer_bytes("output")[:actual_len]


def _classify_invalid_wtls_digest(operation: Callable[[], int | None], *, label: str) -> None:
    exc: AssertionError | None = None
    try:
        operation()
    except AssertionError as caught:
        exc = caught
    reject_or_classify(
        exc,
        _WTLS_INVALID_DIGEST_REJECT_RVS,
        label=label,
    )


def _derive_wtls_master_key_invalid_digest(
    rs: Any,
    base_key: int,
    mechanism: int,
    *,
    label: str,
    with_version: bool = True,
) -> None:
    mech = mech_wtls_master_key_derive(
        mechanism,
        digest_mechanism=int(CKM_VENDOR_DEFINED),
        client_random=_CLIENT_RANDOM,
        server_random=_SERVER_RANDOM,
        with_version=with_version,
    )
    derived = 0

    def operation() -> int:
        nonlocal derived
        derived = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            mechanism,
            attrs=_wtls_derived_secret_attrs(),
            mech_param=mech,
        )
        return derived

    try:
        _classify_invalid_wtls_digest(operation, label=label)
    finally:
        destroy_quietly(rs.raw, rs.sh, derived)


def _derive_wtls_key_material_invalid_digest(
    rs: Any,
    base_key: int,
    mechanism: int,
    *,
    label: str,
) -> None:
    mech = mech_wtls_key_mat(
        mechanism,
        digest_mechanism=int(CKM_VENDOR_DEFINED),
        client_random=_CLIENT_RANDOM,
        server_random=_SERVER_RANDOM,
        iv_size_bits=64,
    )

    def operation() -> None:
        _derive_key_material_to_params(
            rs,
            base_key,
            _wtls_derived_secret_attrs(),
            mech,
        )

    try:
        _classify_invalid_wtls_digest(operation, label=label)
    finally:
        out = mech.key_mat_out
        destroy_returned_handles(rs, out.hMacSecret, out.hKey)


def _derive_wtls_key_material_template_conflict(
    rs: Any,
    base_key: int,
    mechanism: int,
    *,
    label: str,
) -> None:
    """Verify WTLS key material rejects template protection values that differ."""
    mech = mech_wtls_key_mat(
        mechanism,
        digest_mechanism=CKM_SHA256,
        client_random=_CLIENT_RANDOM,
        server_random=_SERVER_RANDOM,
    )
    exc: AssertionError | None = None
    try:
        _derive_key_material_to_params(
            rs,
            base_key,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_SENSITIVE: True,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech,
        )
    except AssertionError as caught:
        exc = caught
    finally:
        out = mech.key_mat_out
        destroy_returned_handles(rs, out.hMacSecret, out.hKey)

    reject_or_classify(
        exc,
        _WTLS_TEMPLATE_CONFLICT_REJECT_RVS,
        label=label,
    )


class TestWTLSPreMasterKeyGen:
    """CKM_WTLS_PRE_MASTER_KEY_GEN - generate a WTLS pre-master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_PRE_MASTER_KEY_GEN is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

    def test_generate_pre_master_key(self, p11_raw_session: Any) -> None:
        """Generate a WTLS pre-master secret key."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            from ctypes import byref

            from pkcs11_check.raw.rv import expect_rv
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

            mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
            tmpl = template(
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 20),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_DERIVE, 1),
                attr_ulong(CKA_SENSITIVE, 0),
                attr_ulong(CKA_EXTRACTABLE, 1),
                attr_ulong(CKA_TOKEN, 0),
            )
            key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
            expect_rv(rv, CKR_OK)
            try:
                if key.value == 0:
                    C.fail_as(
                        "self_contradiction",
                        kind="lifecycle",
                        label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey handle",
                        operation="C_GenerateKey",
                        mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                        actual=rv,
                        summary=(
                            "CKM_WTLS_PRE_MASTER_KEY_GEN returned CKR_OK without a key handle"
                        ),
                        detail={"handle": {"actual": 0, "expected": "non-zero"}},
                    )
                key_type = _read_provider_attribute(
                    rs.raw,
                    rs.sh,
                    key.value,
                    CKA_KEY_TYPE,
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_KEY_TYPE readback",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    error_rvs=_WTLS_ERROR_RVS,
                )
                if key_type is not MISSING_ATTRIBUTE:
                    mismatch: C.Classification | None = None
                    if not isinstance(key_type, int):
                        mismatch = _record_wrong_attribute(
                            attr=CKA_KEY_TYPE,
                            label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_KEY_TYPE readback",
                            expected="integer",
                            actual=key_type,
                            kind="metadata",
                            mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                            operation="C_GenerateKey",
                        )
                    elif key_type != CKK_GENERIC_SECRET:
                        mismatch = _record_wrong_attribute(
                            attr=CKA_KEY_TYPE,
                            label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_KEY_TYPE readback",
                            expected=CKK_GENERIC_SECRET,
                            actual=key_type,
                            kind="metadata",
                            mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                            operation="C_GenerateKey",
                        )
                    if mismatch is not None:
                        _raise_strongest([mismatch])
            finally:
                if key.value != 0:
                    destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
            raise

    def test_generate_yields_non_zero_material(self, p11_raw_session: Any) -> None:
        """Generated pre-master key must not be all-zero bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            from ctypes import byref

            from pkcs11_check.raw.rv import expect_rv
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

            mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
            tmpl = template(
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 20),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_DERIVE, 1),
                attr_ulong(CKA_SENSITIVE, 0),
                attr_ulong(CKA_EXTRACTABLE, 1),
                attr_ulong(CKA_TOKEN, 0),
            )
            key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
            expect_rv(rv, CKR_OK)
            try:
                value = MISSING_ATTRIBUTE
                hard_results: list[C.Classification] = []
                if _guard_producer_handle(
                    key.value,
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey output handle",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    records=hard_results,
                ):
                    value = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        key.value,
                        CKA_VALUE,
                        label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_VALUE readback",
                        mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                        error_rvs=_WTLS_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    value,
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_VALUE readback",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    operation="C_GenerateKey",
                    expected_len=20,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
                elif (
                    value is not MISSING_ATTRIBUTE
                    and isinstance(value, bytes)
                    and value == bytes(len(value))
                ):
                    hard_results.append(
                        _record_wrong_attribute(
                            attr=CKA_VALUE,
                            label="CKM_WTLS_PRE_MASTER_KEY_GEN:randomness",
                            expected="non-zero output",
                            actual=value,
                            kind="crypto",
                            mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                            operation="C_GenerateKey",
                        )
                    )
                _raise_strongest(hard_results)
            finally:
                if key.value != 0:
                    destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
            raise

    def test_two_generated_keys_differ(self, p11_raw_session: Any) -> None:
        """Two independently generated pre-master keys must differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            from ctypes import byref

            from pkcs11_check.raw.rv import expect_rv
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

            mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
            tmpl = template(
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 20),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_DERIVE, 1),
                attr_ulong(CKA_SENSITIVE, 0),
                attr_ulong(CKA_EXTRACTABLE, 1),
                attr_ulong(CKA_TOKEN, 0),
            )
            key1 = CK_OBJECT_HANDLE(0)
            key2 = CK_OBJECT_HANDLE(0)
            hard_results: list[C.Classification] = []
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key1),
            )
            expect_rv(rv, CKR_OK)
            try:
                val1 = MISSING_ATTRIBUTE
                if key1.value == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_WTLS_PRE_MASTER_KEY_GEN:first output handle",
                            actual=key1.value,
                            operation="C_GenerateKey",
                            mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                        )
                    )
                else:
                    val1 = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        key1.value,
                        CKA_VALUE,
                        label="CKM_WTLS_PRE_MASTER_KEY_GEN:first CKA_VALUE readback",
                        mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                        error_rvs=_WTLS_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    val1,
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:first CKA_VALUE readback",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    operation="C_GenerateKey",
                    expected_len=20,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)

                try:
                    rv = rs.raw.C_GenerateKey(
                        rs.sh,
                        mech.byref(),
                        tmpl.ptr,
                        tmpl.count,
                        byref(key2),
                    )
                    expect_rv(rv, CKR_OK)
                    val2 = MISSING_ATTRIBUTE
                    if key2.value == 0:
                        hard_results.append(
                            _record_handle_mismatch(
                                label="CKM_WTLS_PRE_MASTER_KEY_GEN:second output handle",
                                actual=key2.value,
                                operation="C_GenerateKey",
                                mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                            )
                        )
                    else:
                        val2 = _read_provider_attribute(
                            rs.raw,
                            rs.sh,
                            key2.value,
                            CKA_VALUE,
                            label="CKM_WTLS_PRE_MASTER_KEY_GEN:second CKA_VALUE readback",
                            mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                            error_rvs=_WTLS_ERROR_RVS,
                        )
                    mismatch = _validate_output(
                        val2,
                        label="CKM_WTLS_PRE_MASTER_KEY_GEN:second CKA_VALUE readback",
                        mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                        operation="C_GenerateKey",
                        expected_len=20,
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                    if (
                        val1 is not MISSING_ATTRIBUTE
                        and val2 is not MISSING_ATTRIBUTE
                        and isinstance(val1, bytes)
                        and isinstance(val2, bytes)
                        and val1 == val2
                    ):
                        hard_results.append(
                            _record_wrong_attribute(
                                attr=CKA_VALUE,
                                label="CKM_WTLS_PRE_MASTER_KEY_GEN:randomness",
                                expected="different outputs for independent generations",
                                actual=val1,
                                kind="crypto",
                                mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                                operation="C_GenerateKey",
                            )
                        )
                finally:
                    if key2.value != 0:
                        destroy_quietly(rs.raw, rs.sh, key2.value)
            finally:
                if key1.value != 0:
                    destroy_quietly(rs.raw, rs.sh, key1.value)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
            raise


class TestWTLSMasterKeyDerive:
    """CKM_WTLS_MASTER_KEY_DERIVE - derive WTLS master secret from pre-master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_MASTER_KEY_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

    def test_derive_master_key(self, p11_raw_session: Any) -> None:
        """Attempt to derive a WTLS master key with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

        pms = _create_generic_secret(rs, 20)
        hard_results: list[C.Classification] = []
        try:
            mech = mech_wtls_master_key_derive(
                CKM_WTLS_MASTER_KEY_DERIVE,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    pms,
                    CKM_WTLS_MASTER_KEY_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    if not _guard_producer_handle(
                        derived,
                        label="CKM_WTLS_MASTER_KEY_DERIVE:C_DeriveKey output handle",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_MASTER_KEY_DERIVE",
                        records=hard_results,
                    ):
                        _raise_strongest(hard_results)
                finally:
                    if derived != 0:
                        destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_MASTER_KEY_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_MASTER_KEY_DERIVE",
                        summary=f"CKM_WTLS_MASTER_KEY_DERIVE not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_MASTER_KEY_DERIVE must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

        pms = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_master_key_invalid_digest(
                rs,
                pms,
                int(CKM_WTLS_MASTER_KEY_DERIVE),
                label="WTLS master key derive invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


class TestWTLSMasterKeyDeriveDHECC:
    """CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC - derive WTLS master secret via DH/ECC."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

    def test_derive_master_key_dh_ecc(self, p11_raw_session: Any) -> None:
        """Attempt to derive a WTLS master key using the DH/ECC variant."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

        pms = _create_generic_secret(rs, 32)
        hard_results: list[C.Classification] = []
        try:
            mech = mech_wtls_master_key_derive(
                CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
                with_version=False,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    pms,
                    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    if not _guard_producer_handle(
                        derived,
                        label="CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:C_DeriveKey output handle",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
                        records=hard_results,
                    ):
                        _raise_strongest(hard_results)
                finally:
                    if derived != 0:
                        destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
                        summary=f"CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

        pms = _create_generic_secret(rs, 32)
        try:
            _derive_wtls_master_key_invalid_digest(
                rs,
                pms,
                int(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
                label="WTLS master key derive DH/ECC invalid digest mechanism",
                with_version=False,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


class TestWTLSKeyAndMacDerive:
    """CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE and CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE."""

    def test_server_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

    def test_client_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

    def test_server_key_and_mac_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        hard_results: list[C.Classification] = []
        try:
            mech = mech_wtls_key_mat(
                CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
                iv_size_bits=64,
            )
            try:
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech,
                )
                try:
                    out = mech.key_mat_out
                    for handle, label in (
                        (out.hMacSecret, "MAC secret"),
                        (out.hKey, "key"),
                    ):
                        _guard_producer_handle(
                            handle,
                            label=f"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:{label} output handle",
                            operation="C_DeriveKey",
                            mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                            records=hard_results,
                        )
                    iv = mech.buffer_bytes("iv")
                    if not iv:
                        hard_results.append(
                            _record_parameter_mismatch(
                                label="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:IV output",
                                parameter="pIV",
                                expected="non-empty bytes",
                                actual=iv,
                                mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                            )
                        )
                finally:
                    out = mech.key_mat_out
                    destroy_returned_handles(rs, out.hMacSecret, out.hKey)
                _raise_strongest(hard_results)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                        summary=f"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_server_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_invalid_digest(
                rs,
                master,
                int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
                label="WTLS server key-and-MAC derive invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_server_rejects_template_protection_conflict(self, p11_raw_session: Any) -> None:
        """Server key-material derive rejects template protection overrides."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_template_conflict(
                rs,
                master,
                int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
                label="WTLS server key-and-MAC derive template protection conflict",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_client_key_and_mac_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        hard_results: list[C.Classification] = []
        try:
            mech = mech_wtls_key_mat(
                CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
                iv_size_bits=64,
            )
            try:
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech,
                )
                try:
                    out = mech.key_mat_out
                    for handle, label in (
                        (out.hMacSecret, "MAC secret"),
                        (out.hKey, "key"),
                    ):
                        _guard_producer_handle(
                            handle,
                            label=f"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:{label} output handle",
                            operation="C_DeriveKey",
                            mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                            records=hard_results,
                        )
                    iv = mech.buffer_bytes("iv")
                    if not iv:
                        hard_results.append(
                            _record_parameter_mismatch(
                                label="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:IV output",
                                parameter="pIV",
                                expected="non-empty bytes",
                                actual=iv,
                                mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                            )
                        )
                finally:
                    out = mech.key_mat_out
                    destroy_returned_handles(rs, out.hMacSecret, out.hKey)
                _raise_strongest(hard_results)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                        summary=f"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_client_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_invalid_digest(
                rs,
                master,
                int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
                label="WTLS client key-and-MAC derive invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_client_rejects_template_protection_conflict(self, p11_raw_session: Any) -> None:
        """Client key-material derive rejects template protection overrides."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_template_conflict(
                rs,
                master,
                int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
                label="WTLS client key-and-MAC derive template protection conflict",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_server_and_client_differ(self, p11_raw_session: Any) -> None:
        """Server and client derivation of the same master must produce different keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        hard_results: list[C.Classification] = []
        try:
            srv_out: Any | None = None
            cli_out: Any | None = None
            active_operation = "C_DeriveKey"
            active_mechanism = "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
            try:
                srv_mech = mech_wtls_key_mat(
                    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    digest_mechanism=CKM_SHA256,
                    client_random=_CLIENT_RANDOM,
                    server_random=_SERVER_RANDOM,
                )
                # Capture each output structure before its provider call.  If
                # a provider rejects a leg after writing handles, cleanup must
                # still cover those handles.
                srv_out = srv_mech.key_mat_out
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    srv_mech,
                )
                for handle, label in (
                    (srv_out.hMacSecret, "server MAC secret"),
                    (srv_out.hKey, "server key"),
                ):
                    _guard_producer_handle(
                        handle,
                        label=f"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:{label} output handle",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                        records=hard_results,
                    )
                # Finish the successful server leg's independent readback
                # before starting the client leg.  A clean client rejection
                # must not discard evidence already obtained from the server.
                active_operation = "C_GetAttributeValue"
                active_mechanism = "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
                srv_val = MISSING_ATTRIBUTE
                if srv_out.hKey != 0:
                    srv_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        srv_out.hKey,
                        CKA_VALUE,
                        label="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:CKA_VALUE readback",
                        mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                        error_rvs=_WTLS_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    srv_val,
                    label="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:CKA_VALUE readback",
                    mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                    operation="C_DeriveKey",
                )
                if mismatch is not None:
                    hard_results.append(mismatch)

                active_operation = "C_DeriveKey"
                active_mechanism = "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE"
                cli_mech = mech_wtls_key_mat(
                    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    digest_mechanism=CKM_SHA256,
                    client_random=_CLIENT_RANDOM,
                    server_random=_SERVER_RANDOM,
                )
                cli_out = cli_mech.key_mat_out
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    cli_mech,
                )
                for handle, label in (
                    (cli_out.hMacSecret, "client MAC secret"),
                    (cli_out.hKey, "client key"),
                ):
                    _guard_producer_handle(
                        handle,
                        label=f"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:{label} output handle",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                        records=hard_results,
                    )
                active_operation = "C_GetAttributeValue"
                active_mechanism = "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE"
                cli_val = MISSING_ATTRIBUTE
                if cli_out.hKey != 0:
                    cli_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        cli_out.hKey,
                        CKA_VALUE,
                        label="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:CKA_VALUE readback",
                        mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                        error_rvs=_WTLS_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    cli_val,
                    label="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:CKA_VALUE readback",
                    mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                    operation="C_DeriveKey",
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
                if (
                    srv_val is not MISSING_ATTRIBUTE
                    and cli_val is not MISSING_ATTRIBUTE
                    and isinstance(srv_val, bytes)
                    and isinstance(cli_val, bytes)
                    and srv_val == cli_val
                ):
                    hard_results.append(
                        _record_relation_mismatch(
                            label="WTLS server/client key separation",
                            expected="different server and client CKA_VALUE outputs",
                            left=srv_val,
                            left_label="server",
                            left_mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                            right=cli_val,
                            right_label="client",
                            right_mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                        )
                    )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label=f"{active_mechanism}:{active_operation}",
                        operation=active_operation,
                        mechanism=active_mechanism,
                        actual=getattr(exc, "rv", None),
                        summary=f"{active_mechanism} {active_operation} not operational: {exc}",
                    )
                raise
            finally:
                if cli_out is not None:
                    destroy_returned_handles(rs, cli_out.hMacSecret, cli_out.hKey)
                if srv_out is not None:
                    destroy_returned_handles(rs, srv_out.hMacSecret, srv_out.hKey)
            _raise_strongest(hard_results)
        finally:
            destroy_quietly(rs.raw, rs.sh, master)


class TestWTLSPRF:
    """CKM_WTLS_PRF - WTLS pseudo-random function for key material expansion."""

    def _derive_prf_value(
        self,
        rs: Any,
        secret: int,
        *,
        seed: bytes,
        label: bytes = b"key expansion",
    ) -> bytes:
        value = _derive_wtls_prf_output(
            rs,
            secret,
            seed=seed,
            label=label,
            output_len=16,
        )
        assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
        return value

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_PRF is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

    def test_prf_derive(self, p11_raw_session: Any) -> None:
        """Attempt to use CKM_WTLS_PRF for key derivation with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, len(_WTLS_PRF_SECRET))
        try:
            try:
                value = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=_WTLS_PRF_SEED,
                    label=_WTLS_PRF_LABEL,
                    output_len=16,
                )
                assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
                expected = _wtls_prf_sha256_reference(
                    _WTLS_PRF_SECRET,
                    _WTLS_PRF_LABEL,
                    _WTLS_PRF_SEED,
                    16,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_WTLS_PRF:C_DeriveKey KAT (16-byte output)",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_PRF must reject a DigestMechanism outside the WTLS digest set."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            exc: AssertionError | None = None
            try:
                _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                    digest_mechanism=int(CKM_VENDOR_DEFINED),
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(
                exc,
                _WTLS_INVALID_DIGEST_REJECT_RVS,
                label="WTLS PRF invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_seed_affects_output(self, p11_raw_session: Any) -> None:
        """Changing only the WTLS PRF seed must change the derived output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            try:
                val1 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                )
                val2 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(1, 33)),
                )
                assert val1 != val2, "WTLS PRF seed change did not affect derived output"
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_label_affects_output(self, p11_raw_session: Any) -> None:
        """Changing only the WTLS PRF label must change the derived output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            try:
                val1 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                )
                val2 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"client expansion",
                )
                assert val1 != val2, "WTLS PRF label change did not affect derived output"
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_output_len_extends_output(self, p11_raw_session: Any) -> None:
        """A longer WTLS PRF request must preserve the shorter output as a prefix."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, len(_WTLS_PRF_SECRET))
        try:
            try:
                short = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=_WTLS_PRF_SEED,
                    label=_WTLS_PRF_LABEL,
                    output_len=16,
                )
                long = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=_WTLS_PRF_SEED,
                    label=_WTLS_PRF_LABEL,
                    output_len=32,
                )
                assert len(short) == 16, f"Expected 16 bytes, got {len(short)}"
                assert len(long) == 32, f"Expected 32 bytes, got {len(long)}"
                assert_correct(
                    actual=long[: len(short)],
                    expected=short,
                    label="CKM_WTLS_PRF:output-length prefix consistency",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
                expected = _wtls_prf_sha256_reference(
                    _WTLS_PRF_SECRET,
                    _WTLS_PRF_LABEL,
                    _WTLS_PRF_SEED,
                    32,
                )
                assert_correct(
                    actual=long,
                    expected=expected,
                    label="CKM_WTLS_PRF:C_DeriveKey KAT (32-byte output)",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_deterministic(self, p11_raw_session: Any) -> None:
        """Same WTLS PRF inputs must produce the same output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            try:
                val1 = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                )
                val2 = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                )
                assert_correct(
                    actual=val1,
                    expected=val2,
                    label="CKM_WTLS_PRF:C_DeriveKey determinism",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)
