"""Tests for IKE protocol mechanisms.

Covers CKM_IKE2_PRF_PLUS_DERIVE, CKM_IKE_PRF_DERIVE,
CKM_IKE1_PRF_DERIVE, and CKM_IKE1_EXTENDED_DERIVE.

IKE (Internet Key Exchange) mechanisms are used in IPsec VPN implementations.
They use HMAC-based PRFs internally to derive keying material from a shared
secret and nonce data.

OASIS PKCS#11 v3.2 spec: IKE mechanisms.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.pack import (
    mech_bytes,
    mech_ike1_extended_derive,
    mech_ike1_prf_derive,
    mech_ike2_prf_plus_derive,
    mech_ike_prf_derive,
)
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKM_AES_ECB,
    CKM_IKE1_EXTENDED_DERIVE,
    CKM_IKE1_PRF_DERIVE,
    CKM_IKE2_PRF_PLUS_DERIVE,
    CKM_IKE_PRF_DERIVE,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    assert_correct,
    reject_or_classify,
)

pytestmark = pytest.mark.keymgmt

_INVALID_PRF_REJECT_RVS = (CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID)
_INVALID_PRF_MECHANISM = int(CKM_AES_ECB)
_IKE_PRF_REKEY_DATA_AS_KEY_REJECT_RVS = (CKR_ARGUMENTS_BAD,)
_IKE_MECHANISM_NAMES = {
    int(CKM_IKE2_PRF_PLUS_DERIVE): "CKM_IKE2_PRF_PLUS_DERIVE",
    int(CKM_IKE_PRF_DERIVE): "CKM_IKE_PRF_DERIVE",
    int(CKM_IKE1_PRF_DERIVE): "CKM_IKE1_PRF_DERIVE",
    int(CKM_IKE1_EXTENDED_DERIVE): "CKM_IKE1_EXTENDED_DERIVE",
}

# 32-byte base key material (shared secret / SKEYSEED)
_BASE_KEY_BYTES = bytes(range(32))
_IKE1_KEYGXY_BYTES = bytes(range(32, 64))

# Nonce data used in IKE exchanges (Ni | Nr)
_NONCE_I = b"\x01" * 16  # initiator nonce
_NONCE_R = b"\x02" * 16  # responder nonce

# IKE SPI values (8 bytes each)
_SPI_I = b"\xaa" * 8  # initiator SPI
_SPI_R = b"\xbb" * 8  # responder SPI

_DERIVE_ATTRS: dict[int, Any] = {
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}


def _provider_rejection_record(
    exc: BaseException,
    *,
    label: str,
    operation: str,
    mechanism: str | None,
    kind: str,
) -> C.Classification:
    """Build exact evidence for a typed provider CK_RV rejection.

    Standard and vendor-defined CK_RVs are clean provider deviations in a
    positive operation.  Values outside both namespaces contradict the
    return-value contract and therefore remain hard metadata failures.
    """
    if not isinstance(exc, CkrAssertionError):
        raise exc
    rv = exc.rv
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        return C.record_as(
            "not_operational",
            kind=kind,
            label=label,
            operation=operation,
            mechanism=mechanism,
            actual=rv,
            summary=f"{label}: provider rejected operation with {ckr_name(rv)}",
        )
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        actual=rv,
        summary=f"{label}: provider returned undefined CK_RV {ckr_name(rv)}",
        detail={
            "return_value": {
                "expected": "standard or vendor-defined CK_RV",
                "actual": ckr_name(rv),
            }
        },
    )


def _reject_or_classify_derive(
    exc: AssertionError | None,
    expected_rvs: tuple[int, ...],
    *,
    label: str,
    mechanism: str,
) -> None:
    """Classify a negative C_DeriveKey result with exact operation metadata."""
    if exc is None:
        C.classify(
            "accepted_invalid",
            kind="crypto",
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism,
            actual="CKR_OK",
            expected=expected_rvs,
            summary=f"{label}: accepted invalid (CKR_OK) -- must reject",
        )
        return
    if not isinstance(exc, CkrAssertionError):
        raise exc
    if exc.rv not in expected_rvs:
        if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
            C.classify(
                "nonspec_reject",
                kind="crypto",
                label=label,
                operation="C_DeriveKey",
                mechanism=mechanism,
                actual=exc.rv,
                expected=expected_rvs,
                summary=(
                    f"{label}: rejected with non-specific CK_RV {ckr_name(exc.rv)}; "
                    "expected a spec rejection"
                ),
            )
            return
        C.classify(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism,
            actual=exc.rv,
            expected=expected_rvs,
            summary=f"{label}: provider returned undefined CK_RV {ckr_name(exc.rv)}",
            detail={
                "return_value": {
                    "expected": "standard or vendor-defined CK_RV",
                    "actual": ckr_name(exc.rv),
                }
            },
        )
        return
    reject_or_classify(exc, expected_rvs, label=label)


def _xfail_derive_if_known(exc: AssertionError, mechanism: str, label: str) -> None:
    """Classify any typed advertised IKE derive rejection with exact provenance."""
    if getattr(exc, "_pkcs11_check_attribute_read", False) or getattr(
        exc, "_pkcs11_check_create_object", False
    ):
        raise exc
    C.raise_for_record(
        _provider_rejection_record(
            exc,
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism,
            kind="crypto",
        )
    )


def _require_created_handle(handle: int, *, label: str) -> int:
    """Classify a successful C_CreateObject call that returned handle zero."""
    if handle:
        return handle
    C.fail_as(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        operation="C_CreateObject",
        summary=f"{label}: C_CreateObject returned CKR_OK with a zero handle",
        detail={"handle": {"expected": "non-zero", "actual": 0}},
    )


def _create_object_checked(rs: Any, attrs: dict[int, Any], *, label: str) -> int:
    """Create a setup object while preserving C_CreateObject error provenance."""
    try:
        handle = create_object(rs.raw, rs.sh, attrs)
    except CkrAssertionError as exc:
        C.raise_for_record(
            _provider_rejection_record(
                exc,
                label=label,
                operation="C_CreateObject",
                mechanism=None,
                kind="crypto",
            )
        )
    except AssertionError as exc:
        setattr(exc, "_pkcs11_check_create_object", True)
        raise
    return _require_created_handle(handle, label=label)


def _create_base_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create a GENERIC_SECRET base key suitable for IKE derivation."""
    return _create_object_checked(
        rs,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: key_bytes,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        },
        label="GENERIC_SECRET base key",
    )


def _create_sha256_hmac_derive_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create a SHA256-HMAC base key suitable for typed IKE2 PRF+ derivation."""
    return _create_object_checked(
        rs,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_SHA256_HMAC,
            CKA_VALUE: key_bytes,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
        label="SHA256-HMAC derive key",
    )


def _create_ike1_keygxy_key(rs: Any, key_bytes: bytes = _IKE1_KEYGXY_BYTES) -> int:
    """Create the generic-secret g^xy input key used by IKEv1 derivation."""
    return _create_object_checked(
        rs,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: key_bytes,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
        label="IKE1 g^xy key",
    )


def _derive_generic(
    rs: Any,
    base_key: int,
    mech: int,
    param: bytes,
    bits: int = 256,
) -> int:
    """Derive a GENERIC_SECRET key using the given mechanism and params."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: bits // 8,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        mech,
        attrs=attrs,
        mech_param=_ike_mech_param(mech, param),
    )


def _derive_aes128(rs: Any, base_key: int, mech: int, param: bytes) -> int:
    """Derive an AES-128 key using the given mechanism and params."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_VALUE_LEN: 16,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        mech,
        attrs=attrs,
        mech_param=_ike_mech_param(mech, param),
    )


def _classify_invalid_prf_derive(
    rs: Any,
    base_key: int,
    mech: int,
    mech_param: Any,
    *,
    label: str,
    value_len: int = 32,
    key_type: int = CKK_GENERIC_SECRET,
) -> None:
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: value_len,
        **_DERIVE_ATTRS,
    }
    derived = 0
    try:
        exc: AssertionError | None = None
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                mech,
                attrs=attrs,
                mech_param=mech_param,
            )
        except AssertionError as caught:
            exc = caught
        if exc is None and not derived:
            C.classify(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_DeriveKey",
                mechanism=_IKE_MECHANISM_NAMES[int(mech)],
                summary=f"{label}: C_DeriveKey returned CKR_OK with a zero handle",
                detail={"handle": {"expected": "non-zero", "actual": 0}},
            )
        _reject_or_classify_derive(
            exc,
            _INVALID_PRF_REJECT_RVS,
            label=label,
            mechanism=_IKE_MECHANISM_NAMES[int(mech)],
        )
    finally:
        if derived:
            destroy_quietly(rs.raw, rs.sh, derived)


def _derive_ike1_prf(
    rs: Any,
    base_key: int,
    keygxy_key: int,
    *,
    initiator_cookie: bytes = _NONCE_I,
    responder_cookie: bytes = _NONCE_R,
    key_number: int = 0,
    previous_key_handle: int = 0,
    value_len: int = 32,
    key_type: int = CKK_GENERIC_SECRET,
) -> int:
    """Derive a key with typed CK_IKE1_PRF_DERIVE_PARAMS."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: value_len,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_IKE1_PRF_DERIVE,
        attrs=attrs,
        mech_param=mech_ike1_prf_derive(
            CKM_IKE1_PRF_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            keygxy_handle=keygxy_key,
            initiator_cookie=initiator_cookie,
            responder_cookie=responder_cookie,
            key_number=key_number,
            previous_key_handle=previous_key_handle,
        ),
    )


def _derive_ike1_extended(
    rs: Any,
    base_key: int,
    *,
    keygxy_key: int = 0,
    extra_data: bytes = b"",
    value_len: int = 32,
    key_type: int = CKK_GENERIC_SECRET,
) -> int:
    """Derive a key with typed CK_IKE1_EXTENDED_DERIVE_PARAMS."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: value_len,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_IKE1_EXTENDED_DERIVE,
        attrs=attrs,
        mech_param=mech_ike1_extended_derive(
            CKM_IKE1_EXTENDED_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            keygxy_handle=keygxy_key,
            extra_data=extra_data,
        ),
    )


def _acquire_second_or_cleanup(
    rs: Any,
    first_handle: int,
    acquire: Callable[[], int],
) -> int:
    """Acquire a paired handle without leaking the first on a provider rejection."""
    try:
        second_handle = acquire()
        if not second_handle:
            C.fail_as(
                "self_contradiction",
                kind="lifecycle",
                label="paired C_CreateObject",
                operation="C_CreateObject",
                summary="paired C_CreateObject returned CKR_OK with a zero handle",
                detail={"handle": {"expected": "non-zero", "actual": 0}},
            )
        return second_handle
    except BaseException as exc:
        destroy_quietly(rs.raw, rs.sh, first_handle)
        if isinstance(exc, CkrAssertionError):
            C.raise_for_record(
                _provider_rejection_record(
                    exc,
                    label="paired C_CreateObject",
                    operation="C_CreateObject",
                    mechanism=None,
                    kind="crypto",
                )
            )
        raise


def _record_or_raise(record: C.Classification, hard_results: list[C.Classification] | None) -> None:
    """Defer a hard result until sibling provider observations have completed."""
    if hard_results is None:
        C.raise_for_record(record)
    hard_results.append(record)


def _check_handle(
    handle: int,
    *,
    mechanism: str,
    label: str,
    hard_results: list[C.Classification] | None = None,
) -> bool:
    """Record a CKR_OK/zero-handle lifecycle contradiction without reading handle zero."""
    if handle:
        return True
    _record_or_raise(
        C.record_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism,
            summary=f"{label}: C_DeriveKey returned CKR_OK with a zero handle",
            detail={"handle": {"expected": "non-zero", "actual": 0}},
        ),
        hard_results,
    )
    return False


def _get_value(
    rs: Any,
    handle: int,
    *,
    mechanism: str,
    label: str,
    hard_results: list[C.Classification] | None = None,
    soft_results: list[C.Classification] | None = None,
) -> Any:
    """Read CKA_VALUE while retaining missing and malformed provider evidence."""
    if not _check_handle(
        handle,
        mechanism=mechanism,
        label=label,
        hard_results=hard_results,
    ):
        return MISSING_ATTRIBUTE
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
    except CkrAssertionError as exc:
        record = _provider_rejection_record(
            exc,
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            kind="metadata",
        )
        if record.outcome == "fail":
            _record_or_raise(record, hard_results)
        elif soft_results is None:
            C.raise_for_record(record)
        else:
            soft_results.append(record)
        return MISSING_ATTRIBUTE
    except AssertionError as exc:
        # The outer derive guard must not misattribute a C_GetAttributeValue CKR
        # that is actually a harness/test failure.
        setattr(exc, "_pkcs11_check_attribute_read", True)
        raise
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        # label already names the producing derive mechanism at every call site; this
        # is a plain C_GetAttributeValue readback, not the C_DeriveKey outcome (F6).
        label=label,
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        return value
    if not isinstance(value, bytes):
        _record_or_raise(
            C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                summary=f"{label}: provider returned malformed CKA_VALUE",
                detail={
                    "attribute": {
                        "name": "CKA_VALUE",
                        "id": int(CKA_VALUE),
                        "expected": "bytes",
                        "actual": repr(value),
                    }
                },
            ),
            hard_results,
        )
        return MISSING_ATTRIBUTE
    return value


def _assert_value_length(
    value: Any,
    *,
    expected: int,
    mechanism: str,
    label: str,
    hard_results: list[C.Classification] | None = None,
) -> None:
    """Classify a present derived value with the producer's exact operation."""
    if value is MISSING_ATTRIBUTE:
        return
    if len(value) != expected:
        _record_or_raise(
            C.record_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation="C_DeriveKey",
                mechanism=mechanism,
                summary=f"{label}: derived CKA_VALUE length differs from requested length",
                detail={
                    "attribute": {
                        "name": "CKA_VALUE",
                        "id": int(CKA_VALUE),
                        "expected": f"{expected}-byte bytes",
                        "actual": f"bytes[{len(value)}]",
                    }
                },
            ),
            hard_results,
        )


def _assert_values_differ(
    left: Any,
    right: Any,
    *,
    mechanism: str,
    label: str,
    hard_results: list[C.Classification] | None = None,
) -> None:
    """Check a differential IKE oracle only when both values are available."""
    if left is MISSING_ATTRIBUTE or right is MISSING_ATTRIBUTE:
        return
    if left == right:
        _record_or_raise(
            C.record_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation="C_DeriveKey",
                mechanism=mechanism,
                summary=f"{label}: independent inputs produced identical derived values",
                detail={
                    "relation": {
                        "type": "must_differ",
                        "left": "first derivation",
                        "right": "second derivation",
                        "equal": True,
                    }
                },
            ),
            hard_results,
        )


def _raise_strongest(hard_results: list[C.Classification]) -> None:
    """Raise the highest-severity deferred finding after sibling work completes."""
    if hard_results:
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        C.raise_for_record(max(hard_results, key=lambda result: rank[result.severity]))


def _record_derive_rejection(
    exc: AssertionError,
    *,
    mechanism: str,
    label: str,
) -> C.Classification:
    """Record a typed derive rejection without hiding deferred hard evidence."""
    if getattr(exc, "_pkcs11_check_attribute_read", False) or getattr(
        exc, "_pkcs11_check_create_object", False
    ):
        raise exc
    return _provider_rejection_record(
        exc,
        label=label,
        operation="C_DeriveKey",
        mechanism=mechanism,
        kind="crypto",
    )


def _assert_values_equal(
    left: Any,
    right: Any,
    *,
    mechanism: str,
    label: str,
    hard_results: list[C.Classification] | None = None,
) -> None:
    """Check a deterministic oracle only when both values are available."""
    if left is MISSING_ATTRIBUTE or right is MISSING_ATTRIBUTE:
        return
    if left != right:
        _record_or_raise(
            C.record_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation="C_DeriveKey",
                mechanism=mechanism,
                summary=f"{label}: repeated derivations produced different values",
                detail={
                    "relation": {
                        "type": "must_equal",
                        "left": "first derivation",
                        "right": "second derivation",
                        "equal": False,
                    }
                },
            ),
            hard_results,
        )


def _run_pair_oracle(
    rs: Any,
    first: Callable[[], int],
    second: Callable[[], int],
    *,
    mechanism: str,
    first_label: str,
    second_label: str,
    relation_label: str,
    expected_len: int = 32,
    must_differ: bool,
) -> None:
    """Run both IKE legs, retaining every observation before choosing a verdict."""
    hard_results: list[C.Classification] = []
    derive_rejections: list[C.Classification] = []
    read_rejections: list[C.Classification] = []
    read_errors: list[AssertionError] = []
    values: list[Any] = [MISSING_ATTRIBUTE, MISSING_ATTRIBUTE]
    for index, acquire in enumerate((first, second)):
        handle = 0
        try:
            handle = acquire()
        except AssertionError as exc:
            rejection = _record_derive_rejection(
                exc,
                mechanism=mechanism,
                label=(first_label if index == 0 else second_label),
            )
            if rejection.outcome == "fail":
                hard_results.append(rejection)
            else:
                derive_rejections.append(rejection)
            continue
        try:
            try:
                values[index] = _get_value(
                    rs,
                    handle,
                    mechanism=mechanism,
                    label=(first_label if index == 0 else second_label),
                    hard_results=hard_results,
                    soft_results=read_rejections,
                )
                _assert_value_length(
                    values[index],
                    expected=expected_len,
                    mechanism=mechanism,
                    label=(first_label if index == 0 else second_label),
                    hard_results=hard_results,
                )
            except AssertionError as exc:
                read_errors.append(exc)
        finally:
            if handle:
                destroy_quietly(rs.raw, rs.sh, handle)

    # A relation is meaningful only after every present output passed its
    # independent shape check.  Keep malformed-output evidence focused on the
    # producer result and avoid a secondary oracle verdict for the same defect.
    if not hard_results:
        if must_differ:
            _assert_values_differ(
                values[0],
                values[1],
                mechanism=mechanism,
                label=relation_label,
                hard_results=hard_results,
            )
        else:
            _assert_values_equal(
                values[0],
                values[1],
                mechanism=mechanism,
                label=relation_label,
                hard_results=hard_results,
            )
    _raise_strongest(hard_results)
    if read_errors:
        raise read_errors[0]
    if read_rejections:
        C.raise_for_record(read_rejections[0])
    if derive_rejections:
        C.raise_for_record(derive_rejections[0])


def _ike_mech_param(mech: int, param: bytes) -> Any:
    """Build typed IKE mechanism params where the PKCS#11 shape is clear."""
    if mech == CKM_IKE_PRF_DERIVE:
        half = len(param) // 2
        return mech_ike_prf_derive(
            CKM_IKE_PRF_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            initiator_nonce=param[:half],
            responder_nonce=param[half:],
            data_as_key=True,
        )
    if mech == CKM_IKE2_PRF_PLUS_DERIVE:
        return mech_ike2_prf_plus_derive(
            CKM_IKE2_PRF_PLUS_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            seed_data=param,
        )
    return mech_bytes(mech, param)


def _ike_prf_hmac_sha256_reference(
    base_key: bytes,
    initiator_nonce: bytes,
    responder_nonce: bytes,
    *,
    data_as_key: bool,
) -> bytes:
    """Compute the OASIS CKM_IKE_PRF_DERIVE HMAC-SHA256 reference value."""
    nonce_data = initiator_nonce + responder_nonce
    if data_as_key:
        return hmac.new(nonce_data, base_key, hashlib.sha256).digest()
    return hmac.new(base_key, nonce_data, hashlib.sha256).digest()


def _ike2_prf_plus_hmac_sha256_reference(
    base_key: bytes,
    seed: bytes,
    output_len: int,
) -> bytes:
    """Compute the OASIS CKM_IKE2_PRF_PLUS_DERIVE HMAC-SHA256 reference value."""
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    if output_len > 255 * hashlib.sha256().digest_size:
        raise ValueError("output_len exceeds IKE2 PRF+ counter capacity")
    result = b""
    previous = b""
    counter = 1
    while len(result) < output_len:
        previous = hmac.new(base_key, previous + seed + bytes([counter]), hashlib.sha256).digest()
        result += previous
        counter += 1
    return result[:output_len]


def _ike1_prf_hmac_sha256_reference(
    base_key: bytes,
    keygxy: bytes,
    initiator_cookie: bytes,
    responder_cookie: bytes,
    *,
    key_number: int,
    previous_key: bytes | None = None,
) -> bytes:
    """Compute the OASIS CKM_IKE1_PRF_DERIVE HMAC-SHA256 reference value."""
    if not 0 <= key_number <= 0xFF:
        raise ValueError("key_number must fit in one byte")
    prefix = b"" if previous_key is None else previous_key
    data = prefix + keygxy + initiator_cookie + responder_cookie + bytes([key_number])
    return hmac.new(base_key, data, hashlib.sha256).digest()


def _ike1_extended_hmac_sha256_reference(
    base_key: bytes,
    keygxy: bytes | None,
    extra_data: bytes,
    output_len: int,
) -> bytes:
    """Compute the OASIS CKM_IKE1_EXTENDED_DERIVE HMAC-SHA256 reference value."""
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    if keygxy is None and not extra_data and output_len <= len(base_key):
        return base_key[:output_len]
    seed = (keygxy or b"") + extra_data
    result = b""
    previous = b""
    while len(result) < output_len:
        message = previous + seed if previous else seed or b"\x00"
        previous = hmac.new(base_key, message, hashlib.sha256).digest()
        result += previous
    return result[:output_len]


class TestIKE2PRFPlusDerive:
    """CKM_IKE2_PRF_PLUS_DERIVE - IKEv2 PRF+ key derivation (RFC 7296)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")

    def test_derive_generic_secret(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_generic(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
            )
            try:
                raw = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                    label="CKM_IKE2_PRF_PLUS_DERIVE:derived CKA_VALUE",
                )
                _assert_value_length(
                    raw,
                    expected=32,
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                    label="CKM_IKE2_PRF_PLUS_DERIVE:derived CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE2_PRF_PLUS_DERIVE", "CKM_IKE2_PRF_PLUS_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_plus_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE2_PRF_PLUS_DERIVE follows OASIS prf+(baseKey, seedData)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            expected = _ike2_prf_plus_hmac_sha256_reference(
                _BASE_KEY_BYTES,
                _NONCE_I + _NONCE_R,
                32,
            )
            derived = _derive_generic(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
            )
            try:
                actual = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                )
                if actual is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc,
                "CKM_IKE2_PRF_PLUS_DERIVE",
                "CKM_IKE2_PRF_PLUS_DERIVE HMAC-SHA256 exact vector",
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_plus_hmac_sha256_multiblock_exact_vector(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_IKE2_PRF_PLUS_DERIVE follows OASIS prf+ across HMAC blocks."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            expected = _ike2_prf_plus_hmac_sha256_reference(
                _BASE_KEY_BYTES,
                _NONCE_I + _NONCE_R,
                48,
            )
            derived = _derive_generic(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
                bits=384,
            )
            try:
                actual = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey KAT (HMAC-SHA256 multiblock)",
                )
                if actual is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey KAT (HMAC-SHA256 multiblock)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc,
                "CKM_IKE2_PRF_PLUS_DERIVE",
                "CKM_IKE2_PRF_PLUS_DERIVE HMAC-SHA256 multiblock exact vector",
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_aes128(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
            )
            try:
                raw = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                    label="CKM_IKE2_PRF_PLUS_DERIVE:AES-128 CKA_VALUE",
                )
                _assert_value_length(
                    raw,
                    expected=16,
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                    label="CKM_IKE2_PRF_PLUS_DERIVE:AES-128 CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE2_PRF_PLUS_DERIVE", "CKM_IKE2_PRF_PLUS_DERIVE AES-128"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            nonce_b = b"\x03" * 16 + b"\x04" * 16
            _run_pair_oracle(
                rs,
                lambda: _derive_generic(
                    rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R
                ),
                lambda: _derive_generic(rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, nonce_b),
                mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                first_label="CKM_IKE2_PRF_PLUS_DERIVE:first derived CKA_VALUE",
                second_label="CKM_IKE2_PRF_PLUS_DERIVE:second derived CKA_VALUE",
                relation_label="CKM_IKE2_PRF_PLUS_DERIVE:nonce separation",
                must_differ=True,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE2_PRF_PLUS_DERIVE", "CKM_IKE2_PRF_PLUS_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_base_key_affects_output(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key_a = _create_base_key(rs)
        base_key_b: int | None = None
        try:
            base_key_b = _create_base_key(rs, bytes(reversed(_BASE_KEY_BYTES)))
            _run_pair_oracle(
                rs,
                lambda: _derive_generic(
                    rs, base_key_a, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R
                ),
                lambda: _derive_generic(
                    rs, base_key_b, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R
                ),
                mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                first_label="CKM_IKE2_PRF_PLUS_DERIVE:first base-key output",
                second_label="CKM_IKE2_PRF_PLUS_DERIVE:second base-key output",
                relation_label="CKM_IKE2_PRF_PLUS_DERIVE:base-key separation",
                must_differ=True,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE2_PRF_PLUS_DERIVE", "CKM_IKE2_PRF_PLUS_DERIVE")
        finally:
            if base_key_b is not None:
                destroy_quietly(rs.raw, rs.sh, base_key_b)
            destroy_quietly(rs.raw, rs.sh, base_key_a)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE2_PRF_PLUS_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                mech_ike2_prf_plus_derive(
                    CKM_IKE2_PRF_PLUS_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    seed_data=_NONCE_I + _NONCE_R,
                ),
                label="IKE2 PRF+ invalid PRF mechanism",
            )
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE2_PRF_PLUS_DERIVE", "CKM_IKE2_PRF_PLUS_DERIVE invalid PRF setup"
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            _run_pair_oracle(
                rs,
                lambda: _derive_generic(
                    rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R
                ),
                lambda: _derive_generic(
                    rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R
                ),
                mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                first_label="CKM_IKE2_PRF_PLUS_DERIVE:first deterministic output",
                second_label="CKM_IKE2_PRF_PLUS_DERIVE:second deterministic output",
                relation_label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey determinism",
                must_differ=False,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE2_PRF_PLUS_DERIVE", "CKM_IKE2_PRF_PLUS_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)


class TestIKEPRFDerive:
    """CKM_IKE_PRF_DERIVE - IKEv2 PRF key derivation (SKEYSEED computation)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")

    def test_derive_skeyseed(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                value = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE_PRF_DERIVE",
                    label="CKM_IKE_PRF_DERIVE:derived CKA_VALUE",
                )
                _assert_value_length(
                    value,
                    expected=32,
                    mechanism="CKM_IKE_PRF_DERIVE",
                    label="CKM_IKE_PRF_DERIVE:derived CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_data_as_key_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE_PRF_DERIVE case 1 follows OASIS prf(Ni|Nr, baseKey)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        expected = _ike_prf_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _NONCE_I,
            _NONCE_R,
            data_as_key=True,
        )
        try:
            derived = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                actual = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE_PRF_DERIVE",
                    label="CKM_IKE_PRF_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                )
                if actual is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label="CKM_IKE_PRF_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE_PRF_DERIVE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE HMAC-SHA256 exact vector"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_aes128(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                value = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE_PRF_DERIVE",
                    label="CKM_IKE_PRF_DERIVE:AES-128 CKA_VALUE",
                )
                _assert_value_length(
                    value,
                    expected=16,
                    mechanism="CKM_IKE_PRF_DERIVE",
                    label="CKM_IKE_PRF_DERIVE:AES-128 CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE AES-128")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            _run_pair_oracle(
                rs,
                lambda: _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R),
                lambda: _derive_generic(
                    rs, base_key, CKM_IKE_PRF_DERIVE, b"\x05" * 16 + b"\x06" * 16
                ),
                mechanism="CKM_IKE_PRF_DERIVE",
                first_label="CKM_IKE_PRF_DERIVE:first nonce output",
                second_label="CKM_IKE_PRF_DERIVE:second nonce output",
                relation_label="CKM_IKE_PRF_DERIVE:nonce separation",
                must_differ=True,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_base_key_affects_output(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key_a = _create_base_key(rs)
        base_key_b: int | None = None
        try:
            base_key_b = _create_base_key(rs, bytes(reversed(_BASE_KEY_BYTES)))
            _run_pair_oracle(
                rs,
                lambda: _derive_generic(rs, base_key_a, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R),
                lambda: _derive_generic(rs, base_key_b, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R),
                mechanism="CKM_IKE_PRF_DERIVE",
                first_label="CKM_IKE_PRF_DERIVE:first base-key output",
                second_label="CKM_IKE_PRF_DERIVE:second base-key output",
                relation_label="CKM_IKE_PRF_DERIVE:base-key separation",
                must_differ=True,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE")
        finally:
            if base_key_b is not None:
                destroy_quietly(rs.raw, rs.sh, base_key_b)
            destroy_quietly(rs.raw, rs.sh, base_key_a)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE_PRF_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_base_key(rs)
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE_PRF_DERIVE,
                mech_ike_prf_derive(
                    CKM_IKE_PRF_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    initiator_nonce=_NONCE_I,
                    responder_nonce=_NONCE_R,
                    data_as_key=True,
                ),
                label="IKE PRF invalid PRF mechanism",
            )
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE invalid PRF setup"
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_rejects_data_as_key_rekey_combination(self, p11_raw_session: Any) -> None:
        """CKM_IKE_PRF_DERIVE rejects the disallowed bDataAsKey+bRekey pair."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = 0
        rekey_key = 0
        derived = 0
        base_key = _create_base_key(rs)
        rekey_key = _acquire_second_or_cleanup(
            rs,
            base_key,
            lambda: _create_base_key(rs, bytes(reversed(_BASE_KEY_BYTES))),
        )
        try:
            attrs: dict[int, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: 32,
                **_DERIVE_ATTRS,
            }
            exc: AssertionError | None = None
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_IKE_PRF_DERIVE,
                    attrs=attrs,
                    mech_param=mech_ike_prf_derive(
                        CKM_IKE_PRF_DERIVE,
                        prf_mechanism=CKM_SHA256_HMAC,
                        initiator_nonce=_NONCE_I,
                        responder_nonce=_NONCE_R,
                        data_as_key=True,
                        rekey=True,
                        new_key_handle=rekey_key,
                    ),
                )
            except AssertionError as caught:
                exc = caught
            if exc is None and not derived:
                C.classify(
                    "self_contradiction",
                    kind="lifecycle",
                    label="IKE PRF data-as-key rekey combination",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE_PRF_DERIVE",
                    summary=(
                        "IKE PRF data-as-key rekey combination: "
                        "C_DeriveKey returned CKR_OK with a zero handle"
                    ),
                    detail={"handle": {"expected": "non-zero", "actual": 0}},
                )
            _reject_or_classify_derive(
                exc,
                _IKE_PRF_REKEY_DATA_AS_KEY_REJECT_RVS,
                label="IKE PRF data-as-key rekey combination",
                mechanism="CKM_IKE_PRF_DERIVE",
            )
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE data-as-key rekey setup"
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if rekey_key:
                destroy_quietly(rs.raw, rs.sh, rekey_key)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            _run_pair_oracle(
                rs,
                lambda: _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R),
                lambda: _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R),
                mechanism="CKM_IKE_PRF_DERIVE",
                first_label="CKM_IKE_PRF_DERIVE:first deterministic output",
                second_label="CKM_IKE_PRF_DERIVE:second deterministic output",
                relation_label="CKM_IKE_PRF_DERIVE:C_DeriveKey determinism",
                must_differ=False,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE_PRF_DERIVE", "CKM_IKE_PRF_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)


class TestIKE1PRFDerive:
    """CKM_IKE1_PRF_DERIVE - IKEv1 PRF key derivation (RFC 2409)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")

    def test_derive_skeyid(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            derived = _derive_ike1_prf(rs, base_key, keygxy_key)
            try:
                value = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_PRF_DERIVE",
                    label="CKM_IKE1_PRF_DERIVE:derived CKA_VALUE",
                )
                _assert_value_length(
                    value,
                    expected=32,
                    mechanism="CKM_IKE1_PRF_DERIVE",
                    label="CKM_IKE1_PRF_DERIVE:derived CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_PRF_DERIVE", "CKM_IKE1_PRF_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_PRF_DERIVE follows OASIS prf(SKEYID, g^xy|CKYi|CKYr|n)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        expected = _ike1_prf_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _IKE1_KEYGXY_BYTES,
            _NONCE_I,
            _NONCE_R,
            key_number=0,
        )
        try:
            derived = _derive_ike1_prf(rs, base_key, keygxy_key, key_number=0)
            try:
                actual = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_PRF_DERIVE",
                    label="CKM_IKE1_PRF_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                )
                if actual is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label="CKM_IKE1_PRF_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_PRF_DERIVE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE1_PRF_DERIVE", "CKM_IKE1_PRF_DERIVE HMAC-SHA256 exact vector"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            derived = _derive_ike1_prf(
                rs,
                base_key,
                keygxy_key,
                value_len=16,
                key_type=CKK_AES,
            )
            try:
                value = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_PRF_DERIVE",
                    label="CKM_IKE1_PRF_DERIVE:AES-128 CKA_VALUE",
                )
                _assert_value_length(
                    value,
                    expected=16,
                    mechanism="CKM_IKE1_PRF_DERIVE",
                    label="CKM_IKE1_PRF_DERIVE:AES-128 CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_PRF_DERIVE", "CKM_IKE1_PRF_DERIVE AES-128")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            _run_pair_oracle(
                rs,
                lambda: _derive_ike1_prf(rs, base_key, keygxy_key),
                lambda: _derive_ike1_prf(
                    rs,
                    base_key,
                    keygxy_key,
                    initiator_cookie=b"\x07" * 16,
                    responder_cookie=b"\x08" * 16,
                ),
                mechanism="CKM_IKE1_PRF_DERIVE",
                first_label="CKM_IKE1_PRF_DERIVE:first nonce output",
                second_label="CKM_IKE1_PRF_DERIVE:second nonce output",
                relation_label="CKM_IKE1_PRF_DERIVE:nonce separation",
                must_differ=True,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_PRF_DERIVE", "CKM_IKE1_PRF_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_PRF_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = 0
        keygxy_key = 0
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE1_PRF_DERIVE,
                mech_ike1_prf_derive(
                    CKM_IKE1_PRF_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    keygxy_handle=keygxy_key,
                    initiator_cookie=_NONCE_I,
                    responder_cookie=_NONCE_R,
                    key_number=0,
                ),
                label="IKE1 PRF invalid PRF mechanism",
            )
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE1_PRF_DERIVE", "CKM_IKE1_PRF_DERIVE invalid PRF setup"
            )
        finally:
            if keygxy_key:
                destroy_quietly(rs.raw, rs.sh, keygxy_key)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            _run_pair_oracle(
                rs,
                lambda: _derive_ike1_prf(rs, base_key, keygxy_key),
                lambda: _derive_ike1_prf(rs, base_key, keygxy_key),
                mechanism="CKM_IKE1_PRF_DERIVE",
                first_label="CKM_IKE1_PRF_DERIVE:first deterministic output",
                second_label="CKM_IKE1_PRF_DERIVE:second deterministic output",
                relation_label="CKM_IKE1_PRF_DERIVE:C_DeriveKey determinism",
                must_differ=False,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_PRF_DERIVE", "CKM_IKE1_PRF_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)


class TestIKE1ExtendedDerive:
    """CKM_IKE1_EXTENDED_DERIVE - IKEv1 extended key derivation (SKEYID_d/a/e)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")

    def test_derive_skeyid_d(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            derived = _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=param)
            try:
                value = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                    label="CKM_IKE1_EXTENDED_DERIVE:derived CKA_VALUE",
                )
                _assert_value_length(
                    value,
                    expected=32,
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                    label="CKM_IKE1_EXTENDED_DERIVE:derived CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_EXTENDED_DERIVE", "CKM_IKE1_EXTENDED_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_extended_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_EXTENDED_DERIVE follows OASIS prf(SKEYID, g^xy|extraData)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        extra_data = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        expected = _ike1_extended_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _IKE1_KEYGXY_BYTES,
            extra_data,
            32,
        )
        try:
            derived = _derive_ike1_extended(
                rs,
                base_key,
                keygxy_key=keygxy_key,
                extra_data=extra_data,
            )
            try:
                actual = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                    label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                )
                if actual is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc,
                "CKM_IKE1_EXTENDED_DERIVE",
                "CKM_IKE1_EXTENDED_DERIVE HMAC-SHA256 exact vector",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_extended_hmac_sha256_multiblock_exact_vector(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_IKE1_EXTENDED_DERIVE follows OASIS recurrence across HMAC blocks."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        extra_data = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        expected = _ike1_extended_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _IKE1_KEYGXY_BYTES,
            extra_data,
            48,
        )
        try:
            derived = _derive_ike1_extended(
                rs,
                base_key,
                keygxy_key=keygxy_key,
                extra_data=extra_data,
                value_len=48,
            )
            try:
                actual = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                    label=("CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey KAT (HMAC-SHA256 multiblock)"),
                )
                if actual is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey KAT (HMAC-SHA256 multiblock)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc,
                "CKM_IKE1_EXTENDED_DERIVE",
                "CKM_IKE1_EXTENDED_DERIVE HMAC-SHA256 multiblock exact vector",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            derived = _derive_ike1_extended(
                rs,
                base_key,
                keygxy_key=keygxy_key,
                extra_data=param,
                value_len=16,
                key_type=CKK_AES,
            )
            try:
                value = _get_value(
                    rs,
                    derived,
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                    label="CKM_IKE1_EXTENDED_DERIVE:AES-128 CKA_VALUE",
                )
                _assert_value_length(
                    value,
                    expected=16,
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                    label="CKM_IKE1_EXTENDED_DERIVE:AES-128 CKA_VALUE",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc, "CKM_IKE1_EXTENDED_DERIVE", "CKM_IKE1_EXTENDED_DERIVE AES-128"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_spis_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            pa = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
            pb = _NONCE_I + _NONCE_R + b"\xcc" * 8 + b"\xdd" * 8
            _run_pair_oracle(
                rs,
                lambda: _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=pa),
                lambda: _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=pb),
                mechanism="CKM_IKE1_EXTENDED_DERIVE",
                first_label="CKM_IKE1_EXTENDED_DERIVE:first SPI output",
                second_label="CKM_IKE1_EXTENDED_DERIVE:second SPI output",
                relation_label="CKM_IKE1_EXTENDED_DERIVE:SPI separation",
                must_differ=True,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_EXTENDED_DERIVE", "CKM_IKE1_EXTENDED_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_EXTENDED_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = 0
        keygxy_key = 0
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        try:
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE1_EXTENDED_DERIVE,
                mech_ike1_extended_derive(
                    CKM_IKE1_EXTENDED_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    keygxy_handle=keygxy_key,
                    extra_data=_NONCE_I + _NONCE_R + _SPI_I + _SPI_R,
                ),
                label="IKE1 extended invalid PRF mechanism",
            )
        except AssertionError as exc:
            _xfail_derive_if_known(
                exc,
                "CKM_IKE1_EXTENDED_DERIVE",
                "CKM_IKE1_EXTENDED_DERIVE invalid PRF setup",
            )
        finally:
            if keygxy_key:
                destroy_quietly(rs.raw, rs.sh, keygxy_key)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _acquire_second_or_cleanup(rs, base_key, lambda: _create_ike1_keygxy_key(rs))
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            _run_pair_oracle(
                rs,
                lambda: _derive_ike1_extended(
                    rs, base_key, keygxy_key=keygxy_key, extra_data=param
                ),
                lambda: _derive_ike1_extended(
                    rs, base_key, keygxy_key=keygxy_key, extra_data=param
                ),
                mechanism="CKM_IKE1_EXTENDED_DERIVE",
                first_label="CKM_IKE1_EXTENDED_DERIVE:first deterministic output",
                second_label="CKM_IKE1_EXTENDED_DERIVE:second deterministic output",
                relation_label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey determinism",
                must_differ=False,
            )
        except AssertionError as exc:
            _xfail_derive_if_known(exc, "CKM_IKE1_EXTENDED_DERIVE", "CKM_IKE1_EXTENDED_DERIVE")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)
