"""Stateful hash-based signature tests - HSS, XMSS, XMSS^MT (PKCS#11 v3.2).

Tests three stateful hash-based signature families per OASIS PKCS#11 v3.2:
- CKM_HSS_KEY_PAIR_GEN + CKM_HSS - Hierarchical Signature Scheme (RFC 8554)
- CKM_XMSS_KEY_PAIR_GEN + CKM_XMSS - eXtended Merkle Signature Scheme (RFC 8391)
- CKM_XMSSMT_KEY_PAIR_GEN + CKM_XMSSMT - XMSS Multi-Tree (RFC 8391)

IMPORTANT: These are stateful signatures - each signing operation consumes a
one-time key from a finite pool.  Tests sign minimally to avoid exhaustion.
Key generation can be very slow (minutes for large trees); smallest parameter
sets are used throughout.

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
"""

from __future__ import annotations

from collections.abc import Mapping
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import (
    attr_array,
    attr_bool,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_HSS_LEVELS,
    CKA_HSS_LMOTS_TYPES,
    CKA_HSS_LMS_TYPES,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_HSS,
    CKK_XMSS,
    CKK_XMSSMT,
    CKM_HSS,
    CKM_HSS_KEY_PAIR_GEN,
    CKM_XMSS,
    CKM_XMSS_KEY_PAIR_GEN,
    CKM_XMSSMT,
    CKM_XMSSMT_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_KEY_EXHAUSTED,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

pytestmark = [pytest.mark.pqc]

_MESSAGE = b"stateful hash signature test message 2026"

# HSS LMS/LMOTS parameter values (from RFC 8554 / NIST SP 800-208).
# Use the smallest tree for fast keygen.
_LMS_SHA256_M32_H5 = 0x05  # LMS_SHA256_M32_H5: height 5, 32 signatures
_LMOTS_SHA256_N32_W8 = 0x04  # LMOTS_SHA256_N32_W8: Winternitz w=8

# XMSS parameter set OIDs (NIST SP 800-208, Table 11).
_XMSS_SHA2_10_256 = 0x00000001  # XMSS-SHA2_10_256: height 10

# XMSSMT parameter set OIDs (NIST SP 800-208, Table 12).
_XMSSMT_SHA2_20_2_256 = 0x00000001  # XMSSMT-SHA2_20/2_256

_VERIFY_FAIL_RVS = (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE)

_KEYGEN_MECHANISMS = {
    "HSS": "CKM_HSS_KEY_PAIR_GEN",
    "XMSS": "CKM_XMSS_KEY_PAIR_GEN",
    "XMSS^MT": "CKM_XMSSMT_KEY_PAIR_GEN",
}
_SIGN_MECHANISMS = {
    "HSS": "CKM_HSS",
    "XMSS": "CKM_XMSS",
    "XMSS^MT": "CKM_XMSSMT",
}

_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _attribute_detail(attr: int) -> dict[str, object]:
    """Return stable identity for a provider-returned attribute."""
    return {
        "attribute": {
            "name": ATTR_NAMES.get(int(attr), str(attr)),
            "id": int(attr),
        }
    }


def _record_attribute_mismatch(
    value: Any,
    *,
    attr: int,
    expected: Any,
    label: str,
    mechanism: str,
) -> classification.Classification | None:
    """Record a present malformed or contradictory key attribute.

    ``attr_or_record`` has already emitted the independent omission finding, so
    an omitted value is deliberately not treated as a value contradiction here.
    Present values are checked for the ABI type as well as the expected value;
    this keeps malformed provider output a hard, structured finding.
    """
    if value is MISSING_ATTRIBUTE:
        return None

    detail = _attribute_detail(attr)
    detail.update(
        {
            "expected": repr(expected),
            "actual": repr(value),
            "producer_operation": "C_GenerateKeyPair",
            "producer_mechanism": mechanism,
        }
    )
    if isinstance(expected, bool):
        valid_shape = type(value) is bool
        if not valid_shape:
            detail["expected"] = "CK_BBOOL boolean"
    else:
        valid_shape = isinstance(value, int) and not isinstance(value, bool)
        if not valid_shape:
            detail["expected"] = "CK_ULONG integer"

    if not valid_shape or value != expected:
        return classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            detail=detail,
            summary=f"{label}: present value is {value!r}, expected {expected!r}",
        )
    return None


def _raise_strongest(records: list[classification.Classification]) -> None:
    """Raise a deferred hard finding after all sibling attributes were read."""
    if records:
        classification.raise_for_record(
            max(records, key=lambda record: _SEVERITY_PRIORITY[record.severity])
        )


def _check_expected_attributes(
    attrs: Mapping[Any, Any],
    *,
    expected: tuple[tuple[int, Any, str], ...],
    mechanism: str,
) -> list[classification.Classification]:
    """Check each requested value independently and defer every finding."""
    hard: list[classification.Classification] = []
    for attr, expected_value, label in expected:
        record_count = len(classification.get_records())
        value = attr_or_record(
            attrs,
            attr,
            label=label,
            reason="not_operational",
            kind="metadata",
            mechanism=mechanism,
        )
        if value is MISSING_ATTRIBUTE:
            hard.extend(classification.get_records()[record_count:])
            continue
        record = _record_attribute_mismatch(
            value,
            attr=attr,
            expected=expected_value,
            label=label,
            mechanism=mechanism,
        )
        if record is not None:
            hard.append(record)
    return hard


def _finish_keypair_generation(
    rs: Any,
    pub_h: CK_OBJECT_HANDLE,
    priv_h: CK_OBJECT_HANDLE,
    rv: int,
    *,
    name: str,
    mechanism: str,
) -> tuple[int, int]:
    """Classify keygen lifecycle violations and clean partial results on errors."""
    pub = int(pub_h.value)
    priv = int(priv_h.value)
    if rv != CKR_OK:
        # A provider may have created one object before reporting failure.  The
        # failed operation owns those handles; clean them before exposing the
        # typed CKR to the caller's deviation classifier.
        if pub:
            destroy_quietly(rs.raw, rs.sh, pub)
        if priv and priv != pub:
            destroy_quietly(rs.raw, rs.sh, priv)
        expect_rv(rv, CKR_OK)

    if not pub or not priv:
        if pub:
            destroy_quietly(rs.raw, rs.sh, pub)
        if priv and priv != pub:
            destroy_quietly(rs.raw, rs.sh, priv)
        classification.classify(
            "self_contradiction",
            kind="lifecycle",
            label=f"{name}:C_GenerateKeyPair returned CKR_OK with zero handle",
            operation="C_GenerateKeyPair",
            mechanism=mechanism,
            expected="non-zero public and private handles",
            actual=CKR_OK,
            detail={
                "handles": {"public": pub, "private": priv},
                "return_value": "CKR_OK",
            },
            summary=f"{name} key generation returned CKR_OK but did not return both handles",
        )
    return pub, priv


def _skip_if_no(rs: Any, mech_name: str) -> None:
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"CKM_{mech_name} not supported by module")


def _destroy_pair(rs: Any, pub: int, priv: int) -> None:
    """Destroy a key pair, ignoring errors."""
    destroy_quietly(rs.raw, rs.sh, pub)
    destroy_quietly(rs.raw, rs.sh, priv)


def _generate_hss_keypair(rs: Any) -> tuple[int, int]:
    """Generate an HSS key pair with the smallest parameter set."""
    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, True),
        attr_bool(CKA_EXTRACTABLE, False),
        attr_ulong(CKA_HSS_LEVELS, 1),
        attr_array(CKA_HSS_LMS_TYPES, [_LMS_SHA256_M32_H5]),
        attr_array(CKA_HSS_LMOTS_TYPES, [_LMOTS_SHA256_N32_W8]),
    )
    mech = mech_simple(CKM_HSS_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKeyPair(
        rs.sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    return _finish_keypair_generation(
        rs,
        pub_h,
        priv_h,
        rv,
        name="HSS",
        mechanism="CKM_HSS_KEY_PAIR_GEN",
    )


def _generate_xmss_keypair(rs: Any) -> tuple[int, int]:
    """Generate an XMSS key pair with XMSS-SHA2_10_256 (smallest)."""
    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSS_SHA2_10_256),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSS_SHA2_10_256),
        attr_bool(CKA_SENSITIVE, True),
        attr_bool(CKA_EXTRACTABLE, False),
        attr_bool(CKA_TOKEN, False),
    )
    mech = mech_simple(CKM_XMSS_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKeyPair(
        rs.sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    return _finish_keypair_generation(
        rs,
        pub_h,
        priv_h,
        rv,
        name="XMSS",
        mechanism="CKM_XMSS_KEY_PAIR_GEN",
    )


def _generate_xmssmt_keypair(rs: Any) -> tuple[int, int]:
    """Generate an XMSS^MT key pair with XMSSMT-SHA2_20/2_256 (smallest)."""
    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSSMT_SHA2_20_2_256),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSSMT_SHA2_20_2_256),
        attr_bool(CKA_SENSITIVE, True),
        attr_bool(CKA_EXTRACTABLE, False),
        attr_bool(CKA_TOKEN, False),
    )
    mech = mech_simple(CKM_XMSSMT_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKeyPair(
        rs.sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    return _finish_keypair_generation(
        rs,
        pub_h,
        priv_h,
        rv,
        name="XMSSMT",
        mechanism="CKM_XMSSMT_KEY_PAIR_GEN",
    )


def _record_positive_refusal(
    exc: BaseException,
    *,
    kind: str,
    label: str,
    operation: str,
    mechanism: str,
) -> classification.Classification:
    """Record a clean refusal from an advertised positive operation."""
    if not isinstance(exc, CkrAssertionError):
        raise exc

    rv = exc.rv
    expected = (CKR_OK,)
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        reason = "not_operational"
        record_kind = kind
        summary = f"{label}: advertised operation refused with {ckr_name(rv)}"
    else:
        reason = "self_contradiction"
        record_kind = "metadata"
        summary = (
            f"{label}: provider returned undefined CK_RV {ckr_name(rv)}; "
            f"expected {ckr_name(int(CKR_OK))}"
        )

    return classification.record_as(
        reason,
        kind=record_kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected,
        actual=rv,
        summary=summary,
    )


def _record_negative_rejection(
    exc: BaseException,
    *,
    expected: tuple[Any, ...],
    kind: str,
    label: str,
    operation: str,
    mechanism: str,
) -> classification.Classification:
    """Record a non-accepted CK_RV from a negative operation."""
    if not isinstance(exc, CkrAssertionError):
        raise exc

    rv = exc.rv
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        reason = "nonspec_reject"
        record_kind = kind
        summary = (
            f"{label}: provider refused with {ckr_name(rv)}; "
            f"expected one of {[ckr_name(int(code)) for code in expected]}"
        )
    else:
        reason = "self_contradiction"
        record_kind = "metadata"
        summary = (
            f"{label}: provider returned undefined CK_RV {ckr_name(rv)}; "
            f"expected one of {[ckr_name(int(code)) for code in expected]}"
        )
    return classification.record_as(
        reason,
        kind=record_kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected,
        actual=rv,
        summary=summary,
    )


def _read_expected_attributes(
    raw: Any,
    session: int,
    handle: int,
    attr_types: list[int],
    *,
    expected: tuple[tuple[int, Any, str], ...],
    label: str,
    mechanism: str,
) -> list[classification.Classification]:
    """Read one key leg, deferring typed refusals until sibling evidence is read."""
    try:
        attrs = read_attributes(raw, session, handle, attr_types)
    except CkrAssertionError as exc:
        return [
            _record_positive_refusal(
                exc,
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
            )
        ]
    return _check_expected_attributes(attrs, expected=expected, mechanism=mechanism)


def _try_verify(
    rs: Any,
    pub: int,
    mech: int,
    data: bytes,
    signature: bytes,
    *,
    name: str,
) -> bool:
    """Try valid-signature verification and classify every typed refusal."""
    mechanism = _SIGN_MECHANISMS[name]
    try:
        return verify_single(rs.raw, rs.sh, pub, mech, data, signature)
    except BaseException as exc:
        record = _record_positive_refusal(
            exc,
            kind="crypto",
            label=f"{name}:C_Verify valid signature",
            operation="C_Verify",
            mechanism=mechanism,
        )
        classification.raise_for_record(record)
        raise AssertionError("unreachable")


def _try_keygen(gen_fn: Any, rs: Any, name: str) -> tuple[int, int]:
    """Try key generation, xfail if module rejects."""
    try:
        result: tuple[int, int] = gen_fn(rs)
        return result
    except BaseException as exc:
        record = _record_positive_refusal(
            exc,
            kind="crypto",
            label=f"{name}:C_GenerateKeyPair",
            operation="C_GenerateKeyPair",
            mechanism=_KEYGEN_MECHANISMS[name],
        )
        classification.raise_for_record(record)
        raise AssertionError("unreachable")


def _try_sign(rs: Any, priv: int, mech: int, name: str) -> bytes:
    """Try signing, xfail if module rejects."""
    try:
        return sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
    except BaseException as exc:
        record = _record_positive_refusal(
            exc,
            kind="crypto",
            label=f"{name}:C_Sign",
            operation="C_Sign",
            mechanism=_SIGN_MECHANISMS[name],
        )
        classification.raise_for_record(record)
        raise AssertionError("unreachable")


def _record_signature_shape(
    sig: object, *, name: str, mechanism: str
) -> classification.Classification | None:
    """Record a successful sign that returned an unusable signature."""
    if isinstance(sig, bytes) and len(sig) > 0:
        return None
    return classification.record_as(
        "wrong_result",
        kind="crypto",
        label=f"{name}:C_Sign returned an empty or malformed signature",
        operation="C_Sign",
        mechanism=mechanism,
        detail={"expected": "non-empty byte signature", "actual": repr(sig)},
        summary=f"{name} returned CKR_OK but its signature output is unusable",
    )


def _require_signature(sig: bytes, *, name: str, mechanism: str) -> bytes:
    """Classify a successful sign that returned an unusable signature."""
    record = _record_signature_shape(sig, name=name, mechanism=mechanism)
    if record is not None:
        classification.raise_for_record(record)
    return sig


def _require_valid_verification(result: object, *, name: str, mechanism: str) -> None:
    """Classify a valid signature that the module failed to verify."""
    if result is True:
        return
    classification.classify(
        "wrong_result",
        kind="crypto",
        label=f"{name}:C_Verify valid signature",
        operation="C_Verify",
        mechanism=mechanism,
        detail={"expected": True, "actual": repr(result)},
        summary=f"{name} rejected its own valid signature",
    )


def _handle_tampered_verify_error(exc: BaseException, *, name: str, mechanism: str) -> None:
    """Accept signature-invalid and expose provider-specific substitute CKRs."""
    if isinstance(exc, CkrAssertionError) and exc.rv in _VERIFY_FAIL_RVS:
        return
    record = _record_negative_rejection(
        exc,
        expected=_VERIFY_FAIL_RVS,
        kind="crypto",
        label=f"{name}:C_Verify tampered message",
        operation="C_Verify",
        mechanism=mechanism,
    )
    classification.raise_for_record(record)
    raise AssertionError("unreachable")


def _require_tampered_rejection(result: object, *, name: str, mechanism: str) -> None:
    """Classify acceptance of a signature over a tampered message."""
    if not result:
        return
    classification.classify(
        "accepted_invalid",
        kind="crypto",
        label=f"{name}:C_Verify accepted tampered message",
        operation="C_Verify",
        mechanism=mechanism,
        expected=_VERIFY_FAIL_RVS,
        actual=CKR_OK,
        detail={"expected": False, "actual": repr(result)},
        summary=f"{name} accepted a signature for a tampered message",
    )


def _record_exhaustion_result(
    caught: BaseException | None,
    *,
    attempt: int,
    success_signature: object,
) -> list[classification.Classification]:
    """Record one post-budget sign result without stopping its sibling probe."""
    expected = (CKR_KEY_EXHAUSTED,)
    label = (
        f"{attempt}th C_Sign on a 32-leaf HSS key (one-time-key reuse past the leaf "
        "budget is a security gap; RFC 8554 Sec.6.3 requires CKR_KEY_EXHAUSTED)"
    )
    if caught is None:
        records = [
            classification.record_as(
                "accepted_invalid",
                kind="crypto",
                label=label,
                operation="C_Sign",
                mechanism="CKM_HSS",
                expected=expected,
                actual=CKR_OK,
                detail={
                    "attempt": attempt,
                    "expected": "CKR_KEY_EXHAUSTED",
                    "actual": "CKR_OK",
                },
                summary=f"{label}: accepted CKR_OK instead of CKR_KEY_EXHAUSTED",
            )
        ]
        shape_record = _record_signature_shape(
            success_signature,
            name="HSS",
            mechanism="CKM_HSS",
        )
        if shape_record is not None:
            records.append(shape_record)
        return records
    if not isinstance(caught, CkrAssertionError):
        raise caught
    if caught.rv == CKR_KEY_EXHAUSTED:
        return []
    return [
        _record_negative_rejection(
            caught,
            expected=expected,
            kind="lifecycle",
            label=label,
            operation="C_Sign",
            mechanism="CKM_HSS",
        )
    ]


# ---------------------------------------------------------------------------
# HSS tests
# ---------------------------------------------------------------------------


class TestHSSKeyGeneration:
    """CKM_HSS_KEY_PAIR_GEN - HSS key generation (RFC 8554)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_HSS_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_raw_session, "HSS_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an HSS key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        _destroy_pair(rs, pub, priv)

    def test_keypair_key_type(self, p11_raw_session: Any) -> None:
        """HSS keys report CKK_HSS key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            hard_records: list[classification.Classification] = []
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    pub,
                    [CKA_KEY_TYPE],
                    expected=((CKA_KEY_TYPE, CKK_HSS, "HSS:public CKA_KEY_TYPE readback"),),
                    label="HSS:public CKA_KEY_TYPE readback",
                    mechanism="CKM_HSS_KEY_PAIR_GEN",
                )
            )
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_KEY_TYPE],
                    expected=((CKA_KEY_TYPE, CKK_HSS, "HSS:private CKA_KEY_TYPE readback"),),
                    label="HSS:private CKA_KEY_TYPE readback",
                    mechanism="CKM_HSS_KEY_PAIR_GEN",
                )
            )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_classes(self, p11_raw_session: Any) -> None:
        """HSS public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            hard_records: list[classification.Classification] = []
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    pub,
                    [CKA_CLASS],
                    expected=((CKA_CLASS, CKO_PUBLIC_KEY, "HSS:public CKA_CLASS readback"),),
                    label="HSS:public CKA_CLASS readback",
                    mechanism="CKM_HSS_KEY_PAIR_GEN",
                )
            )
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_CLASS],
                    expected=((CKA_CLASS, CKO_PRIVATE_KEY, "HSS:private CKA_CLASS readback"),),
                    label="HSS:private CKA_CLASS readback",
                    mechanism="CKM_HSS_KEY_PAIR_GEN",
                )
            )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_private_key_attributes(self, p11_raw_session: Any) -> None:
        """HSS private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            _raise_strongest(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_SENSITIVE, CKA_EXTRACTABLE],
                    expected=(
                        (CKA_SENSITIVE, True, "HSS:private CKA_SENSITIVE readback"),
                        (CKA_EXTRACTABLE, False, "HSS:private CKA_EXTRACTABLE readback"),
                    ),
                    label="HSS:private key attributes readback",
                    mechanism="CKM_HSS_KEY_PAIR_GEN",
                )
            )
        finally:
            _destroy_pair(rs, pub, priv)


class TestHSSSignVerify:
    """CKM_HSS - HSS sign/verify (RFC 8554)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_HSS is advertised by the module."""
        _skip_if_no(p11_raw_session, "HSS")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """HSS sign + verify round-trip (single signature)."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS")
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            sig = _require_signature(
                _try_sign(rs, priv, CKM_HSS, "HSS"),
                name="HSS",
                mechanism="CKM_HSS",
            )
            _require_valid_verification(
                _try_verify(rs, pub, CKM_HSS, _MESSAGE, sig, name="HSS"),
                name="HSS",
                mechanism="CKM_HSS",
            )
        finally:
            _destroy_pair(rs, pub, priv)

    def test_tampered_message_fails(self, p11_raw_session: Any) -> None:
        """Tampered message must fail HSS verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS")
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            sig = _require_signature(
                _try_sign(rs, priv, CKM_HSS, "HSS"),
                name="HSS",
                mechanism="CKM_HSS",
            )
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            result = verify_single(rs.raw, rs.sh, pub, CKM_HSS, tampered, sig)
            _require_tampered_rejection(result, name="HSS", mechanism="CKM_HSS")
        except AssertionError as exc:
            _handle_tampered_verify_error(exc, name="HSS", mechanism="CKM_HSS")
        finally:
            _destroy_pair(rs, pub, priv)


# ---------------------------------------------------------------------------
# XMSS tests
# ---------------------------------------------------------------------------


class TestXMSSKeyGeneration:
    """CKM_XMSS_KEY_PAIR_GEN - XMSS key generation (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSS_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSS_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an XMSS key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        _destroy_pair(rs, pub, priv)

    def test_keypair_key_type(self, p11_raw_session: Any) -> None:
        """XMSS keys report CKK_XMSS key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            hard_records: list[classification.Classification] = []
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    pub,
                    [CKA_KEY_TYPE],
                    expected=((CKA_KEY_TYPE, CKK_XMSS, "XMSS:public CKA_KEY_TYPE readback"),),
                    label="XMSS:public CKA_KEY_TYPE readback",
                    mechanism="CKM_XMSS_KEY_PAIR_GEN",
                )
            )
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_KEY_TYPE],
                    expected=((CKA_KEY_TYPE, CKK_XMSS, "XMSS:private CKA_KEY_TYPE readback"),),
                    label="XMSS:private CKA_KEY_TYPE readback",
                    mechanism="CKM_XMSS_KEY_PAIR_GEN",
                )
            )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_classes(self, p11_raw_session: Any) -> None:
        """XMSS public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            hard_records: list[classification.Classification] = []
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    pub,
                    [CKA_CLASS],
                    expected=((CKA_CLASS, CKO_PUBLIC_KEY, "XMSS:public CKA_CLASS readback"),),
                    label="XMSS:public CKA_CLASS readback",
                    mechanism="CKM_XMSS_KEY_PAIR_GEN",
                )
            )
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_CLASS],
                    expected=((CKA_CLASS, CKO_PRIVATE_KEY, "XMSS:private CKA_CLASS readback"),),
                    label="XMSS:private CKA_CLASS readback",
                    mechanism="CKM_XMSS_KEY_PAIR_GEN",
                )
            )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_private_key_attributes(self, p11_raw_session: Any) -> None:
        """XMSS private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            _raise_strongest(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_SENSITIVE, CKA_EXTRACTABLE],
                    expected=(
                        (CKA_SENSITIVE, True, "XMSS:private CKA_SENSITIVE readback"),
                        (CKA_EXTRACTABLE, False, "XMSS:private CKA_EXTRACTABLE readback"),
                    ),
                    label="XMSS:private key attributes readback",
                    mechanism="CKM_XMSS_KEY_PAIR_GEN",
                )
            )
        finally:
            _destroy_pair(rs, pub, priv)


class TestXMSSSignVerify:
    """CKM_XMSS - XMSS sign/verify (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSS is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSS")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """XMSS sign + verify round-trip (single signature)."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS")
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            sig = _require_signature(
                _try_sign(rs, priv, CKM_XMSS, "XMSS"),
                name="XMSS",
                mechanism="CKM_XMSS",
            )
            _require_valid_verification(
                _try_verify(rs, pub, CKM_XMSS, _MESSAGE, sig, name="XMSS"),
                name="XMSS",
                mechanism="CKM_XMSS",
            )
        finally:
            _destroy_pair(rs, pub, priv)

    def test_tampered_message_fails(self, p11_raw_session: Any) -> None:
        """Tampered message must fail XMSS verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS")
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            sig = _require_signature(
                _try_sign(rs, priv, CKM_XMSS, "XMSS"),
                name="XMSS",
                mechanism="CKM_XMSS",
            )
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            result = verify_single(rs.raw, rs.sh, pub, CKM_XMSS, tampered, sig)
            _require_tampered_rejection(result, name="XMSS", mechanism="CKM_XMSS")
        except AssertionError as exc:
            _handle_tampered_verify_error(exc, name="XMSS", mechanism="CKM_XMSS")
        finally:
            _destroy_pair(rs, pub, priv)


# ---------------------------------------------------------------------------
# XMSS^MT tests
# ---------------------------------------------------------------------------


class TestXMSSMTKeyGeneration:
    """CKM_XMSSMT_KEY_PAIR_GEN - XMSS^MT key generation (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSSMT_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSSMT_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an XMSS^MT key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        _destroy_pair(rs, pub, priv)

    def test_keypair_key_type(self, p11_raw_session: Any) -> None:
        """XMSS^MT keys report CKK_XMSSMT key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            hard_records: list[classification.Classification] = []
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    pub,
                    [CKA_KEY_TYPE],
                    expected=((CKA_KEY_TYPE, CKK_XMSSMT, "XMSSMT:public CKA_KEY_TYPE readback"),),
                    label="XMSSMT:public CKA_KEY_TYPE readback",
                    mechanism="CKM_XMSSMT_KEY_PAIR_GEN",
                )
            )
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_KEY_TYPE],
                    expected=((CKA_KEY_TYPE, CKK_XMSSMT, "XMSSMT:private CKA_KEY_TYPE readback"),),
                    label="XMSSMT:private CKA_KEY_TYPE readback",
                    mechanism="CKM_XMSSMT_KEY_PAIR_GEN",
                )
            )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_classes(self, p11_raw_session: Any) -> None:
        """XMSS^MT public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            hard_records: list[classification.Classification] = []
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    pub,
                    [CKA_CLASS],
                    expected=((CKA_CLASS, CKO_PUBLIC_KEY, "XMSSMT:public CKA_CLASS readback"),),
                    label="XMSSMT:public CKA_CLASS readback",
                    mechanism="CKM_XMSSMT_KEY_PAIR_GEN",
                )
            )
            hard_records.extend(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_CLASS],
                    expected=((CKA_CLASS, CKO_PRIVATE_KEY, "XMSSMT:private CKA_CLASS readback"),),
                    label="XMSSMT:private CKA_CLASS readback",
                    mechanism="CKM_XMSSMT_KEY_PAIR_GEN",
                )
            )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_private_key_attributes(self, p11_raw_session: Any) -> None:
        """XMSS^MT private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            _raise_strongest(
                _read_expected_attributes(
                    rs.raw,
                    rs.sh,
                    priv,
                    [CKA_SENSITIVE, CKA_EXTRACTABLE],
                    expected=(
                        (CKA_SENSITIVE, True, "XMSSMT:private CKA_SENSITIVE readback"),
                        (CKA_EXTRACTABLE, False, "XMSSMT:private CKA_EXTRACTABLE readback"),
                    ),
                    label="XMSSMT:private key attributes readback",
                    mechanism="CKM_XMSSMT_KEY_PAIR_GEN",
                )
            )
        finally:
            _destroy_pair(rs, pub, priv)


class TestXMSSMTSignVerify:
    """CKM_XMSSMT - XMSS^MT sign/verify (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSSMT is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSSMT")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """XMSS^MT sign + verify round-trip (single signature)."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT")
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            sig = _require_signature(
                _try_sign(rs, priv, CKM_XMSSMT, "XMSS^MT"),
                name="XMSSMT",
                mechanism="CKM_XMSSMT",
            )
            _require_valid_verification(
                _try_verify(rs, pub, CKM_XMSSMT, _MESSAGE, sig, name="XMSS^MT"),
                name="XMSSMT",
                mechanism="CKM_XMSSMT",
            )
        finally:
            _destroy_pair(rs, pub, priv)

    def test_tampered_message_fails(self, p11_raw_session: Any) -> None:
        """Tampered message must fail XMSS^MT verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT")
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            sig = _require_signature(
                _try_sign(rs, priv, CKM_XMSSMT, "XMSS^MT"),
                name="XMSSMT",
                mechanism="CKM_XMSSMT",
            )
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            result = verify_single(rs.raw, rs.sh, pub, CKM_XMSSMT, tampered, sig)
            _require_tampered_rejection(result, name="XMSSMT", mechanism="CKM_XMSSMT")
        except AssertionError as exc:
            _handle_tampered_verify_error(exc, name="XMSSMT", mechanism="CKM_XMSSMT")
        finally:
            _destroy_pair(rs, pub, priv)


# ---------------------------------------------------------------------------
# Key-pool exhaustion (stress)
# ---------------------------------------------------------------------------

# Only CKR_KEY_EXHAUSTED is the exact PKCS#11 v3.2 exhaustion result.  Other
# clean CKRs remain visible xfail deviations; they must never silently become
# an accepted exhaustion result.
_EXHAUSTION_OK_RVS = (CKR_KEY_EXHAUSTED,)


@pytest.mark.stress
class TestHSSKeyExhaustion:
    """Sign past the leaf budget — verify exact CKR_KEY_EXHAUSTED behavior.

    HSS with single-level LMS_SHA256_M32_H5 has 2^5 = 32 one-time keys.
    Signing 33 times must return CKR_KEY_EXHAUSTED on attempt #33, and the
    independent #34 attempt must remain exhausted.  A clean alternative CKR is
    reported as a provider deviation; silently accepting either attempt is a
    crypto finding, and a crash is always a finding.

    Marked @stress because 32+ HSS signatures can take 10-60 seconds
    depending on module.
    """

    def test_hss_sign_past_leaf_budget_returns_key_exhausted(self, p11_raw_session: Any) -> None:
        """Sign 33 times on a 32-leaf HSS key; the 33rd attempt must error."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS")
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")

        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            # Sign all 32 leaves
            for i in range(32):
                try:
                    sig = sign_single(rs.raw, rs.sh, priv, CKM_HSS, _MESSAGE)
                except BaseException as exc:
                    record = _record_positive_refusal(
                        exc,
                        kind="crypto",
                        label=f"CKM_HSS:C_Sign attempt {i + 1} before exhaustion",
                        operation="C_Sign",
                        mechanism="CKM_HSS",
                    )
                    classification.raise_for_record(record)
                    raise AssertionError("unreachable")
                _require_signature(sig, name="HSS", mechanism="CKM_HSS")

            # Both post-budget attempts are required: a provider must not reuse
            # a leaf on #33, and must remain exhausted on #34.  Clean deviations
            # are retained while the independent second observation runs.
            hard_records: list[classification.Classification] = []
            for attempt in (33, 34):
                caught = None
                signature: object = b""
                try:
                    signature = sign_single(rs.raw, rs.sh, priv, CKM_HSS, _MESSAGE)
                except BaseException as exc:
                    caught = exc
                hard_records.extend(
                    _record_exhaustion_result(
                        caught,
                        attempt=attempt,
                        success_signature=signature,
                    )
                )
            _raise_strongest(hard_records)
        finally:
            _destroy_pair(rs, pub, priv)
