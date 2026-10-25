"""Attribute sensitivity enforcement tests.

Verifies that PKCS#11 modules enforce CKA_SENSITIVE and CKA_EXTRACTABLE
correctly - sensitive key values must not be readable, non-extractable
keys must not be wrappable.
"""

from __future__ import annotations

import ctypes
import itertools
from collections.abc import Mapping
from ctypes import byref
from dataclasses import dataclass
from typing import Any, NoReturn, cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pkcs11_check import classification
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.metadata_std import ATTR_NAMES, MECHANISM_NAMES
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_keypair,
    import_secret_key,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CK_UNAVAILABLE_INFORMATION,
    CK_UNAVAILABLE_INFORMATION_32,
    CKA_ALWAYS_SENSITIVE,
    CKA_BASE,
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECAPSULATE,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_ENCAPSULATE,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PARAMETER_SET,
    CKA_PRIME,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SEED,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_AES,
    CKK_DH,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_ML_DSA,
    CKK_ML_KEM,
    CKK_RSA,
    CKK_SLH_DSA,
    CKK_X9_42_DH,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKM_X9_42_DH_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKP_ML_DSA_44,
    CKP_ML_KEM_512,
    CKP_SLH_DSA_SHA2_128S,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    create_object_negotiated,
    gen_ec_keypair_or_xfail,
    gen_edwards_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_ec_private_key_negotiated,
    import_rsa_private_key_negotiated,
    import_secret_key_negotiated,
    is_known_error,
    require_operational_aes_keygen,
    skip_unless_create_object_supported,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.test_dh_key_agreement import DH_GEN, DH_PRIME_2048
from pkcs11_check.testcases.test_x942_dh import (
    X942_GEN,
    X942_PRIME_2048,
    X942_SUBPRIME,
)

pytestmark = pytest.mark.security

_SENSITIVE_IMPORT_REJECT_RVS = (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


def _record_bool_readback(
    value: Any,
    *,
    attr: int,
    expected: bool | None,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None,
) -> classification.Classification | None:
    """Record a present boolean shape/value contradiction without stopping probes."""
    if value is MISSING_ATTRIBUTE:
        return None
    detail: dict[str, Any] = {
        "attribute": {"name": ATTR_NAMES.get(int(attr), str(attr)), "id": int(attr)},
        "expected": "CK_BBOOL boolean" if expected is None else expected,
        "actual": repr(value),
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
    }
    if type(value) is not bool:
        return classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=producer_mechanism,
            detail=detail,
            summary=f"{label}: present value has invalid CK_BBOOL shape: {value!r}",
        )
    if expected is not None and value is not expected:
        return classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=producer_mechanism,
            detail=detail,
            summary=f"{label}: expected {expected!r}, got {value!r}",
        )
    return None


def _record_bytes_readback(
    value: Any,
    *,
    attr: int,
    expected_length: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None,
) -> classification.Classification | None:
    """Record malformed present key material as a hard provider result."""
    if value is MISSING_ATTRIBUTE:
        return None
    if isinstance(value, bytes) and len(value) == expected_length:
        return None
    return classification.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=producer_mechanism,
        detail={
            "attribute": {"name": ATTR_NAMES.get(int(attr), str(attr)), "id": int(attr)},
            "expected": f"{expected_length}-byte bytes",
            "actual": repr(value),
            "producer_operation": producer_operation,
            "producer_mechanism": producer_mechanism,
        },
        summary=f"{label}: present value is not {expected_length}-byte bytes",
    )


def _raise_deferred_hard(records: list[classification.Classification]) -> None:
    """Raise a deferred malformed provider result after independent reads finish."""
    if records:
        priorities = {
            "CRITICAL": 3,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0,
            "INFO": 0,
        }
        strongest = max(
            records,
            key=lambda record: (
                record.outcome == "fail",
                priorities.get(record.severity, 0),
            ),
        )
        classification.raise_for_record(strongest)


def _classify_get_attribute_rv(
    rv: int,
    expected: tuple[int, ...],
    *,
    label: str,
    kind: str,
) -> None:
    """Classify a raw attribute read while retaining C_GetAttributeValue identity."""
    if rv == CKR_OK:
        record = classification.record_as(
            "accepted_invalid",
            kind=kind,
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            expected=expected,
            actual=rv,
            summary=f"{label}: accepted invalid (CKR_OK) -- must reject",
        )
        classification.raise_for_record(record)
    if rv in expected:
        return
    reason = (
        "nonspec_reject"
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv)
        else "self_contradiction"
    )
    record = classification.record_as(
        reason,
        kind=kind if reason == "nonspec_reject" else "metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        expected=expected,
        actual=rv,
    )
    classification.raise_for_record(record)


def _classify_sensitive_policy(
    *,
    claimed: bool,
    violated: bool,
    label: str,
    mechanism: str | None,
) -> None:
    """Classify a sensitivity effect with the raw read operation identity."""
    if claimed and not violated:
        return
    reason = "self_contradiction" if claimed else "honest_deviation"
    record = classification.record_as(
        reason,
        kind="policy",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        summary=(
            f"{label}: claimed the protection then violated it"
            if claimed
            else f"{label}: module does not claim the protection (honest non-support)"
        ),
    )
    classification.raise_for_record(record)


def _record_mixed_sensitive_row(
    attr: Any,
    *,
    rv: int,
    records: list[classification.Classification],
    attr_id: int = int(CKA_VALUE),
    attr_name: str = "CKA_VALUE",
    accept_32bit: bool = False,
) -> None:
    """Check the sensitive row only after a present protection claim.

    The default member identity keeps the historical AES ``CKA_VALUE`` detail;
    the QC1 matrix passes its own protected member through. The 64-bit
    sentinel alone counts as unavailable here (legacy behavior); the matrix
    opts into the 32-bit spelling via ``accept_32bit``, matching
    ``read_attributes`` (some modules return ``0xFFFFFFFF`` on 64-bit
    platforms).
    """
    if int(attr[0].ulValueLen) == int(CK_UNAVAILABLE_INFORMATION) or (
        accept_32bit and int(attr[0].ulValueLen) == int(CK_UNAVAILABLE_INFORMATION_32)
    ):
        return
    records.append(
        classification.record_as(
            "wrong_result",
            kind="policy",
            label="C_GetAttributeValue mixed sensitive row",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=rv,
            detail={
                "attribute": {"name": attr_name, "id": int(attr_id)},
                "expected": "CK_UNAVAILABLE_INFORMATION",
                "actual": int(attr[0].ulValueLen),
                "return_value": rv,
            },
            summary=(f"sensitive {attr_name} row did not report CK_UNAVAILABLE_INFORMATION"),
        )
    )


def _record_mixed_safe_row(
    attr: Any,
    label_buf: Any,
    label: bytes,
    *,
    rv: int,
    records: list[classification.Classification],
    accept_32bit: bool = False,
) -> None:
    """Validate safe-row metadata before inspecting its caller-owned buffer.

    The 64-bit sentinel alone marks explicit unavailability (legacy
    behavior); the matrix opts into the 32-bit spelling via
    ``accept_32bit``.
    """
    reported_length = int(attr[1].ulValueLen)
    unavailable = (
        reported_length == int(CK_UNAVAILABLE_INFORMATION)
        or (accept_32bit and reported_length == int(CK_UNAVAILABLE_INFORMATION_32))
    ) and rv in (
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_BUFFER_TOO_SMALL,
    )
    if reported_length != len(label):
        records.append(
            classification.record_as(
                "not_operational" if unavailable else "wrong_result",
                kind="policy",
                label="C_GetAttributeValue mixed safe row length",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=rv,
                detail={
                    "attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)},
                    "expected": len(label),
                    "actual": reported_length,
                    "supplied_capacity": len(label_buf),
                    "return_value": rv,
                },
                summary=(
                    "safe CKA_LABEL row is explicitly unavailable"
                    if unavailable
                    else "safe CKA_LABEL row returned an unexpected value length"
                ),
            )
        )
    elif bytes(label_buf[: attr[1].ulValueLen]) != label:
        records.append(
            classification.record_as(
                "wrong_result",
                kind="policy",
                label="C_GetAttributeValue mixed safe row value",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=rv,
                detail={
                    "attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)},
                    "expected": repr(label),
                    "actual": repr(bytes(label_buf[: attr[1].ulValueLen])),
                    "return_value": rv,
                },
                summary="C_GetAttributeValue did not populate the later safe CKA_LABEL row",
            )
        )


def _defer_mixed_raw_rv(rv: int, *, classify: bool) -> classification.Classification | None:
    """Return a raw-return classification so row checks can run first."""
    if not classify:
        return None
    try:
        _classify_get_attribute_rv(
            rv,
            (CKR_ATTRIBUTE_SENSITIVE,),
            label="C_GetAttributeValue mixed sensitive/safe template",
            kind="policy",
        )
    except (pytest.fail.Exception, pytest.xfail.Exception) as exc:
        record = getattr(exc, "_pkcs11_check_classification", None)
        if record is None:
            raise
        return cast(classification.Classification, record)
    return None


def _find_copied_secret_fragment(
    secret: bytes,
    observed: bytes,
    sentinel: bytes,
) -> tuple[int, int] | None:
    """Find a localized known-secret fragment at its actual buffer offset.

    Nonzero known bytes remain evidence when surrounding bytes are overwritten.
    An all-zero match needs the otherwise unchanged sentinel to distinguish a
    localized copy of the secret's leading ``00`` from blanket zeroization.
    """
    candidates: list[tuple[int, int]] = []
    for start in range(len(secret)):
        end = start
        while end < len(secret) and end < len(observed) and observed[end] == secret[end]:
            end += 1
        if end == start:
            continue
        for candidate_end in range(end, start, -1):
            fragment = observed[start:candidate_end]
            localized_zero = (
                observed[:start] == sentinel[:start]
                and observed[candidate_end:] == sentinel[candidate_end:]
            )
            if fragment != sentinel[start:candidate_end] and (any(fragment) or localized_zero):
                candidates.append((start, candidate_end - start))
                break
    return max(candidates, key=lambda candidate: candidate[1], default=None)


def _record_sensitive_value_leak(
    *,
    rv: int,
    fragment: tuple[int, int] | None,
    observed: bytes,
    records: list[classification.Classification],
) -> None:
    """Record a copied known-secret fragment as an independent hard finding."""
    if fragment is None:
        return
    fragment_offset, fragment_length = fragment
    records.append(
        classification.record_as(
            "self_contradiction",
            kind="policy",
            label=("raw C_GetAttributeValue copied CKA_VALUE bytes for a protected AES key"),
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            expected=(CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID),
            actual=rv,
            detail={
                "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
                "expected": "no key bytes copied",
                "actual": "sensitive key bytes observed in pValue",
                "copied_fragment_offset": fragment_offset,
                "copied_fragment_length": fragment_length,
                "observed_fragment": observed[
                    fragment_offset : fragment_offset + fragment_length
                ].hex(),
                "return_value": rv,
            },
            summary=("raw C_GetAttributeValue copied CKA_VALUE bytes for a protected AES key"),
        )
    )


class TestSensitiveKeyValue:
    """Test that CKA_VALUE is protected on sensitive keys."""

    def test_sensitive_aes_value_not_readable(self, p11_raw_session: Any) -> None:
        """Reading CKA_VALUE on a SENSITIVE=True AES key must fail."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            # policy claim/effect-check. read_attributes omits unavailable
            # (sensitive) attributes rather than raising, so verify the effect:
            #   claimed  = the key reports CKA_SENSITIVE=True back,
            #   violated = the protected CKA_VALUE is actually readable.
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            sensitive = attr_or_record(
                sens_attrs,
                CKA_SENSITIVE,
                label=(
                    "CKA_SENSITIVE=True on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                sensitive,
                attr=CKA_SENSITIVE,
                expected=None,
                label="CKA_SENSITIVE=True on generated AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            violated = CKA_VALUE in val_attrs
            # CKA_VALUE of a CKA_SENSITIVE key is exactly the protected secret this test
            # probes for -- legitimately sensitive, so a clean CKR_ATTRIBUTE_SENSITIVE
            # refusal is conformant (sensitive_is_conformant=True), not a deviation.
            # attr_or_record is now called unconditionally (previously only `if violated`,
            # i.e. only when the attribute was present and no recording happened at all) so
            # the correctly-protected case -- an absent CKA_VALUE -- is a visible record
            # instead of a dead branch with zero report.jsonl output.
            value = attr_or_record(
                val_attrs,
                CKA_VALUE,
                label=(
                    "CKA_VALUE on a CKA_SENSITIVE=True AES key (producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="honest_deviation",
                kind="policy",
                inherit_mechanism=False,
                sensitive_is_conformant=True,
            )
            record = _record_bytes_readback(
                value,
                attr=CKA_VALUE,
                expected_length=32,
                label="CKA_VALUE on a CKA_SENSITIVE=True AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)
            _raise_deferred_hard(hard_records)
            # gen_aes_key() above raises unless C_GenerateKey returns CKR_OK, so
            # reaching this point already proves the module accepted the
            # CKA_SENSITIVE=True template at creation -- that acceptance is
            # independent claim evidence.  A missing CKA_SENSITIVE readback (the
            # _record_bool_readback() call above already records it) must not
            # downgrade the claim: `violated` was observed directly from the
            # CKA_VALUE readback and is real evidence regardless.
            if sensitive is MISSING_ATTRIBUTE:
                claimed = True
            else:
                claimed = sensitive is True
            _classify_sensitive_policy(
                claimed=claimed,
                violated=violated,
                label="read CKA_VALUE on a CKA_SENSITIVE=True AES key "
                "(PKCS#11 v3.2: sensitive attributes cannot be revealed)",
                mechanism="CKM_AES_KEY_GEN",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_value_not_copied_on_rejected_get_attribute(
        self,
        p11_raw_session: Any,
    ) -> None:
        """A rejected sensitive-value read must not copy bytes into pValue."""
        rs = p11_raw_session
        secret = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                secret,
                attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False},
            )
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _SENSITIVE_IMPORT_REJECT_RVS,
                "import sensitive AES key for raw CKA_VALUE probe is not operational",
            )
            raise

        try:
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            sensitive = attr_or_record(
                sens_attrs,
                CKA_SENSITIVE,
                inherit_mechanism=False,
                label="CKA_SENSITIVE=True on imported AES key",
                reason="not_operational",
                kind="policy",
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                sensitive,
                attr=CKA_SENSITIVE,
                expected=None,
                label="CKA_SENSITIVE=True on imported AES key",
                producer_operation="C_CreateObject",
                producer_mechanism=None,
            )
            if record is not None:
                hard_records.append(record)

            sentinel = b"\xa5" * len(secret)
            value_buf = (ctypes.c_ubyte * len(secret)).from_buffer_copy(sentinel)
            attr = (CK_ATTRIBUTE * 1)()
            attr[0].type = CKA_VALUE
            attr[0].pValue = ctypes.cast(value_buf, ctypes.c_void_p)
            attr[0].ulValueLen = len(secret)

            rv = rs.raw.C_GetAttributeValue(rs.sh, key, attr, 1)
            observed = bytes(value_buf)
            copied_fragment = _find_copied_secret_fragment(secret, observed, sentinel)
            leaked = copied_fragment is not None
            # Keep the raw buffer observation separate from the return-code observation.
            deferred_rv: BaseException | None = None
            if rv != CKR_OK:
                try:
                    _classify_get_attribute_rv(
                        rv,
                        (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID),
                        label="C_GetAttributeValue(CKA_VALUE on sensitive key)",
                        kind="policy",
                    )
                except (pytest.fail.Exception, pytest.xfail.Exception) as exc:
                    if not leaked:
                        raise
                    # Preserve an unexpected clean CKR, but defer its xfail/fail
                    # outcome until the stronger raw-value leak is recorded.
                    deferred_rv = exc
            # CKR_ATTRIBUTE_SENSITIVE is direct protection evidence.  Any
            # copied known-secret fragment is independent of CKA_SENSITIVE
            # readback; for all other CKRs a present True claim is required.
            if sensitive is MISSING_ATTRIBUTE:
                if rv == CKR_ATTRIBUTE_SENSITIVE:
                    _record_sensitive_value_leak(
                        rv=rv,
                        fragment=copied_fragment,
                        observed=observed,
                        records=hard_records,
                    )
            else:
                if rv == CKR_ATTRIBUTE_SENSITIVE or sensitive is True:
                    _record_sensitive_value_leak(
                        rv=rv,
                        fragment=copied_fragment,
                        observed=observed,
                        records=hard_records,
                    )
            _raise_deferred_hard(hard_records)
            if deferred_rv is not None:
                raise deferred_rv
            # import_secret_key() above either raises (re-raised unless a known
            # rejection RV, which already xfails) or succeeds, so reaching this
            # point already proves the module accepted the CKA_SENSITIVE=True
            # template at creation -- independent claim evidence that a missing
            # CKA_SENSITIVE readback must not downgrade.
            if sensitive is MISSING_ATTRIBUTE:
                claimed = True
            else:
                claimed = sensitive is True
            _classify_sensitive_policy(
                claimed=claimed,
                violated=rv == CKR_OK or leaked,
                label=(
                    "raw C_GetAttributeValue copied CKA_VALUE bytes for a "
                    "CKA_SENSITIVE=True AES key"
                ),
                mechanism=None,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_get_attribute_value_mixed_sensitive_template_continues(
        self,
        p11_raw_session: Any,
    ) -> None:
        """A sensitive template row must not prevent later safe rows from filling."""
        rs = p11_raw_session
        secret = bytes.fromhex("2031425364758697a8b9cadbecfd0e1f")
        label = b"p11chk-mixed-sensitive"
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                secret,
                attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False, CKA_LABEL: label},
            )
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _SENSITIVE_IMPORT_REJECT_RVS,
                "import sensitive AES key for mixed-attribute probe is not operational",
            )
            raise

        try:
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            sensitive = attr_or_record(
                sens_attrs,
                CKA_SENSITIVE,
                inherit_mechanism=False,
                label="mixed C_GetAttributeValue CKA_SENSITIVE claim",
                reason="not_operational",
                kind="policy",
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                sensitive,
                attr=CKA_SENSITIVE,
                expected=None,
                label="mixed C_GetAttributeValue CKA_SENSITIVE claim",
                producer_operation="C_CreateObject",
                producer_mechanism=None,
            )
            if record is not None:
                hard_records.append(record)

            label_buf = (ctypes.c_ubyte * len(label))()
            attr = (CK_ATTRIBUTE * 2)()
            attr[0].type = CKA_VALUE
            attr[0].pValue = None
            attr[0].ulValueLen = 0
            attr[1].type = CKA_LABEL
            attr[1].pValue = ctypes.cast(label_buf, ctypes.c_void_p)
            attr[1].ulValueLen = len(label)

            rv = rs.raw.C_GetAttributeValue(rs.sh, key, attr, 2)
            # Classify the raw return before choosing any terminal path.  A
            # malformed refusal must remain visible even if a row oracle also
            # finds a stronger contradiction.
            if sensitive is MISSING_ATTRIBUTE:
                raw_record = _defer_mixed_raw_rv(
                    rv, classify=rv not in (CKR_OK, CKR_ATTRIBUTE_SENSITIVE)
                )
            else:
                raw_record = _defer_mixed_raw_rv(
                    rv,
                    classify=sensitive is True or rv not in (CKR_OK, CKR_ATTRIBUTE_SENSITIVE),
                )
            if raw_record is not None:
                hard_records.append(raw_record)

            # A missing/False claim disables the dependent
            # sensitive-row oracle, but never the independent safe-row check.
            rows_may_be_partial = rv in (
                CKR_ATTRIBUTE_TYPE_INVALID,
                CKR_BUFFER_TOO_SMALL,
            )
            if rv in (CKR_OK, CKR_ATTRIBUTE_SENSITIVE):
                if sensitive is MISSING_ATTRIBUTE:
                    pass
                else:
                    if sensitive is True:
                        _record_mixed_sensitive_row(attr, rv=rv, records=hard_records)
                _record_mixed_safe_row(attr, label_buf, label, rv=rv, records=hard_records)
            elif rows_may_be_partial:
                # The supplied label capacity is known to be sufficient. Validate
                # every present returned length before attempting byte inspection.
                _record_mixed_safe_row(attr, label_buf, label, rv=rv, records=hard_records)

            if sensitive is MISSING_ATTRIBUTE:
                pass
            elif sensitive is True:
                pass
            else:
                hard_records.append(
                    classification.record_as(
                        "honest_deviation",
                        kind="policy",
                        label="mixed C_GetAttributeValue CKA_SENSITIVE claim",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        mechanism=None,
                        actual=rv,
                        summary=(
                            "mixed C_GetAttributeValue probe requires a key that "
                            "reports CKA_SENSITIVE=True"
                        ),
                    )
                )
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_non_sensitive_aes_value_readable(self, p11_raw_session: Any) -> None:
        """CKA_VALUE is readable when SENSITIVE=False."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            value = attr_or_record(
                attrs,
                CKA_VALUE,
                label=(
                    "CKA_VALUE on a CKA_SENSITIVE=False AES key "
                    "(producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            if value is MISSING_ATTRIBUTE:
                return
            record = _record_bytes_readback(
                value,
                attr=CKA_VALUE,
                expected_length=32,
                label="CKA_VALUE on a CKA_SENSITIVE=False AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _raise_deferred_hard([record] if record is not None else [])
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_rsa_private_exponent_not_readable(self, p11_raw_session: Any) -> None:
        """Reading CKA_PRIVATE_EXPONENT on a sensitive RSA private key must fail."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SENSITIVE: True},
        )
        try:
            # policy claim/effect-check (see test_sensitive_aes_value_not_readable).
            sens_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SENSITIVE])
            sensitive = attr_or_record(
                sens_attrs,
                CKA_SENSITIVE,
                label=(
                    "CKA_SENSITIVE=True on RSA private key "
                    "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
                ),
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                sensitive,
                attr=CKA_SENSITIVE,
                expected=None,
                label="CKA_SENSITIVE=True on RSA private key",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if record is not None:
                hard_records.append(record)
            exp_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_PRIVATE_EXPONENT])
            violated = CKA_PRIVATE_EXPONENT in exp_attrs
            # CKA_PRIVATE_EXPONENT is legitimately sensitive on this key (it is the
            # secret this test probes for), so sensitive_is_conformant=True records a
            # clean CKR_ATTRIBUTE_SENSITIVE refusal as conformant. attr_or_record is now
            # called unconditionally -- previously only `if violated` (i.e. only once the
            # attribute was already known present), leaving the correctly-protected case
            # a dead branch with zero report.jsonl record for the absence.
            value = attr_or_record(
                exp_attrs,
                CKA_PRIVATE_EXPONENT,
                label=(
                    "CKA_PRIVATE_EXPONENT on a CKA_SENSITIVE=True RSA private key "
                    "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
                ),
                reason="honest_deviation",
                kind="policy",
                inherit_mechanism=False,
                sensitive_is_conformant=True,
            )
            if value is not MISSING_ATTRIBUTE and violated:
                if not isinstance(value, bytes) or not value:
                    hard_records.append(
                        classification.record_as(
                            "wrong_result",
                            kind="metadata",
                            label="CKA_PRIVATE_EXPONENT on a CKA_SENSITIVE=True RSA private key",
                            operation="C_GetAttributeValue",
                            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                            detail={
                                "attribute": {
                                    "name": ATTR_NAMES.get(
                                        int(CKA_PRIVATE_EXPONENT), str(CKA_PRIVATE_EXPONENT)
                                    ),
                                    "id": int(CKA_PRIVATE_EXPONENT),
                                },
                                "expected": "non-empty bytes",
                                "actual": repr(value),
                                "producer_operation": "C_GenerateKeyPair",
                                "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                            },
                            summary=(
                                "present CKA_PRIVATE_EXPONENT has an invalid provider value shape"
                            ),
                        )
                    )
            _raise_deferred_hard(hard_records)
            # gen_rsa_keypair_or_xfail() above raises/xfails unless the module
            # accepted the CKA_SENSITIVE=True private-key template, so reaching
            # this point already proves creation-time acceptance -- independent
            # claim evidence that a missing CKA_SENSITIVE readback must not
            # downgrade.  `violated` was observed directly from the
            # CKA_PRIVATE_EXPONENT readback and is real evidence regardless.
            if sensitive is MISSING_ATTRIBUTE:
                claimed = True
            else:
                claimed = sensitive is True
            _classify_sensitive_policy(
                claimed=claimed,
                violated=violated,
                label="read CKA_PRIVATE_EXPONENT on a CKA_SENSITIVE=True RSA private key "
                "(PKCS#11 v3.2: sensitive attributes cannot be revealed)",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestExtractableEnforcement:
    """Test CKA_EXTRACTABLE enforcement."""

    def test_non_extractable_by_default(self, p11_raw_session: Any) -> None:
        """Default-generated AES key extractability.

        Per OASIS PKCS#11 spec, CKA_EXTRACTABLE has no mandated default value
        -- it is implementation-defined. Both True and False are spec-conformant.
        This test documents which default the module uses via a compliance note.
        """
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
                extractable = attr_or_record(
                    attrs,
                    CKA_EXTRACTABLE,
                    label=(
                        "CKA_EXTRACTABLE default on generated AES key "
                        "(producer_mechanism=CKM_AES_KEY_GEN)"
                    ),
                    reason="honest_deviation",
                    kind="metadata",
                    inherit_mechanism=False,
                )
            except CkrAssertionError as e:
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    deviation_record = classification.record_as(
                        "honest_deviation",
                        kind="metadata",
                        label="CKA_EXTRACTABLE default on generated AES key",
                        operation="C_GetAttributeValue",
                        mechanism="CKM_AES_KEY_GEN",
                        expected=CKR_OK,
                        actual=e.rv,
                        detail={
                            "attribute": {
                                "name": "CKA_EXTRACTABLE",
                                "id": int(CKA_EXTRACTABLE),
                            }
                        },
                        summary=(f"CKA_EXTRACTABLE default readback is unavailable: {e.rv!r}"),
                    )
                    classification.raise_for_record(deviation_record)
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

        if extractable is MISSING_ATTRIBUTE:
            return
        record = _record_bool_readback(
            extractable,
            attr=CKA_EXTRACTABLE,
            expected=None,
            label="CKA_EXTRACTABLE default on generated AES key",
            producer_operation="C_GenerateKey",
            producer_mechanism="CKM_AES_KEY_GEN",
        )
        _raise_deferred_hard([record] if record is not None else [])

        from pkcs11_check.compliance import ComplianceLevel, note

        if extractable is True:
            note(
                "Module defaults CKA_EXTRACTABLE to True for generated AES keys; "
                "PKCS#11 spec does not mandate a specific default",
                ComplianceLevel.VENDOR,
            )
        else:
            note(
                "Module defaults CKA_EXTRACTABLE to False for generated AES keys; "
                "PKCS#11 spec does not mandate a specific default",
                ComplianceLevel.VENDOR,
            )
        # Both True and False are spec-conformant; _record_bool_readback has
        # already enforced the provider's CK_BBOOL shape.

    def test_extractable_when_requested(self, p11_raw_session: Any) -> None:
        """AES key with EXTRACTABLE=True allows VALUE read (when also not sensitive)."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
            extractable = attr_or_record(
                attrs,
                CKA_EXTRACTABLE,
                label=(
                    "CKA_EXTRACTABLE=True on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                extractable,
                attr=CKA_EXTRACTABLE,
                expected=True,
                label="CKA_EXTRACTABLE=True on generated AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            value = attr_or_record(
                val_attrs,
                CKA_VALUE,
                label="CKA_VALUE on extractable AES key (producer_mechanism=CKM_AES_KEY_GEN)",
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            record = _record_bytes_readback(
                value,
                attr=CKA_VALUE,
                expected_length=32,
                label="CKA_VALUE on extractable AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestSensitiveFlag:
    """Test that CKA_SENSITIVE flag behaves correctly."""

    def test_sensitive_flag_is_true_when_requested(self, p11_raw_session: Any) -> None:
        """AES key with SENSITIVE=True has SENSITIVE=True."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            value = attr_or_record(
                attrs,
                CKA_SENSITIVE,
                label=(
                    "CKA_SENSITIVE=True on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            record = _record_bool_readback(
                value,
                attr=CKA_SENSITIVE,
                expected=True,
                label="CKA_SENSITIVE=True on generated AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _raise_deferred_hard([record] if record is not None else [])
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_flag_settable_at_creation(self, p11_raw_session: Any) -> None:
        """SENSITIVE=False can be set at creation time."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: False})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            value = attr_or_record(
                attrs,
                CKA_SENSITIVE,
                label=(
                    "CKA_SENSITIVE=False on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            record = _record_bool_readback(
                value,
                attr=CKA_SENSITIVE,
                expected=False,
                label="CKA_SENSITIVE=False on generated AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _raise_deferred_hard([record] if record is not None else [])
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_always_sensitive_flag(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is readable and consistent."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key_sensitive = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        key_not_sensitive: int | None = None
        try:
            key_not_sensitive = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_SENSITIVE: False},
            )
            # ALWAYS_SENSITIVE should be True for keys that were always sensitive
            a1 = read_attributes(rs.raw, rs.sh, key_sensitive, [CKA_ALWAYS_SENSITIVE])
            always_sensitive = attr_or_record(
                a1,
                CKA_ALWAYS_SENSITIVE,
                label=(
                    "CKA_ALWAYS_SENSITIVE on sensitive AES key (producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                always_sensitive,
                attr=CKA_ALWAYS_SENSITIVE,
                expected=True,
                label="CKA_ALWAYS_SENSITIVE on sensitive AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)
            # ALWAYS_SENSITIVE should be False for keys that started non-sensitive
            a2 = read_attributes(rs.raw, rs.sh, key_not_sensitive, [CKA_ALWAYS_SENSITIVE])
            always_sensitive = attr_or_record(
                a2,
                CKA_ALWAYS_SENSITIVE,
                label=(
                    "CKA_ALWAYS_SENSITIVE on non-sensitive AES key "
                    "(producer_mechanism=CKM_AES_KEY_GEN)"
                ),
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            record = _record_bool_readback(
                always_sensitive,
                attr=CKA_ALWAYS_SENSITIVE,
                expected=False,
                label="CKA_ALWAYS_SENSITIVE on non-sensitive AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_sensitive)
            if key_not_sensitive is not None:
                destroy_quietly(rs.raw, rs.sh, key_not_sensitive)


# ---------------------------------------------------------------------------
# QC1 protected-component read matrix (#54.1)
#
# Table-defined protected members by key family and creation path. Every
# attribute ID below already exists in the tree's attribute tables; the
# matrix invents none (in particular SLH-DSA has no CKA_SEED row).
# ---------------------------------------------------------------------------

_MATRIX_READ_CAP = 8192
_MATRIX_SENTINEL_BYTE = 0xA5
_MATRIX_READABLE_MAX = 65536

_UNAVAILABLE_64 = int(CK_UNAVAILABLE_INFORMATION)
_UNAVAILABLE_32 = int(CK_UNAVAILABLE_INFORMATION_32)

# Attribute-read returns that guarantee completed per-member processing: the
# three special attribute-status returns (spec section 5.7.5) plus CKR_OK.
# Lengths and buffers are only interpreted under these; any other return
# leaves outputs uninterpretable (clean refusals xfail, malformed RVs fail)
# while demonstrated disclosure is still checked independently.
_MATRIX_COMPLETED_READ_RVS = frozenset(
    {
        int(CKR_OK),
        int(CKR_ATTRIBUTE_SENSITIVE),
        int(CKR_ATTRIBUTE_TYPE_INVALID),
        int(CKR_BUFFER_TOO_SMALL),
    }
)


def _matrix_gen_seed_obligation(family_id: str, creation: str, attr: int) -> bool:
    """Whether a missing seed is a deviation rather than an optional absence.

    Standard ML-DSA/ML-KEM generation contributes CKA_SEED to the private
    key (spec sections 6.67.4/6.68.4); imports carry no such obligation.
    """
    return creation == "gen" and family_id in ("mldsa", "mlkem") and int(attr) == int(CKA_SEED)


def _matrix_is_unavailable(length: int) -> bool:
    """Whether a returned length is the unavailable sentinel (either width)."""
    return length == _UNAVAILABLE_64 or length == _UNAVAILABLE_32


def _matrix_pattern(length: int) -> bytes:
    """Deterministic pattern bytes holding no read-sentinel byte."""

    def _byte(index: int) -> int:
        value = (index * 37 + 11) % 256
        return 0x5A if value == _MATRIX_SENTINEL_BYTE else value

    return bytes(_byte(index) for index in range(length))


_MATRIX_AES_SECRET = _matrix_pattern(32)
_MATRIX_EC_SCALAR = b"\x01" + _matrix_pattern(31)
_MATRIX_ED_SEED = _matrix_pattern(32)
_MATRIX_MONT_SCALAR = _matrix_pattern(32)
_MATRIX_DH_VALUE = b"\x01" + _matrix_pattern(255)
_MATRIX_X942_VALUE = b"\x01" + _matrix_pattern(31)
_MATRIX_SLH_VALUE = _matrix_pattern(64)

# Differential alternate plantings: different bytes, same validity shape.
# The disclosure differential re-imports with these and compares: output that
# tracks the planting is disclosure, identical output is constant scrubbing.
_MATRIX_AES_SECRET_ALT = _matrix_pattern(40)[8:]
_MATRIX_EC_SCALAR_ALT = b"\x02" + _matrix_pattern(39)[8:]
_MATRIX_ED_SEED_ALT = _matrix_pattern(40)[8:]
_MATRIX_MONT_SCALAR_ALT = _matrix_pattern(40)[8:]
_MATRIX_DH_VALUE_ALT = b"\x01" + _matrix_pattern(263)[8:]
_MATRIX_X942_VALUE_ALT = b"\x01" + _matrix_pattern(39)[8:]
_MATRIX_SLH_VALUE_ALT = _matrix_pattern(72)[8:]

_SECP256R1_OID = encode_named_curve_parameters("secp256r1")
_ED25519_OID = encode_named_curve_parameters("ed25519")
_X25519_OID = encode_named_curve_parameters("x25519")
_X448_OID = encode_named_curve_parameters("x448")

# First ML-DSA-44 noseed secret key (2560 bytes) from the vendored
# Wycheproof corpus (group privateKey). Pinned by provenance contract.
_MATRIX_MLDSA44_SK = bytes.fromhex(
    "db9ac67708f2ba0fac1f92bd802f9be89ecab966feef59872a1a9ac90b111117"
    "43426e639f2c42e861e7f94ab0f744de48a7c5a27137e7b0a9c4855676df8b23"
    "9c4fa4df25ba91314a29ff442622734bdb60bdd6e32da000ed543cc0715e74f6"
    "9a06f1b020ec8e6a82bc1309e7c184b9290518ece32f6115f535b09a55694d46"
    "03086ca0268d18a224180449e4a8616416921323268414256444121c14001994"
    "219a0249d34029c08851d3b20840c48559b260c4946903462d09422821444c63"
    "906513c14920b725e4104284c888a4023283404d4014101295415048258c082d"
    "410641a08821c200210a45200406900989891c2431ca262ed2248814100da080"
    "70da42064b286811180c13b110da3805003305dab2811a1021209909da324d00"
    "a17112178522a66524318ec024129440202123481ac28cd9140040b401640005"
    "988265030110044364d0c82052880853840088c06ccaa080d2082452224e2020"
    "1124880198c82813342a0a33700b43720c2211d1c804cc9610c83681214212c2"
    "40128198505a204211c62d22378519290ca4226461463284980920a868e30609"
    "21302a5a0004d9b02193b449d3a8501c18421994459a2685084752c9402ed012"
    "22230841c9044ec00651e184859aa20c9a80011409480c06805bc48d8b12910b"
    "c0318c383099a22901816cd41482083045233585e0248ac414681b8264120690"
    "c4440e9c2002918004c026051cc540cc308914b8105b9425e2a4244b440563c4"
    "6059108280b86841808109298020078848b024e2248c94060a09890ca116024b"
    "964c60146c61342e9b068554b461549610a132254ca20d0190404c402aa11624"
    "00b5819a940d89480ecb18704ba2205bc66990484e1b91659830911b07665cb0"
    "70434824a1408e99426219803002045062046d4a2249c3b00154b611534090d1"
    "986508014e04372124406c0901260996242280611804490344265b140e540485"
    "c0c611911449d4448e1c4286db0201541060824881d9122648a461e4280d8208"
    "3104142a03a3805312020a9710d432069332850c8005d9824dc22851d2a620c4"
    "06518bb0285342704b0650c386042327820a2086221631999849d33225e32609"
    "03850450106d11a124140526093148d8362498a689501008d9a2209a262688c4"
    "80a2182a0ab808d4380248082119446200218844c841c3983143306e14146e1b"
    "1664c2988584820983902451c200d2086d54987124956800442663104cd0124c"
    "c19ce4edd5e09263253b56113712ef0d6f73b5270184bd74a62fcb4cdaa3dbbb"
    "82e9efa266561f0522e2457215180809df96cf7efa12be2bb4e32536ef4461c4"
    "566f7aafdf3bc7d99d00f6d70a4f050ddd25570d397fe47b85f1578c01fa8aa9"
    "0cf6475a97030ad03be687cfd88692991eaf5a7dcf8d057a3df3abec07190f79"
    "1a6896a4a1b9665fbdb87a4a618704f80b3f689288537d3bfc4be79fe1ef9cbc"
    "a4acd3927b30c1b34333a203243b09813cfb4b03137bb3855620c4aa7b76d318"
    "015c338be67509f280d38ed5171a7deb3af3e297eca64d65ac26ff9b068d10f0"
    "a4aa774029e617bda5977a54673a44d2c70f7398d42acefe174a60f72976930c"
    "472abee642530d72abb76adef0dbae1e70194a48d83632e223a7b741ab388939"
    "f87af0a7661f1f49c978ff7efe41d43d26881330adb9805722852c35410bfc44"
    "3a70173132a3ad1e2b26796ed3856e1ba7246f96b92ab16891aa48af667b2831"
    "703355ba54ff5aa927d2b2c322da05e7067ecb9e06fae97b9e35e1ebfc1ad5ff"
    "9d0abfc9924ffa80a14e8e527947dd69d19806fa1c915470ed3585724eb3398b"
    "f0d3ec748781df9e31bb3a308acd55ac6ae4980284ed2126a7ad673c4109cda7"
    "6becfa1d0b0765e9166e696f719d2d0472f6eba685171767a559945696ea31a8"
    "987cd0787261e287739c1c2b95d09ef883c2457853a4a60ac78a18acfbbe0adc"
    "02bdb818d076c7c58f2fe6d5b29fb68ee76c2aa463e0ed0e28b71df3430e2516"
    "de04343ddd66e17475c0c372ea5e3bb22ec9ff201886bd32ff95e58df8a1cde7"
    "4c76951181b2ef5650de4fd907ccf47bbd2202d4be66c8391a6d74bd72ed70ba"
    "63e85df4da2c339476e28542b831e3094db98fca0c0e7d8ea75abcdf2eba4d8f"
    "cf65878dfa349fb022fd1b8fe2d09171c09470934c07ae3763f8f395b3224652"
    "7bdd96cc2b7d10ab7ceeeb4fbf0976128023357ab6b54a6216137ebd93b5b6cb"
    "0f8412fabbc95d5830cf820da3ba96fe9248129d72219d655c9147f78a4ef23a"
    "041ebced275a6c8c7883a25152bfcc44e77f4f0c77896a81e5b1cc84af36dcce"
    "7bcf1626d30128916c459a680c5092d0a2c8cbd6ff39b377b6dc9255a87e24ac"
    "065d8b595036de0b8560bb9adf66b095e73d2b8613ca9ab0ff9087417c521b7e"
    "c146492c2a1c1a051c1b643f7663ca68ac22abdb834327f1ed2a426de982d66d"
    "57984f7d62589ff1298b935a4ba8bc254b359107442120b07b77e4de25fb1f41"
    "df945dcd34d9e48a788e8261d6079656d29807e9d421b58af2cd6d5997ba589c"
    "c3f8cd0b4b3a52f77cfb09040886f374ca4ce278cd97d4b1becd96e203afac47"
    "bf928358becb5ae1e806a9b3f0c34bad4d1b5dc80d76547e9c5ac22c5d694c49"
    "dafad6a6585619119b76dcfa13721ccb6f672b8f4a91c80b1b91c273215efbbb"
    "c9e1b0703d6da0e69f486d131b80b518ee30346d59fded78a144cf1a7eabd137"
    "0de87dca0b8f694b2364a6e69e480ce08d026c89faaf045c25f2caf01a1fd6fa"
    "bc0e5010a03163a6d23fa995566755d6ced4f0ed5adeeb067d385353342bc8dd"
    "bb676fe5b00e2196d5979a4ff3da88f628751ed1b54880d7258b03b5fbb925b7"
    "9816120ca3fc3f2e97a6d72e8562c503afdcf19a70404beff8cee6199d85068a"
    "1a0c5433a38637134d05fbae0027f3a4062afe32e29e0453619d2ea7aed2b3ff"
    "a539afb0fc119368203f31f59adb42485b93db1d9abb32d31a58a56f42d9375e"
    "50999292ac38f15d765482b18c51df9bf611fd33806c8b9423108133e80347c7"
    "d1be87d20e024168e4c8e55bcb1dc6c6faa151a648cf423bd5fe8aed0e2bd212"
    "92156366a9a7f1fe16e7e168599b8ba0557a3b3ac29167c362bc1edd50cd2ada"
    "f1f23d161ca48597ec53de2b0b0776222c0c47ce6cb8085441f26f2e8395cd7d"
    "30a32fb246ab5627a53cb3235d45ebabac56f572e777c945dee586798e2b5484"
    "c84eb20e835ea3224a3d1799ad6e8890ad11825a1770976b28d2eba8c75ec657"
    "e6dd6a6834fd4d21a3765056ee2535d2c5b85b33e5885978718c9a8c54d3efcd"
    "2b063bf441a7390fd7b9e37db78c3a8e47da4979adf6ab6df993aec0c43fcd5d"
    "0fcf0b392f3cad251e43c8a297ca824c801015114a8b0849a0b6a574f60bb9e4"
    "d1eb2b846bbc54a8d233217dc79c7a8043f7aadc99bca62b4083dc4110a1af76"
    "683a79ae5161b49c6197ee7d85292018311c13c87b7b715c13fd6ddf246ede63"
    "d3974a3544599faa17299d259c571ebefe862a193e3c47a762511c1ad4e1e41d"
    "ae0dfed92c9fd6f0a0f3b90f2475c46c7330e610ea1aac5d9a01e301755027d6"
)

# Matched ML-KEM-512 decapsulation key (1632 bytes) + seed (64 bytes,
# d || z) from the vendored Wycheproof keygen_seed vector tc1.
_MATRIX_MLKEM512_DK = bytes.fromhex(
    "9cda1686a3396a7c109b415289f56a9ec44cd5b9b674c38a3bbab30a2c90f004"
    "37a264b0be9a1e8ba887d3c3b100898054272f941c88a1f208f1c914f964c1aa"
    "d613a6a84f88e42d3556835fb161fdc5cd15a3bc7e74b6f2612fa8271c7ea112"
    "b05c2a36cc707ce38d5d1acc5115462a8c1aabf07276c72318337f74b5cbefea"
    "7a803790bc0393f3a54c724a5765a48f296b03f484376023626930222704c08f"
    "d3bc729315d1fc70eb7975a97b9deed162f486bbc64a097111952d89b57d765e"
    "8a991a2e564206ea7bf5e4007a66358831ca0e34b2f6a84d10f79c477cb66a8a"
    "952569367388130d7b974a63aa51996c97709bb8eabc94e6a535d792d2905474"
    "952d6b8c2222b2ae56dc66fb0461192066cddb43ec05984fb4982649771397c6"
    "a8379f3b5643069848875919e89cc439a3be2f081490f341bd1240add80ddb8c"
    "9963b47a2a0992290338da9c3b725c6da44718c01046812562afb084837acb3c"
    "575e4f93936c352ac0e70aa3845ee485296e6b02de0b47b5c4c96b0b7cf94c4a"
    "be95486153118e43c2b9c84d9da91c6c5acd5a57002d058497992799e5ba1ce6"
    "c25eb29844d858ba1c37850c0c2f57c60de37f77c082ec14494eba288a659151"
    "16c20a325de31aaadd680db19c0cfcc3460f0aa01a87a6a580c6ca291faef0cc"
    "c49b76a8dac4f9d41640509dbd0b4045c1530ed34755d47462700f2a8caf9680"
    "a6d7e38a7e2a63e937650a23306d855da2a2b7ef505ca596ab0485013ea927c7"
    "342343613643ba4007d6c874b980c79c3aa1c74f8581c34849b36ea79815fbb4"
    "ccf9610583081d7c5b4409b8d0531c04bcaf7cc751103a5fd1ba4470833e8977"
    "5aded970b5471859250fe7267105835f390030c5e7cd3f961019eaaea23777d3"
    "47bb2adcb673c02034f394342271bcea6414e546c3b20bd57481c7ea14c77c38"
    "8cc86251c12558b100f8c5b3d03ca2c70713909659c8ba26d0d1765e0bc823d6"
    "8ca5570de600cd0941725d386e14c1012df5951beb8d8281a4f6815d3760b764"
    "295ad0406c2bf7928ad65032b65f14b77ccb8917c93a29d6287d8a6062399cb6"
    "400865ed10b619aa5811139bc086825782b2b7124f757c83ae794444bc78a478"
    "96acf1262c81351077893bfc56f90449c2fa5f6e586dd37c0b9b581992638cb7"
    "e7bcbbb99afe4781d80a50e69463fbd988722c3635423e27466c71dcc674527c"
    "cd728968cbcdc00c5c9035bb0af2c9922c7881a41dd2875273925131230f6ca5"
    "9e9136b39f956c93b3b2d14c641b089e07d0a840c893ecd76bbf92c805456668"
    "d07c621491c5c054991a656f511619556eb97782e27a3c785124c70b0daba6c6"
    "24d18e0f9793f96ba9e1599b17b30dccc0b4f3766a07b23b257309cd76aba072"
    "c2b9c9744394c6ab9cb6c54a97b5c57861a58dc0a03519832ee32a07654a070c"
    "0c8c4e8648addc355f274fc6b92a087b3f9751923e44274f858c49caba72b658"
    "51b3adc48936955097cad9553f5a263f1844b52a020ff7ca89e881a01b95d957"
    "a3153c0a5e0a1ccd66b1821a2b8632546e24c7cbbc4cb08808cac37f7da6b16f"
    "8aced052cdb2564948f1ab0f768a0d3286ccc7c3749c63c781530fa1ae670542"
    "855004a645b522881ec1412bdae342085a9dd5f8126af96bbdb0c1af69a15562"
    "cb2a155a100309d1b641d08b2d4ed17bfbf0bc04265f9b10c108f850309504d7"
    "72811bba8e2be16249aa737d879fc7fb255ee7a6a0a753bd93741c61658ec074"
    "f6e002b019345769113cc013ff7494ba8378b11a172260aaa53421bde03a3558"
    "9d57e322fefa4100a4743926ab7d62258b87b31ccbb5e6b89cb10b271aa05d99"
    "4bb5708b23ab327ecb93c0f3156869f0883da2064f795e0e2ab7d3c64d61d230"
    "3fc3a29e1619923ca801e59fd752ca6e7649d303c9d20788e1214651b06995eb"
    "260c929a1344a849b25ca0a01f1eb52913686bba619e23714464031a78439287"
    "fca78f4c0476223eea61b7f25a7ce42cca901b2aea129817894ba3470823854f"
    "3e5b28d86ba979e54671862d90470b1e7838972a81a48107d6ac0611406b21fb"
    "cce1db7702ea9dd6ba6e40527b9dc663f3c93bad056dc28511f66c3e0b928db8"
    "879d22c592685cc775a6cd574ac3bce3b27591c821929076358a2200b377365f"
    "7efb9e40c3bf0ff0432986ae4bc1a242ce9921aa9e22448819585dea308eb039"
    "50c8dd152a4531aab560d2fc7ca9a40ad8af25ad1dd08c6d79afe4dd4d1eee5a"
    "8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"
)
_MATRIX_MLKEM512_SEED = bytes.fromhex(
    "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d"
    "8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"
)


def _matrix_flipped_head(secret: bytes, width: int) -> bytes:
    """Return ``secret`` with its first ``width`` bytes inverted (alt planting)."""
    return bytes(byte ^ 0xFF for byte in secret[:width]) + secret[width:]


def _matrix_flipped_tail(secret: bytes, width: int) -> bytes:
    """Return ``secret`` with its last ``width`` bytes inverted (alt planting)."""
    return secret[:-width] + bytes(byte ^ 0xFF for byte in secret[-width:])


# ML-DSA secret keys open with the 32-byte rho seed: flipping its head keeps
# a well-formed key, and the opaque tail (key/signature material) tolerates
# the same. ML-KEM decapsulation keys open with opaque encapsulation-key
# bytes and close with the 32-byte z; the 64-byte seed is uniform d || z, so
# it varies end to end. Every planting varies each observed region class
# (prefix, interior-adjacent, suffix) while staying structurally well-formed,
# so a short disclosure cannot hide behind an unvaried fragment.
_MATRIX_MLDSA44_SK_ALT = _matrix_flipped_tail(_matrix_flipped_head(_MATRIX_MLDSA44_SK, 8), 32)
_MATRIX_MLKEM512_DK_ALT = _matrix_flipped_tail(_matrix_flipped_head(_MATRIX_MLKEM512_DK, 8), 32)
_MATRIX_MLKEM512_SEED_ALT = bytes(byte ^ 0xFF for byte in _MATRIX_MLKEM512_SEED)


def _matrix_all_mechanism_names() -> frozenset[str]:
    """Every CKM_* mechanism name known to the tree's mechanism metadata."""
    from pkcs11_check.raw import types_std

    names = set(MECHANISM_NAMES.values())
    for attr_name in dir(types_std):
        if (
            attr_name.startswith("CKM_")
            and attr_name.isupper()
            and isinstance(getattr(types_std, attr_name), int)
        ):
            names.add(attr_name)
    return frozenset(names)


_MATRIX_ALL_MECHANISM_NAMES = _matrix_all_mechanism_names()


def _matrix_mechanism_matches_family(name: str, family_id: str) -> bool:
    """Whether a CKM_* metadata name evidences import capability for a family.

    Import cells only need the token to handle the family's key type, so
    every usage mechanism counts -- not just key generation. The match runs
    over the tree's mechanism metadata (standard names plus the registered
    CKM_* aliases), never a hand list, so newly tabled mechanisms are
    recognized without code changes.
    """
    if family_id == "aes":
        return name.startswith("CKM_AES_")
    if family_id == "rsa":
        return "_RSA_" in name
    if family_id == "ec":
        return name.startswith("CKM_EC") and not name.startswith(
            ("CKM_EC_EDWARDS", "CKM_EC_MONTGOMERY")
        )
    if family_id == "edwards":
        return name.startswith("CKM_EC_EDWARDS") or name.startswith("CKM_EDDSA")
    if family_id == "montgomery":
        return name.startswith(("CKM_EC_MONTGOMERY", "CKM_ECDH1_")) or name == "CKM_XEDDSA"
    if family_id == "dh":
        return name.startswith("CKM_DH_")
    if family_id == "x942":
        return name.startswith("CKM_X9_42")
    if family_id == "mldsa":
        return "ML_DSA" in name
    if family_id == "mlkem":
        return "ML_KEM" in name
    if family_id == "slhdsa":
        return "SLH_DSA" in name
    raise AssertionError(f"unknown matrix family {family_id!r}")


def _matrix_import_mechanisms(family_id: str) -> tuple[str, ...]:
    """Derive a family's recognized import mechanisms from mechanism metadata."""
    bare = sorted(
        name[len("CKM_") :]
        for name in _MATRIX_ALL_MECHANISM_NAMES
        if name.startswith("CKM_") and _matrix_mechanism_matches_family(name, family_id)
    )
    assert bare, f"no import mechanisms derived for {family_id}"
    return tuple(bare)


@dataclass(frozen=True)
class _MatrixComponent:
    """One protected member: ``mandatory`` members fail when readable."""

    attr: int
    mandatory: bool


@dataclass(frozen=True)
class _MatrixFamily:
    """One matrix row: protected members plus creation-path gates."""

    family: str
    key_type: int
    spec_ref: str
    protected: tuple[_MatrixComponent, ...]
    public: tuple[int, ...]
    family_mechanisms: tuple[str, ...]
    keygen_mechanism: str | None
    import_mechanisms: tuple[str, ...]
    creations: tuple[str, ...]


_MATRIX_FAMILIES: tuple[_MatrixFamily, ...] = (
    _MatrixFamily(
        family="aes",
        key_type=int(CKK_AES),
        spec_ref="PKCS#11 v3.2 secret-key CKA_VALUE",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(),
        family_mechanisms=("AES_KEY_GEN",),
        keygen_mechanism="AES_KEY_GEN",
        import_mechanisms=_matrix_import_mechanisms("aes"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="rsa",
        key_type=int(CKK_RSA),
        spec_ref="PKCS#11 v3.2 RSA private key components",
        protected=(
            _MatrixComponent(int(CKA_PRIVATE_EXPONENT), True),
            _MatrixComponent(int(CKA_PRIME_1), False),
            _MatrixComponent(int(CKA_PRIME_2), False),
            _MatrixComponent(int(CKA_EXPONENT_1), False),
            _MatrixComponent(int(CKA_EXPONENT_2), False),
            _MatrixComponent(int(CKA_COEFFICIENT), False),
        ),
        public=(int(CKA_PUBLIC_EXPONENT),),
        family_mechanisms=("RSA_PKCS_KEY_PAIR_GEN", "RSA_X9_31_KEY_PAIR_GEN"),
        keygen_mechanism="RSA_PKCS_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("rsa"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="ec",
        key_type=int(CKK_EC),
        spec_ref="PKCS#11 v3.2 EC private key CKA_VALUE",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(int(CKA_EC_PARAMS),),
        family_mechanisms=("EC_KEY_PAIR_GEN", "ECDSA_KEY_PAIR_GEN"),
        keygen_mechanism="EC_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("ec"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="edwards",
        key_type=int(CKK_EC_EDWARDS),
        spec_ref="PKCS#11 v3.2 Edwards private key CKA_VALUE",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(int(CKA_EC_PARAMS),),
        family_mechanisms=("EC_EDWARDS_KEY_PAIR_GEN",),
        keygen_mechanism="EC_EDWARDS_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("edwards"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="montgomery",
        key_type=int(CKK_EC_MONTGOMERY),
        spec_ref="PKCS#11 v3.2 Montgomery private key CKA_VALUE",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(int(CKA_EC_PARAMS),),
        family_mechanisms=("EC_MONTGOMERY_KEY_PAIR_GEN",),
        keygen_mechanism="EC_MONTGOMERY_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("montgomery"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="dh",
        key_type=int(CKK_DH),
        spec_ref="PKCS#11 v3.2 DH private key CKA_VALUE",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(int(CKA_PRIME), int(CKA_BASE)),
        family_mechanisms=("DH_PKCS_KEY_PAIR_GEN", "DH_PKCS_DERIVE"),
        keygen_mechanism="DH_PKCS_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("dh"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="x942",
        key_type=int(CKK_X9_42_DH),
        spec_ref="PKCS#11 v3.2 X9.42 DH private key CKA_VALUE",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(int(CKA_PRIME), int(CKA_SUBPRIME), int(CKA_BASE)),
        family_mechanisms=("X9_42_DH_KEY_PAIR_GEN", "X9_42_DH_DERIVE"),
        keygen_mechanism="X9_42_DH_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("x942"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="mldsa",
        key_type=int(CKK_ML_DSA),
        spec_ref="PKCS#11 v3.2 ML-DSA private key CKA_VALUE + CKA_SEED",
        protected=(
            _MatrixComponent(int(CKA_VALUE), True),
            _MatrixComponent(int(CKA_SEED), False),
        ),
        public=(),
        family_mechanisms=("ML_DSA_KEY_PAIR_GEN", "ML_DSA"),
        keygen_mechanism="ML_DSA_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("mldsa"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="mlkem",
        key_type=int(CKK_ML_KEM),
        spec_ref="PKCS#11 v3.2 ML-KEM private key CKA_VALUE + CKA_SEED",
        protected=(
            _MatrixComponent(int(CKA_VALUE), True),
            _MatrixComponent(int(CKA_SEED), False),
        ),
        public=(),
        family_mechanisms=("ML_KEM_KEY_PAIR_GEN", "ML_KEM"),
        keygen_mechanism="ML_KEM_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("mlkem"),
        creations=("gen", "import"),
    ),
    _MatrixFamily(
        family="slhdsa",
        key_type=int(CKK_SLH_DSA),
        spec_ref="PKCS#11 v3.2 SLH-DSA private key CKA_VALUE (no CKA_SEED row)",
        protected=(_MatrixComponent(int(CKA_VALUE), True),),
        public=(),
        family_mechanisms=("SLH_DSA_KEY_PAIR_GEN", "SLH_DSA"),
        keygen_mechanism="SLH_DSA_KEY_PAIR_GEN",
        import_mechanisms=_matrix_import_mechanisms("slhdsa"),
        creations=("gen", "import"),
    ),
)

_MATRIX_FAMILIES_BY_ID = {family.family: family for family in _MATRIX_FAMILIES}

# Seal id -> (CKA_SENSITIVE, CKA_EXTRACTABLE). Each flag varies with the
# other held: sensitive-only vs unsealed isolates CKA_SENSITIVE, both vs
# sensitive-only varies CKA_EXTRACTABLE under a held seal, and
# extractable-only vs unsealed isolates CKA_EXTRACTABLE=False, which seals
# the table-marked attributes on its own (spec sections 4.10-4.11).
_MATRIX_SEALS: dict[str, tuple[bool, bool]] = {
    "sensitive-only": (True, True),
    "both": (True, False),
    "unsealed": (False, True),
    "extractable-only": (False, False),
}
_MATRIX_SEALED_SEALS = ("sensitive-only", "both", "extractable-only")
_MATRIX_UNSEALED_SEALS = ("unsealed",)

# Clean C_CreateObject rejects that mean "advertised import not operational".
_MATRIX_IMPORT_XFAIL_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_TYPE_INVALID,
)

# Import rejects that mean genuine capability absence, not a deviation.
_MATRIX_IMPORT_SKIP_RVS = (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

# Sealed AES generation rejects beyond the plain-keygen operational probe.
_MATRIX_AES_SEAL_XFAIL_RVS = (
    *_SENSITIVE_IMPORT_REJECT_RVS,
    *AES_KEYGEN_RUNTIME_REJECT_RVS,
)


@dataclass
class _MatrixKey:
    """A created matrix key: handle, cleanup set, and known material."""

    handle: int
    cleanup: tuple[int, ...]
    known: dict[int, bytes | None]
    label: bytes
    producer_operation: str
    producer_mechanism: str | None


def _matrix_create_outcome(exc: Exception, purpose: str) -> NoReturn:
    """Route a matrix import rejection to skip, xfail, or a loud re-raise."""
    rv = getattr(exc, "rv", None)
    if rv in _MATRIX_IMPORT_SKIP_RVS:
        pytest.skip(f"{purpose} not supported: {ckr_name(rv)}")
    xfail_if_known_ckr(exc, _MATRIX_IMPORT_XFAIL_RVS, f"{purpose} is not operational")
    raise exc


def _matrix_rsa_components() -> dict[str, bytes]:
    """Generate a valid RSA-2048 key and export its CRT components."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_numbers()
    public = private.public_numbers
    return {
        "modulus": public.n.to_bytes(256, "big"),
        "public_exponent": public.e.to_bytes(3, "big"),
        "private_exponent": private.d.to_bytes(256, "big"),
        "prime_1": private.p.to_bytes(128, "big"),
        "prime_2": private.q.to_bytes(128, "big"),
        "exponent_1": private.dmp1.to_bytes(128, "big"),
        "exponent_2": private.dmq1.to_bytes(128, "big"),
        "coefficient": private.iqmp.to_bytes(128, "big"),
    }


def _matrix_rsa_known(comp: dict[str, bytes]) -> dict[int, bytes | None]:
    """Map RSA CRT components to their attribute ids (known material)."""
    return {
        int(CKA_MODULUS): comp["modulus"],
        int(CKA_PUBLIC_EXPONENT): comp["public_exponent"],
        int(CKA_PRIVATE_EXPONENT): comp["private_exponent"],
        int(CKA_PRIME_1): comp["prime_1"],
        int(CKA_PRIME_2): comp["prime_2"],
        int(CKA_EXPONENT_1): comp["exponent_1"],
        int(CKA_EXPONENT_2): comp["exponent_2"],
        int(CKA_COEFFICIENT): comp["coefficient"],
    }


def _matrix_keypair_or_xfail(
    rs: Any,
    mechanism: int,
    pub_base: list[Any],
    priv_base: list[Any],
    public_attrs: Mapping[Any, Any],
    private_attrs: Mapping[Any, Any],
    pub_skip: set[Any] | frozenset[Any] | None,
    purpose: str,
) -> tuple[int, int]:
    """Generate a keypair, routing setup rejects to skip or xfail."""
    try:
        return gen_keypair(
            rs.raw,
            rs.sh,
            mechanism,
            pub_base=pub_base,
            priv_base=priv_base,
            public_attrs=dict(public_attrs),
            private_attrs=dict(private_attrs),
            pub_skip=pub_skip,
        )
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip(f"{purpose}: curve or domain parameters not supported")
        if isinstance(exc, CkrAssertionError) and exc.rv == CKR_MECHANISM_PARAM_INVALID:
            pytest.skip(f"{purpose}: parameter set not supported")
        xfail_if_known_ckr(exc, KEYPAIR_RUNTIME_REJECT_RVS, f"{purpose} is not operational")
        raise


def _matrix_seal_attrs(sensitive: bool, extractable: bool, label: bytes) -> dict[int, Any]:
    """Seal flags plus label shared by every matrix creation template."""
    return {CKA_SENSITIVE: sensitive, CKA_EXTRACTABLE: extractable, CKA_LABEL: label}


def _matrix_gen_dh(rs: Any, seal: dict[int, Any], purpose: str) -> tuple[int, int]:
    """Generate a DH keypair carrying the matrix seal on the private half."""
    pub_tmpl = template(
        attr_bytes(CKA_PRIME, DH_PRIME_2048),
        attr_bytes(CKA_BASE, DH_GEN),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_DERIVE, True),
    )
    priv_tmpl = template(
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_DERIVE, True),
        *pack_attrs(seal),
    )
    mech = mech_simple(CKM_DH_PKCS_KEY_PAIR_GEN)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)
    try:
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub_handle),
            byref(priv_handle),
        )
        expect_rv(rv, CKR_OK)
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip(f"{purpose}: domain parameters not supported")
        xfail_if_known_ckr(exc, KEYPAIR_RUNTIME_REJECT_RVS, f"{purpose} is not operational")
        raise
    return pub_handle.value, priv_handle.value


def _matrix_gen_x942(rs: Any, seal: dict[int, Any], purpose: str) -> tuple[int, int]:
    """Generate an X9.42 DH keypair carrying the matrix seal on the private half."""
    pub_tmpl = template(
        attr_bytes(CKA_PRIME, X942_PRIME_2048),
        attr_bytes(CKA_BASE, X942_GEN),
        attr_bytes(CKA_SUBPRIME, X942_SUBPRIME),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_DERIVE, True),
    )
    priv_tmpl = template(
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_DERIVE, True),
        *pack_attrs(seal),
    )
    mech = mech_simple(CKM_X9_42_DH_KEY_PAIR_GEN)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)
    try:
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub_handle),
            byref(priv_handle),
        )
        expect_rv(rv, CKR_OK)
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip(f"{purpose}: domain parameters not supported")
        xfail_if_known_ckr(exc, KEYPAIR_RUNTIME_REJECT_RVS, f"{purpose} is not operational")
        raise
    return pub_handle.value, priv_handle.value


def _matrix_gen_montgomery(rs: Any, seal: dict[int, Any], purpose: str) -> tuple[int, int, bytes]:
    """Generate a Montgomery keypair, trying X25519 then X448."""
    curve_rejects: list[BaseException] = []
    for _curve_name, curve_oid in (("X25519", _X25519_OID), ("X448", _X448_OID)):
        try:
            pub, priv = gen_keypair(
                rs.raw,
                rs.sh,
                int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN),
                pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                priv_base=[],
                public_attrs={CKA_TOKEN: False, CKA_DERIVE: True},
                private_attrs={CKA_TOKEN: False, CKA_DERIVE: True, **seal},
                pub_skip={CKA_EC_PARAMS},
            )
            return pub, priv, curve_oid
        except CkrAssertionError as exc:
            if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
                curve_rejects.append(exc)
                continue
            xfail_if_known_ckr(exc, KEYPAIR_RUNTIME_REJECT_RVS, f"{purpose} is not operational")
            raise
    detail = "; ".join(str(exc) for exc in curve_rejects)
    pytest.skip(f"{purpose}: neither X25519 nor X448 supported ({detail})")


def _matrix_gen_aes(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    require_operational_aes_keygen(rs)
    try:
        handle = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs=_matrix_seal_attrs(sensitive, extractable, label),
        )
    except CkrAssertionError as exc:
        xfail_if_known_ckr(exc, _MATRIX_AES_SEAL_XFAIL_RVS, f"{purpose} is not operational")
        raise
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known={},
        label=label,
        producer_operation="C_GenerateKey",
        producer_mechanism="CKM_AES_KEY_GEN",
    )


def _matrix_gen_rsa(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, _purpose: str
) -> _MatrixKey:
    pub, priv = gen_rsa_keypair_or_xfail(
        rs,
        2048,
        private_attrs=_matrix_seal_attrs(sensitive, extractable, label),
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={int(CKA_PUBLIC_EXPONENT): None},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
    )


def _matrix_gen_ec(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, _purpose: str
) -> _MatrixKey:
    pub, priv = gen_ec_keypair_or_xfail(
        rs,
        _SECP256R1_OID,
        private_attrs=_matrix_seal_attrs(sensitive, extractable, label),
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={int(CKA_EC_PARAMS): _SECP256R1_OID},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_EC_KEY_PAIR_GEN",
    )


def _matrix_gen_edwards(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, _purpose: str
) -> _MatrixKey:
    pub, priv = gen_edwards_keypair_or_xfail(
        rs,
        _ED25519_OID,
        private_attrs=_matrix_seal_attrs(sensitive, extractable, label),
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={int(CKA_EC_PARAMS): _ED25519_OID},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_EC_EDWARDS_KEY_PAIR_GEN",
    )


def _matrix_gen_montgomery_key(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    pub, priv, curve_oid = _matrix_gen_montgomery(
        rs, _matrix_seal_attrs(sensitive, extractable, label), purpose
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={int(CKA_EC_PARAMS): curve_oid},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
    )


def _matrix_gen_dh_key(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    pub, priv = _matrix_gen_dh(rs, _matrix_seal_attrs(sensitive, extractable, label), purpose)
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={int(CKA_PRIME): DH_PRIME_2048, int(CKA_BASE): DH_GEN},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_DH_PKCS_KEY_PAIR_GEN",
    )


def _matrix_gen_x942_key(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    pub, priv = _matrix_gen_x942(rs, _matrix_seal_attrs(sensitive, extractable, label), purpose)
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={
            int(CKA_PRIME): X942_PRIME_2048,
            int(CKA_SUBPRIME): X942_SUBPRIME,
            int(CKA_BASE): X942_GEN,
        },
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_X9_42_DH_KEY_PAIR_GEN",
    )


def _matrix_gen_mldsa(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    pub, priv = _matrix_keypair_or_xfail(
        rs,
        int(CKM_ML_DSA_KEY_PAIR_GEN),
        [attr_ulong(CKA_PARAMETER_SET, int(CKP_ML_DSA_44))],
        [],
        {CKA_VERIFY: True, CKA_TOKEN: False},
        {CKA_SIGN: True, CKA_TOKEN: False, **_matrix_seal_attrs(sensitive, extractable, label)},
        {CKA_PARAMETER_SET},
        purpose,
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_ML_DSA_KEY_PAIR_GEN",
    )


def _matrix_gen_mlkem(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    pub, priv = _matrix_keypair_or_xfail(
        rs,
        int(CKM_ML_KEM_KEY_PAIR_GEN),
        [attr_ulong(CKA_PARAMETER_SET, int(CKP_ML_KEM_512))],
        [],
        {CKA_ENCAPSULATE: True, CKA_TOKEN: False},
        {
            CKA_DECAPSULATE: True,
            CKA_TOKEN: False,
            **_matrix_seal_attrs(sensitive, extractable, label),
        },
        {CKA_PARAMETER_SET},
        purpose,
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_ML_KEM_KEY_PAIR_GEN",
    )


def _matrix_gen_slhdsa(
    rs: Any, sensitive: bool, extractable: bool, label: bytes, purpose: str
) -> _MatrixKey:
    pub, priv = _matrix_keypair_or_xfail(
        rs,
        int(CKM_SLH_DSA_KEY_PAIR_GEN),
        [attr_ulong(CKA_PARAMETER_SET, int(CKP_SLH_DSA_SHA2_128S))],
        [],
        {CKA_VERIFY: True, CKA_TOKEN: False},
        {CKA_SIGN: True, CKA_TOKEN: False, **_matrix_seal_attrs(sensitive, extractable, label)},
        {CKA_PARAMETER_SET},
        purpose,
    )
    return _MatrixKey(
        handle=priv,
        cleanup=(pub, priv),
        known={},
        label=label,
        producer_operation="C_GenerateKeyPair",
        producer_mechanism="CKM_SLH_DSA_KEY_PAIR_GEN",
    )


def _matrix_import_aes(
    rs: Any,
    sensitive: bool,
    extractable: bool,
    label: bytes,
    purpose: str,
    *,
    material: bytes | None = None,
) -> _MatrixKey:
    secret = _MATRIX_AES_SECRET if material is None else material
    try:
        handle = import_secret_key_negotiated(
            rs,
            CKK_AES,
            secret,
            attrs=_matrix_seal_attrs(sensitive, extractable, label),
            purpose=purpose,
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        _matrix_create_outcome(exc, purpose)
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known={int(CKA_VALUE): secret},
        label=label,
        producer_operation="C_CreateObject",
        producer_mechanism=None,
    )


def _matrix_import_rsa(
    rs: Any,
    sensitive: bool,
    extractable: bool,
    label: bytes,
    purpose: str,
    *,
    components: dict[str, bytes] | None = None,
) -> _MatrixKey:
    comp = _matrix_rsa_components() if components is None else components
    try:
        handle = import_rsa_private_key_negotiated(
            rs,
            n=comp["modulus"],
            e=comp["public_exponent"],
            d=comp["private_exponent"],
            p=comp["prime_1"],
            q=comp["prime_2"],
            dmp1=comp["exponent_1"],
            dmq1=comp["exponent_2"],
            iqmp=comp["coefficient"],
            attrs=_matrix_seal_attrs(sensitive, extractable, label),
            purpose=purpose,
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        _matrix_create_outcome(exc, purpose)
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known=_matrix_rsa_known(comp),
        label=label,
        producer_operation="C_CreateObject",
        producer_mechanism=None,
    )


def _matrix_import_ec_family(
    rs: Any,
    key_type: int,
    ec_params: bytes,
    value: bytes,
    sensitive: bool,
    extractable: bool,
    label: bytes,
    purpose: str,
) -> _MatrixKey:
    try:
        handle = import_ec_private_key_negotiated(
            rs,
            ec_params=ec_params,
            value=value,
            key_type=key_type,
            attrs=_matrix_seal_attrs(sensitive, extractable, label),
            purpose=purpose,
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        _matrix_create_outcome(exc, purpose)
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known={int(CKA_EC_PARAMS): ec_params, int(CKA_VALUE): value},
        label=label,
        producer_operation="C_CreateObject",
        producer_mechanism=None,
    )


def _matrix_import_dh(
    rs: Any,
    sensitive: bool,
    extractable: bool,
    label: bytes,
    purpose: str,
    *,
    material: bytes | None = None,
) -> _MatrixKey:
    secret = _MATRIX_DH_VALUE if material is None else material
    try:
        handle = create_object_negotiated(
            rs,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: CKK_DH,
                CKA_TOKEN: False,
                CKA_DERIVE: True,
                CKA_PRIME: DH_PRIME_2048,
                CKA_BASE: DH_GEN,
                CKA_VALUE: secret,
                **_matrix_seal_attrs(sensitive, extractable, label),
            },
            purpose=purpose,
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        _matrix_create_outcome(exc, purpose)
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known={
            int(CKA_PRIME): DH_PRIME_2048,
            int(CKA_BASE): DH_GEN,
            int(CKA_VALUE): secret,
        },
        label=label,
        producer_operation="C_CreateObject",
        producer_mechanism=None,
    )


def _matrix_import_x942(
    rs: Any,
    sensitive: bool,
    extractable: bool,
    label: bytes,
    purpose: str,
    *,
    material: bytes | None = None,
) -> _MatrixKey:
    secret = _MATRIX_X942_VALUE if material is None else material
    try:
        handle = create_object_negotiated(
            rs,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: CKK_X9_42_DH,
                CKA_TOKEN: False,
                CKA_DERIVE: True,
                CKA_PRIME: X942_PRIME_2048,
                CKA_SUBPRIME: X942_SUBPRIME,
                CKA_BASE: X942_GEN,
                CKA_VALUE: secret,
                **_matrix_seal_attrs(sensitive, extractable, label),
            },
            purpose=purpose,
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        _matrix_create_outcome(exc, purpose)
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known={
            int(CKA_PRIME): X942_PRIME_2048,
            int(CKA_SUBPRIME): X942_SUBPRIME,
            int(CKA_BASE): X942_GEN,
            int(CKA_VALUE): secret,
        },
        label=label,
        producer_operation="C_CreateObject",
        producer_mechanism=None,
    )


def _matrix_import_pqc(
    rs: Any,
    key_type: int,
    parameter_set: int,
    value: bytes,
    seed: bytes | None,
    sensitive: bool,
    extractable: bool,
    label: bytes,
    purpose: str,
) -> _MatrixKey:
    extra: dict[int, Any] = dict(_matrix_seal_attrs(sensitive, extractable, label))
    if seed is not None:
        extra[int(CKA_SEED)] = seed
    try:
        handle = create_object_negotiated(
            rs,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: key_type,
                CKA_TOKEN: False,
                CKA_PARAMETER_SET: parameter_set,
                CKA_VALUE: value,
                **extra,
            },
            purpose=purpose,
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        _matrix_create_outcome(exc, purpose)
    known: dict[int, bytes | None] = {int(CKA_VALUE): value}
    if seed is not None:
        known[int(CKA_SEED)] = seed
    return _MatrixKey(
        handle=handle,
        cleanup=(handle,),
        known=known,
        label=label,
        producer_operation="C_CreateObject",
        producer_mechanism=None,
    )


def _create_matrix_key(rs: Any, family: _MatrixFamily, creation: str, seal: str) -> _MatrixKey:
    """Create one matrix key, skipping unsupported families and paths."""
    sensitive, extractable = _MATRIX_SEALS[seal]
    label = f"p11chk-qc1-{family.family}-{creation}-{seal}".encode()
    purpose = f"QC1 {family.family}/{creation}/{seal} key creation"
    if creation == "gen":
        if not any(rs.has_mechanism(name) for name in family.family_mechanisms):
            pytest.skip(f"{purpose}: no {family.family} mechanism advertised")
        keygen = family.keygen_mechanism
        if keygen is None or not rs.has_mechanism(keygen):
            pytest.skip(f"{purpose}: {family.keygen_mechanism} not supported")
        if family.family == "aes":
            return _matrix_gen_aes(rs, sensitive, extractable, label, purpose)
        if family.family == "rsa":
            return _matrix_gen_rsa(rs, sensitive, extractable, label, purpose)
        if family.family == "ec":
            return _matrix_gen_ec(rs, sensitive, extractable, label, purpose)
        if family.family == "edwards":
            return _matrix_gen_edwards(rs, sensitive, extractable, label, purpose)
        if family.family == "montgomery":
            return _matrix_gen_montgomery_key(rs, sensitive, extractable, label, purpose)
        if family.family == "dh":
            return _matrix_gen_dh_key(rs, sensitive, extractable, label, purpose)
        if family.family == "x942":
            return _matrix_gen_x942_key(rs, sensitive, extractable, label, purpose)
        if family.family == "mldsa":
            return _matrix_gen_mldsa(rs, sensitive, extractable, label, purpose)
        if family.family == "mlkem":
            return _matrix_gen_mlkem(rs, sensitive, extractable, label, purpose)
        assert family.family == "slhdsa"
        return _matrix_gen_slhdsa(rs, sensitive, extractable, label, purpose)
    if not any(rs.has_mechanism(name) for name in family.import_mechanisms):
        pytest.skip(f"{purpose}: no {family.family} mechanism advertised")
    skip_unless_create_object_supported(rs)
    if family.family == "aes":
        return _matrix_import_aes(rs, sensitive, extractable, label, purpose)
    if family.family == "rsa":
        return _matrix_import_rsa(rs, sensitive, extractable, label, purpose)
    if family.family == "ec":
        return _matrix_import_ec_family(
            rs,
            int(CKK_EC),
            _SECP256R1_OID,
            _MATRIX_EC_SCALAR,
            sensitive,
            extractable,
            label,
            purpose,
        )
    if family.family == "edwards":
        return _matrix_import_ec_family(
            rs,
            int(CKK_EC_EDWARDS),
            _ED25519_OID,
            _MATRIX_ED_SEED,
            sensitive,
            extractable,
            label,
            purpose,
        )
    if family.family == "montgomery":
        return _matrix_import_ec_family(
            rs,
            int(CKK_EC_MONTGOMERY),
            _X25519_OID,
            _MATRIX_MONT_SCALAR,
            sensitive,
            extractable,
            label,
            purpose,
        )
    if family.family == "dh":
        return _matrix_import_dh(rs, sensitive, extractable, label, purpose)
    if family.family == "x942":
        return _matrix_import_x942(rs, sensitive, extractable, label, purpose)
    if family.family == "mldsa":
        # No matched seed exists in-tree for this secret, so none is
        # supplied; the optional seed row then stays visibly absent.
        return _matrix_import_pqc(
            rs,
            int(CKK_ML_DSA),
            int(CKP_ML_DSA_44),
            _MATRIX_MLDSA44_SK,
            None,
            sensitive,
            extractable,
            label,
            purpose,
        )
    if family.family == "mlkem":
        return _matrix_import_pqc(
            rs,
            int(CKK_ML_KEM),
            int(CKP_ML_KEM_512),
            _MATRIX_MLKEM512_DK,
            _MATRIX_MLKEM512_SEED,
            sensitive,
            extractable,
            label,
            purpose,
        )
    assert family.family == "slhdsa"
    return _matrix_import_pqc(
        rs,
        int(CKK_SLH_DSA),
        int(CKP_SLH_DSA_SHA2_128S),
        _MATRIX_SLH_VALUE,
        None,
        sensitive,
        extractable,
        label,
        purpose,
    )


def _matrix_size_query(raw: Any, sh: int, handle: int, attr: int) -> tuple[int, int]:
    """Length-only read of one attribute: (rv, returned length)."""
    tmpl = (CK_ATTRIBUTE * 1)()
    tmpl[0].type = attr
    tmpl[0].pValue = None
    tmpl[0].ulValueLen = 0
    rv = raw.C_GetAttributeValue(sh, handle, tmpl, 1)
    return int(rv), int(tmpl[0].ulValueLen)


_MATRIX_ALT_SENTINEL_BYTE = 0x5A


def _matrix_data_read(
    raw: Any,
    sh: int,
    handle: int,
    attr: int,
    cap: int,
    *,
    sentinel_byte: int = _MATRIX_SENTINEL_BYTE,
) -> tuple[int, int, bytes]:
    """Buffer read of one attribute: (rv, returned length, observed bytes)."""
    sentinel = bytes([sentinel_byte]) * cap
    buf = (ctypes.c_ubyte * cap).from_buffer_copy(sentinel)
    tmpl = (CK_ATTRIBUTE * 1)()
    tmpl[0].type = attr
    tmpl[0].pValue = ctypes.cast(buf, ctypes.c_void_p)
    tmpl[0].ulValueLen = cap
    rv = raw.C_GetAttributeValue(sh, handle, tmpl, 1)
    return int(rv), int(tmpl[0].ulValueLen), bytes(buf)


def _matrix_multi_read(
    raw: Any, sh: int, handle: int, attrs: list[int], cap: int
) -> tuple[int, list[tuple[int, bytes]]]:
    """One buffer read across several attributes: (rv, [(length, bytes)])."""
    tmpl = (CK_ATTRIBUTE * len(attrs))()
    bufs: list[Any] = []
    for index, attr in enumerate(attrs):
        sentinel = bytes([_MATRIX_SENTINEL_BYTE]) * cap
        buf = (ctypes.c_ubyte * cap).from_buffer_copy(sentinel)
        bufs.append(buf)
        tmpl[index].type = attr
        tmpl[index].pValue = ctypes.cast(buf, ctypes.c_void_p)
        tmpl[index].ulValueLen = cap
    rv = raw.C_GetAttributeValue(sh, handle, tmpl, len(attrs))
    return int(rv), [
        (int(tmpl[index].ulValueLen), bytes(bufs[index])) for index in range(len(attrs))
    ]


def _matrix_sentinel_block(length: int) -> bytes:
    return bytes([_MATRIX_SENTINEL_BYTE]) * length


def _matrix_member_name(attr: int) -> str:
    return ATTR_NAMES.get(int(attr), str(attr))


def _record_matrix_leak(
    *,
    label: str,
    summary: str,
    detail: dict[str, Any],
    actual: int,
    records: list[classification.Classification],
) -> None:
    """Record observed protected bytes as an independent hard finding."""
    records.append(
        classification.record_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            actual=actual,
            detail=detail,
            summary=summary,
        )
    )


def _record_matrix_bad_effect(
    *,
    label: str,
    summary: str,
    detail: dict[str, Any],
    actual: int,
    records: list[classification.Classification],
) -> None:
    """Record a wrong length or buffer effect as a hard finding."""
    records.append(
        classification.record_as(
            "wrong_result",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            actual=actual,
            detail=detail,
            summary=summary,
        )
    )


def _record_matrix_deviation(
    *,
    label: str,
    summary: str,
    detail: dict[str, Any],
    actual: int | None,
    records: list[classification.Classification],
) -> None:
    """Record a non-leak deviation (terminal xfail when raised)."""
    records.append(
        classification.record_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            actual=actual,
            detail=detail,
            summary=summary,
        )
    )


def _record_matrix_wrong_bytes(
    *,
    label: str,
    summary: str,
    detail: dict[str, Any],
    records: list[classification.Classification],
) -> None:
    """Record readable-but-wrong bytes as a hard metadata finding."""
    records.append(
        classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            detail=detail,
            summary=summary,
        )
    )


def _record_matrix_sealed_summary(
    *,
    label: str,
    summary: str,
    detail: dict[str, Any],
) -> None:
    """Record a held seal as a visible conformant observation."""
    classification.record_as(
        "sanctioned_refusal",
        kind="policy",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        detail=detail,
        summary=summary,
    )


def _matrix_defer_rv(
    rv: int, expected: tuple[int, ...], *, label: str
) -> classification.Classification | None:
    """Classify a raw return without terminating, so row checks can run first."""
    try:
        _classify_get_attribute_rv(rv, expected, label=label, kind="policy")
    except (pytest.fail.Exception, pytest.xfail.Exception) as exc:
        record = getattr(exc, "_pkcs11_check_classification", None)
        if record is None:
            raise
        return cast(classification.Classification, record)
    return None


def _matrix_fragment(secret: bytes | None, observed: bytes) -> tuple[int, int] | None:
    """Find known-secret bytes in an observed buffer, if the secret is known."""
    if secret is None:
        return None
    return _find_copied_secret_fragment(secret, observed, _matrix_sentinel_block(len(observed)))


_matrix_alt_label_counter = itertools.count(1)


def _matrix_supports_differential(family_id: str, attr: int) -> bool:
    """Whether the disclosure differential can plant distinct material.

    Public parameters shared across plantings (curve OIDs, domain
    parameters, the fixed RSA public exponent) cannot separate disclosure
    from scrubbing, so those keep their direct verdicts.
    """
    _ = family_id
    return int(attr) not in (
        int(CKA_EC_PARAMS),
        int(CKA_PUBLIC_EXPONENT),
        int(CKA_PRIME),
        int(CKA_BASE),
        int(CKA_SUBPRIME),
    )


def _matrix_differential_varies_fragment(
    secret: bytes,
    alt_secret: bytes | None,
    observed: bytes,
    fragment: tuple[int, int] | None,
) -> bool:
    """Whether the alternate planting varies the suspected matching fragment.

    Identical output across plantings only proves secret-independent
    scrubbing when the alternate material actually changes the observed
    fragment. A leaked prefix over plantings that differ solely in their
    tails is uninformative: the differential then stays inconclusive
    (fail closed) instead of exonerating the observation. The variation must
    sit within the suspected matching fragment itself: changed bytes
    elsewhere -- a scrub background around an unvaried copied interior -- do
    not exonerate. Without a suspected fragment (pure scrub with no secret
    match), variation anywhere the read returned bytes still applies.
    """
    if alt_secret is None:
        return False
    sentinel = _matrix_sentinel_block(len(observed))
    if fragment is not None:
        span = range(fragment[0], fragment[0] + fragment[1])
    else:
        span = range(len(observed))
    for offset in span:
        if offset >= len(observed):
            continue
        if observed[offset] == sentinel[offset]:
            continue
        original = secret[offset] if offset < len(secret) else None
        alternate = alt_secret[offset] if offset < len(alt_secret) else None
        if original != alternate:
            return True
    return False


#: Bounded local attempts to select RSA alternate components that vary
#: the compared span (P3). Each attempt is one local key generation; the
#: first varying candidate is planted, so the common case costs one.
_MATRIX_RSA_ALT_ATTEMPTS = 8


def _matrix_rsa_alt_components(
    *,
    secret: bytes,
    attr: int,
    observed: bytes,
    fragment: tuple[int, int] | None,
) -> dict[str, bytes]:
    """Select valid RSA components varying the compared span (P3).

    Two distinct RSA keys can share the short suspected fragment (e.g.
    one 0x5A byte matched by constant scrub output); planting such a
    colliding alternate cannot prove constancy and would fail closed on
    a coin flip. Selection is local and bounded: candidates are checked
    against the span before any import, and when none varies within the
    bound the last candidate is returned so the verdict stays
    inconclusive (fail closed) on real evidence.
    """
    comp = _matrix_rsa_components()
    for _ in range(_MATRIX_RSA_ALT_ATTEMPTS - 1):
        if _matrix_differential_varies_fragment(
            secret, _matrix_rsa_known(comp).get(int(attr)), observed, fragment
        ):
            return comp
        comp = _matrix_rsa_components()
    return comp


def _matrix_differential_import(
    rs: Any,
    family: _MatrixFamily,
    sensitive: bool,
    extractable: bool,
    purpose: str,
    *,
    secret: bytes | None = None,
    attr: int = 0,
    observed: bytes = b"",
    fragment: tuple[int, int] | None = None,
) -> _MatrixKey | None:
    """Import a second key with different planted material for the differential.

    Returns None when the differential setup itself fails (a swallowed setup
    refusal honestly records why). RSA regenerates, and its alternate is
    selected to vary the compared span (see _matrix_rsa_alt_components).
    """
    label = f"p11chk-qc1d-{next(_matrix_alt_label_counter)}".encode()
    try:
        if family.family == "aes":
            return _matrix_import_aes(
                rs, sensitive, extractable, label, purpose, material=_MATRIX_AES_SECRET_ALT
            )
        if family.family == "rsa":
            components = (
                _matrix_rsa_alt_components(
                    secret=secret, attr=attr, observed=observed, fragment=fragment
                )
                if secret is not None
                else None
            )
            return _matrix_import_rsa(
                rs, sensitive, extractable, label, purpose, components=components
            )
        if family.family == "ec":
            return _matrix_import_ec_family(
                rs,
                int(CKK_EC),
                _SECP256R1_OID,
                _MATRIX_EC_SCALAR_ALT,
                sensitive,
                extractable,
                label,
                purpose,
            )
        if family.family == "edwards":
            return _matrix_import_ec_family(
                rs,
                int(CKK_EC_EDWARDS),
                _ED25519_OID,
                _MATRIX_ED_SEED_ALT,
                sensitive,
                extractable,
                label,
                purpose,
            )
        if family.family == "montgomery":
            return _matrix_import_ec_family(
                rs,
                int(CKK_EC_MONTGOMERY),
                _X25519_OID,
                _MATRIX_MONT_SCALAR_ALT,
                sensitive,
                extractable,
                label,
                purpose,
            )
        if family.family == "dh":
            return _matrix_import_dh(
                rs, sensitive, extractable, label, purpose, material=_MATRIX_DH_VALUE_ALT
            )
        if family.family == "x942":
            return _matrix_import_x942(
                rs, sensitive, extractable, label, purpose, material=_MATRIX_X942_VALUE_ALT
            )
        if family.family == "mldsa":
            return _matrix_import_pqc(
                rs,
                int(CKK_ML_DSA),
                int(CKP_ML_DSA_44),
                _MATRIX_MLDSA44_SK_ALT,
                None,
                sensitive,
                extractable,
                label,
                purpose,
            )
        if family.family == "mlkem":
            return _matrix_import_pqc(
                rs,
                int(CKK_ML_KEM),
                int(CKP_ML_KEM_512),
                _MATRIX_MLKEM512_DK_ALT,
                _MATRIX_MLKEM512_SEED_ALT,
                sensitive,
                extractable,
                label,
                purpose,
            )
        assert family.family == "slhdsa"
        return _matrix_import_pqc(
            rs,
            int(CKK_SLH_DSA),
            int(CKP_SLH_DSA_SHA2_128S),
            _MATRIX_SLH_VALUE_ALT,
            None,
            sensitive,
            extractable,
            label,
            purpose,
        )
    except (CkrAssertionError, pytest.skip.Exception, pytest.xfail.Exception):
        # audit-ok: differential-setup failure degrades to inconclusive
        # (fail-closed wrong_result), never hides a finding.
        return None


def _matrix_disclosure_verdict(
    *,
    rs: Any,
    family: _MatrixFamily,
    creation: str,
    sensitive: bool,
    extractable: bool,
    attr: int,
    secret: bytes | None,
    observed: bytes,
    fragment: tuple[int, int] | None,
    shape: str,
    members: tuple[int, ...],
    purpose: str,
    label: str,
    records: list[classification.Classification],
    sealed_protected: bool,
) -> str:
    """Classify a refused-read buffer modification via differential planting.

    Returns "tracking" (output follows the planted secret: whole-secret
    reproduction, or own-secret fragments on both plantings),
    "independent" (identical output across plantings whose material varies
    the suspected fragment itself, or output that differs without tracking
    either secret), "inconclusive" (the differential setup failed, the
    alternate read did not complete comparably, only the differential key
    shows bytes, or the fragment was not varied: fail closed without leak
    attribution), or "undetermined" (no differential applies: generated
    keys, public parameters -- the caller keeps its direct verdict).

    Every alternate-read return value is classified in its protection
    context and retained: malformed returns are hard findings, a sealed
    CKR_OK alternate is itself a hard sealed-member violation (never
    differential evidence), other non-comparable returns stay visible
    deviations, and a failed measurement never exonerates the observation.
    Completed alternate lengths are validated before any buffer comparison:
    sealed refusals must report unavailable length (violations are hard
    findings preserving the RV and length), while successful unsealed reads
    must report an available length within capacity matching the known
    value. Invalid metadata makes the measurement inconclusive.
    """
    if (
        creation != "import"
        or secret is None
        or not _matrix_supports_differential(family.family, attr)
    ):
        return "undetermined"
    if fragment is not None and len(secret) >= 16 and fragment[1] == len(secret):
        return "tracking"
    alt = _matrix_differential_import(
        rs,
        family,
        sensitive,
        extractable,
        purpose,
        secret=secret,
        attr=int(attr),
        observed=observed,
        fragment=fragment,
    )
    if alt is None:
        return "inconclusive"
    try:
        cap = len(observed)
        if shape == "multi":
            alt_rv, rows = _matrix_multi_read(rs.raw, rs.sh, alt.handle, list(members), cap)
            alt_len, alt_observed = dict(zip(members, rows, strict=True))[int(attr)]
        elif shape == "mixed":
            alt_rv, rows = _matrix_multi_read(
                rs.raw, rs.sh, alt.handle, [int(attr), int(CKA_LABEL)], cap
            )
            alt_len, alt_observed = rows[0]
        else:
            alt_rv, alt_len, alt_observed = _matrix_data_read(
                rs.raw, rs.sh, alt.handle, int(attr), cap
            )
        attribute = {"name": _matrix_member_name(attr), "id": int(attr)}
        alt_malformed = not (is_standard_ckr(alt_rv) or is_vendor_defined_ckr(alt_rv))
        alt_sealed_ok = sealed_protected and alt_rv == int(CKR_OK)
        if alt_malformed or alt_sealed_ok:
            if alt_sealed_ok and not alt_malformed:
                problem = "succeeded on a sealed member"
                summary = f"{label}: differential alternate read succeeded on a sealed member"
                want = "CKR_ATTRIBUTE_SENSITIVE or another clean refusal"
            else:
                problem = "returned an unrecognized return value"
                summary = f"{label}: differential alternate read returned an unrecognized CK_RV"
                want = "CKR_OK or a clean refusal"
            _record_matrix_bad_effect(
                label=f"{label}: differential alternate read {problem}",
                summary=summary,
                detail={
                    "attribute": attribute,
                    "expected": want,
                    "alternate_rv": ckr_name(alt_rv),
                },
                actual=alt_rv,
                records=records,
            )
            return "inconclusive"
        if alt_rv not in (int(CKR_OK), int(CKR_ATTRIBUTE_SENSITIVE)):
            _record_matrix_deviation(
                label=f"{label}: differential alternate read refused",
                summary=(
                    f"{label}: differential alternate read was refused "
                    f"({ckr_name(alt_rv)}); constancy unproven"
                ),
                detail={
                    "attribute": attribute,
                    "expected": "a comparable completed read",
                    "alternate_rv": ckr_name(alt_rv),
                },
                actual=alt_rv,
                records=records,
            )
            return "inconclusive"
        alt_secret = alt.known.get(int(attr))
        if sealed_protected:
            # A completed sealed refusal must not report an available length:
            # the violation is recorded with its RV and length, and the
            # measurement stays inconclusive instead of becoming evidence.
            if alt_rv == int(CKR_ATTRIBUTE_SENSITIVE) and not _matrix_is_unavailable(alt_len):
                _record_matrix_bad_effect(
                    label=(
                        f"{label}: differential alternate read reported an "
                        "available length on a sealed member"
                    ),
                    summary=(
                        f"{label}: differential alternate read reported an "
                        "available length on a sealed member"
                    ),
                    detail={
                        "attribute": attribute,
                        "expected": "CK_UNAVAILABLE_INFORMATION",
                        "alternate_rv": ckr_name(alt_rv),
                        "alternate_length": alt_len,
                    },
                    actual=alt_rv,
                    records=records,
                )
                return "inconclusive"
        elif alt_rv == int(CKR_OK):
            # A successful unsealed alternate must carry a valid measurement:
            # an available length within capacity matching the known value.
            alt_len_ok = (
                not _matrix_is_unavailable(alt_len)
                and 0 < alt_len <= cap
                and (alt_secret is None or alt_len == len(alt_secret))
            )
            if not alt_len_ok:
                return "inconclusive"
        if alt_observed == observed:
            if _matrix_differential_varies_fragment(secret, alt_secret, observed, fragment):
                return "independent"
            return "inconclusive"
        alt_fragment = _matrix_fragment(alt_secret, alt_observed)
        if fragment is not None and alt_fragment is not None:
            return "tracking"
        if alt_fragment is not None:
            return "inconclusive"
        return "independent"
    finally:
        for handle in alt.cleanup:
            destroy_quietly(rs.raw, rs.sh, handle)


def _check_matrix_sealed_member(
    *,
    rs: Any,
    raw: Any,
    sh: int,
    handle: int,
    family: _MatrixFamily,
    creation: str,
    sensitive: bool,
    extractable: bool,
    attr: int,
    mandatory: bool,
    known: bytes | None,
    prefix: str,
    gen_mandatory: bool,
    records: list[classification.Classification],
) -> str | None:
    """Probe one sealed member; return "absent" when optionally unimplemented.

    Both the size query and the data call are classified independently; only
    a both-calls-consistent TYPE_INVALID absence is exempt, and each
    returned length is only interpreted when its own call guarantees
    completed processing. Demonstrated disclosure fails regardless.
    """
    name = _matrix_member_name(attr)
    label = f"{prefix}: sealed {name} single-attr read"
    rv_q, len_q = _matrix_size_query(raw, sh, handle, attr)
    rv_d, len_d, observed = _matrix_data_read(raw, sh, handle, attr, _MATRIX_READ_CAP)
    fragment = _matrix_fragment(known, observed)
    q_real = not _matrix_is_unavailable(len_q)
    d_real = not _matrix_is_unavailable(len_d)
    intact = observed == _matrix_sentinel_block(len(observed))
    if (
        not mandatory
        and not gen_mandatory
        and rv_q == CKR_ATTRIBUTE_TYPE_INVALID
        and rv_d == CKR_ATTRIBUTE_TYPE_INVALID
        and not q_real
        and not d_real
        and intact
        and fragment is None
    ):
        return "absent"
    before = len(records)
    deferred_q = _matrix_defer_rv(rv_q, (CKR_ATTRIBUTE_SENSITIVE,), label=f"{label} size query")
    if deferred_q is not None:
        records.append(deferred_q)
    deferred = _matrix_defer_rv(rv_d, (CKR_ATTRIBUTE_SENSITIVE,), label=label)
    if deferred is not None:
        records.append(deferred)
    completed_q = rv_q in _MATRIX_COMPLETED_READ_RVS
    completed_d = rv_d in _MATRIX_COMPLETED_READ_RVS
    attribute = {"name": name, "id": int(attr)}
    nonzero_modification = not intact and observed != bytes(len(observed))
    if fragment is not None or nonzero_modification:
        verdict = _matrix_disclosure_verdict(
            rs=rs,
            family=family,
            creation=creation,
            sensitive=sensitive,
            extractable=extractable,
            attr=attr,
            secret=known,
            observed=observed,
            fragment=fragment,
            shape="single",
            members=(),
            purpose=f"{prefix}: disclosure-differential import",
            label=label,
            records=records,
            sealed_protected=True,
        )
    else:
        verdict = "undetermined"
    if fragment is not None and verdict not in ("independent", "inconclusive"):
        offset, frag_len = fragment
        _record_matrix_leak(
            label=f"{label}: protected bytes observed",
            summary=f"{label}: protected {name} bytes observed in pValue",
            detail={
                "attribute": attribute,
                "expected": "no key bytes copied",
                "actual": "protected bytes observed in pValue",
                "copied_fragment_offset": offset,
                "copied_fragment_length": frag_len,
                "size_query_rv": ckr_name(rv_q),
                "size_query_length": len_q,
                "data_rv": ckr_name(rv_d),
                "data_length": len_d,
            },
            actual=rv_d,
            records=records,
        )
    elif (completed_q and q_real) or (completed_d and d_real):
        _record_matrix_bad_effect(
            label=f"{label}: available length on a refused member",
            summary=f"{label}: sealed {name} reported an available length",
            detail={
                "attribute": attribute,
                "expected": "CK_UNAVAILABLE_INFORMATION",
                "size_query_rv": ckr_name(rv_q),
                "size_query_length": len_q,
                "data_rv": ckr_name(rv_d),
                "data_length": len_d,
            },
            actual=rv_d,
            records=records,
        )
    elif (completed_d and not intact) or verdict in ("independent", "inconclusive"):
        if verdict == "independent" or (
            verdict == "undetermined" and observed == bytes(len(observed))
        ):
            if verdict == "independent":
                problem = "constant overwrite, proven secret-independent"
                actual = "secret-independent overwrite (differential)"
            else:
                problem = "output buffer zeroed on refusal"
                actual = "all-zero buffer"
            _record_matrix_deviation(
                label=f"{label}: {problem}",
                summary=(
                    f"{label}: provider overwrote the buffer with output identical "
                    "across differently-planted keys (differential)"
                    if verdict == "independent"
                    else f"{label}: provider zeroed the output buffer on a refused read"
                ),
                detail={
                    "attribute": attribute,
                    "expected": "pre-call sentinel bytes intact",
                    "actual": actual,
                    "data_rv": ckr_name(rv_d),
                },
                actual=rv_d,
                records=records,
            )
        else:
            if verdict == "inconclusive":
                problem = "unproven buffer modification"
                summary = (
                    f"{label}: provider modified the output buffer on a refused read "
                    "but the differential re-import failed, so constancy is unproven"
                )
                actual = "modified buffer, differential inconclusive"
            else:
                problem = "output buffer scribbled on refusal"
                summary = f"{label}: provider modified the output buffer on a refused read"
                actual = "buffer differs from sentinel"
            _record_matrix_bad_effect(
                label=f"{label}: {problem}",
                summary=summary,
                detail={
                    "attribute": attribute,
                    "expected": "pre-call sentinel bytes intact",
                    "actual": actual,
                    "data_rv": ckr_name(rv_d),
                    "data_length": len_d,
                },
                actual=rv_d,
                records=records,
            )
    return None if len(records) == before else "finding"


def _check_matrix_sealed_multi(
    *,
    rs: Any,
    raw: Any,
    sh: int,
    handle: int,
    family: _MatrixFamily,
    creation: str,
    sensitive: bool,
    extractable: bool,
    members: list[tuple[int, bool]],
    known: Mapping[int, bytes | None],
    prefix: str,
    absent_attrs: frozenset[int],
    records: list[classification.Classification],
) -> None:
    """One aggregate read across every protected member: no partial leaks.

    A template mixing refused sensitive members with established absent
    optionals may return either applicable attribute status; every member's
    length and buffer checks still run. Lengths and buffers are only
    interpreted when the aggregate guarantees completed processing, while
    demonstrated disclosure fails regardless.
    """
    attrs = [attr for attr, _mandatory in members]
    rv, rows = _matrix_multi_read(raw, sh, handle, attrs, _MATRIX_READ_CAP)
    expected: tuple[int, ...] = (
        (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID)
        if absent_attrs
        else (CKR_ATTRIBUTE_SENSITIVE,)
    )
    deferred = _matrix_defer_rv(rv, expected, label=f"{prefix}: sealed aggregate protected read")
    if deferred is not None:
        records.append(deferred)
    completed = rv in _MATRIX_COMPLETED_READ_RVS
    member_ids = tuple(int(member_attr) for member_attr, _mandatory in members)
    for (attr, _mandatory), (length, observed) in zip(members, rows):
        name = _matrix_member_name(attr)
        label = f"{prefix}: sealed aggregate {name} row"
        secret = known.get(attr)
        fragment = _matrix_fragment(secret, observed)
        real = not _matrix_is_unavailable(length)
        intact = observed == _matrix_sentinel_block(len(observed))
        attribute = {"name": name, "id": int(attr)}
        nonzero_modification = not intact and observed != bytes(len(observed))
        if fragment is not None or nonzero_modification:
            verdict = _matrix_disclosure_verdict(
                rs=rs,
                family=family,
                creation=creation,
                sensitive=sensitive,
                extractable=extractable,
                attr=attr,
                secret=secret,
                observed=observed,
                fragment=fragment,
                shape="multi",
                members=member_ids,
                purpose=f"{prefix}: disclosure-differential import",
                label=label,
                records=records,
                sealed_protected=True,
            )
        else:
            verdict = "undetermined"
        if fragment is not None and verdict not in ("independent", "inconclusive"):
            offset, frag_len = fragment
            _record_matrix_leak(
                label=f"{label}: protected bytes observed",
                summary=f"{label}: protected {name} bytes observed in pValue",
                detail={
                    "attribute": attribute,
                    "expected": "no key bytes copied",
                    "actual": "protected bytes observed in pValue",
                    "copied_fragment_offset": offset,
                    "copied_fragment_length": frag_len,
                    "aggregate_rv": ckr_name(rv),
                    "row_length": length,
                },
                actual=rv,
                records=records,
            )
        elif completed and real:
            _record_matrix_bad_effect(
                label=f"{label}: available length on a refused member",
                summary=f"{label}: sealed {name} reported an available length",
                detail={
                    "attribute": attribute,
                    "expected": "CK_UNAVAILABLE_INFORMATION",
                    "aggregate_rv": ckr_name(rv),
                    "row_length": length,
                },
                actual=rv,
                records=records,
            )
        elif (completed and not intact) or verdict in ("independent", "inconclusive"):
            if verdict == "independent" or (
                verdict == "undetermined" and observed == bytes(len(observed))
            ):
                if verdict == "independent":
                    problem = "constant overwrite, proven secret-independent"
                    actual = "secret-independent overwrite (differential)"
                    summary = (
                        f"{label}: provider overwrote the buffer with output identical "
                        "across differently-planted keys (differential)"
                    )
                else:
                    problem = "output buffer zeroed on refusal"
                    actual = "all-zero buffer"
                    summary = f"{label}: provider zeroed the output buffer on a refused read"
                _record_matrix_deviation(
                    label=f"{label}: {problem}",
                    summary=summary,
                    detail={
                        "attribute": attribute,
                        "expected": "pre-call sentinel bytes intact",
                        "actual": actual,
                        "aggregate_rv": ckr_name(rv),
                    },
                    actual=rv,
                    records=records,
                )
            else:
                if verdict == "inconclusive":
                    problem = "unproven buffer modification"
                    actual = "modified buffer, differential inconclusive"
                    summary = (
                        f"{label}: provider modified the output buffer on a refused read "
                        "but the differential re-import failed, so constancy is unproven"
                    )
                else:
                    problem = "output buffer scribbled on refusal"
                    actual = "buffer differs from sentinel"
                    summary = f"{label}: provider modified the output buffer on a refused read"
                _record_matrix_bad_effect(
                    label=f"{label}: {problem}",
                    summary=summary,
                    detail={
                        "attribute": attribute,
                        "expected": "pre-call sentinel bytes intact",
                        "actual": actual,
                        "aggregate_rv": ckr_name(rv),
                        "row_length": length,
                    },
                    actual=rv,
                    records=records,
                )


def _check_matrix_mixed(
    *,
    rs: Any,
    raw: Any,
    sh: int,
    handle: int,
    family: _MatrixFamily,
    creation: str,
    sensitive: bool,
    extractable: bool,
    attr: int,
    known: bytes | None,
    label_bytes: bytes,
    prefix: str,
    records: list[classification.Classification],
) -> None:
    """Mixed protected/public template: the protected row seals, the label fills."""
    name = _matrix_member_name(attr)
    label = f"{prefix}: sealed mixed {name}/CKA_LABEL template"
    sentinel = _matrix_sentinel_block(_MATRIX_READ_CAP)
    prot_buf = (ctypes.c_ubyte * _MATRIX_READ_CAP).from_buffer_copy(sentinel)
    label_buf = (ctypes.c_ubyte * len(label_bytes))()
    tmpl = (CK_ATTRIBUTE * 2)()
    tmpl[0].type = attr
    tmpl[0].pValue = ctypes.cast(prot_buf, ctypes.c_void_p)
    tmpl[0].ulValueLen = _MATRIX_READ_CAP
    tmpl[1].type = CKA_LABEL
    tmpl[1].pValue = ctypes.cast(label_buf, ctypes.c_void_p)
    tmpl[1].ulValueLen = len(label_bytes)
    rv = int(raw.C_GetAttributeValue(sh, handle, tmpl, 2))
    raw_record = _defer_mixed_raw_rv(rv, classify=True)
    if raw_record is not None:
        records.append(raw_record)
    completed_full = rv in (int(CKR_OK), int(CKR_ATTRIBUTE_SENSITIVE))
    completed_partial = rv in (
        int(CKR_ATTRIBUTE_TYPE_INVALID),
        int(CKR_BUFFER_TOO_SMALL),
    )
    if completed_full:
        _record_mixed_sensitive_row(
            tmpl,
            rv=rv,
            records=records,
            attr_id=int(attr),
            attr_name=name,
            accept_32bit=True,
        )
    if completed_full or completed_partial:
        _record_mixed_safe_row(
            tmpl, label_buf, label_bytes, rv=rv, records=records, accept_32bit=True
        )
    observed = bytes(prot_buf)
    fragment = _matrix_fragment(known, observed)
    nonzero_modification = observed != sentinel and observed != bytes(len(observed))
    if fragment is not None or nonzero_modification:
        verdict = _matrix_disclosure_verdict(
            rs=rs,
            family=family,
            creation=creation,
            sensitive=sensitive,
            extractable=extractable,
            attr=attr,
            secret=known,
            observed=observed,
            fragment=fragment,
            shape="mixed",
            members=(),
            purpose=f"{prefix}: disclosure-differential import",
            label=label,
            records=records,
            sealed_protected=True,
        )
    else:
        verdict = "undetermined"
    if fragment is not None and verdict not in ("independent", "inconclusive"):
        offset, frag_len = fragment
        _record_matrix_leak(
            label=f"{label}: protected bytes observed",
            summary=f"{label}: protected {name} bytes observed in pValue",
            detail={
                "attribute": {"name": name, "id": int(attr)},
                "expected": "no key bytes copied",
                "actual": "protected bytes observed in pValue",
                "copied_fragment_offset": offset,
                "copied_fragment_length": frag_len,
                "aggregate_rv": ckr_name(rv),
                "row_length": int(tmpl[0].ulValueLen),
            },
            actual=rv,
            records=records,
        )
    elif (
        (completed_full or completed_partial)
        and observed != sentinel
        and _matrix_is_unavailable(int(tmpl[0].ulValueLen))
    ) or verdict in ("independent", "inconclusive"):
        if verdict == "independent" or (
            verdict == "undetermined" and observed == bytes(len(observed))
        ):
            if verdict == "independent":
                problem = "constant overwrite, proven secret-independent"
                actual = "secret-independent overwrite (differential)"
                summary = (
                    f"{label}: provider overwrote the buffer with output identical "
                    "across differently-planted keys (differential)"
                )
            else:
                problem = "output buffer zeroed on refusal"
                actual = "all-zero buffer"
                summary = f"{label}: provider zeroed the output buffer on a refused read"
            _record_matrix_deviation(
                label=f"{label}: {problem}",
                summary=summary,
                detail={
                    "attribute": {"name": name, "id": int(attr)},
                    "expected": "pre-call sentinel bytes intact",
                    "actual": actual,
                    "aggregate_rv": ckr_name(rv),
                },
                actual=rv,
                records=records,
            )
        else:
            if verdict == "inconclusive":
                problem = "unproven buffer modification"
                actual = "modified buffer, differential inconclusive"
                summary = (
                    f"{label}: provider modified the output buffer on a refused read "
                    "but the differential re-import failed, so constancy is unproven"
                )
            else:
                problem = "output buffer scribbled on refusal"
                actual = "buffer differs from sentinel"
                summary = f"{label}: provider modified the output buffer on a refused read"
            _record_matrix_bad_effect(
                label=f"{label}: {problem}",
                summary=summary,
                detail={
                    "attribute": {"name": name, "id": int(attr)},
                    "expected": "pre-call sentinel bytes intact",
                    "actual": actual,
                    "aggregate_rv": ckr_name(rv),
                },
                actual=rv,
                records=records,
            )


def _check_matrix_seal_claim(
    *,
    rs: Any,
    handle: int,
    expect_sensitive: bool,
    expect_extractable: bool,
    sealed_context: bool,
    prefix: str,
    producer_operation: str,
    producer_mechanism: str | None,
    records: list[classification.Classification],
) -> tuple[bool | None, bool | None]:
    """Read back both protection flags; creation acceptance is the fallback.

    Either flag seals the table-marked attributes, so both readbacks are
    validated: malformed shapes fail in any context, while a well-formed
    flag disagreeing with the accepted creation template is a visible seal
    mismatch on sealed cells (readable cells adjudicate flips downstream).
    An unreadable flag falls back to creation acceptance, like before.
    """
    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_SENSITIVE, CKA_EXTRACTABLE])
    value: Any = MISSING_ATTRIBUTE
    extractable_value: Any = MISSING_ATTRIBUTE
    for flag_attr in (int(CKA_SENSITIVE), int(CKA_EXTRACTABLE)):
        flag_value = attr_or_record(
            attrs,
            flag_attr,
            label=f"{prefix}: {_matrix_member_name(flag_attr)} seal claim",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if flag_attr == int(CKA_SENSITIVE):
            value = flag_value
        else:
            extractable_value = flag_value
    if value is MISSING_ATTRIBUTE:
        sensitive_claim = None
        sensitive_shape_ok = True
    elif not isinstance(value, bool):
        sensitive_claim = None
        sensitive_shape_ok = False
    else:
        sensitive_claim = value
        sensitive_shape_ok = True
    if extractable_value is MISSING_ATTRIBUTE:
        extractable_claim = None
        extractable_shape_ok = True
    elif not isinstance(extractable_value, bool):
        extractable_claim = None
        extractable_shape_ok = False
    else:
        extractable_claim = extractable_value
        extractable_shape_ok = True
    if sensitive_shape_ok and not extractable_shape_ok:
        shape_value: Any = extractable_value
        shape_attr = int(CKA_EXTRACTABLE)
        shape_label = f"{prefix}: CKA_EXTRACTABLE seal claim"
    else:
        shape_value = value
        shape_attr = int(CKA_SENSITIVE)
        shape_label = f"{prefix}: CKA_SENSITIVE seal claim"
    record = _record_bool_readback(
        shape_value,
        attr=shape_attr,
        expected=None,
        label=shape_label,
        producer_operation=producer_operation,
        producer_mechanism=producer_mechanism,
    )
    if record is not None:
        records.append(record)
    mismatches: dict[str, dict[str, bool]] = {}
    if sensitive_claim is not None and sensitive_claim != expect_sensitive:
        mismatches["CKA_SENSITIVE"] = {
            "requested": expect_sensitive,
            "reported": sensitive_claim,
        }
    if extractable_claim is not None and extractable_claim != expect_extractable:
        mismatches["CKA_EXTRACTABLE"] = {
            "requested": expect_extractable,
            "reported": extractable_claim,
        }
    both_malformed = not sensitive_shape_ok and not extractable_shape_ok
    if (sealed_context and mismatches) or both_malformed:
        if both_malformed:
            summary = (
                f"{prefix}: creation accepted CKA_SENSITIVE={expect_sensitive!r} and "
                "CKA_EXTRACTABLE="
                f"{expect_extractable!r} but the key reports malformed readbacks"
            )
        else:
            names = ", ".join(mismatches)
            summary = (
                f"{prefix}: creation accepted the seal but the key reports "
                f"different protection flags: {names}"
            )
        _record_matrix_deviation(
            label=f"{prefix}: protection seal mismatch",
            summary=summary,
            detail={
                "requested": {
                    "CKA_SENSITIVE": expect_sensitive,
                    "CKA_EXTRACTABLE": expect_extractable,
                },
                "reported": {
                    "CKA_SENSITIVE": sensitive_claim,
                    "CKA_EXTRACTABLE": extractable_claim,
                },
                "mismatches": mismatches,
            },
            actual=None,
            records=records,
        )
    return sensitive_claim, extractable_claim


def _matrix_first_length_problem(length: int, cap: int) -> tuple[str, str, str]:
    """Describe an invalid first data length for the pre-reread check.

    Returns the (problem, want, got) triple the shared readable-bytes record
    reports: an over-capacity length is impossible, an empty one leaves the
    buffer unproven.
    """
    if length > cap:
        return ("impossible reported length", f"at most {cap} bytes", f"{length}")
    return ("untouched buffer", "provider-written bytes", "pre-call sentinel bytes intact")


def _check_matrix_readable_member(
    *,
    rs: Any,
    raw: Any,
    sh: int,
    handle: int,
    family: _MatrixFamily,
    creation: str,
    sensitive: bool,
    extractable: bool,
    attr: int,
    expected: bytes | None,
    mandatory: bool,
    claim: tuple[bool | None, bool | None],
    sealed_context: bool,
    prefix: str,
    gen_mandatory: bool,
    records: list[classification.Classification],
) -> None:
    """Verify a supposedly readable member: correct bytes or a clean refusal.

    Reported lengths are validated against the supplied capacity (and the
    known size, when planted) before any byte is inspected; unknown generated
    material additionally proves buffer population through a second read with
    a different sentinel. Each call's return is classified independently: a
    failed size query stays visible even when the data call succeeds, and
    only an established TYPE_INVALID absence on a non-obligated optional
    stays silent. Public controls on sealed keys never attribute refused-read
    bytes as protected disclosure.
    """
    name = _matrix_member_name(attr)
    label = f"{prefix}: readable {name} read"
    attribute = {"name": name, "id": int(attr)}
    sensitive_claim, extractable_claim = claim
    sealed_by_claim = sensitive_claim is True or extractable_claim is False
    rv_q, len_q = _matrix_size_query(raw, sh, handle, attr)
    q_malformed = not (is_standard_ckr(rv_q) or is_vendor_defined_ckr(rv_q))
    # A failed size query guarantees no completed length: only a completed
    # query return lets the length drive verdicts or allocation capacity.
    # Anything else falls back to a bounded buffer while the query refusal
    # stays visible and the data call is adjudicated independently.
    q_completed = rv_q in _MATRIX_COMPLETED_READ_RVS
    q_huge = q_completed and not _matrix_is_unavailable(len_q) and len_q > _MATRIX_READABLE_MAX
    if q_malformed or q_huge:
        if q_malformed:
            problem = "unrecognized size-query return value"
            want = "a CK_RV"
            got: object = ckr_name(rv_q)
        else:
            problem = "implausible length"
            want = f"at most {_MATRIX_READABLE_MAX} bytes"
            got = len_q
        _record_matrix_wrong_bytes(
            label=f"{label}: {problem}",
            summary=f"{label}: size query reported an {problem}",
            detail={
                "attribute": attribute,
                "expected": want,
                "actual": got,
                "size_query_rv": ckr_name(rv_q),
            },
            records=records,
        )
        return
    if q_completed and not _matrix_is_unavailable(len_q):
        rv_d, len_d, observed = _matrix_data_read(raw, sh, handle, attr, max(len_q, 1))
    else:
        rv_d, len_d, observed = _matrix_data_read(raw, sh, handle, attr, _MATRIX_READ_CAP)
    established_absence = (
        not mandatory
        and not gen_mandatory
        and rv_q == CKR_ATTRIBUTE_TYPE_INVALID
        and rv_d == CKR_ATTRIBUTE_TYPE_INVALID
        and _matrix_is_unavailable(len_q)
        and _matrix_is_unavailable(len_d)
    )
    if rv_q != int(CKR_OK) and not established_absence:
        _record_matrix_deviation(
            label=f"{label}: size query refused",
            summary=(
                f"{label}: size query was refused ({ckr_name(rv_q)}); "
                "the data call is adjudicated independently"
            ),
            detail={
                "attribute": attribute,
                "expected": "CKR_OK with the attribute length",
                "size_query_rv": ckr_name(rv_q),
                "size_query_length": len_q,
            },
            actual=rv_q,
            records=records,
        )
    refused = rv_d != int(CKR_OK) or _matrix_is_unavailable(len_d)
    sentinel = _matrix_sentinel_block(len(observed))
    intact = observed == sentinel
    fragment = _matrix_fragment(expected, observed) if refused else None
    nonzero_modification = refused and not intact and observed != bytes(len(observed))
    if fragment is not None or nonzero_modification:
        verdict = _matrix_disclosure_verdict(
            rs=rs,
            family=family,
            creation=creation,
            sensitive=sensitive,
            extractable=extractable,
            attr=attr,
            secret=expected,
            observed=observed,
            fragment=fragment,
            shape="single",
            members=(),
            purpose=f"{prefix}: disclosure-differential import",
            label=label,
            records=records,
            sealed_protected=False,
        )
    else:
        verdict = "undetermined"
    if not (is_standard_ckr(rv_d) or is_vendor_defined_ckr(rv_d)):
        # An unrecognized data-call return never becomes a clean public-control
        # refusal: classify it before the fragment and other early returns.
        _record_matrix_bad_effect(
            label=f"{label}: unrecognized return value",
            summary=f"{label}: read returned an unrecognized CK_RV",
            detail={
                "attribute": attribute,
                "expected": "CKR_OK or a clean refusal",
                "data_rv": ckr_name(rv_d),
            },
            actual=rv_d,
            records=records,
        )
        return
    if fragment is not None and verdict not in ("independent", "inconclusive"):
        offset, frag_len = fragment
        if sealed_context:
            # A public control on a refused read: the bytes are public
            # material, so even a genuine copy is not protected disclosure.
            # The clean operational refusal stays a visible deviation.
            _record_matrix_deviation(
                label=f"{label}: public attribute refused",
                summary=(
                    f"{label}: public attribute on a sealed key was refused "
                    f"({ckr_name(rv_d)}); path unproven"
                ),
                detail={
                    "attribute": attribute,
                    "expected": "attribute available",
                    "data_rv": ckr_name(rv_d),
                    "copied_fragment_offset": offset,
                    "copied_fragment_length": frag_len,
                },
                actual=rv_d,
                records=records,
            )
            return
        _record_matrix_leak(
            label=f"{label}: bytes observed despite a refused read",
            summary=f"{label}: {name} bytes observed despite a refused read",
            detail={
                "attribute": attribute,
                "expected": "no bytes copied on a refused read",
                "actual": "bytes observed in pValue despite refusal",
                "copied_fragment_offset": offset,
                "copied_fragment_length": frag_len,
                "data_rv": ckr_name(rv_d),
                "data_length": len_d,
            },
            actual=rv_d,
            records=records,
        )
        return
    if not refused:
        cap = len(observed)
        if expected is None:
            # Validate the successful first result before rereading: a refused
            # reread must not hide an already-invalid length. The hard record
            # is retained via the shared readable-bytes site below while the
            # reread itself is classified independently.
            first_len_ok = 0 < len_d <= cap
            rv_again, len_again, observed_again = _matrix_data_read(
                raw, sh, handle, attr, cap, sentinel_byte=_MATRIX_ALT_SENTINEL_BYTE
            )
            if not (is_standard_ckr(rv_again) or is_vendor_defined_ckr(rv_again)):
                _record_matrix_wrong_bytes(
                    label=(
                        f"{label}: unrecognized verification-reread return value"
                        if first_len_ok
                        else f"{label}: impossible first length with malformed verification reread"
                    ),
                    summary=(
                        f"{label}: verification reread returned an unrecognized CK_RV"
                        if first_len_ok
                        else (
                            f"{label}: first read reported length {len_d} in a {cap}-byte "
                            f"buffer and the verification reread returned "
                            f"{ckr_name(rv_again)}"
                        )
                    ),
                    detail={
                        "attribute": attribute,
                        "expected": (
                            "CKR_OK" if first_len_ok else f"at most {cap} bytes, then CKR_OK"
                        ),
                        "actual": ckr_name(rv_again),
                        "reread_rv": ckr_name(rv_again),
                        "first_data_length": len_d,
                    },
                    records=records,
                )
                return
            if rv_again != int(CKR_OK):
                _record_matrix_deviation(
                    label=f"{label}: verification reread refused",
                    summary=(
                        f"{label}: verification reread was refused "
                        f"({ckr_name(rv_again)}); population unproven"
                    ),
                    detail={
                        "attribute": attribute,
                        "expected": "a matching successful reread",
                        "reread_rv": ckr_name(rv_again),
                    },
                    actual=rv_again,
                    records=records,
                )
                if first_len_ok:
                    return
                problem, want, got = _matrix_first_length_problem(len_d, cap)
                correct = False
            elif not first_len_ok:
                problem, want, got = _matrix_first_length_problem(len_d, cap)
                correct = False
            else:
                lengths_ok = len_d <= cap and len_again <= cap and len_again == len_d
                delivered = observed[:len_d] if lengths_ok else b""
                redelivered = observed_again[:len_again] if lengths_ok else b""
                consistent = lengths_ok and delivered == redelivered
                # Consistency across different initial sentinels already proves
                # provider-written values, even when they equal a sentinel.
                populated = consistent and len(delivered) > 0
                if not lengths_ok:
                    problem = "impossible reported length"
                    want = f"at most {cap} bytes, stable across reads"
                    got = f"{len_d}/{len_again}"
                elif not consistent:
                    problem = "inconsistent reread"
                    want = "identical bytes across sentinel-distinct reads"
                    got = f"{len(delivered)} vs {len(redelivered)} bytes"
                elif not populated:
                    problem = "untouched buffer"
                    want = "provider-written bytes"
                    got = "pre-call sentinel bytes intact"
                else:
                    problem = ""
                    want = ""
                    got = ""
                correct = populated
        else:
            lengths_ok = len_d <= cap and len_d == len(expected)
            delivered = observed[:len_d] if lengths_ok else b""
            correct = lengths_ok and delivered == expected
            if not lengths_ok:
                problem = "impossible reported length"
                want = f"{len(expected)} bytes in a {cap}-byte buffer"
                got = f"{len_d}"
            else:
                problem = "wrong bytes"
                want = f"{len(expected)}-byte known value"
                got = f"{len(delivered)} bytes"
        if not correct:
            _record_matrix_wrong_bytes(
                label=f"{label}: {problem}",
                summary=f"{label}: read returned {problem} for {name}",
                detail={
                    "attribute": attribute,
                    "expected": want,
                    "actual": got,
                    "data_rv": ckr_name(rv_d),
                },
                records=records,
            )
            return
        if sealed_by_claim and not sealed_context:
            sealed_via = "CKA_SENSITIVE" if sensitive_claim is True else "CKA_EXTRACTABLE"
            _record_matrix_leak(
                label=f"{label}: sealed key delivered bytes",
                summary=(f"{label}: key claims {sealed_via} sealing yet {name} reads back"),
                detail={
                    "attribute": attribute,
                    "expected": "CK_UNAVAILABLE_INFORMATION",
                    "actual": f"{len(delivered)} bytes delivered",
                    "data_rv": ckr_name(rv_d),
                },
                actual=rv_d,
                records=records,
            )
        return
    completed_q = rv_q in _MATRIX_COMPLETED_READ_RVS
    completed_d = rv_d in _MATRIX_COMPLETED_READ_RVS
    q_real = not _matrix_is_unavailable(len_q)
    d_real = not _matrix_is_unavailable(len_d)
    # The unavailable-length invariant covers protected members only: public
    # parameters stay readable despite the key's protection flags, so a
    # successful public size query plus an operational data refusal is a
    # clean unproven path, never a sealed-member violation.
    protected_attr = any(int(comp.attr) == int(attr) for comp in family.protected)
    if (
        ((completed_q and q_real) or (completed_d and d_real))
        and sealed_by_claim
        and protected_attr
    ):
        _record_matrix_bad_effect(
            label=f"{label}: available length on a sealed member",
            summary=f"{label}: sealed {name} reported an available length",
            detail={
                "attribute": attribute,
                "expected": "CK_UNAVAILABLE_INFORMATION",
                "size_query_rv": ckr_name(rv_q),
                "size_query_length": len_q,
                "data_rv": ckr_name(rv_d),
                "data_length": len_d,
            },
            actual=rv_d,
            records=records,
        )
        return
    if (completed_d and not intact) or verdict in ("independent", "inconclusive"):
        if verdict == "independent" or (
            verdict == "undetermined" and observed == bytes(len(observed))
        ):
            if verdict == "independent":
                problem = "constant overwrite, proven secret-independent"
                actual = "secret-independent overwrite (differential)"
                summary = (
                    f"{label}: provider overwrote the buffer with output identical "
                    "across differently-planted keys (differential)"
                )
            else:
                problem = "output buffer zeroed on refusal"
                actual = "all-zero buffer"
                summary = f"{label}: provider zeroed the output buffer on a refused read"
            _record_matrix_deviation(
                label=f"{label}: {problem}",
                summary=summary,
                detail={
                    "attribute": attribute,
                    "expected": "pre-call sentinel bytes intact",
                    "actual": actual,
                    "data_rv": ckr_name(rv_d),
                },
                actual=rv_d,
                records=records,
            )
        else:
            if verdict == "inconclusive":
                problem = "unproven buffer modification"
                actual = "modified buffer, differential inconclusive"
                summary = (
                    f"{label}: provider modified the output buffer on a refused read "
                    "but the differential re-import failed, so constancy is unproven"
                )
            else:
                problem = "output buffer scribbled on refusal"
                actual = "buffer differs from sentinel"
                summary = f"{label}: provider modified the output buffer on a refused read"
            _record_matrix_bad_effect(
                label=f"{label}: {problem}",
                summary=summary,
                detail={
                    "attribute": attribute,
                    "expected": "pre-call sentinel bytes intact",
                    "actual": actual,
                    "data_rv": ckr_name(rv_d),
                },
                actual=rv_d,
                records=records,
            )
        return
    if established_absence:
        return
    # Malformed data returns were classified up front, so only clean refusals
    # reach this visible deviation.
    context = "public attribute on a sealed key" if sealed_context else "unsealed read"
    _record_matrix_deviation(
        label=f"{label}: {context} refused",
        summary=f"{label}: {context} was refused ({ckr_name(rv_d)}); path unproven",
        detail={
            "attribute": attribute,
            "expected": "attribute available",
            "claim": sensitive_claim,
            "extractable_claim": extractable_claim,
            "data_rv": ckr_name(rv_d),
        },
        actual=rv_d,
        records=records,
    )


def _run_matrix_sealed_probes(
    rs: Any, family: _MatrixFamily, key: _MatrixKey, creation: str, seal: str
) -> None:
    """Run every sealed leg for one matrix cell, then raise the strongest."""
    prefix = f"QC1 {family.family}/{creation}/{seal}"
    terminal: list[classification.Classification] = []
    expect_sensitive, expect_extractable = _MATRIX_SEALS[seal]
    claim = _check_matrix_seal_claim(
        rs=rs,
        handle=key.handle,
        expect_sensitive=expect_sensitive,
        expect_extractable=expect_extractable,
        sealed_context=True,
        prefix=prefix,
        producer_operation=key.producer_operation,
        producer_mechanism=key.producer_mechanism,
        records=terminal,
    )
    absent_attrs: set[int] = set()
    for component in family.protected:
        status = _check_matrix_sealed_member(
            rs=rs,
            raw=rs.raw,
            sh=rs.sh,
            handle=key.handle,
            family=family,
            creation=creation,
            sensitive=expect_sensitive,
            extractable=expect_extractable,
            attr=component.attr,
            mandatory=component.mandatory,
            known=key.known.get(component.attr),
            prefix=prefix,
            gen_mandatory=_matrix_gen_seed_obligation(family.family, creation, component.attr),
            records=terminal,
        )
        if status == "absent":
            absent_attrs.add(int(component.attr))
    if len(family.protected) > 1:
        _check_matrix_sealed_multi(
            rs=rs,
            raw=rs.raw,
            sh=rs.sh,
            handle=key.handle,
            family=family,
            creation=creation,
            sensitive=expect_sensitive,
            extractable=expect_extractable,
            members=[(comp.attr, comp.mandatory) for comp in family.protected],
            known=key.known,
            prefix=prefix,
            absent_attrs=frozenset(absent_attrs),
            records=terminal,
        )
    first_mandatory = next(comp for comp in family.protected if comp.mandatory)
    _check_matrix_mixed(
        rs=rs,
        raw=rs.raw,
        sh=rs.sh,
        handle=key.handle,
        family=family,
        creation=creation,
        sensitive=expect_sensitive,
        extractable=expect_extractable,
        attr=first_mandatory.attr,
        known=key.known.get(first_mandatory.attr),
        label_bytes=key.label,
        prefix=prefix,
        records=terminal,
    )
    for attr in family.public:
        _check_matrix_readable_member(
            rs=rs,
            raw=rs.raw,
            sh=rs.sh,
            handle=key.handle,
            family=family,
            creation=creation,
            sensitive=expect_sensitive,
            extractable=expect_extractable,
            attr=attr,
            expected=key.known.get(attr),
            mandatory=True,
            claim=claim,
            sealed_context=True,
            prefix=prefix,
            gen_mandatory=False,
            records=terminal,
        )
    if not any(record.outcome == "fail" for record in terminal):
        _record_matrix_sealed_summary(
            label=f"{prefix}: sealed read protection holds",
            summary=(f"{prefix}: every tested protected member refused without leaking"),
            detail={
                "protected": [_matrix_member_name(comp.attr) for comp in family.protected],
                "optional_absent": sorted(_matrix_member_name(attr) for attr in absent_attrs),
                "claim": claim[0],
                "extractable_claim": claim[1],
            },
        )
    _raise_deferred_hard(terminal)


def _run_matrix_readable_probes(
    rs: Any, family: _MatrixFamily, key: _MatrixKey, creation: str, seal: str
) -> None:
    """Prove the read path on an unsealed cell, then raise the strongest."""
    prefix = f"QC1 {family.family}/{creation}/{seal}"
    terminal: list[classification.Classification] = []
    expect_sensitive, expect_extractable = _MATRIX_SEALS[seal]
    claim = _check_matrix_seal_claim(
        rs=rs,
        handle=key.handle,
        expect_sensitive=expect_sensitive,
        expect_extractable=expect_extractable,
        sealed_context=False,
        prefix=prefix,
        producer_operation=key.producer_operation,
        producer_mechanism=key.producer_mechanism,
        records=terminal,
    )
    for component in family.protected:
        _check_matrix_readable_member(
            rs=rs,
            raw=rs.raw,
            sh=rs.sh,
            handle=key.handle,
            family=family,
            creation=creation,
            sensitive=expect_sensitive,
            extractable=expect_extractable,
            attr=component.attr,
            expected=key.known.get(component.attr),
            mandatory=component.mandatory,
            claim=claim,
            sealed_context=False,
            prefix=prefix,
            gen_mandatory=_matrix_gen_seed_obligation(family.family, creation, component.attr),
            records=terminal,
        )
    _raise_deferred_hard(terminal)


def _matrix_params(seals: tuple[str, ...]) -> tuple[list[list[str]], list[str]]:
    """Build (argvalues, ids) for one matrix test method in table order."""
    argvalues: list[list[str]] = []
    ids: list[str] = []
    for family in _MATRIX_FAMILIES:
        for creation in family.creations:
            for seal in seals:
                argvalues.append([family.family, creation, seal])
                ids.append(f"{family.family}-{creation}-{seal}")
    return argvalues, ids


_MATRIX_SEALED_PARAMS, _MATRIX_SEALED_IDS = _matrix_params(_MATRIX_SEALED_SEALS)
_MATRIX_UNSEALED_PARAMS, _MATRIX_UNSEALED_IDS = _matrix_params(_MATRIX_UNSEALED_SEALS)


class TestProtectedComponentMatrix:
    """QC1: table-defined protected reads by family, creation path, and seal."""

    @pytest.mark.parametrize(
        "family_id,creation,seal", _MATRIX_SEALED_PARAMS, ids=_MATRIX_SEALED_IDS
    )
    def test_sealed_components_unavailable(
        self, p11_raw_session: Any, family_id: str, creation: str, seal: str
    ) -> None:
        """Every protected member of a sealed key refuses without leaking."""
        rs = p11_raw_session
        family = _MATRIX_FAMILIES_BY_ID[family_id]
        key = _create_matrix_key(rs, family, creation, seal)
        try:
            _run_matrix_sealed_probes(rs, family, key, creation, seal)
        finally:
            for handle in key.cleanup:
                destroy_quietly(rs.raw, rs.sh, handle)

    @pytest.mark.parametrize(
        "family_id,creation,seal", _MATRIX_UNSEALED_PARAMS, ids=_MATRIX_UNSEALED_IDS
    )
    def test_unsealed_components_readable(
        self, p11_raw_session: Any, family_id: str, creation: str, seal: str
    ) -> None:
        """Unsealed members read back, proving the read path works."""
        rs = p11_raw_session
        family = _MATRIX_FAMILIES_BY_ID[family_id]
        key = _create_matrix_key(rs, family, creation, seal)
        try:
            _run_matrix_readable_probes(rs, family, key, creation, seal)
        finally:
            for handle in key.cleanup:
                destroy_quietly(rs.raw, rs.sh, handle)
