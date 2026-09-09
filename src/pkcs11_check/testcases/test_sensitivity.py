"""Attribute sensitivity enforcement tests.

Verifies that PKCS#11 modules enforce CKA_SENSITIVE and CKA_EXTRACTABLE
correctly - sensitive key values must not be readable, non-extractable
keys must not be wrappable.
"""

from __future__ import annotations

import ctypes
from typing import Any, cast

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_UNAVAILABLE_INFORMATION,
    CKA_ALWAYS_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKK_AES,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    gen_rsa_keypair_or_xfail,
    is_known_error,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
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
) -> None:
    """Check the sensitive row only after a present protection claim."""
    if attr[0].ulValueLen == CK_UNAVAILABLE_INFORMATION:
        return
    records.append(
        classification.record_as(
            "wrong_result",
            kind="policy",
            label="C_GetAttributeValue mixed sensitive row",
            operation="C_GetAttributeValue",
            actual=rv,
            detail={
                "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
                "expected": "CK_UNAVAILABLE_INFORMATION",
                "actual": int(attr[0].ulValueLen),
                "return_value": rv,
            },
            summary=("sensitive CKA_VALUE row did not report CK_UNAVAILABLE_INFORMATION"),
        )
    )


def _record_mixed_safe_row(
    attr: Any,
    label_buf: Any,
    label: bytes,
    *,
    rv: int,
    records: list[classification.Classification],
) -> None:
    """Validate safe-row metadata before inspecting its caller-owned buffer."""
    reported_length = int(attr[1].ulValueLen)
    unavailable = reported_length == CK_UNAVAILABLE_INFORMATION and rv in (
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
                label="CKA_SENSITIVE=True on generated AES key",
                reason="not_operational",
                kind="policy",
                mechanism="CKM_AES_KEY_GEN",
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
            value = (
                attr_or_record(
                    val_attrs,
                    CKA_VALUE,
                    label="CKA_VALUE on a CKA_SENSITIVE=True AES key",
                    reason="honest_deviation",
                    kind="policy",
                    mechanism="CKM_AES_KEY_GEN",
                )
                if violated
                else MISSING_ATTRIBUTE
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
            if sensitive is MISSING_ATTRIBUTE:
                return
            _classify_sensitive_policy(
                claimed=sensitive is True,
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
            if sensitive is MISSING_ATTRIBUTE:
                return
            _classify_sensitive_policy(
                claimed=sensitive is True,
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
                label="CKA_VALUE on a CKA_SENSITIVE=False AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_SENSITIVE=True on RSA private key",
                reason="not_operational",
                kind="policy",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
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
            value = (
                attr_or_record(
                    exp_attrs,
                    CKA_PRIVATE_EXPONENT,
                    label="CKA_PRIVATE_EXPONENT on a CKA_SENSITIVE=True RSA private key",
                    reason="honest_deviation",
                    kind="policy",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                if violated
                else MISSING_ATTRIBUTE
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
            if sensitive is MISSING_ATTRIBUTE:
                return
            _classify_sensitive_policy(
                claimed=sensitive is True,
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
                    label="CKA_EXTRACTABLE default on generated AES key",
                    reason="honest_deviation",
                    kind="metadata",
                    mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_EXTRACTABLE=True on generated AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_VALUE on extractable AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_SENSITIVE=True on generated AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_SENSITIVE=False on generated AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_ALWAYS_SENSITIVE on sensitive AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
                label="CKA_ALWAYS_SENSITIVE on non-sensitive AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
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
