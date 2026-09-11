"""Generated AEAD wrap parameter output tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.pack import (
    mech_ccm_wrap,
    mech_ccm_wrap_generated_nonce,
    mech_gcm_wrap,
    mech_gcm_wrap_generated_iv,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    get_mechanism_info,
    read_attributes,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKF_UNWRAP,
    CKF_WRAP,
    CKK_AES,
    CKM,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    skip_if_mech_param_unsupported,
    unwrap_key_for_mechanism_roundtrip,
)

pytestmark = [pytest.mark.keymgmt, pytest.mark.wrap]


def _require_wrap_flags(rs: Any, mechanism: CKM | int, name: str) -> None:
    info = get_mechanism_info(rs.raw, rs.slot_id, mechanism)
    flags = info["flags"]
    if not (flags & int(CKF_WRAP)) or not (flags & int(CKF_UNWRAP)):
        pytest.skip(f"{name} does not advertise CKF_WRAP and CKF_UNWRAP")


_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _read_attribute(
    attrs: Mapping[Any, Any],
    attr: Any,
    *,
    label: str,
    mechanism: str,
) -> Any:
    """Read one provider attribute while retaining unavailable-value evidence."""
    return attr_or_record(
        attrs,
        attr,
        label=f"{label} (producer_mechanism={mechanism})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )


def _record_attribute_mismatch(
    *,
    label: str,
    expected: Any,
    actual: Any,
    mechanism: str,
    operation: str = "C_GetAttributeValue",
) -> C.Classification:
    """Record a malformed or incorrect CKA_VALUE without raising before cleanup."""
    if actual is MISSING_ATTRIBUTE:
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            summary=f"{label}: provider did not return the requested attribute",
            detail={"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}},
        )
    if expected is MISSING_ATTRIBUTE:
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            summary=f"{label}: expected value unavailable",
            detail={"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}},
        )
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual!r}; expected {expected!r}",
        detail={
            "attribute": {
                "name": "CKA_VALUE",
                "id": int(CKA_VALUE),
                "expected": repr(expected),
                "actual": repr(actual),
            }
        },
    )


def _record_parameter_mismatch(
    *,
    label: str,
    parameter: str,
    expected: str,
    actual: Any,
    mechanism: str,
) -> C.Classification:
    """Record a wrong C_WrapKey mechanism-parameter output."""
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_WrapKey",
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual!r}; expected {expected}",
        detail={
            "parameter": {
                "name": parameter,
                "expected": expected,
                "actual": repr(actual),
            }
        },
    )


def _validate_value(
    value: Any,
    *,
    expected: bytes | None,
    expected_len: int,
    label: str,
    mechanism: str,
) -> C.Classification | None:
    """Return a hard finding for a present malformed or mismatched CKA_VALUE."""
    if value is MISSING_ATTRIBUTE:
        return None
    if expected is MISSING_ATTRIBUTE:
        return None
    if not isinstance(value, bytes) or len(value) != expected_len:
        return _record_attribute_mismatch(
            label=label,
            expected=f"{expected_len}-byte bytes",
            actual=value,
            mechanism=mechanism,
        )
    if expected is not None and value != expected:
        return _record_attribute_mismatch(
            label=label,
            expected=expected,
            actual=value,
            mechanism=mechanism,
            operation="C_UnwrapKey",
        )
    return None


def _is_trustworthy_value(value: Any) -> bool:
    """Return whether a recovered key value is safe to use as an equality oracle."""
    if value is MISSING_ATTRIBUTE:
        return False
    return isinstance(value, bytes) and len(value) == 16


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest hard output finding after all key handles are destroyed."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            _KIND_PRIORITY.get(record.kind or "", 0),
            _SEVERITY_PRIORITY.get(record.severity, 0),
        ),
    )
    C.raise_for_record(strongest)


def _make_keys(rs: Any, mechanism: str = "CKM_AES_GCM") -> tuple[int, int, Any]:
    """Create keys while retaining handles for caller cleanup and output checks."""
    wrap_h = 0
    target = 0
    try:
        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
        )
        original = _read_attribute(
            read_attributes(rs.raw, rs.sh, target, [CKA_VALUE]),
            CKA_VALUE,
            label=f"{mechanism}:target CKA_VALUE readback",
            mechanism=mechanism,
        )
        _validate_value(
            original,
            expected=None,
            expected_len=16,
            label=f"{mechanism}:target CKA_VALUE readback",
            mechanism=mechanism,
        )
        return wrap_h, target, original
    except BaseException:
        if target:
            destroy_quietly(rs.raw, rs.sh, target)
        if wrap_h:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
        raise


def test_gcm_wrap_generated_iv_roundtrip(
    p11_raw_session: Any, p11_config: Any, p11_interface_version: str
) -> None:
    rs = p11_raw_session
    if p11_interface_version != "3.2":
        pytest.skip("CK_GCM_WRAP_PARAMS generated IV requires v3.2")
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("CKM_AES_GCM not supported")
    _require_wrap_flags(rs, CKM_AES_GCM, "CKM_AES_GCM")

    wrap_h = target = unwrapped = 0
    hard_results: list[C.Classification] = []
    try:
        setup_record_start = len(C.get_records())
        wrap_h, target, original = _make_keys(rs, "CKM_AES_GCM")
        target_label = "CKM_AES_GCM:target CKA_VALUE readback"
        if original is MISSING_ATTRIBUTE and not any(
            record.label == target_label
            and record.reason == "not_operational"
            and record.operation == "C_GetAttributeValue"
            for record in C.get_records()[setup_record_start:]
        ):
            _read_attribute(
                {},
                CKA_VALUE,
                label=target_label,
                mechanism="CKM_AES_GCM",
            )
        target_records = [
            record
            for record in C.get_records()[setup_record_start:]
            if record.label == target_label and record.reason == "wrong_result"
        ]
        if original is not MISSING_ATTRIBUTE and not target_records:
            target_mismatch = _validate_value(
                original,
                expected=None,
                expected_len=16,
                label=target_label,
                mechanism="CKM_AES_GCM",
            )
            if target_mismatch is not None:
                target_records.append(target_mismatch)
        hard_results.extend(target_records)
        target_is_trustworthy = _is_trustworthy_value(original)
        aad = b"gcm wrap generated iv"
        wrap_mech = mech_gcm_wrap_generated_iv(CKM_AES_GCM, iv_len=12, aad=aad, tag_bits=128)
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_GCM, mech_param=wrap_mech)
        except AssertionError as exc:
            skip_if_mech_param_unsupported(exc, "CK_GCM_WRAP_PARAMS generated IV C_WrapKey")

        iv = wrap_mech.buffer_bytes("iv")
        if not isinstance(iv, bytes) or not any(iv):
            hard_results.append(
                _record_parameter_mismatch(
                    label="CKM_AES_GCM:pIv",
                    parameter="pIv",
                    expected="non-zero IV",
                    actual=iv,
                    mechanism="CKM_AES_GCM",
                )
            )

        if isinstance(iv, bytes) and iv:
            unwrap_mech = mech_gcm_wrap(CKM_AES_GCM, iv, aad=aad, tag_bits=128)
            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrap_h,
                wrapped_key=wrapped,
                mechanism=CKM_AES_GCM,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                mech_param=unwrap_mech,
                purpose="AES-GCM generated-IV wrap roundtrip",
            )
            value = _read_attribute(
                read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE]),
                CKA_VALUE,
                label="CKM_AES_GCM:unwrapped CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            mismatch = _validate_value(
                value,
                expected=original if target_is_trustworthy else None,
                expected_len=16,
                label="CKM_AES_GCM:unwrapped CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
    finally:
        if unwrapped:
            destroy_quietly(rs.raw, rs.sh, unwrapped)
        if wrap_h:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
        if target:
            destroy_quietly(rs.raw, rs.sh, target)
    _raise_strongest(hard_results)


def test_ccm_wrap_generated_nonce_roundtrip(
    p11_raw_session: Any, p11_config: Any, p11_interface_version: str
) -> None:
    rs = p11_raw_session
    if p11_interface_version != "3.2":
        pytest.skip("CK_CCM_WRAP_PARAMS generated nonce requires v3.2")
    if not rs.has_mechanism("AES_CCM"):
        pytest.skip("CKM_AES_CCM not supported")
    _require_wrap_flags(rs, CKM_AES_CCM, "CKM_AES_CCM")

    wrap_h = target = unwrapped = 0
    hard_results: list[C.Classification] = []
    try:
        setup_record_start = len(C.get_records())
        wrap_h, target, original = _make_keys(rs, "CKM_AES_CCM")
        target_label = "CKM_AES_CCM:target CKA_VALUE readback"
        if original is MISSING_ATTRIBUTE and not any(
            record.label == target_label
            and record.reason == "not_operational"
            and record.operation == "C_GetAttributeValue"
            for record in C.get_records()[setup_record_start:]
        ):
            _read_attribute(
                {},
                CKA_VALUE,
                label=target_label,
                mechanism="CKM_AES_CCM",
            )
        target_records = [
            record
            for record in C.get_records()[setup_record_start:]
            if record.label == target_label and record.reason == "wrong_result"
        ]
        if original is not MISSING_ATTRIBUTE and not target_records:
            target_mismatch = _validate_value(
                original,
                expected=None,
                expected_len=16,
                label=target_label,
                mechanism="CKM_AES_CCM",
            )
            if target_mismatch is not None:
                target_records.append(target_mismatch)
        hard_results.extend(target_records)
        target_is_trustworthy = _is_trustworthy_value(original)
        aad = b"ccm wrap generated nonce"
        wrap_mech = mech_ccm_wrap_generated_nonce(
            CKM_AES_CCM,
            data_len=16,
            nonce_len=12,
            aad=aad,
            mac_len=16,
        )
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_CCM, mech_param=wrap_mech)
        except AssertionError as exc:
            skip_if_mech_param_unsupported(exc, "CK_CCM_WRAP_PARAMS generated nonce C_WrapKey")

        nonce = wrap_mech.buffer_bytes("nonce")
        if not isinstance(nonce, bytes) or not any(nonce):
            hard_results.append(
                _record_parameter_mismatch(
                    label="CKM_AES_CCM:pNonce",
                    parameter="pNonce",
                    expected="non-zero nonce",
                    actual=nonce,
                    mechanism="CKM_AES_CCM",
                )
            )

        if isinstance(nonce, bytes) and nonce:
            unwrap_mech = mech_ccm_wrap(
                CKM_AES_CCM,
                nonce,
                data_len=16,
                aad=aad,
                mac_len=16,
            )
            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrap_h,
                wrapped_key=wrapped,
                mechanism=CKM_AES_CCM,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                mech_param=unwrap_mech,
                purpose="AES-CCM generated-nonce wrap roundtrip",
            )
            value = _read_attribute(
                read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE]),
                CKA_VALUE,
                label="CKM_AES_CCM:unwrapped CKA_VALUE readback",
                mechanism="CKM_AES_CCM",
            )
            mismatch = _validate_value(
                value,
                expected=original if target_is_trustworthy else None,
                expected_len=16,
                label="CKM_AES_CCM:unwrapped CKA_VALUE readback",
                mechanism="CKM_AES_CCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
    finally:
        if unwrapped:
            destroy_quietly(rs.raw, rs.sh, unwrapped)
        if wrap_h:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
        if target:
            destroy_quietly(rs.raw, rs.sh, target)
    _raise_strongest(hard_results)
