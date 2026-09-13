"""Tests for extended HKDF mechanisms.

Covers CKM_HKDF_DATA and CKM_HKDF_KEY_GEN.
CKM_HKDF_DERIVE is tested in test_kdf.py.

OASIS PKCS#11 v3.2 spec: HKDF mechanisms.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import record_as, xfail_as
from pkcs11_check.raw.pack import mech_hkdf, mech_simple
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKM_HKDF_DATA,
    CKM_HKDF_DERIVE,
    CKM_HKDF_KEY_GEN,
    CKM_SHA256,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    IMPORT_STORAGE_SHAPE_REJECTS,
    assert_correct,
    import_secret_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

# Common derive error RVs
_DERIVE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
}

# Keygen error RVs
_KEYGEN_ERROR_RVS = {
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
}

_KEYGEN_VALUE_READ_ERROR_RVS = {
    CKR_ATTRIBUTE_VALUE_INVALID,
}


def _gen_hkdf_key(rs: Any, key_type: int, bits: int = 256) -> int:
    """Generate a key via CKM_HKDF_KEY_GEN."""
    from ctypes import byref

    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    packed = [
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_ulong(CKA_VALUE_LEN, bits // 8),
        attr_bool(CKA_DERIVE, True),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_TOKEN, False),
    ]
    tmpl = template(*packed)
    mech = mech_simple(CKM_HKDF_KEY_GEN)
    key_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
    expect_rv(rv, CKR_OK, context="CKM_HKDF_KEY_GEN C_GenerateKey")
    return key_h.value


def _create_base_key(rs: Any) -> int:
    """Create a GENERIC_SECRET key suitable for HKDF derivation."""
    ikm = bytes(range(32))
    return import_secret_key_negotiated(
        rs,
        CKK_GENERIC_SECRET,
        ikm,
        attrs={
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        },
    )


_HKDF_DATA_OUTPUT_LEN = 32
_HKDF_CREATE_REF = "PKCS#11 v3.2 · C_CreateObject"
_HKDF_DERIVE_REF = "PKCS#11 v3.2 · C_DeriveKey · CKM_HKDF_DATA"
_HKDF_READ_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


def _hkdf_data_detail(
    *,
    producer_operation: str,
    producer_mechanism: str | None,
    consumer_operation: str,
    consumer_mechanism: str | None,
) -> dict[str, Any]:
    """Describe the producer and consumer of an HKDF_DATA object."""
    return {
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
        "consumer_operation": consumer_operation,
        "consumer_mechanism": consumer_mechanism,
    }


def _create_hkdf_data_base_or_xfail(rs: Any) -> int:
    """Provision the generic-secret input, classifying exhausted shape rejects."""
    try:
        handle = _create_base_key(rs)
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
            summary=f"CKM_HKDF_DATA base-key provisioning refused ({ckr_name(exc.rv)})",
            detail=_hkdf_data_detail(
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            ),
        )
    if handle == 0:
        C.fail_as(
            "self_contradiction",
            kind="lifecycle",
            label="CKM_HKDF_DATA base-key provisioning handle",
            operation="C_CreateObject",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_HKDF_CREATE_REF,
            expected="non-zero object handle",
            actual=handle,
            summary="CKM_HKDF_DATA base-key provisioning returned a zero handle",
            detail=_hkdf_data_detail(
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            ),
        )
    return handle


def _derive_hkdf_data_or_xfail(rs: Any, base_key: int, salt: bytes, info: bytes) -> int:
    """Run C_DeriveKey, xfail only the established HKDF derive refusals."""
    try:
        handle = _hkdf_data_derive(rs, base_key, salt, info)
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
            detail=_hkdf_data_detail(
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            ),
        )
    if handle == 0:
        C.fail_as(
            "self_contradiction",
            kind="lifecycle",
            label="CKM_HKDF_DATA derived-object handle",
            operation="C_DeriveKey",
            mechanism="CKM_HKDF_DATA",
            inherit_mechanism=False,
            spec_ref=_HKDF_DERIVE_REF,
            expected="non-zero object handle",
            actual=handle,
            summary="CKM_HKDF_DATA C_DeriveKey returned a zero handle",
            detail=_hkdf_data_detail(
                producer_operation="C_DeriveKey",
                producer_mechanism="CKM_HKDF_DATA",
                consumer_operation="C_GetAttributeValue",
                consumer_mechanism=None,
            ),
        )
    return handle


def _record_hkdf_data_readback_failure(
    *, label: str, attribute: int, expected: object, actual: object
) -> Any:
    """Record malformed CKO_DATA metadata without inheriting the derive mechanism."""
    names = {int(CKA_CLASS): "CKA_CLASS", int(CKA_VALUE): "CKA_VALUE"}
    actual_detail: object
    if attribute == int(CKA_VALUE):
        actual_detail = {
            "type": type(actual).__name__,
            "length": len(actual) if hasattr(actual, "__len__") else None,
        }
    else:
        actual_detail = actual
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        spec_ref=_HKDF_READ_REF,
        summary=f"{label}: malformed CKM_HKDF_DATA output metadata",
        detail={
            "attribute": {"name": names.get(attribute, str(attribute)), "id": attribute},
            "expected": expected,
            "actual": actual_detail,
            **_hkdf_data_detail(
                producer_operation="C_DeriveKey",
                producer_mechanism="CKM_HKDF_DATA",
                consumer_operation="C_GetAttributeValue",
                consumer_mechanism=None,
            ),
        },
    )


def _read_hkdf_data_output(rs: Any, handle: int, label: str) -> Any:
    """Read CKO_DATA class/value and validate the exact output length."""
    # Readback is an independent metadata consumer.  It has no negotiated
    # refusal set: mechanism/template errors here are unexpected provider
    # behavior and must remain hard failures rather than being attributed to
    # the preceding C_DeriveKey operation.
    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_CLASS, CKA_VALUE])

    records_before = len(C.get_records())
    object_class = attr_or_record(
        attrs,
        CKA_CLASS,
        label=f"{label} CKA_CLASS readback",
        reason="not_operational",
        kind="metadata",
        mechanism=None,
        inherit_mechanism=False,
    )
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label=f"{label} CKA_VALUE readback",
        reason="not_operational",
        kind="metadata",
        mechanism=None,
        inherit_mechanism=False,
    )
    malformed: list[Any] = []
    if object_class is not MISSING_ATTRIBUTE and (
        not isinstance(object_class, int)
        or isinstance(object_class, bool)
        or object_class != int(CKO_DATA)
    ):
        malformed.append(
            _record_hkdf_data_readback_failure(
                label=f"{label} CKA_CLASS readback",
                attribute=int(CKA_CLASS),
                expected=int(CKO_DATA),
                actual=object_class,
            )
        )
    if value is not MISSING_ATTRIBUTE and (
        type(value) is not bytes or len(value) != _HKDF_DATA_OUTPUT_LEN
    ):
        malformed.append(
            _record_hkdf_data_readback_failure(
                label=f"{label} CKA_VALUE readback",
                attribute=int(CKA_VALUE),
                expected={"type": "bytes", "length": _HKDF_DATA_OUTPUT_LEN},
                actual=value,
            )
        )
    if malformed:
        C.raise_for_record(malformed[-1])
    if value is MISSING_ATTRIBUTE and len(C.get_records()) == records_before:
        raise AssertionError(f"{label}: missing CKA_VALUE produced no classification record")
    return value


def _hkdf_derive(rs: Any, base_key: int, salt: bytes, info: bytes) -> int:
    """Derive a GENERIC_SECRET key via HKDF."""
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_HKDF_DERIVE,
        attrs={
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_TOKEN: False,
        },
        mech_param=mech_hkdf(
            CKM_HKDF_DERIVE,
            hash_mech=CKM_SHA256,
            extract=True,
            expand=True,
            salt=salt,
            info=info,
        ),
    )


def _hkdf_data_derive(rs: Any, base_key: int, salt: bytes, info: bytes) -> int:
    """Derive a CKO_DATA object via CKM_HKDF_DATA."""
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_HKDF_DATA,
        attrs={
            CKA_CLASS: CKO_DATA,
            CKA_VALUE_LEN: 32,
            CKA_TOKEN: False,
        },
        mech_param=mech_hkdf(
            CKM_HKDF_DATA,
            hash_mech=CKM_SHA256,
            extract=True,
            expand=True,
            salt=salt,
            info=info,
        ),
    )


class TestHKDFKeyGen:
    """CKM_HKDF_KEY_GEN tests - generate keys for HKDF input keying material."""

    @pytest.mark.parametrize(
        "key_type",
        [CKK_HKDF, CKK_GENERIC_SECRET],
        ids=["CKK_HKDF", "CKK_GENERIC_SECRET"],
    )
    def test_hkdf_key_gen_basic(
        self,
        p11_raw_session: Any,
        key_type: int,
    ) -> None:
        """Generate a key via CKM_HKDF_KEY_GEN with the given key type.

        Per the OASIS HKDF profile, ``CKM_HKDF_KEY_GEN`` produces a ``CKK_HKDF``
        key.  Requesting ``CKK_GENERIC_SECRET`` therefore probes a spec
        constraint: a module that produces ``CKK_HKDF`` regardless (the
        spec-correct type) is a clean, noted deviation from the requested type
        (``honest_deviation``); a module that honors ``CKK_GENERIC_SECRET`` as
        asked is also acceptable.  This replaces the prior declarative
        ``@pytest.mark.xfail`` so every outcome carries a classify() record.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")

        handle = 0
        try:
            handle = _gen_hkdf_key(rs, key_type, 256)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _KEYGEN_ERROR_RVS,
                f"CKM_HKDF_KEY_GEN advertised but key_type={key_type:#x} keygen rejected",
            )
        try:
            assert handle != 0
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    handle,
                    [CKA_KEY_TYPE, CKA_VALUE, CKA_DERIVE],
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _KEYGEN_VALUE_READ_ERROR_RVS,
                    "CKM_HKDF_KEY_GEN generated key CKA_VALUE readback rejected",
                )
            actual_key_type = attr_or_record(
                attrs,
                CKA_KEY_TYPE,
                inherit_mechanism=False,
                label="CKM_HKDF_KEY_GEN:CKA_KEY_TYPE readback",
                reason="honest_deviation",
            )
            derive = attr_or_record(
                attrs,
                CKA_DERIVE,
                inherit_mechanism=False,
                label="CKM_HKDF_KEY_GEN:CKA_DERIVE readback",
                reason="honest_deviation",
            )
            value = attr_or_record(
                attrs,
                CKA_VALUE,
                inherit_mechanism=False,
                label="CKM_HKDF_KEY_GEN:CKA_VALUE readback",
                reason="not_operational",
            )
            checks: list[tuple[Any, Any, str, str]] = []
            if actual_key_type is not MISSING_ATTRIBUTE:
                if key_type == CKK_GENERIC_SECRET and actual_key_type == CKK_HKDF:
                    # The module ignored the requested CKK_GENERIC_SECRET and produced
                    # the spec-mandated CKK_HKDF: a clean, noted deviation from the
                    # requested type, recorded via classify() rather than a bare
                    # declarative xfail (which would emit no classification record).
                    record_as(
                        "honest_deviation",
                        label="CKM_HKDF_KEY_GEN:key_type",
                        operation="C_GenerateKey",
                        mechanism="CKM_HKDF_KEY_GEN",
                        summary=(
                            "CKM_HKDF_KEY_GEN produced CKK_HKDF (the spec-mandated type) "
                            "for a CKK_GENERIC_SECRET request"
                        ),
                    )
                else:
                    checks.append(
                        (
                            actual_key_type,
                            key_type,
                            "CKM_HKDF_KEY_GEN:CKA_KEY_TYPE readback",
                            "C_GenerateKey",
                        )
                    )
            if value is not MISSING_ATTRIBUTE:
                checks.append(
                    (
                        len(value),
                        32,
                        "CKM_HKDF_KEY_GEN:CKA_VALUE length",
                        "C_GetAttributeValue",
                    )
                )
            if derive is not MISSING_ATTRIBUTE:
                checks.append(
                    (
                        derive,
                        True,
                        "CKM_HKDF_KEY_GEN:CKA_DERIVE readback",
                        "C_GetAttributeValue",
                    )
                )

            mismatches = [check for check in checks if check[0] != check[1]]
            for _actual, _expected, label, operation in mismatches[:-1]:
                record_as(
                    "wrong_result",
                    kind="metadata",
                    label=label,
                    operation=operation,
                    mechanism="CKM_HKDF_KEY_GEN",
                    summary=f"{label}: output does not match known answer",
                )
            if mismatches:
                actual, expected, label, operation = mismatches[-1]
                assert_correct(
                    actual=actual,
                    expected=expected,
                    label=label,
                    operation=operation,
                    mechanism="CKM_HKDF_KEY_GEN",
                    kind="metadata",
                )
            if (
                actual_key_type is MISSING_ATTRIBUTE
                or value is MISSING_ATTRIBUTE
                or derive is MISSING_ATTRIBUTE
            ):
                return
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_hkdf_key_gen_usable_for_derive(self, p11_raw_session: Any) -> None:
        """Key generated via CKM_HKDF_KEY_GEN can be used with CKM_HKDF_DERIVE."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")

        # Try CKK_HKDF first, then CKK_GENERIC_SECRET
        base_key: int | None = None
        rejects: list[str] = []
        for kt in (CKK_HKDF, CKK_GENERIC_SECRET):
            try:
                base_key = _gen_hkdf_key(rs, kt, 256)
                break
            except AssertionError as exc:
                if not is_known_error(exc, _KEYGEN_ERROR_RVS):
                    raise
                rejects.append(str(exc))
        if base_key is None:
            xfail_as(
                "not_operational",
                label="CKM_HKDF_KEY_GEN",
                operation="C_GenerateKey",
                mechanism="CKM_HKDF_KEY_GEN",
                summary=(
                    "CKM_HKDF_KEY_GEN advertised but no tested key type is operational: "
                    + "; ".join(rejects)
                ),
            )

        derived = 0
        try:
            derived = _hkdf_derive(rs, base_key, b"salt-value", b"info-value")
            okm = attr_or_record(
                read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE]),
                CKA_VALUE,
                inherit_mechanism=False,
                label="CKM_HKDF_DERIVE:CKA_VALUE readback",
                reason="not_operational",
            )
            if okm is MISSING_ATTRIBUTE:
                return
            assert len(okm) == 32
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "HKDF_DERIVE with HKDF_KEY_GEN key failed")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)


class TestHKDFData:
    """CKM_HKDF_DATA tests - derive data objects via HKDF."""

    def test_hkdf_data_derive(self, p11_raw_session: Any) -> None:
        """Derive a data object using CKM_HKDF_DATA mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = _create_hkdf_data_base_or_xfail(rs)
        derived = 0
        try:
            derived = _derive_hkdf_data_or_xfail(rs, base_key, b"salt", b"info")
            value = _read_hkdf_data_output(rs, derived, "CKM_HKDF_DATA")
            if value is MISSING_ATTRIBUTE:
                return
            assert len(value) == _HKDF_DATA_OUTPUT_LEN  # 256 bits = 32 bytes
            assert value != bytes(32), "Derived value should not be all zeros"
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_hkdf_data_deterministic(self, p11_raw_session: Any) -> None:
        """Same HKDF_DATA inputs produce identical output."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = _create_hkdf_data_base_or_xfail(rs)
        derived_1 = 0
        derived_2 = 0
        try:
            derived_1 = _derive_hkdf_data_or_xfail(rs, base_key, b"det-salt", b"det-info")
            derived_2 = _derive_hkdf_data_or_xfail(rs, base_key, b"det-salt", b"det-info")
            val_1 = _read_hkdf_data_output(rs, derived_1, "CKM_HKDF_DATA deterministic output 1")
            val_2 = _read_hkdf_data_output(rs, derived_2, "CKM_HKDF_DATA deterministic output 2")
            if val_1 is MISSING_ATTRIBUTE or val_2 is MISSING_ATTRIBUTE:
                return
            if val_1 != val_2:
                C.fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_HKDF_DATA:C_GetAttributeValue determinism",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    spec_ref=_HKDF_READ_REF,
                    expected={"type": "bytes", "length": _HKDF_DATA_OUTPUT_LEN},
                    actual={
                        "type": type(val_1).__name__,
                        "length": len(val_1) if hasattr(val_1, "__len__") else None,
                    },
                    summary="CKM_HKDF_DATA repeated inputs produced different values",
                    detail=_hkdf_data_detail(
                        producer_operation="C_DeriveKey",
                        producer_mechanism="CKM_HKDF_DATA",
                        consumer_operation="C_GetAttributeValue",
                        consumer_mechanism=None,
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived_1:
                destroy_quietly(rs.raw, rs.sh, derived_1)
            if derived_2:
                destroy_quietly(rs.raw, rs.sh, derived_2)

    def test_hkdf_data_different_info_different_output(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Different 'info' values produce different HKDF_DATA output."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = _create_hkdf_data_base_or_xfail(rs)
        derived_a = 0
        derived_b = 0
        try:
            derived_a = _derive_hkdf_data_or_xfail(rs, base_key, b"salt", b"info-alpha")
            derived_b = _derive_hkdf_data_or_xfail(rs, base_key, b"salt", b"info-bravo")
            val_a = _read_hkdf_data_output(rs, derived_a, "CKM_HKDF_DATA different-info output 1")
            val_b = _read_hkdf_data_output(rs, derived_b, "CKM_HKDF_DATA different-info output 2")
            if val_a is MISSING_ATTRIBUTE or val_b is MISSING_ATTRIBUTE:
                return
            assert val_a != val_b, "Different info strings must produce different output"
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived_a:
                destroy_quietly(rs.raw, rs.sh, derived_a)
            if derived_b:
                destroy_quietly(rs.raw, rs.sh, derived_b)
