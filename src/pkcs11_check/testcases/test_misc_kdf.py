"""Miscellaneous simple key derivation mechanism tests.

Covers CKM_CONCATENATE_BASE_AND_KEY, CKM_CONCATENATE_BASE_AND_DATA,
CKM_CONCATENATE_DATA_AND_BASE, CKM_XOR_BASE_AND_DATA, and
CKM_EXTRACT_KEY_FROM_KEY.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
import hashlib
from collections.abc import Callable
from ctypes import byref
from typing import Any, NamedTuple, NoReturn

import pytest

from pkcs11_check.classification import (
    Classification,
    classify,
    fail_as,
    get_records,
    raise_for_record,
    record_as,
    xfail_as,
)
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import (
    attr_bytes,
    mech_hkdf,
    mech_simple,
    mech_string_data,
    mech_ulong,
    template,
    template_ptr_count,
)
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    find_objects,
    gen_aes_key,
    pack_attrs,
    read_attributes,
    wrap_key,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKK_CDMF,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_DATA_AND_BASE,
    CKM_DES3_ECB,
    CKM_DES_ECB,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_HKDF_DERIVE,
    CKM_SHA1_KEY_DERIVATION,
    CKM_SHA256,
    CKM_XOR_BASE_AND_DATA,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    refusal_rv_for,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    probe_operability,
    xfail_vacuous_reject,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    classify_negative_rv,
    import_secret_key_negotiated,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.mechanism_helpers import gen_generic_secret

pytestmark = pytest.mark.keymgmt


def _read_attr_or_record(
    raw: Any,
    sh: int,
    handle: int,
    attr: Any,
    *,
    label: str,
) -> Any:
    """Read one provider attribute while preserving an unavailable-value record."""
    attrs = read_attributes(raw, sh, handle, [attr])
    return attr_or_record(
        attrs, attr, inherit_mechanism=False, label=label, reason="not_operational"
    )


def _assert_misc_bytes_length(
    value: Any,
    *,
    expected_len: int,
    label: str,
    mechanism: str,
) -> None:
    """Classify malformed provider output while retaining missing-attribute evidence."""
    if value is MISSING_ATTRIBUTE:
        return
    # This finding is about C_DeriveKey's output bytes, not the
    # C_GetAttributeValue readback that retrieved it (F6): all call sites pass a
    # C_DeriveKey-family KDF mechanism here.
    if not isinstance(value, bytes):
        classify(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism,
            expected="bytes",
            actual=type(value).__name__,
            summary=f"{label}: provider returned a non-byte value",
        )
    assert_correct(
        actual=len(value),
        expected=expected_len,
        label=label,
        operation="C_DeriveKey",
        mechanism=mechanism,
        kind="metadata",
    )


def _assert_misc_different(
    first: Any,
    second: Any,
    *,
    label: str,
    mechanism: str,
) -> None:
    """Classify equal provider outputs where a diversity check is required."""
    if first is MISSING_ATTRIBUTE or second is MISSING_ATTRIBUTE:
        return
    if first == second:
        # This finding is about C_DeriveKey's output diversity, not the
        # C_GetAttributeValue readback that retrieved it (F6): all call sites pass a
        # C_DeriveKey-family KDF mechanism here.
        classify(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism,
            summary=f"{label}: independent provider outputs were equal",
        )


# ---------------------------------------------------------------------------
# Acceptable error RVs for derive operations on non-conforming modules
# ---------------------------------------------------------------------------
_DERIVE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ARGUMENTS_BAD,
}

# ---------------------------------------------------------------------------
# Helper: import a GENERIC_SECRET key for derivation
# ---------------------------------------------------------------------------

_DERIVE_ATTRS = {
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}


def _import_generic_secret(rs: Any, value: bytes) -> int:
    """Import ``value`` as a GENERIC_SECRET key with DERIVE=True."""
    return import_secret_key_negotiated(
        rs,
        CKK_GENERIC_SECRET,
        value,
        attrs={
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_DERIVE: True,
        },
    )


def _derive_generic_secret(
    rs: Any,
    base: int,
    mechanism: Any,
    key_len_bits: int,
    *,
    mech_param: Any = None,
) -> int:
    """Derive a GENERIC_SECRET key with standard attributes."""
    attrs = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base,
        mechanism,
        attrs=attrs,
        mech_param=mech_param,
    )


# ---------------------------------------------------------------------------
# TestConcatenateBaseAndKey
# ---------------------------------------------------------------------------


class TestConcatenateBaseAndKey:
    """CKM_CONCATENATE_BASE_AND_KEY - derive by concatenating two key values."""

    def test_concat_two_keys_value(self, p11_raw_session: Any) -> None:
        """Derived value equals base_key_bytes || second_key_bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_KEY"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_KEY not supported")

        base_bytes = b"\x01" * 16
        second_bytes = b"\x02" * 16
        expected = base_bytes + second_bytes

        base = _import_generic_secret(rs, base_bytes)
        second = _import_generic_secret(rs, second_bytes)
        derived = 0
        try:
            # CK_OBJECT_HANDLE is a single CK_ULONG parameter
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_BASE_AND_KEY,
                len(expected) * 8,
                mech_param=mech_ulong(CKM_CONCATENATE_BASE_AND_KEY, second),
            )
            derived_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_CONCATENATE_BASE_AND_KEY:CKA_VALUE readback",
            )
            if derived_value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=derived_value,
                expected=expected,
                label="CKM_CONCATENATE_BASE_AND_KEY:C_DeriveKey KAT",
                operation="C_DeriveKey",
                mechanism="CKM_CONCATENATE_BASE_AND_KEY",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_CONCATENATE_BASE_AND_KEY derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)
            destroy_quietly(rs.raw, rs.sh, second)

    def test_concat_produces_combined_length(self, p11_raw_session: Any) -> None:
        """Derived key length equals sum of base and second key lengths."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_KEY"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_KEY not supported")

        base_bytes = b"\xaa" * 16
        second_bytes = b"\xbb" * 16

        base = _import_generic_secret(rs, base_bytes)
        second = _import_generic_secret(rs, second_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_BASE_AND_KEY,
                32 * 8,
                mech_param=mech_ulong(CKM_CONCATENATE_BASE_AND_KEY, second),
            )
            val = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_CONCATENATE_BASE_AND_KEY:CKA_VALUE readback",
            )
            if val is MISSING_ATTRIBUTE:
                return
            _assert_misc_bytes_length(
                val,
                expected_len=32,
                label="CKM_CONCATENATE_BASE_AND_KEY:CKA_VALUE readback",
                mechanism="CKM_CONCATENATE_BASE_AND_KEY",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_CONCATENATE_BASE_AND_KEY derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)
            destroy_quietly(rs.raw, rs.sh, second)


# ---------------------------------------------------------------------------
# TestConcatenateBaseAndData
# ---------------------------------------------------------------------------


class TestConcatenateBaseAndData:
    """CKM_CONCATENATE_BASE_AND_DATA - derive by appending data to base key value."""

    def test_concat_value_cross_verify(self, p11_raw_session: Any) -> None:
        """Derived value equals base_key_bytes || data_bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        base_bytes = b"AAAA" * 4  # 16 bytes
        data_bytes = b"BBBB" * 4  # 16 bytes
        expected = base_bytes + data_bytes

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_BASE_AND_DATA,
                len(expected) * 8,
                mech_param=mech_string_data(CKM_CONCATENATE_BASE_AND_DATA, data_bytes),
            )
            derived_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_CONCATENATE_BASE_AND_DATA:CKA_VALUE readback",
            )
            if derived_value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=derived_value,
                expected=expected,
                label="CKM_CONCATENATE_BASE_AND_DATA:C_DeriveKey KAT",
                operation="C_DeriveKey",
                mechanism="CKM_CONCATENATE_BASE_AND_DATA",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_CONCATENATE_BASE_AND_DATA derive failed"
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)

    def test_different_data_produces_different_derived_key(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Different data bytes yield different derived keys from the same base."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        base_bytes = b"\x55" * 16
        data_a = b"\x11" * 16
        data_b = b"\x22" * 16

        base = _import_generic_secret(rs, base_bytes)
        derived_a = 0
        derived_b = 0
        try:
            derived_a = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_BASE_AND_DATA,
                32 * 8,
                mech_param=mech_string_data(CKM_CONCATENATE_BASE_AND_DATA, data_a),
            )
            derived_b = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_BASE_AND_DATA,
                32 * 8,
                mech_param=mech_string_data(CKM_CONCATENATE_BASE_AND_DATA, data_b),
            )
            val_a = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived_a,
                CKA_VALUE,
                label="CKM_CONCATENATE_BASE_AND_DATA:first CKA_VALUE readback",
            )
            val_b = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived_b,
                CKA_VALUE,
                label="CKM_CONCATENATE_BASE_AND_DATA:second CKA_VALUE readback",
            )
            if val_a is MISSING_ATTRIBUTE or val_b is MISSING_ATTRIBUTE:
                return
            _assert_misc_different(
                val_a,
                val_b,
                label="CKM_CONCATENATE_BASE_AND_DATA:distinct data outputs",
                mechanism="CKM_CONCATENATE_BASE_AND_DATA",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_CONCATENATE_BASE_AND_DATA derive failed"
            )
        finally:
            for h in (derived_a, derived_b):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)
            destroy_quietly(rs.raw, rs.sh, base)


# ---------------------------------------------------------------------------
# TestConcatenateDataAndBase
# ---------------------------------------------------------------------------


class TestConcatenateDataAndBase:
    """CKM_CONCATENATE_DATA_AND_BASE - derive by prepending data to base key value."""

    def test_concat_value_cross_verify(self, p11_raw_session: Any) -> None:
        """Derived value equals data_bytes || base_key_bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_DATA_AND_BASE"):
            pytest.skip("CKM_CONCATENATE_DATA_AND_BASE not supported")

        base_bytes = b"BBBB" * 4  # 16 bytes
        data_bytes = b"AAAA" * 4  # 16 bytes
        expected = data_bytes + base_bytes

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_DATA_AND_BASE,
                len(expected) * 8,
                mech_param=mech_string_data(CKM_CONCATENATE_DATA_AND_BASE, data_bytes),
            )
            derived_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_CONCATENATE_DATA_AND_BASE:CKA_VALUE readback",
            )
            if derived_value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=derived_value,
                expected=expected,
                label="CKM_CONCATENATE_DATA_AND_BASE:C_DeriveKey KAT",
                operation="C_DeriveKey",
                mechanism="CKM_CONCATENATE_DATA_AND_BASE",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_CONCATENATE_DATA_AND_BASE derive failed"
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)

    def test_base_and_data_ordering_differ(self, p11_raw_session: Any) -> None:
        """CONCATENATE_BASE_AND_DATA and CONCATENATE_DATA_AND_BASE yield different results."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")
        if not rs.has_mechanism("CONCATENATE_DATA_AND_BASE"):
            pytest.skip("CKM_CONCATENATE_DATA_AND_BASE not supported")

        base_bytes = b"\x11" * 16
        data_bytes = b"\x22" * 16

        base = _import_generic_secret(rs, base_bytes)
        derived_bd = 0
        derived_db = 0
        try:
            derived_bd = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_BASE_AND_DATA,
                32 * 8,
                mech_param=mech_string_data(CKM_CONCATENATE_BASE_AND_DATA, data_bytes),
            )
            derived_db = _derive_generic_secret(
                rs,
                base,
                CKM_CONCATENATE_DATA_AND_BASE,
                32 * 8,
                mech_param=mech_string_data(CKM_CONCATENATE_DATA_AND_BASE, data_bytes),
            )
            val_bd = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived_bd,
                CKA_VALUE,
                label="CKM_CONCATENATE_BASE_AND_DATA:base-data CKA_VALUE readback",
            )
            val_db = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived_db,
                CKA_VALUE,
                label="CKM_CONCATENATE_DATA_AND_BASE:data-base CKA_VALUE readback",
            )
            if val_bd is MISSING_ATTRIBUTE or val_db is MISSING_ATTRIBUTE:
                return
            _assert_misc_different(
                val_bd,
                val_db,
                label=(
                    "CKM_CONCATENATE_BASE_AND_DATA:base-data vs "
                    "CKM_CONCATENATE_DATA_AND_BASE:data-base"
                ),
                mechanism="CKM_CONCATENATE_DATA_AND_BASE",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CONCATENATE ordering test failed")
        finally:
            for h in (derived_bd, derived_db):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)
            destroy_quietly(rs.raw, rs.sh, base)


# ---------------------------------------------------------------------------
# TestXorBaseAndData
# ---------------------------------------------------------------------------


class TestXorBaseAndData:
    """CKM_XOR_BASE_AND_DATA - derive by XOR-ing base key value with data bytes."""

    def test_xor_cross_verify(self, p11_raw_session: Any) -> None:
        """Derived value equals base_key_bytes XOR data_bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("XOR_BASE_AND_DATA"):
            pytest.skip("CKM_XOR_BASE_AND_DATA not supported")

        base_bytes = b"\xff" * 16
        data_bytes = b"\x0f" * 16
        expected = bytes(a ^ b for a, b in zip(base_bytes, data_bytes))

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_XOR_BASE_AND_DATA,
                len(base_bytes) * 8,
                mech_param=mech_string_data(CKM_XOR_BASE_AND_DATA, data_bytes),
            )
            derived_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_XOR_BASE_AND_DATA:CKA_VALUE readback",
            )
            if derived_value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=derived_value,
                expected=expected,
                label="CKM_XOR_BASE_AND_DATA:C_DeriveKey KAT (cross-verify)",
                operation="C_DeriveKey",
                mechanism="CKM_XOR_BASE_AND_DATA",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_XOR_BASE_AND_DATA derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)

    def test_xor_with_zero_data_is_identity(self, p11_raw_session: Any) -> None:
        """XOR with all-zero data bytes leaves the key value unchanged."""
        rs = p11_raw_session
        if not rs.has_mechanism("XOR_BASE_AND_DATA"):
            pytest.skip("CKM_XOR_BASE_AND_DATA not supported")

        base_bytes = b"\xab\xcd\xef\x01" * 4  # 16 bytes
        data_bytes = b"\x00" * 16

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_XOR_BASE_AND_DATA,
                len(base_bytes) * 8,
                mech_param=mech_string_data(CKM_XOR_BASE_AND_DATA, data_bytes),
            )
            val = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_XOR_BASE_AND_DATA:zero-data CKA_VALUE readback",
            )
            if val is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=val,
                expected=base_bytes,
                label="CKM_XOR_BASE_AND_DATA:C_DeriveKey KAT (zero-data identity)",
                operation="C_DeriveKey",
                mechanism="CKM_XOR_BASE_AND_DATA",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_XOR_BASE_AND_DATA derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)

    def test_xor_with_all_ones_is_bitflip(self, p11_raw_session: Any) -> None:
        """XOR with all-0xFF bytes inverts every bit of the base key."""
        rs = p11_raw_session
        if not rs.has_mechanism("XOR_BASE_AND_DATA"):
            pytest.skip("CKM_XOR_BASE_AND_DATA not supported")

        base_bytes = b"\x55" * 16
        data_bytes = b"\xff" * 16
        expected = bytes(b ^ 0xFF for b in base_bytes)

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_XOR_BASE_AND_DATA,
                len(base_bytes) * 8,
                mech_param=mech_string_data(CKM_XOR_BASE_AND_DATA, data_bytes),
            )
            val = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_XOR_BASE_AND_DATA:all-ones CKA_VALUE readback",
            )
            if val is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_XOR_BASE_AND_DATA:C_DeriveKey KAT (all-ones bitflip)",
                operation="C_DeriveKey",
                mechanism="CKM_XOR_BASE_AND_DATA",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_XOR_BASE_AND_DATA derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)


# ---------------------------------------------------------------------------
# TestExtractKeyFromKey
# ---------------------------------------------------------------------------


class TestExtractKeyFromKey:
    """CKM_EXTRACT_KEY_FROM_KEY - extract a sub-key from a base key at a bit offset."""

    def test_extract_from_offset_zero(self, p11_raw_session: Any) -> None:
        """Extract at bit offset 0 yields the leading bytes of the base key."""
        rs = p11_raw_session
        if not rs.has_mechanism("EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")

        base_bytes = bytes(range(32))
        expected = base_bytes[:16]

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_EXTRACT_KEY_FROM_KEY,
                128,
                mech_param=mech_ulong(CKM_EXTRACT_KEY_FROM_KEY, 0),
            )
            derived_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_EXTRACT_KEY_FROM_KEY:offset-zero CKA_VALUE readback",
            )
            if derived_value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=derived_value,
                expected=expected,
                label="CKM_EXTRACT_KEY_FROM_KEY:C_DeriveKey KAT (offset 0)",
                operation="C_DeriveKey",
                mechanism="CKM_EXTRACT_KEY_FROM_KEY",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_EXTRACT_KEY_FROM_KEY derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)

    def test_extract_at_byte_boundary_offset(self, p11_raw_session: Any) -> None:
        """Extract at bit offset 128 (byte 16) yields the second half of a 32-byte key."""
        rs = p11_raw_session
        if not rs.has_mechanism("EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")

        base_bytes = bytes(range(32))
        expected = base_bytes[16:]

        base = _import_generic_secret(rs, base_bytes)
        derived = 0
        try:
            derived = _derive_generic_secret(
                rs,
                base,
                CKM_EXTRACT_KEY_FROM_KEY,
                128,
                mech_param=mech_ulong(CKM_EXTRACT_KEY_FROM_KEY, 128),
            )
            derived_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived,
                CKA_VALUE,
                label="CKM_EXTRACT_KEY_FROM_KEY:offset-128 CKA_VALUE readback",
            )
            if derived_value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=derived_value,
                expected=expected,
                label="CKM_EXTRACT_KEY_FROM_KEY:C_DeriveKey KAT (offset 128)",
                operation="C_DeriveKey",
                mechanism="CKM_EXTRACT_KEY_FROM_KEY",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_EXTRACT_KEY_FROM_KEY derive failed")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)

    def test_extract_different_offsets_yield_different_keys(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Different bit offsets yield different extracted key values."""
        rs = p11_raw_session
        if not rs.has_mechanism("EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")

        base_bytes = bytes(range(32))

        base = _import_generic_secret(rs, base_bytes)
        derived_a = 0
        derived_b = 0
        try:
            derived_a = _derive_generic_secret(
                rs,
                base,
                CKM_EXTRACT_KEY_FROM_KEY,
                128,
                mech_param=mech_ulong(CKM_EXTRACT_KEY_FROM_KEY, 0),
            )
            derived_b = _derive_generic_secret(
                rs,
                base,
                CKM_EXTRACT_KEY_FROM_KEY,
                128,
                mech_param=mech_ulong(CKM_EXTRACT_KEY_FROM_KEY, 128),
            )
            val_a = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived_a,
                CKA_VALUE,
                label="CKM_EXTRACT_KEY_FROM_KEY:offset-zero CKA_VALUE readback",
            )
            val_b = _read_attr_or_record(
                rs.raw,
                rs.sh,
                derived_b,
                CKA_VALUE,
                label="CKM_EXTRACT_KEY_FROM_KEY:offset-128 CKA_VALUE readback",
            )
            if val_a is MISSING_ATTRIBUTE or val_b is MISSING_ATTRIBUTE:
                return
            _assert_misc_different(
                val_a,
                val_b,
                label="CKM_EXTRACT_KEY_FROM_KEY:distinct offsets",
                mechanism="CKM_EXTRACT_KEY_FROM_KEY",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_EXTRACT_KEY_FROM_KEY derive failed")
        finally:
            for h in (derived_a, derived_b):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)
            destroy_quietly(rs.raw, rs.sh, base)


# ---------------------------------------------------------------------------
# QC2: byte-operation protection inheritance (PKCS#11 v3.2 §6.43; #52.2 and
# the normative half of #54.3)
#
# The value oracles above run on unsealed keys and are unchanged. The legs
# below derive from sealed sources and check that the child inherits the
# sources' protection: CKA_SENSITIVE/CKA_EXTRACTABLE, the
# CKA_ALWAYS_SENSITIVE/CKA_NEVER_EXTRACTABLE histories, raw value access
# and wrap enforcement. For the two-key mechanism
# (CKM_CONCATENATE_BASE_AND_KEY) history and protection derive from BOTH
# source keys via that mechanism's own rule, never from a single-source
# formula applied indiscriminately. Success-path legs collect
# nonterminating observations and raise the strongest verdict (S5). HKDF
# runs under its own oracle (§6.62.3 independent selection, S1), not the
# byte-operation inheritance rule.
# ---------------------------------------------------------------------------

_BASE_AND_KEY_NAME = "CKM_CONCATENATE_BASE_AND_KEY"
_EXTRACT_NAME = "CKM_EXTRACT_KEY_FROM_KEY"
_HKDF_DERIVE_NAME = "CKM_HKDF_DERIVE"

#: Reviewed §6.43 row order: the two-key mechanism first, then the four
#: single-source mechanisms (caller-supplied data/offset params are public
#: and never feed the rule).
_BYTE_KDF_MECH_IDS: dict[str, int] = {
    _BASE_AND_KEY_NAME: int(CKM_CONCATENATE_BASE_AND_KEY),
    "CKM_CONCATENATE_BASE_AND_DATA": int(CKM_CONCATENATE_BASE_AND_DATA),
    "CKM_CONCATENATE_DATA_AND_BASE": int(CKM_CONCATENATE_DATA_AND_BASE),
    "CKM_XOR_BASE_AND_DATA": int(CKM_XOR_BASE_AND_DATA),
    _EXTRACT_NAME: int(CKM_EXTRACT_KEY_FROM_KEY),
}

_BYTE_KDF_SINGLE_SOURCE_MECHS: tuple[str, ...] = (
    "CKM_CONCATENATE_BASE_AND_DATA",
    "CKM_CONCATENATE_DATA_AND_BASE",
    "CKM_XOR_BASE_AND_DATA",
    _EXTRACT_NAME,
)

_BYTE_KDF_SEALS: tuple[str, ...] = ("sensitive_only", "unextractable_only", "both")
_BYTE_KDF_MODES: tuple[str, ...] = ("omitted", "matching", "downgrade")
_BYTE_KDF_PLACEMENTS: tuple[str, ...] = ("base", "aux", "both")

#: Seal name to (CKA_SENSITIVE, CKA_EXTRACTABLE). "unsealed" is the
#: asymmetric-placement partner for the two-key mechanism, never a matrix
#: seal of its own.
_SEAL_FLAG_PAIRS: dict[str, tuple[bool, bool]] = {
    "sensitive_only": (True, True),
    "unextractable_only": (False, False),
    "both": (True, False),
    "unsealed": (False, True),
}

_LABEL_TAGS: dict[str, str] = {
    _BASE_AND_KEY_NAME: "bak",
    "CKM_CONCATENATE_BASE_AND_DATA": "bad",
    "CKM_CONCATENATE_DATA_AND_BASE": "dab",
    "CKM_XOR_BASE_AND_DATA": "xor",
    _EXTRACT_NAME: "ext",
}

#: Public caller-supplied derivation data shared by the data-taking rows.
#: 32 bytes so the XOR row also satisfies the equal-length shape.
_BYTE_KDF_DATA = bytes(range(32))

_SOURCE_BITS = 256
_EXTRACT_LEN = 16
_SHORT_CHILD_LEN = 1

#: Explicit child output lengths per §6.43 row (S2). Sources hold 32 bytes
#: (256 bits) and the derivation data is 32 bytes, so concatenation rows
#: yield 64 bytes and XOR yields 32. Every child template states its
#: length: these rows derive variable-length keys, and §§6.43.3–6.43.6
#: require a complete template — a token must not invent the length.
_BYTE_KDF_CHILD_LENS: dict[str, int] = {
    _BASE_AND_KEY_NAME: 64,
    "CKM_CONCATENATE_BASE_AND_DATA": 64,
    "CKM_CONCATENATE_DATA_AND_BASE": 64,
    "CKM_XOR_BASE_AND_DATA": 32,
    _EXTRACT_NAME: _EXTRACT_LEN,
}

#: HKDF expansion output length (S2): the scope-control expansion asks
#: for 32 bytes of SHA-256 output, stated explicitly like every other row.
_HKDF_CHILD_LEN = 32

_DERIVE_SPEC = "PKCS#11 v3.2 · C_DeriveKey"
_READ_SPEC = "PKCS#11 v3.2 · C_GetAttributeValue"
_WRAP_SPEC = "PKCS#11 v3.2 · C_WrapKey"


def _is_defined_rv(rv: int) -> bool:
    """Whether ``rv`` is a defined CK_RV (standard or vendor-defined)."""
    return is_standard_ckr(rv) or is_vendor_defined_ckr(rv)


def _xfail_setup_refusal(
    rv: int,
    *,
    label: str,
    operation: str | None,
    mechanism: str | None,
    spec_ref: str | None = None,
    summary: str,
) -> NoReturn:
    """Xfail a refused setup/readback step; undefined RVs fail (S9).

    Every terminating setup/readback xfail route funnels through here so
    an undefined return value can never read as a clean operational
    deviation: defined codes xfail ``not_operational`` with the original
    RV preserved, anything else fails as a metadata RV-contract
    violation. Nonterminating success-path legs inline the same
    membership check and return a fail record instead of raising.
    """
    if not _is_defined_rv(rv):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism=mechanism,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=rv,
            spec_ref=spec_ref,
            summary=f"{label}: refused with undefined CK_RV {ckr_name(rv)}",
        )
    xfail_as(
        "not_operational",
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        spec_ref=spec_ref,
        summary=summary,
    )


def _seal_attrs(seal: str) -> dict[int, bool]:
    """Return the {SENSITIVE, EXTRACTABLE} template fragment for a seal."""
    sensitive, extractable = _SEAL_FLAG_PAIRS[seal]
    return {CKA_SENSITIVE: sensitive, CKA_EXTRACTABLE: extractable}


def _child_mode_attrs(seal: str, mode: str) -> dict[int, bool]:
    """Return the child-template protection fragment for a matrix mode."""
    if mode == "omitted":
        return {}
    if mode == "matching":
        return _seal_attrs(seal)
    if mode == "downgrade":
        return {CKA_SENSITIVE: False, CKA_EXTRACTABLE: True}
    raise ValueError(f"unknown child-template mode: {mode!r}")


class _SourcePremise(NamedTuple):
    """Observed source protection feeding one inheritance expectation."""

    sensitive: bool
    extractable: bool
    always: bool | None
    never: bool | None


def _read_source_premise(
    rs: Any, handle: int, *, seal: str, label: str, mechanism: str
) -> _SourcePremise:
    """Read back a source seal; xfail when the premise is unprovable.

    The expected child protection is computed from OBSERVED source flags,
    never assumed from the requested seal: a source the token weakened or
    hides at creation voids this leg (a creation-faithfulness deviation
    owned elsewhere), it must not silently rebase the expectation.
    """
    try:
        attrs = read_attributes(
            rs.raw,
            rs.sh,
            handle,
            [CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE],
        )
    except CkrAssertionError as exc:
        _xfail_setup_refusal(
            exc.rv,
            label=f"{label}: source seal readback ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            spec_ref=_READ_SPEC,
            summary=f"{label}: source seal readback refused ({seal}); premise unprovable",
        )
    sensitive = attr_or_record(
        attrs,
        CKA_SENSITIVE,
        label=f"{label}: source seal readback ({seal})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if sensitive is MISSING_ATTRIBUTE:
        xfail_as(
            "not_operational",
            label=f"{label}: source seal premise ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=f"{label}: source SENSITIVE unreadable; premise unprovable",
        )
    extractable = attr_or_record(
        attrs,
        CKA_EXTRACTABLE,
        label=f"{label}: source seal readback ({seal})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if extractable is MISSING_ATTRIBUTE:
        xfail_as(
            "not_operational",
            label=f"{label}: source seal premise ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=f"{label}: source EXTRACTABLE unreadable; premise unprovable",
        )
    requested = _SEAL_FLAG_PAIRS[seal]
    if (
        type(sensitive) is not bool
        or type(extractable) is not bool
        or (sensitive, extractable) != requested
    ):
        xfail_as(
            "not_operational",
            label=f"{label}: source seal premise ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=(
                f"{label}: source reports {sensitive!r}/{extractable!r}, "
                f"requested {requested[0]!r}/{requested[1]!r}; premise unprovable"
            ),
            detail={"requested": list(requested), "mechanism": mechanism},
        )
    assert type(sensitive) is bool and type(extractable) is bool
    always_raw = attr_or_record(
        attrs,
        CKA_ALWAYS_SENSITIVE,
        label=f"{label}: source history readback ({seal})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if always_raw is MISSING_ATTRIBUTE:
        refusal_rv = refusal_rv_for(attrs, CKA_ALWAYS_SENSITIVE)
        if refusal_rv is None:
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: source history readback ({seal})",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                spec_ref=_READ_SPEC,
                summary=(
                    f"{label}: source ALWAYS_SENSITIVE omitted "
                    "without a refusal; history premise unprovable"
                ),
            )
        if not _is_defined_rv(refusal_rv):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: source history readback ({seal})",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=refusal_rv,
                spec_ref=_READ_SPEC,
                summary=(
                    f"{label}: source ALWAYS_SENSITIVE refused "
                    f"with undefined CK_RV {ckr_name(refusal_rv)}"
                ),
            )
        # A defined clean refusal: the attr_or_record record above already
        # carries the not_operational evidence, so this component goes
        # unavailable while its sibling is still observed (S8). Rebind the
        # routed sentinel so the shape logic below sees a handled value.
        always_raw = MISSING_ATTRIBUTE
    never_raw = attr_or_record(
        attrs,
        CKA_NEVER_EXTRACTABLE,
        label=f"{label}: source history readback ({seal})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if never_raw is MISSING_ATTRIBUTE:
        refusal_rv = refusal_rv_for(attrs, CKA_NEVER_EXTRACTABLE)
        if refusal_rv is None:
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: source history readback ({seal})",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                spec_ref=_READ_SPEC,
                summary=(
                    f"{label}: source NEVER_EXTRACTABLE omitted "
                    "without a refusal; history premise unprovable"
                ),
            )
        if not _is_defined_rv(refusal_rv):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: source history readback ({seal})",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=refusal_rv,
                spec_ref=_READ_SPEC,
                summary=(
                    f"{label}: source NEVER_EXTRACTABLE refused "
                    f"with undefined CK_RV {ckr_name(refusal_rv)}"
                ),
            )
        # A defined clean refusal: the attr_or_record record above already
        # carries the not_operational evidence, so this component goes
        # unavailable while its sibling stays observed (S8). Rebind the
        # routed sentinel so the shape logic below sees a handled value.
        never_raw = MISSING_ATTRIBUTE
    if (always_raw is True and sensitive is not True) or (
        never_raw is True and extractable is not False
    ):
        xfail_as(
            "not_operational",
            label=f"{label}: source history premise ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=f"{label}: source history contradicts source flags; premise unprovable",
        )
    # Per-component premises (S8): a malformed history is recorded as
    # evidence before its premise goes unavailable, and never discards
    # its independently provable sibling. Absences were already recorded
    # by attr_or_record above.
    always_flag = always_raw if type(always_raw) is bool else None
    if always_raw is not MISSING_ATTRIBUTE and type(always_raw) is not bool:
        record_as(
            "not_operational",
            kind="metadata",
            label=f"{label}: source history readback ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=(
                f"{label}: source ALWAYS_SENSITIVE malformed "
                f"({type(always_raw).__name__}); history premise partially unavailable"
            ),
        )
    never_flag = never_raw if type(never_raw) is bool else None
    if never_raw is not MISSING_ATTRIBUTE and type(never_raw) is not bool:
        record_as(
            "not_operational",
            kind="metadata",
            label=f"{label}: source history readback ({seal})",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=(
                f"{label}: source NEVER_EXTRACTABLE malformed "
                f"({type(never_raw).__name__}); history premise partially unavailable"
            ),
        )
    return _SourcePremise(
        sensitive=sensitive, extractable=extractable, always=always_flag, never=never_flag
    )


def _derive_raw(
    rs: Any, mech_id: int, base: int, child_attrs: dict[int, Any], *, mech_param: Any
) -> tuple[int, int]:
    """Run C_DeriveKey capturing the raw RV and out-handle (never raising)."""
    tmpl = template(*pack_attrs(child_attrs))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_DeriveKey(
        rs.sh, mech_param.byref(), base, *template_ptr_count(tmpl), byref(handle)
    )
    return int(rv), int(handle.value)


def _derive_byte_child(
    rs: Any, mech_name: str, sources: list[int], child_attrs: dict[int, Any]
) -> tuple[int, int]:
    """Derive via one §6.43 row; returns (rv, child handle, 0 when refused)."""
    mech_id = _BYTE_KDF_MECH_IDS[mech_name]
    if mech_name == _BASE_AND_KEY_NAME:
        mech_param = mech_ulong(mech_id, sources[1])
    elif mech_name == _EXTRACT_NAME:
        mech_param = mech_ulong(mech_id, 0)
    else:
        mech_param = mech_string_data(mech_id, _BYTE_KDF_DATA)
    return _derive_raw(rs, mech_id, sources[0], child_attrs, mech_param=mech_param)


def _derive_hkdf_child(rs: Any, sources: list[int], child_attrs: dict[int, Any]) -> tuple[int, int]:
    """Derive via CKM_HKDF_DERIVE (the unaffected-mechanism scope control)."""
    mech_param = mech_hkdf(
        CKM_HKDF_DERIVE,
        hash_mech=CKM_SHA256,
        extract=True,
        expand=True,
        salt=b"qc2-hkdf-salt",
        info=b"qc2-hkdf-info",
    )
    return _derive_raw(rs, int(CKM_HKDF_DERIVE), sources[0], child_attrs, mech_param=mech_param)


def _verify_child_flags(
    rs: Any,
    child: int,
    *,
    label: str,
    mechanism: str,
    expected: tuple[bool, bool] | None,
    exact: bool,
) -> tuple[tuple[bool, bool] | None, Classification | None]:
    """Read an accepted child's live protection; return (flags, verdict).

    Nonterminating (S5): the observation is recorded and returned for
    the runner to raise, never raised here. ``expected=None`` (HKDF with
    no explicit request) reads and shape-checks only: HKDF has no
    inheritance floor, so omitted attributes take the token's defaults.
    Otherwise ``expected`` is the inheritance floor for byte rows —
    one-sided unless ``exact`` — or the explicit request for HKDF
    matching and downgrade (S1+S7). A weakened child fails the
    protection policy in every row family (T6): absence of a floor does
    not remove an explicit request.

    A hidden or malformed flag fails — the seal would otherwise be
    unprovable and the oracle vacuous against hiding tokens (judgment
    (c)). A defined clean read error is xfail evidence (S4); an
    undefined RV fails the RV contract (S9).
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, child, [CKA_SENSITIVE, CKA_EXTRACTABLE])
    except CkrAssertionError as exc:
        if not _is_defined_rv(exc.rv):
            return None, record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: child protection readback",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=exc.rv,
                spec_ref=_READ_SPEC,
                summary=(
                    f"{label}: child protection flags refused "
                    f"with undefined CK_RV {ckr_name(exc.rv)}"
                ),
            )
        return None, record_as(
            "not_operational",
            kind="metadata",
            label=f"{label}: child protection readback",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            spec_ref=_READ_SPEC,
            summary=(
                f"{label}: child protection flags unreadable ({ckr_name(exc.rv)}); seal unprovable"
            ),
        )
    sensitive = attr_or_record(
        attrs,
        CKA_SENSITIVE,
        label=f"{label}: child protection readback",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if sensitive is MISSING_ATTRIBUTE:
        return None, record_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: child protection seal",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=f"{label}: child SENSITIVE hidden; seal unprovable",
        )
    extractable = attr_or_record(
        attrs,
        CKA_EXTRACTABLE,
        label=f"{label}: child protection readback",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if extractable is MISSING_ATTRIBUTE:
        return None, record_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: child protection seal",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=f"{label}: child EXTRACTABLE hidden; seal unprovable",
        )
    if type(sensitive) is not bool or type(extractable) is not bool:
        return None, record_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: child protection shape",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=(
                f"{label}: child reports {sensitive!r}/{extractable!r} "
                "for SENSITIVE/EXTRACTABLE; seal unprovable"
            ),
        )
    assert type(sensitive) is bool and type(extractable) is bool
    if expected is None:
        return (sensitive, extractable), None
    expected_sensitive, expected_extractable = expected
    weakened = (expected_sensitive and not sensitive) or (not expected_extractable and extractable)
    if weakened:
        return (sensitive, extractable), record_as(
            "self_contradiction",
            kind="policy",
            label=f"{label}: child protection inheritance",
            operation="C_DeriveKey",
            mechanism=mechanism,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=(
                f"{label}: derived child weakened to "
                f"SENSITIVE={sensitive!r} EXTRACTABLE={extractable!r}"
            ),
            detail={
                "expected": {
                    "sensitive": expected_sensitive,
                    "extractable": expected_extractable,
                },
                "actual": {"sensitive": sensitive, "extractable": extractable},
            },
        )
    if (sensitive, extractable) == (expected_sensitive, expected_extractable):
        return (sensitive, extractable), None
    if not exact:
        # A strengthening token default on an omitted template is
        # conformant: only weakening fails the one-sided oracle.
        return (sensitive, extractable), None
    return (sensitive, extractable), record_as(
        "accepted_invalid",
        kind="metadata",
        label=f"{label}: child protection exactness",
        operation="C_DeriveKey",
        mechanism=mechanism,
        spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
        summary=(
            f"{label}: derived child reports "
            f"SENSITIVE={sensitive!r} EXTRACTABLE={extractable!r}, requested "
            f"SENSITIVE={expected_sensitive!r} EXTRACTABLE={expected_extractable!r}"
        ),
        detail={
            "expected": {
                "sensitive": expected_sensitive,
                "extractable": expected_extractable,
            },
            "actual": {"sensitive": sensitive, "extractable": extractable},
        },
    )


def _three_valued_and(factors: list[bool | None]) -> bool | None:
    """Conjoin three-valued factors: a false factor proves false (T5).

    ``None`` is unknown (a hidden or malformed history). A single false
    factor establishes a false conjunction despite unknown factors, so a
    component with a false factor is provable even when its siblings are
    unavailable; all-true proves true; anything else stays unknown.
    """
    if any(factor is False for factor in factors):
        return False
    if all(factor is True for factor in factors):
        return True
    return None


def _verify_child_histories(
    rs: Any,
    child: int,
    *,
    label: str,
    mechanism: str,
    child_sensitive: bool,
    child_extractable: bool,
    source_always: list[bool | None],
    source_never: list[bool | None],
) -> Classification | None:
    """Check the child's histories per provable component; return the verdict.

    Strict equality once a component's expectation is provable: a lost
    history contradicts the inheritance rule exactly as an invented one
    does. Each ALWAYS/NEVER expectation is a three-valued conjunction
    over the source histories and the child's own flags, so a false
    factor proves the expectation despite unknown factors (T5). A
    component is checked exactly when its expectation is provable and
    the child's value is observed — an unprovable component never
    discards its provable sibling (S8). Unobservable child components
    are recorded visibly (source-side gaps were already recorded at
    premise time). Nonterminating (S5): the verdict is recorded and
    returned, and an undefined read RV fails the RV contract instead of
    skipping (S9).
    """
    expected_always = _three_valued_and([*source_always, child_sensitive])
    expected_never = _three_valued_and([*source_never, not child_extractable])
    if expected_always is None and expected_never is None:
        return None
    try:
        attrs = read_attributes(rs.raw, rs.sh, child, [CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE])
    except CkrAssertionError as exc:
        if not _is_defined_rv(exc.rv):
            return record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: child history readback",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=exc.rv,
                spec_ref=_READ_SPEC,
                summary=(
                    f"{label}: child history readback refused "
                    f"with undefined CK_RV {ckr_name(exc.rv)}"
                ),
            )
        return record_as(
            "not_operational",
            kind="metadata",
            label=f"{label}: child history readback",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            spec_ref=_READ_SPEC,
            summary=f"{label}: child history readback refused; history check skipped",
        )
    always = attr_or_record(
        attrs,
        CKA_ALWAYS_SENSITIVE,
        label=f"{label}: child history readback",
        reason="honest_deviation",
        kind="metadata",
        inherit_mechanism=False,
    )
    never = attr_or_record(
        attrs,
        CKA_NEVER_EXTRACTABLE,
        label=f"{label}: child history readback",
        reason="honest_deviation",
        kind="metadata",
        inherit_mechanism=False,
    )
    omitted: list[Classification] = []
    if always is MISSING_ATTRIBUTE:
        refusal_rv = refusal_rv_for(attrs, CKA_ALWAYS_SENSITIVE)
        if refusal_rv is None:
            omitted.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: child history readback",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    spec_ref=_READ_SPEC,
                    summary=(
                        f"{label}: child ALWAYS_SENSITIVE omitted "
                        "without a refusal; history check skipped for that component"
                    ),
                )
            )
        elif not _is_defined_rv(refusal_rv):
            omitted.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: child history readback",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    expected=CKR_OK,
                    actual=refusal_rv,
                    spec_ref=_READ_SPEC,
                    summary=(
                        f"{label}: child ALWAYS_SENSITIVE refused "
                        f"with undefined CK_RV {ckr_name(refusal_rv)}"
                    ),
                )
            )
        # A defined clean refusal: the attr_or_record record above already
        # evidences the skip, so this component goes unchecked while its
        # sibling is still verified (S8). Rebind the routed sentinel so the
        # shape logic below sees a handled value.
        always = MISSING_ATTRIBUTE
    if never is MISSING_ATTRIBUTE:
        refusal_rv = refusal_rv_for(attrs, CKA_NEVER_EXTRACTABLE)
        if refusal_rv is None:
            omitted.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: child history readback",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    spec_ref=_READ_SPEC,
                    summary=(
                        f"{label}: child NEVER_EXTRACTABLE omitted "
                        "without a refusal; history check skipped for that component"
                    ),
                )
            )
        elif not _is_defined_rv(refusal_rv):
            omitted.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: child history readback",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    expected=CKR_OK,
                    actual=refusal_rv,
                    spec_ref=_READ_SPEC,
                    summary=(
                        f"{label}: child NEVER_EXTRACTABLE refused "
                        f"with undefined CK_RV {ckr_name(refusal_rv)}"
                    ),
                )
            )
        # A defined clean refusal: the attr_or_record record above already
        # evidences the skip, so this component goes unchecked while its
        # sibling is still verified (S8). Rebind the routed sentinel so the
        # shape logic below sees a handled value.
        never = MISSING_ATTRIBUTE
    child_always_ok = type(always) is bool
    child_never_ok = type(never) is bool
    malformed = [
        name
        for name, value in (
            ("ALWAYS_SENSITIVE", always),
            ("NEVER_EXTRACTABLE", never),
        )
        if value is not MISSING_ATTRIBUTE and type(value) is not bool
    ]
    shape_record: Classification | None = None
    if malformed:
        shape_record = record_as(
            "honest_deviation",
            kind="metadata",
            label=f"{label}: child history shape",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_READ_SPEC,
            summary=(
                f"{label}: child history malformed "
                f"({', '.join(malformed)}); skipping those components"
            ),
            detail={"malformed": malformed},
        )
    contradictions = [
        name
        for name, check, value, expected in (
            (
                "ALWAYS_SENSITIVE",
                expected_always is not None and child_always_ok,
                always,
                expected_always,
            ),
            (
                "NEVER_EXTRACTABLE",
                expected_never is not None and child_never_ok,
                never,
                expected_never,
            ),
        )
        if check and value is not expected
    ]
    if contradictions:
        return record_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: child history inheritance",
            operation="C_DeriveKey",
            mechanism=mechanism,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=(
                f"{label}: derived child history contradicts the source histories "
                f"({', '.join(contradictions)})"
            ),
            detail={
                "expected": {"always": expected_always, "never": expected_never},
                "actual": {
                    "always": always if child_always_ok else None,
                    "never": never if child_never_ok else None,
                },
            },
        )
    if omitted:
        # A demonstrated contradiction (above) is the stronger verdict; an
        # omission fails only when no provable component contradicted.
        return omitted[0]
    return shape_record


def _classify_value_read_rv(rv: int, *, label: str) -> Classification | None:
    """Classify a non-canonical sealed-value refusal; canonical returns None."""
    if rv == CKR_ATTRIBUTE_SENSITIVE:
        return None
    if _is_defined_rv(rv):
        return record_as(
            "nonspec_reject",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_ATTRIBUTE_SENSITIVE,
            actual=rv,
            spec_ref=_READ_SPEC,
        )
    return record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        expected=CKR_ATTRIBUTE_SENSITIVE,
        actual=rv,
        spec_ref=_READ_SPEC,
    )


def _check_child_value_refused(rs: Any, child: int, *, label: str) -> Classification | None:
    """Prove an accepted sealed child's value is unavailable (single read).

    The single-attribute form makes the refusal attribution unambiguous:
    delivered bytes fail, a refusal CKR with bytes fails, the canonical
    CKR_ATTRIBUTE_SENSITIVE passes, and any other clean refusal xfails
    with the original RV preserved. Nonterminating (S5): the verdict is
    recorded and returned.
    """
    leg = f"{label}: sealed-child value readback"
    try:
        attrs = read_attributes(rs.raw, rs.sh, child, [CKA_VALUE])
    except CkrAssertionError as exc:
        return _classify_value_read_rv(exc.rv, label=leg)
    refusal_rv = refusal_rv_for(attrs, CKA_VALUE)
    if refusal_rv is not None:
        return _classify_value_read_rv(refusal_rv, label=leg)
    # No clean refusal observed: delivered bytes, refusal-with-data, or no
    # refusal at all. attr_or_record keeps the structural record (a
    # refusal-with-data contradiction, if that is the shape) and the
    # just-emitted records below tell that shape from a plain absence:
    # refusal_rv_for deliberately hides leaked_len, so record-sniffing is
    # the documented composition, not a shortcut.
    records_before = len(get_records())
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label=leg,
        reason="honest_deviation",
        kind="metadata",
        inherit_mechanism=False,
        sensitive_is_conformant=True,
    )
    if value is MISSING_ATTRIBUTE:
        added = get_records()[records_before:]
        if any(record.reason == "self_contradiction" for record in added):
            return record_as(
                "self_contradiction",
                kind="policy",
                label=leg,
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_ATTRIBUTE_SENSITIVE,
                spec_ref=_READ_SPEC,
                summary=f"{leg}: refusal carried value bytes (see structural record)",
            )
        return record_as(
            "honest_deviation",
            kind="metadata",
            label=leg,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_ATTRIBUTE_SENSITIVE,
            actual=CKR_OK,
            spec_ref=_READ_SPEC,
            summary=f"{leg}: value unavailable but without the canonical refusal",
        )
    return record_as(
        "self_contradiction",
        kind="policy",
        label=leg,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        expected=CKR_ATTRIBUTE_SENSITIVE,
        actual=CKR_OK,
        spec_ref=_READ_SPEC,
        summary=f"{leg}: sealed child value was readable",
    )


def _check_child_value_readable(rs: Any, child: int, *, label: str) -> Classification | None:
    """Prove an accepted unsealed child's value is available (single read).

    The access check for a child whose ACTUAL protection is unsealed (S1):
    the flags promise readability, so delivered bytes pass, a semantic
    per-attribute refusal contradicts the flags, and an undefined RV
    fails the RV contract (S9). A defined whole-call operational error
    (T2) demonstrates no contradiction — the call failed before any
    protection statement, and such errors are explicitly permitted for
    C_GetAttributeValue (§5.7.5) — so it is xfail evidence with the
    original RV preserved. Nonterminating (S5): the verdict is recorded
    and returned.
    """
    leg = f"{label}: unsealed-child value readback"
    try:
        attrs = read_attributes(rs.raw, rs.sh, child, [CKA_VALUE])
    except CkrAssertionError as exc:
        if not _is_defined_rv(exc.rv):
            return record_as(
                "self_contradiction",
                kind="metadata",
                label=leg,
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=exc.rv,
                spec_ref=_READ_SPEC,
                summary=f"{leg}: refused with undefined CK_RV {ckr_name(exc.rv)}",
            )
        return record_as(
            "not_operational",
            kind="metadata",
            label=leg,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            spec_ref=_READ_SPEC,
            summary=(
                f"{leg}: unsealed child value read refused "
                f"({ckr_name(exc.rv)}); readability unprovable"
            ),
        )
    refusal_rv = refusal_rv_for(attrs, CKA_VALUE)
    if refusal_rv is not None:
        if not _is_defined_rv(refusal_rv):
            return record_as(
                "self_contradiction",
                kind="metadata",
                label=leg,
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=refusal_rv,
                spec_ref=_READ_SPEC,
                summary=f"{leg}: refused with undefined CK_RV {ckr_name(refusal_rv)}",
            )
        return record_as(
            "self_contradiction",
            kind="policy",
            label=leg,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=refusal_rv,
            spec_ref=_READ_SPEC,
            summary=(
                f"{leg}: unsealed child value refused "
                f"({ckr_name(refusal_rv)}); flags promise readability"
            ),
        )
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label=leg,
        reason="honest_deviation",
        kind="metadata",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        return record_as(
            "self_contradiction",
            kind="policy",
            label=leg,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            spec_ref=_READ_SPEC,
            summary=f"{leg}: unsealed child value unavailable; flags promise readability",
        )
    return None


def _classify_child_wrap_refusal(
    rv: int, *, child_extractable: bool, label: str
) -> Classification | None:
    """Classify a child-wrap refusal against the observed extractability.

    Clean refusals of an extractable child are xfail evidence (S3):
    CKR_KEY_NOT_WRAPPABLE explicitly permits token-specific refusal
    despite EXTRACTABLE=true (§5.18.3). Nonterminating (S5): the verdict
    is recorded and returned.
    """
    leg = f"{label}: sealed-child wrap"
    if not child_extractable and rv == CKR_KEY_UNEXTRACTABLE:
        return None
    if child_extractable:
        if _is_defined_rv(rv):
            return record_as(
                "not_operational",
                kind="policy",
                label=leg,
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                expected=CKR_OK,
                actual=rv,
                spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
                summary=(
                    f"{leg}: extractable child refused a proven-valid wrap "
                    f"({ckr_name(rv)}); wrap leg unprovable"
                ),
            )
        return record_as(
            "self_contradiction",
            kind="metadata",
            label=leg,
            operation="C_WrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            expected=CKR_OK,
            actual=rv,
            spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
            summary=f"{leg}: extractable child refused with undefined CK_RV {ckr_name(rv)}",
        )
    if _is_defined_rv(rv):
        return record_as(
            "nonspec_reject",
            kind="policy",
            label=leg,
            operation="C_WrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            expected=CKR_KEY_UNEXTRACTABLE,
            actual=rv,
            spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
        )
    return record_as(
        "self_contradiction",
        kind="metadata",
        label=leg,
        operation="C_WrapKey",
        mechanism="CKM_AES_KEY_WRAP",
        expected=CKR_KEY_UNEXTRACTABLE,
        actual=rv,
        spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
    )


def _check_child_wrap(
    rs: Any, child: int, *, child_extractable: bool, label: str
) -> Classification | None:
    """Wrap an accepted child with an independently validated setup.

    The wrapping key and mechanism first wrap an extractable control key,
    so a child refusal is attributable to the child's own protection, not
    to a broken setup. Extractable children must wrap; unextractable
    children must refuse with CKR_KEY_UNEXTRACTABLE. Nonterminating
    (S5): the verdict is recorded and returned, and an undefined setup
    RV fails the RV contract (S9).
    """
    if not rs.has_mechanism("AES_KEY_WRAP"):
        note(
            f"{label}: wrap leg skipped, CKM_AES_KEY_WRAP not advertised",
            ComplianceLevel.VENDOR,
        )
        return None
    if not rs.has_mechanism("AES_KEY_GEN"):
        note(
            f"{label}: wrap leg skipped, CKM_AES_KEY_GEN not advertised",
            ComplianceLevel.VENDOR,
        )
        return None
    try:
        wrapping_key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_WRAP: True, CKA_TOKEN: False})
    except CkrAssertionError as exc:
        if not _is_defined_rv(exc.rv):
            return record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: wrap setup (wrapping key)",
                operation="C_GenerateKey",
                mechanism="CKM_AES_KEY_GEN",
                expected=CKR_OK,
                actual=exc.rv,
                summary=(
                    f"{label}: wrapping-key setup refused with undefined CK_RV {ckr_name(exc.rv)}"
                ),
            )
        return record_as(
            "not_operational",
            label=f"{label}: wrap setup (wrapping key)",
            operation="C_GenerateKey",
            mechanism="CKM_AES_KEY_GEN",
            expected=CKR_OK,
            actual=exc.rv,
            summary=f"{label}: wrapping-key setup refused; wrap leg unprovable",
        )
    control = 0
    try:
        try:
            control = gen_generic_secret(rs, 256)
        except CkrAssertionError as exc:
            if not _is_defined_rv(exc.rv):
                return record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: wrap setup (control key)",
                    operation="C_GenerateKey",
                    mechanism="CKM_GENERIC_SECRET_KEY_GEN",
                    expected=CKR_OK,
                    actual=exc.rv,
                    summary=(
                        f"{label}: control-key setup refused "
                        f"with undefined CK_RV {ckr_name(exc.rv)}"
                    ),
                )
            return record_as(
                "not_operational",
                label=f"{label}: wrap setup (control key)",
                operation="C_GenerateKey",
                mechanism="CKM_GENERIC_SECRET_KEY_GEN",
                expected=CKR_OK,
                actual=exc.rv,
                summary=f"{label}: control-key setup refused; wrap leg unprovable",
            )
        try:
            control_wrapped = wrap_key(rs.raw, rs.sh, wrapping_key, control, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            if not _is_defined_rv(exc.rv):
                return record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: wrap setup (control wrap)",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    expected=CKR_OK,
                    actual=exc.rv,
                    spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
                    summary=(
                        f"{label}: control wrap refused with undefined CK_RV {ckr_name(exc.rv)}"
                    ),
                )
            return record_as(
                "not_operational",
                label=f"{label}: wrap setup (control wrap)",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                expected=CKR_OK,
                actual=exc.rv,
                spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
                summary=f"{label}: control wrap refused; wrap leg unprovable",
            )
        if not control_wrapped:
            return record_as(
                "not_operational",
                label=f"{label}: wrap setup (control output)",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
                summary=f"{label}: control wrap returned no bytes; wrap leg unprovable",
            )
        try:
            child_wrapped = wrap_key(rs.raw, rs.sh, wrapping_key, child, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            return _classify_child_wrap_refusal(
                exc.rv, child_extractable=child_extractable, label=label
            )
        if not child_extractable:
            return record_as(
                "self_contradiction",
                kind="policy",
                label=f"{label}: sealed-child wrap",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                expected=CKR_KEY_UNEXTRACTABLE,
                actual=CKR_OK,
                spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
                summary=f"{label}: unextractable child was wrapped",
            )
        if not child_wrapped:
            return record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: sealed-child wrap output",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                spec_ref=f"{_WRAP_SPEC} · CKM_AES_KEY_WRAP",
                summary=f"{label}: extractable-child wrap returned no bytes",
            )
        return None
    finally:
        if control:
            destroy_quietly(rs.raw, rs.sh, control)
        destroy_quietly(rs.raw, rs.sh, wrapping_key)


def _check_no_child_created(rs: Any, *, label: str, mechanism: str) -> None:
    """Prove a refused derive created no labelled object (residual noted).

    The child template always carries the unique label, so a survivor
    proves the refusal did not take effect. A token that ignores
    CKA_LABEL in derive templates would dodge this search; that residual
    gap is documented, not guessed at.
    """
    find_tmpl = template(attr_bytes(CKA_LABEL, label.encode("utf-8")))
    try:
        survivors = find_objects(rs.raw, rs.sh, find_tmpl)
    except CkrAssertionError as exc:
        _xfail_setup_refusal(
            exc.rv,
            label=f"{label}: no-object search",
            operation="C_FindObjects",
            mechanism=None,
            summary=f"{label}: label search refused; no-object effect unprovable",
        )
    if survivors:
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=f"{label}: no-object effect",
            operation="C_DeriveKey",
            mechanism=mechanism,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=f"{label}: refused derive left {len(survivors)} labelled object(s)",
            detail={"label": label, "survivor_count": len(survivors)},
        )


def _xfail_permitted_derive_refusal(rv: int, *, label: str, mechanism: str) -> NoReturn:
    """Classify a refused matching/omitted derive (a permitted operation)."""
    if _is_defined_rv(rv):
        xfail_as(
            "not_operational",
            label=f"{label}: permitted derive",
            operation="C_DeriveKey",
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=f"{label}: permitted derive refused; inheritance unprovable",
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=f"{label}: permitted derive",
        operation="C_DeriveKey",
        mechanism=mechanism,
        expected=CKR_OK,
        actual=rv,
        spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
    )


def _handle_refused_derive(rs: Any, handle: int, *, label: str, mechanism: str) -> None:
    """Prove a refused derive created no labelled object, then clean up (S6).

    The post-call inventory is observed BEFORE the returned out-handle
    is destroyed: a labelled survivor fails the lifecycle effect check
    even when the refusal RV itself is canonical. The dirty handle is
    always destroyed afterward (in ``finally``) so a failing search
    cannot leak it. Output handles are meaningless on failure, so the
    dirt itself stays a recorded hygiene deviation.
    """
    if handle != 0:
        record_as(
            "honest_deviation",
            kind="metadata",
            label=f"{label}: refused-derive out-handle",
            operation="C_DeriveKey",
            mechanism=mechanism,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=f"{label}: refused derive left a nonzero out-handle (destroyed below)",
        )
    try:
        _check_no_child_created(rs, label=label, mechanism=mechanism)
    finally:
        if handle != 0:
            destroy_quietly(rs.raw, rs.sh, handle)


def _observe_no_child_created(rs: Any, *, label: str, mechanism: str) -> Classification | None:
    """Search the derive label; return the effect verdict without raising (T3).

    The nonterminating twin of :func:`_check_no_child_created` with
    identical record shapes: a labelled survivor is a lifecycle failure,
    a refused search voids the effect (undefined search RVs fail the RV
    contract), and a clean search returns None.
    """
    leg = f"{label}: no-object search"
    find_tmpl = template(attr_bytes(CKA_LABEL, label.encode("utf-8")))
    try:
        survivors = find_objects(rs.raw, rs.sh, find_tmpl)
    except CkrAssertionError as exc:
        if not _is_defined_rv(exc.rv):
            return record_as(
                "self_contradiction",
                kind="metadata",
                label=leg,
                operation="C_FindObjects",
                mechanism=None,
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=exc.rv,
                summary=f"{leg}: refused with undefined CK_RV {ckr_name(exc.rv)}",
            )
        return record_as(
            "not_operational",
            label=leg,
            operation="C_FindObjects",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            summary=f"{label}: label search refused; no-object effect unprovable",
        )
    if survivors:
        return record_as(
            "self_contradiction",
            kind="lifecycle",
            label=f"{label}: no-object effect",
            operation="C_DeriveKey",
            mechanism=mechanism,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=f"{label}: refused derive left {len(survivors)} labelled object(s)",
            detail={"label": label, "survivor_count": len(survivors)},
        )
    return None


def _handle_refused_permitted_derive(
    rs: Any, rv: int, handle: int, *, label: str, mechanism: str
) -> NoReturn:
    """Validate a refused permitted derive without hiding either verdict (T3).

    The derive RV is recorded and validated BEFORE the no-object
    search: an undefined RV is a fail candidate that a later clean
    search refusal must not hide. The search is then collected without
    terminating, the dirty handle is always destroyed, and the
    strongest verdict is raised afterward. A defined RV with a clean
    search keeps the single not_operational record; a search finding
    (survivor or refused search) is raised on its own so the effect
    evidence keeps its existing shape.
    """
    if handle != 0:
        record_as(
            "honest_deviation",
            kind="metadata",
            label=f"{label}: refused-derive out-handle",
            operation="C_DeriveKey",
            mechanism=mechanism,
            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            summary=f"{label}: refused derive left a nonzero out-handle (destroyed below)",
        )
    try:
        derive_fail: Classification | None = None
        if not _is_defined_rv(rv):
            derive_fail = record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: permitted derive",
                operation="C_DeriveKey",
                mechanism=mechanism,
                expected=CKR_OK,
                actual=rv,
                spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
            )
        search_verdict = _observe_no_child_created(rs, label=label, mechanism=mechanism)
    finally:
        if handle != 0:
            destroy_quietly(rs.raw, rs.sh, handle)
    if derive_fail is not None:
        # A fail is always the strongest collected verdict (a search
        # xfail cannot outrank it, and a search fail ties with the
        # earlier record winning).
        raise_for_record(derive_fail)
    if search_verdict is not None:
        raise_for_record(search_verdict)
    _xfail_permitted_derive_refusal(rv, label=label, mechanism=mechanism)


def _byte_kdf_operability_key(mechanism: str, source_seals: list[str]) -> str:
    """Cache key for one mechanism + source-shape operability control."""
    return f"BYTE_KDF:{mechanism}:{','.join(source_seals)}"


def _operability_for_derive_outcome(rv: int, handle: int, *, label: str) -> OperabilityResult:
    """Map a matching-template derive outcome to operability evidence."""
    if rv == CKR_OK and handle != 0:
        return OperabilityResult(Operability.OPERATIONAL, f"{label}: matching derive accepted")
    if rv == CKR_OK:
        return OperabilityResult(
            Operability.WRONG_OUTPUT,
            f"{label}: matching derive returned CKR_OK with a zero handle",
        )
    if _is_defined_rv(rv):
        return OperabilityResult(
            Operability.NOT_OPERATIONAL, f"matching derive refused with {ckr_name(rv)}"
        )
    return OperabilityResult(
        Operability.WRONG_OUTPUT, f"matching derive returned undefined CK_RV {ckr_name(rv)}"
    )


def _observe_matching_operability(
    mechanism: str, source_seals: list[str], rv: int, handle: int, *, label: str
) -> None:
    """Publish a success-expected derive outcome as operability evidence (S10).

    Matching/omitted legs derive with a non-downgrade template, so their
    outcome answers "does this mechanism derive on this source shape"
    for free; the first observation per key wins (the probe-cache
    pattern). Downgrade derives never publish: their refusal is the
    verdict under test, not operability evidence.
    """
    probe_operability(
        _byte_kdf_operability_key(mechanism, source_seals),
        lambda: _operability_for_derive_outcome(rv, handle, label=label),
    )


def _consult_matching_operability(
    rs: Any,
    sources: list[int],
    *,
    mechanism: str,
    seal: str,
    source_seals: list[str],
    label: str,
    child_extra: dict[int, Any],
    derive: Callable[[list[int], dict[int, Any]], tuple[int, int]],
) -> None:
    """Route a canonical downgrade refusal through the operability control (S10).

    On a cache miss the control is established inline — a
    matching-template derive on the same sources — so downgrade nodes
    selected alone still get vacuous-rejection protection; a cache hit
    (matching ran first in this process) reuses it without an extra
    derive. Only a NOT_OPERATIONAL control downgrades the pass to a
    vacuous xfail — OPERATIONAL/WRONG_OUTPUT leave the genuine pass
    standing, since the refusal was then actually evaluated.
    """
    key = _byte_kdf_operability_key(mechanism, source_seals)

    def _probe() -> OperabilityResult:
        probe_label = f"{label}:operability"
        probe_attrs: dict[int, Any] = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_TOKEN: False,
            CKA_LABEL: probe_label,
            **child_extra,
            **_child_mode_attrs(seal, "matching"),
        }
        probe_rv, probe_handle = derive(sources, probe_attrs)
        if probe_rv != CKR_OK:
            # A refused control proves its no-object effect before its
            # handle is destroyed (T4): only an effect-free refusal
            # supplies NOT_OPERATIONAL evidence, while a labelled
            # survivor fails the lifecycle check exactly as on the
            # primary path.
            _handle_refused_derive(rs, probe_handle, label=probe_label, mechanism=mechanism)
            return _operability_for_derive_outcome(probe_rv, probe_handle, label=label)
        try:
            return _operability_for_derive_outcome(probe_rv, probe_handle, label=label)
        finally:
            if probe_handle:
                destroy_quietly(rs.raw, rs.sh, probe_handle)

    result = probe_operability(key, _probe)
    xfail_vacuous_reject(result, label=f"{label}: downgrade refusal")


def _raise_strongest_terminal(verdicts: list[Classification]) -> None:
    """Raise the strongest collected verdict: first fail, else first xfail (S5).

    Returns normally when every check passed. History-skip observations
    never reach this list (the history check keeps them ledger-only by
    design); only history CONTRADICTIONS (fail) are terminal.
    """
    for verdict in verdicts:
        if verdict.outcome == "fail":
            raise_for_record(verdict)
    for verdict in verdicts:
        if verdict.outcome == "xfail":
            raise_for_record(verdict)


def _record_accepted_downgrade_fallback(*, label: str, mechanism: str, note: str) -> Classification:
    """Record the template-contract failure for an accepted downgrade (S5).

    Acceptance of the forbidden template is established by the CKR_OK
    derive itself, independently of any later readback; ``note`` states
    what the success legs established about the child (or that they
    could not run).
    """
    return record_as(
        "accepted_invalid",
        kind="metadata",
        label=f"{label}: downgrade derive acceptance",
        operation="C_DeriveKey",
        mechanism=mechanism,
        expected=CKR_TEMPLATE_INCONSISTENT,
        actual=CKR_OK,
        spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
        summary=f"{label}: downgrade request accepted ({note})",
    )


def _run_success_checks(
    rs: Any,
    child: int,
    *,
    label: str,
    mechanism: str,
    premises: list[_SourcePremise],
    expected: tuple[bool, bool] | None,
    exact: bool,
    fallback_accepted_invalid: bool,
    check_wrap: bool,
) -> None:
    """Run the success-path legs, collecting observations, raising strongest (S5).

    Flags, histories, value access and wrap are independent observations:
    each is recorded and the strongest terminal verdict is raised at the
    end, so an early xfail (or fail) never hides a later defect. The
    value leg follows the child's ACTUAL protection (sealed means
    refused, unsealed means readable). Accepted downgrade children run
    every leg BEFORE the fallback template-contract failure is emitted.
    """
    terminal: list[Classification] = []
    flags, flags_verdict = _verify_child_flags(
        rs, child, label=label, mechanism=mechanism, expected=expected, exact=exact
    )
    if flags_verdict is not None:
        terminal.append(flags_verdict)
    if flags is None:
        # The seal is unprovable: every remaining leg depends on the
        # observed flags, so none can run — but the acceptance itself is
        # already established, so the fallback is still emitted (T1) and
        # the strongest collected verdict explains the outcome.
        if fallback_accepted_invalid:
            terminal.append(
                _record_accepted_downgrade_fallback(
                    label=label, mechanism=mechanism, note="child protection unreadable"
                )
            )
        _raise_strongest_terminal(terminal)
        return
    observed_sensitive, observed_extractable = flags
    history_verdict = _verify_child_histories(
        rs,
        child,
        label=label,
        mechanism=mechanism,
        child_sensitive=observed_sensitive,
        child_extractable=observed_extractable,
        source_always=[premise.always for premise in premises],
        source_never=[premise.never for premise in premises],
    )
    if history_verdict is not None and history_verdict.outcome == "fail":
        terminal.append(history_verdict)
    if observed_sensitive or not observed_extractable:
        value_verdict = _check_child_value_refused(rs, child, label=label)
    else:
        value_verdict = _check_child_value_readable(rs, child, label=label)
    if value_verdict is not None:
        terminal.append(value_verdict)
    if check_wrap:
        wrap_verdict = _check_child_wrap(
            rs, child, child_extractable=observed_extractable, label=label
        )
        if wrap_verdict is not None:
            terminal.append(wrap_verdict)
    if fallback_accepted_invalid:
        terminal.append(
            _record_accepted_downgrade_fallback(
                label=label, mechanism=mechanism, note="child sealed defensively"
            )
        )
    _raise_strongest_terminal(terminal)


def _run_protection_case(
    rs: Any,
    *,
    mechanism: str,
    mode: str,
    seal: str,
    source_seals: list[str],
    label: str,
    child_extra: dict[int, Any],
    check_wrap: bool,
    hkdf: bool = False,
    derive: Callable[[list[int], dict[int, Any]], tuple[int, int]],
) -> None:
    """Run one seal × child-template cell against any derive function.

    Sources are generated sealed, their protection is read back as the
    premise, and the byte-row expectation is computed from the OBSERVED
    sources: sensitive when any source is sensitive, unextractable when
    any source is unextractable, histories AND-combined. Byte-row
    downgrade legs require CKR_TEMPLATE_INCONSISTENT plus no created
    object (routed through the matching operability control, S10);
    success legs collect the flag, history, readback and (unless the
    child is too short for AES key wrap) wrap observations and raise
    the strongest verdict (S5). HKDF legs (S1, ``hkdf=True``) have no
    inheritance floor: downgrade requests are permitted, explicit
    (matching and downgrade) requests are verified exactly, and
    histories and access follow the child's ACTUAL protection.
    """
    if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
        pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")
    sources: list[int] = []
    try:
        for source_seal in source_seals:
            try:
                sources.append(
                    gen_generic_secret(
                        rs,
                        _SOURCE_BITS,
                        extra_attrs={
                            CKA_DERIVE: True,
                            **_seal_attrs(source_seal),
                        },
                    )
                )
            except CkrAssertionError as exc:
                _xfail_setup_refusal(
                    exc.rv,
                    label=f"{label}: sealed-source setup ({source_seal})",
                    operation="C_GenerateKey",
                    mechanism="CKM_GENERIC_SECRET_KEY_GEN",
                    summary=f"{label}: sealed-source setup refused; premise unprovable",
                )
        premises = [
            _read_source_premise(rs, handle, seal=source_seal, label=label, mechanism=mechanism)
            for handle, source_seal in zip(sources, source_seals, strict=True)
        ]
        expected_sensitive = any(premise.sensitive for premise in premises)
        expected_extractable = all(premise.extractable for premise in premises)
        child_attrs: dict[int, Any] = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_TOKEN: False,
            CKA_LABEL: label,
            **child_extra,
            **_child_mode_attrs(seal, mode),
        }
        child = 0
        try:
            rv, handle = derive(sources, child_attrs)
            if mode == "downgrade" and not hkdf:
                if rv == CKR_OK:
                    if handle == 0:
                        fail_as(
                            "self_contradiction",
                            kind="lifecycle",
                            label=f"{label}: downgrade derive handle",
                            operation="C_DeriveKey",
                            mechanism=mechanism,
                            spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
                            summary=f"{label}: downgrade derive returned CKR_OK with a zero handle",
                        )
                    child = handle
                    # Accepted despite the downgrade request: run every
                    # success leg against the inherited floor BEFORE the
                    # fallback template-contract failure (S5), so a
                    # weakened child fails policy and a sealed one fails
                    # accepted_invalid — with full evidence either way.
                    _run_success_checks(
                        rs,
                        child,
                        label=label,
                        mechanism=mechanism,
                        premises=premises,
                        expected=(expected_sensitive, expected_extractable),
                        exact=False,
                        fallback_accepted_invalid=True,
                        check_wrap=check_wrap,
                    )
                    return
                _handle_refused_derive(rs, handle, label=label, mechanism=mechanism)
                if rv == CKR_TEMPLATE_INCOMPLETE:
                    # The refusal does not answer the downgrade question:
                    # the template was incomplete, so the downgrade
                    # premise itself is unprovable (S2).
                    xfail_as(
                        "not_operational",
                        label=f"{label}: downgrade refusal",
                        operation="C_DeriveKey",
                        mechanism=mechanism,
                        expected=CKR_TEMPLATE_INCONSISTENT,
                        actual=rv,
                        spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
                        summary=(
                            f"{label}: downgrade template refused as incomplete; "
                            "downgrade premise unprovable"
                        ),
                    )
                classify_negative_rv(
                    rv,
                    (CKR_TEMPLATE_INCONSISTENT,),
                    label=f"{label}: downgrade refusal",
                    kind="policy",
                )
                _consult_matching_operability(
                    rs,
                    sources,
                    mechanism=mechanism,
                    seal=seal,
                    source_seals=source_seals,
                    label=label,
                    child_extra=child_extra,
                    derive=derive,
                )
                return
            # Success-expected legs: matching/omitted for every row, plus
            # HKDF downgrades (a permitted request under §6.62.3, S1).
            _observe_matching_operability(mechanism, source_seals, rv, handle, label=label)
            if rv != CKR_OK:
                _handle_refused_permitted_derive(rs, rv, handle, label=label, mechanism=mechanism)
            if handle == 0:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label=f"{label}: derive handle",
                    operation="C_DeriveKey",
                    mechanism=mechanism,
                    spec_ref=f"{_DERIVE_SPEC} · {mechanism}",
                    summary=f"{label}: CKR_OK derive returned a zero handle",
                )
            child = handle
            if hkdf:
                if mode == "omitted":
                    child_expected = None
                    child_exact = False
                else:
                    # Matching and downgrade both state an explicit
                    # request; HKDF honors it exactly (S1+S7).
                    requested = _child_mode_attrs(seal, mode)
                    child_expected = (
                        requested[CKA_SENSITIVE],
                        requested[CKA_EXTRACTABLE],
                    )
                    child_exact = True
            else:
                child_expected = (expected_sensitive, expected_extractable)
                child_exact = mode == "matching"
            _run_success_checks(
                rs,
                child,
                label=label,
                mechanism=mechanism,
                premises=premises,
                expected=child_expected,
                exact=child_exact,
                fallback_accepted_invalid=False,
                check_wrap=check_wrap,
            )
        finally:
            if child:
                destroy_quietly(rs.raw, rs.sh, child)
    finally:
        for source in sources:
            destroy_quietly(rs.raw, rs.sh, source)


class TestByteKdfInheritance:
    """QC2: §6.43 protection inheritance across the seal × template matrix."""

    @pytest.mark.parametrize("mode", _BYTE_KDF_MODES)
    @pytest.mark.parametrize("seal", _BYTE_KDF_SEALS)
    @pytest.mark.parametrize("mech_name", _BYTE_KDF_SINGLE_SOURCE_MECHS)
    def test_inheritance_single_source(
        self, p11_raw_session: Any, mech_name: str, seal: str, mode: str
    ) -> None:
        """One source key feeds the rule; data/offset params are public."""
        rs = p11_raw_session
        short = mech_name.removeprefix("CKM_")
        if not rs.has_mechanism(short):
            pytest.skip(f"{mech_name} not supported")
        child_extra: dict[int, Any] = {CKA_VALUE_LEN: _BYTE_KDF_CHILD_LENS[mech_name]}
        _run_protection_case(
            rs,
            mechanism=mech_name,
            mode=mode,
            seal=seal,
            source_seals=[seal],
            label=f"qc2-{_LABEL_TAGS[mech_name]}-{seal}-{mode}",
            child_extra=child_extra,
            check_wrap=True,
            derive=lambda sources, attrs: _derive_byte_child(rs, mech_name, sources, attrs),
        )

    @pytest.mark.parametrize("placement", _BYTE_KDF_PLACEMENTS)
    @pytest.mark.parametrize("mode", _BYTE_KDF_MODES)
    @pytest.mark.parametrize("seal", _BYTE_KDF_SEALS)
    def test_inheritance_base_and_key(
        self, p11_raw_session: Any, seal: str, mode: str, placement: str
    ) -> None:
        """Both base and aux keys feed the two-key rule (each placement)."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_KEY"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_KEY not supported")
        if placement == "base":
            source_seals = [seal, "unsealed"]
        elif placement == "aux":
            source_seals = ["unsealed", seal]
        elif placement == "both":
            source_seals = [seal, seal]
        else:
            raise ValueError(f"unknown seal placement: {placement!r}")
        _run_protection_case(
            rs,
            mechanism=_BASE_AND_KEY_NAME,
            mode=mode,
            seal=seal,
            source_seals=source_seals,
            label=f"qc2-bak-{seal}-{mode}-{placement}",
            child_extra={CKA_VALUE_LEN: _BYTE_KDF_CHILD_LENS[_BASE_AND_KEY_NAME]},
            check_wrap=True,
            derive=lambda sources, attrs: _derive_byte_child(
                rs, _BASE_AND_KEY_NAME, sources, attrs
            ),
        )


class TestByteKdfShortChild:
    """QC2: permitted short children keep inheritance (recovery is QC12b)."""

    def test_extract_single_byte_sealed_base_keeps_protection(self, p11_raw_session: Any) -> None:
        """A permitted 1-byte child of a sealed base stays sealed.

        QC12b boundary (Task 23, the #54.3 recovery half): a sealed
        1-byte child still has only 256 possible values, so inheritance
        compliance here does NOT establish resistance to a composed
        recovery attack (DigestKey/HMAC over the 256 candidates). No
        recovery oracle is built in this module by design.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")
        # No wrap leg: a 1-byte child is below any AES key-wrap minimum.
        _run_protection_case(
            rs,
            mechanism=_EXTRACT_NAME,
            mode="matching",
            seal="both",
            source_seals=["both"],
            label="qc2-ext-both-1byte",
            child_extra={CKA_VALUE_LEN: _SHORT_CHILD_LEN},
            check_wrap=False,
            derive=lambda sources, attrs: _derive_byte_child(rs, _EXTRACT_NAME, sources, attrs),
        )

    def test_extract_single_byte_unsealed_control(self, p11_raw_session: Any) -> None:
        """Unsealed 1-byte extraction succeeds with the exact byte (KAT).

        Positive control proving short lengths are permitted: blanket
        refusal would contradict the permitted §6.43 lengths.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")
        label = "qc2-ext-open-1byte"
        base_bytes = bytes(range(32))
        try:
            base = import_secret_key_negotiated(
                rs,
                CKK_GENERIC_SECRET,
                base_bytes,
                attrs={
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                },
            )
        except CkrAssertionError as exc:
            _xfail_setup_refusal(
                exc.rv,
                label=f"{label}: unsealed base import",
                operation="C_CreateObject",
                mechanism=None,
                summary=f"{label}: unsealed base import refused; control unprovable",
            )
        derived = 0
        try:
            rv, handle = _derive_byte_child(
                rs,
                _EXTRACT_NAME,
                [base],
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_TOKEN: False,
                    CKA_LABEL: label,
                    CKA_VALUE_LEN: _SHORT_CHILD_LEN,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
            if rv != CKR_OK:
                _handle_refused_permitted_derive(
                    rs, rv, handle, label=label, mechanism=_EXTRACT_NAME
                )
            if handle == 0:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label=f"{label}: derive handle",
                    operation="C_DeriveKey",
                    mechanism=_EXTRACT_NAME,
                    spec_ref=f"{_DERIVE_SPEC} · {_EXTRACT_NAME}",
                    summary=f"{label}: CKR_OK derive returned a zero handle",
                )
            derived = handle
            try:
                value = _read_attr_or_record(
                    rs.raw,
                    rs.sh,
                    derived,
                    CKA_VALUE,
                    label=f"{label}:CKA_VALUE readback",
                )
            except CkrAssertionError as exc:
                if _is_defined_rv(exc.rv):
                    xfail_as(
                        "not_operational",
                        label=f"{label}:CKA_VALUE readback",
                        operation="C_GetAttributeValue",
                        mechanism=None,
                        inherit_mechanism=False,
                        expected=CKR_OK,
                        actual=exc.rv,
                        spec_ref=_READ_SPEC,
                        summary=f"{label}: unsealed child readback refused; control unprovable",
                    )
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}:CKA_VALUE readback",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    expected=CKR_OK,
                    actual=exc.rv,
                    spec_ref=_READ_SPEC,
                )
            if value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=value,
                expected=base_bytes[:_SHORT_CHILD_LEN],
                label=f"{label}:C_DeriveKey KAT (1-byte extract)",
                operation="C_DeriveKey",
                mechanism=_EXTRACT_NAME,
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base)


class TestHkdfInheritanceScope:
    """QC2: HKDF from a sealed base under its own oracle (S1).

    §6.62.3 lets the caller select the HKDF child's SENSITIVE/EXTRACTABLE
    independently: there is no inheritance floor, so a permitted unsealed
    child passes and histories and access follow the child's ACTUAL
    protection. Downgrade requests are permitted (a refusal xfails as an
    unproven permitted operation); explicit matching and downgrade
    requests are verified exactly against the request.
    """

    @pytest.mark.parametrize("mode", _BYTE_KDF_MODES)
    def test_hkdf_sealed_base(self, p11_raw_session: Any, mode: str) -> None:
        """HKDF honors the requested child protection; no byte-rule floor."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")
        _run_protection_case(
            rs,
            mechanism=_HKDF_DERIVE_NAME,
            mode=mode,
            seal="both",
            source_seals=["both"],
            label=f"qc2-hkdf-both-{mode}",
            child_extra={CKA_VALUE_LEN: _HKDF_CHILD_LEN},
            check_wrap=True,
            hkdf=True,
            derive=lambda sources, attrs: _derive_hkdf_child(rs, sources, attrs),
        )


# ---------------------------------------------------------------------------
# QC8c: DES-family parity on byte-operation / SHA-1 derives (#61.3)
#
# Appended after the QC2 block; the QC2 tables and helpers above are
# read-only here and no QC2 verdict changes. Parity is asserted only
# where a sentence is pinned: the five §6.43 byte mechanisms and
# CKM_SHA1_KEY_DERIVATION without DES3. Bases are unsealed and known, so
# expected bytes come from Python, never from a provider twin (the
# generic-secret twin is a control that must stay unadjusted).
# ---------------------------------------------------------------------------

_DES_PARITY_MECH_NAMES: tuple[str, ...] = tuple(_BYTE_KDF_MECH_IDS)
_DES_PARITY_TYPE_NAMES: tuple[str, ...] = ("DES", "DES3", "DES2", "CDMF")
_DES_PARITY_TYPES: dict[str, tuple[int, int]] = {
    "DES": (int(CKK_DES), 8),
    "DES2": (int(CKK_DES2), 16),
    "DES3": (int(CKK_DES3), 24),
    "CDMF": (int(CKK_CDMF), 8),
}
_DES_PARITY_SHA1_TYPES: tuple[str, ...] = ("DES",)
_SHA1_DERIVATION_NAME = "CKM_SHA1_KEY_DERIVATION"
_KAT_BLOCK = bytes.fromhex("0123456789abcdef")


def _odd_parity_adjust(raw: bytes) -> bytes:
    """Force every byte to odd parity by flipping the LSB where needed."""
    return bytes(b if b.bit_count() % 2 == 1 else b ^ 0x01 for b in raw)


def _parity_pattern(length: int, start: int, step: int = 1) -> bytes:
    return bytes((start + i * step) % 256 for i in range(length))


def _des_parity_materials(mech_name: str, out_len: int) -> tuple[bytes, bytes, bytes]:
    """Return (base, aux-or-data, raw expected) sized to exactly ``out_len``."""
    if mech_name == _EXTRACT_NAME:
        base = _parity_pattern(32, 0x10)
        return base, b"", base[:out_len]
    if mech_name == "CKM_XOR_BASE_AND_DATA":
        base = _parity_pattern(out_len, 0x10)
        data = _parity_pattern(out_len, 0x40, step=3)
        return base, data, bytes(a ^ b for a, b in zip(base, data, strict=True))
    base_len = out_len // 2 + 1
    base = _parity_pattern(base_len, 0x10)
    aux = _parity_pattern(out_len - base_len, 0x40, step=3)
    if mech_name == _BASE_AND_KEY_NAME:
        return base, aux, base + aux
    if mech_name == "CKM_CONCATENATE_BASE_AND_DATA":
        return base, aux, base + aux
    if mech_name == "CKM_CONCATENATE_DATA_AND_BASE":
        return base, aux, aux + base
    raise ValueError(f"not a DES-parity byte mechanism: {mech_name!r}")


def _require_even_parity_premise(raw: bytes, *, label: str) -> None:
    """Fail as harness error when a row cannot expose missing adjustment."""
    if any(b.bit_count() % 2 == 0 for b in raw):
        return
    fail_as(
        "harness_error",
        label=label,
        operation="C_DeriveKey",
        inherit_mechanism=False,
        summary=f"{label}: raw expected bytes are already all odd parity; row proves nothing",
    )


def _des_parity_mech_param(mech_name: str, sources: list[int], aux: bytes) -> Any:
    mech_id = _BYTE_KDF_MECH_IDS[mech_name]
    if mech_name == _BASE_AND_KEY_NAME:
        return mech_ulong(mech_id, sources[1])
    if mech_name == _EXTRACT_NAME:
        return mech_ulong(mech_id, 0)
    return mech_string_data(mech_id, aux)


def _import_parity_source(rs: Any, value: bytes, *, label: str, mech_name: str) -> int:
    try:
        return _import_generic_secret(rs, value)
    except CkrAssertionError as exc:
        _xfail_setup_refusal(
            exc.rv,
            label=f"{label}: unsealed source import",
            operation="C_CreateObject",
            mechanism=None,
            summary=f"{label}: unsealed source import refused for {mech_name}; row unprovable",
        )


def _derive_parity_child(
    rs: Any,
    *,
    mech_name: str,
    mech_id: int,
    base: int,
    mech_param: Any,
    child_attrs: dict[int, Any],
    label: str,
) -> int:
    rv, handle = _derive_raw(rs, mech_id, base, child_attrs, mech_param=mech_param)
    if rv != int(CKR_OK):
        _xfail_setup_refusal(
            rv,
            label=label,
            operation="C_DeriveKey",
            mechanism=mech_name,
            spec_ref=_DERIVE_SPEC,
            summary=f"{label}: advertised derive refused cleanly ({ckr_name(rv)})",
        )
    if handle == 0:
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation="C_DeriveKey",
            mechanism=mech_name,
            spec_ref=_DERIVE_SPEC,
            summary=f"{label}: CKR_OK derive returned a zero handle",
        )
    return handle


def _read_derived_value(rs: Any, handle: int, *, label: str) -> bytes:
    try:
        value = _read_attr_or_record(rs.raw, rs.sh, handle, CKA_VALUE, label=label)
    except CkrAssertionError as exc:
        _xfail_setup_refusal(
            exc.rv,
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            spec_ref=_READ_SPEC,
            summary=f"{label}: derived value readback refused; format unprovable",
        )
    if value is MISSING_ATTRIBUTE:
        for record in get_records():
            if record.label == label:
                raise_for_record(record)
        xfail_as(
            "not_operational",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: derived CKA_VALUE unavailable",
        )
    if not isinstance(value, bytes):
        classify(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            expected="bytes",
            actual=type(value).__name__,
            summary=f"{label}: provider returned a non-byte CKA_VALUE",
        )
    return bytes(value)


def _assert_des_ecb_kat(
    rs: Any, handle: int, *, adjusted: bytes, type_name: str, label: str
) -> None:
    """Functional KAT: provider ECB on a fixed block vs the TripleDES oracle.

    DES ignores parity bits, so this proves material/operability only;
    the byte check in ``_assert_des_child_value`` is the parity detector.
    CDMF has no ECB mechanism here, so its rows stop at byte equality.
    """
    if type_name == "DES":
        ecb_id, ecb_name, short = int(CKM_DES_ECB), "CKM_DES_ECB", "DES_ECB"
    elif type_name in ("DES3", "DES2"):
        ecb_id, ecb_name, short = int(CKM_DES3_ECB), "CKM_DES3_ECB", "DES3_ECB"
    else:
        return
    if not rs.has_mechanism(short):
        return
    mech = mech_simple(ecb_id)
    rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), handle)
    if rv != int(CKR_OK):
        _xfail_setup_refusal(
            int(rv),
            label=f"{label}: ECB KAT init",
            operation="C_EncryptInit",
            mechanism=ecb_name,
            summary=f"{label}: ECB KAT init refused ({ckr_name(int(rv))})",
        )
    in_buf = (ctypes.c_ubyte * len(_KAT_BLOCK)).from_buffer_copy(_KAT_BLOCK)
    out_buf = (ctypes.c_ubyte * len(_KAT_BLOCK))()
    out_len = CK_ULONG(len(_KAT_BLOCK))
    rv = rs.raw.C_Encrypt(rs.sh, in_buf, len(_KAT_BLOCK), out_buf, byref(out_len))
    if rv != int(CKR_OK):
        _xfail_setup_refusal(
            int(rv),
            label=f"{label}: ECB KAT encrypt",
            operation="C_Encrypt",
            mechanism=ecb_name,
            summary=f"{label}: ECB KAT encrypt refused ({ckr_name(int(rv))})",
        )
    if int(out_len.value) != len(_KAT_BLOCK):
        classify(
            "wrong_result",
            kind="metadata",
            label=f"{label}: ECB KAT output length",
            operation="C_Encrypt",
            mechanism=ecb_name,
            expected=len(_KAT_BLOCK),
            actual=int(out_len.value),
            summary=f"{label}: ECB KAT produced {int(out_len.value)} bytes",
        )
    from cryptography.hazmat.decrepit.ciphers import algorithms
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    effective = (
        adjusted * 3
        if len(adjusted) == 8
        else adjusted + adjusted[:8]
        if len(adjusted) == 16
        else adjusted
    )
    encryptor = Cipher(algorithms.TripleDES(effective), modes.ECB()).encryptor()  # nosec B305
    expected = encryptor.update(_KAT_BLOCK) + encryptor.finalize()
    assert_correct(
        actual=bytes(out_buf[: int(out_len.value)]),
        expected=expected,
        label=f"{label}:ECB KAT",
        operation="C_Encrypt",
        mechanism=ecb_name,
    )


def _assert_des_child_value(
    rs: Any,
    handle: int,
    *,
    mech_name: str,
    type_name: str,
    out_len: int,
    raw_expected: bytes,
) -> None:
    value = _read_derived_value(rs, handle, label=f"{mech_name}->{type_name}:CKA_VALUE readback")
    _assert_misc_bytes_length(
        value,
        expected_len=out_len,
        label=f"{mech_name}->{type_name}:derived DES value length",
        mechanism=mech_name,
    )
    even_positions = [i for i, b in enumerate(value) if b.bit_count() % 2 == 0]
    if even_positions:
        classify(
            "wrong_result",
            kind="crypto",
            label=f"{mech_name}->{type_name}:derived DES parity",
            operation="C_DeriveKey",
            mechanism=mech_name,
            summary=(
                f"{mech_name}->{type_name}: derived key bytes at positions "
                f"{even_positions} have even parity; adjustment missing"
            ),
            detail={"even_positions": even_positions},
        )
    adjusted = _odd_parity_adjust(raw_expected)
    assert_correct(
        actual=value,
        expected=adjusted,
        label=f"{mech_name}->{type_name}:derived DES value",
        operation="C_DeriveKey",
        mechanism=mech_name,
    )
    _assert_des_ecb_kat(
        rs, handle, adjusted=adjusted, type_name=type_name, label=f"{mech_name}->{type_name}"
    )


def _assert_generic_child_value(
    rs: Any, handle: int, *, mech_name: str, raw_expected: bytes
) -> None:
    value = _read_derived_value(rs, handle, label=f"{mech_name}->generic:CKA_VALUE readback")
    _assert_misc_bytes_length(
        value,
        expected_len=len(raw_expected),
        label=f"{mech_name}->generic:derived value length",
        mechanism=mech_name,
    )
    assert_correct(
        actual=value,
        expected=raw_expected,
        label=f"{mech_name}:generic-secret twin value",
        operation="C_DeriveKey",
        mechanism=mech_name,
    )


def _des_child_attrs(key_type: int, out_len: int) -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: out_len,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
    }


def _generic_child_attrs(out_len: int) -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: out_len,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
    }


class TestDerivedDesParity:
    """QC8c: DES-family output bytes of byte/SHA-1 derives are parity-adjusted."""

    @pytest.mark.parametrize("type_name", _DES_PARITY_TYPE_NAMES)
    @pytest.mark.parametrize("mech_name", _DES_PARITY_MECH_NAMES)
    def test_byte_derive_des_parity(
        self, p11_raw_session: Any, mech_name: str, type_name: str
    ) -> None:
        """Byte-derive to DES-family: odd parity, adjusted bytes, ECB KAT.

        DES2/CDMF are admission-gated rows of the same table: a clean
        template/mechanism refusal xfails visibly instead of skipping.
        """
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name.removeprefix("CKM_")):
            pytest.skip(f"{mech_name} not supported")
        key_type, out_len = _DES_PARITY_TYPES[type_name]
        label = f"qc8c-{mech_name}->{type_name}"
        base_bytes, aux_bytes, raw_expected = _des_parity_materials(mech_name, out_len)
        assert len(raw_expected) == out_len
        _require_even_parity_premise(raw_expected, label=label)
        sources: list[int] = []
        children: list[int] = []
        try:
            sources.append(_import_parity_source(rs, base_bytes, label=label, mech_name=mech_name))
            if mech_name == _BASE_AND_KEY_NAME:
                sources.append(
                    _import_parity_source(rs, aux_bytes, label=label, mech_name=mech_name)
                )
            child = _derive_parity_child(
                rs,
                mech_name=mech_name,
                mech_id=_BYTE_KDF_MECH_IDS[mech_name],
                base=sources[0],
                mech_param=_des_parity_mech_param(mech_name, sources, aux_bytes),
                child_attrs=_des_child_attrs(key_type, out_len),
                label=f"{label}: DES-family derive",
            )
            children.append(child)
            _assert_des_child_value(
                rs,
                child,
                mech_name=mech_name,
                type_name=type_name,
                out_len=out_len,
                raw_expected=raw_expected,
            )
            twin = _derive_parity_child(
                rs,
                mech_name=mech_name,
                mech_id=_BYTE_KDF_MECH_IDS[mech_name],
                base=sources[0],
                mech_param=_des_parity_mech_param(mech_name, sources, aux_bytes),
                child_attrs=_generic_child_attrs(out_len),
                label=f"{label}: generic-secret twin derive",
            )
            children.append(twin)
            _assert_generic_child_value(rs, twin, mech_name=mech_name, raw_expected=raw_expected)
        finally:
            for handle in children:
                destroy_quietly(rs.raw, rs.sh, handle)
            for handle in sources:
                destroy_quietly(rs.raw, rs.sh, handle)

    def test_sha1_derive_des_parity(self, p11_raw_session: Any) -> None:
        """SHA-1 derive to DES only: DES3 is excluded, never asserted."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA1_KEY_DERIVATION"):
            pytest.skip("CKM_SHA1_KEY_DERIVATION not supported")
        label = "qc8c-CKM_SHA1_KEY_DERIVATION"
        base_bytes = _parity_pattern(20, 0x20)
        digest = hashlib.sha1(base_bytes, usedforsecurity=False).digest()
        sources: list[int] = []
        children: list[int] = []
        try:
            sources.append(
                _import_parity_source(rs, base_bytes, label=label, mech_name=_SHA1_DERIVATION_NAME)
            )
            for type_name in _DES_PARITY_SHA1_TYPES:
                key_type, out_len = _DES_PARITY_TYPES[type_name]
                raw_expected = digest[:out_len]
                _require_even_parity_premise(raw_expected, label=f"{label}->{type_name}")
                child = _derive_parity_child(
                    rs,
                    mech_name=_SHA1_DERIVATION_NAME,
                    mech_id=int(CKM_SHA1_KEY_DERIVATION),
                    base=sources[0],
                    mech_param=mech_simple(CKM_SHA1_KEY_DERIVATION),
                    child_attrs=_des_child_attrs(key_type, out_len),
                    label=f"{label}->{type_name}: derive",
                )
                children.append(child)
                _assert_des_child_value(
                    rs,
                    child,
                    mech_name=_SHA1_DERIVATION_NAME,
                    type_name=type_name,
                    out_len=out_len,
                    raw_expected=raw_expected,
                )
                twin = _derive_parity_child(
                    rs,
                    mech_name=_SHA1_DERIVATION_NAME,
                    mech_id=int(CKM_SHA1_KEY_DERIVATION),
                    base=sources[0],
                    mech_param=mech_simple(CKM_SHA1_KEY_DERIVATION),
                    child_attrs=_generic_child_attrs(out_len),
                    label=f"{label}->generic: twin derive",
                )
                children.append(twin)
                _assert_generic_child_value(
                    rs, twin, mech_name=_SHA1_DERIVATION_NAME, raw_expected=raw_expected
                )
        finally:
            for handle in children:
                destroy_quietly(rs.raw, rs.sh, handle)
            for handle in sources:
                destroy_quietly(rs.raw, rs.sh, handle)
