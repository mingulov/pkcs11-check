"""Miscellaneous simple key derivation mechanism tests.

Covers CKM_CONCATENATE_BASE_AND_KEY, CKM_CONCATENATE_BASE_AND_DATA,
CKM_CONCATENATE_DATA_AND_BASE, CKM_XOR_BASE_AND_DATA, and
CKM_EXTRACT_KEY_FROM_KEY.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_string_data, mech_ulong
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_DATA_AND_BASE,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_XOR_BASE_AND_DATA,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    import_secret_key_negotiated,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

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
            derived_value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 32
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
            derived_value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            val_a = read_attributes(rs.raw, rs.sh, derived_a, [CKA_VALUE])[CKA_VALUE]
            val_b = read_attributes(rs.raw, rs.sh, derived_b, [CKA_VALUE])[CKA_VALUE]
            assert val_a != val_b
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
            derived_value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            val_bd = read_attributes(rs.raw, rs.sh, derived_bd, [CKA_VALUE])[CKA_VALUE]
            val_db = read_attributes(rs.raw, rs.sh, derived_db, [CKA_VALUE])[CKA_VALUE]
            assert val_bd != val_db
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
            derived_value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            derived_value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            derived_value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            val_a = read_attributes(rs.raw, rs.sh, derived_a, [CKA_VALUE])[CKA_VALUE]
            val_b = read_attributes(rs.raw, rs.sh, derived_b, [CKA_VALUE])[CKA_VALUE]
            assert val_a != val_b
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_EXTRACT_KEY_FROM_KEY derive failed")
        finally:
            for h in (derived_a, derived_b):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)
            destroy_quietly(rs.raw, rs.sh, base)
