"""Tests for AES key derivation by data encryption.

Covers CKM_AES_ECB_ENCRYPT_DATA and CKM_AES_CBC_ENCRYPT_DATA - mechanisms
that derive new keys by encrypting supplied data with a base key.

OASIS PKCS#11 v3.2 spec: AES/DES key derivation by data encryption.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.pack import mech_string_data
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
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_CBC_ENCRYPT_DATA,
    CKM_AES_ECB_ENCRYPT_DATA,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import import_secret_key_negotiated

pytestmark = pytest.mark.keymgmt

# 32-byte AES key for base key creation
_BASE_KEY_BYTES = bytes(range(32))

# Data inputs must be multiples of 16 bytes (AES block size)
_DATA_16 = b"derive__test__01"  # 16 bytes
_DATA_32 = b"derive__test__01derive__test__02"  # 32 bytes
_ALT_DATA_16 = b"alt_derive_data!"  # 16 bytes, different content

# 16-byte IV for CBC mode
_IV = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"


def _read_derived_value(
    rs: Any,
    handle: int,
    *,
    label: str,
) -> Any:
    """Read one derived value while preserving a provider-unavailable observation."""
    return attr_or_record(
        read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE]),
        CKA_VALUE,
        label=label,
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )


def _derived_value_shape_record(
    value: Any,
    *,
    leg: str,
    label: str,
    mechanism: str,
    expected_length: int,
) -> C.Classification | None:
    """Record a present derived value whose shape cannot support an oracle."""
    if value is MISSING_ATTRIBUTE:
        return None
    if type(value) is bytes and len(value) == expected_length:
        return None
    try:
        actual_length: int | None = len(value)
    except TypeError:
        actual_length = None
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        summary=f"{label}: provider returned a derived CKA_VALUE with the wrong shape",
        detail={
            "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
            "leg": leg,
            "expected": {"type": "bytes", "length": expected_length},
            "actual": {"type": type(value).__name__, "length": actual_length},
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": mechanism,
        },
    )


def _derived_value_zero_record(
    value: Any,
    *,
    leg: str,
    label: str,
    mechanism: str,
) -> C.Classification | None:
    """Record an all-zero derived key: a crypto-correctness break, not a shape defect."""
    if value is MISSING_ATTRIBUTE:
        return None
    if not isinstance(value, bytes) or not value:
        return None
    if value != b"\x00" * len(value):
        return None
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        mechanism=mechanism,
        summary=f"{label}: derived key material is all zeros",
        detail={
            "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
            "leg": leg,
            "actual": {"length": len(value)},
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": mechanism,
        },
    )


def _read_pair_value(
    rs: Any,
    handle: int,
    *,
    leg: str,
    label: str,
    mechanism: str,
) -> tuple[Any, C.Classification | None]:
    """Read and immediately validate one paired output before its sibling read."""
    value_label = f"{label}:{leg} CKA_VALUE"
    value = _read_derived_value(rs, handle, label=value_label)
    return value, _derived_value_shape_record(
        value,
        leg=leg,
        label=value_label,
        mechanism=mechanism,
        expected_length=16,
    )


def _check_derived_pair(
    values: tuple[Any, Any],
    *,
    shape_records: tuple[C.Classification | None, C.Classification | None],
    relation: str,
    mechanism: str,
    label: str,
) -> None:
    """Validate both outputs before using them as a relation oracle."""
    hard_shape_records = [record for record in shape_records if record is not None]
    if hard_shape_records:
        C.raise_for_record(hard_shape_records[0])
    first, second = values
    if first is MISSING_ATTRIBUTE:
        return
    if second is MISSING_ATTRIBUTE:
        return

    relation_holds = first == second if relation == "equal" else first != second
    if relation_holds:
        return
    record = C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        mechanism=mechanism,
        summary=f"{label}: derived outputs violate the required relation",
        detail={"relation": relation, "legs": ["output 1", "output 2"]},
    )
    C.raise_for_record(record)


def _check_derived_value(
    value: Any,
    *,
    leg: str,
    label: str,
    mechanism: str,
    expected_length: int,
) -> Any:
    """Validate one output and return it when it is usable."""
    shape_record = _derived_value_shape_record(
        value,
        leg=leg,
        label=label,
        mechanism=mechanism,
        expected_length=expected_length,
    )
    if shape_record is not None:
        C.raise_for_record(shape_record)
    return value


def _mech_cbc_encrypt_data(iv: bytes, data: bytes) -> Any:
    """Build a PackedMechanism for CKM_AES_CBC_ENCRYPT_DATA with proper struct."""
    import ctypes

    from pkcs11_check.raw.pack import PackedMechanism, PointerArg
    from pkcs11_check.raw.types_std import (
        CK_AES_CBC_ENCRYPT_DATA_PARAMS,
        CK_BYTE,
        CK_MECHANISM,
    )

    params = CK_AES_CBC_ENCRYPT_DATA_PARAMS()
    for i in range(16):
        params.iv[i] = CK_BYTE(iv[i])
    data_buf = (ctypes.c_ubyte * len(data))(*data)
    params.pData = ctypes.cast(data_buf, ctypes.c_void_p)
    params.length = len(data)
    pointer_arg = PointerArg.to_storage(params, origin="mech_cbc_encrypt_data")
    from pkcs11_check.raw.pack import LengthArg

    length_arg = LengthArg.native(ctypes.sizeof(params))
    result = PackedMechanism(
        CK_MECHANISM(CKM_AES_CBC_ENCRYPT_DATA, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    result._keepalive.append(data_buf)
    return result


def _create_base_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create an AES base key suitable for derivation."""
    return import_secret_key_negotiated(
        rs,
        CKK_AES,
        key_bytes,
        attrs={
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        },
    )


_DERIVE_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_AES,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
    CKA_VALUE_LEN: 16,
}

_DERIVE_ATTRS_32: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_AES,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
    CKA_VALUE_LEN: 32,
}


class TestAESECBEncryptData:
    """CKM_AES_ECB_ENCRYPT_DATA - derive keys by AES-ECB encrypting data."""

    def test_derive_basic(self, p11_raw_session: Any) -> None:
        """Derive an AES key via ECB encryption and verify it is non-empty."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_AES_ECB_ENCRYPT_DATA,
                attrs=_DERIVE_ATTRS,
                mech_param=mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, _DATA_16),
            )
            try:
                okm = _read_derived_value(
                    rs,
                    derived,
                    label="CKM_AES_ECB_ENCRYPT_DATA:derived CKA_VALUE",
                )
                if okm is MISSING_ATTRIBUTE:
                    return
                _check_derived_value(
                    okm,
                    leg="derived",
                    label="CKM_AES_ECB_ENCRYPT_DATA:derived CKA_VALUE",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                    expected_length=16,
                )
                zero_record = _derived_value_zero_record(
                    okm,
                    leg="derived",
                    label="CKM_AES_ECB_ENCRYPT_DATA:derived CKA_VALUE",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                )
                if zero_record is not None:
                    C.raise_for_record(zero_record)
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        """Same base key + same data produces the same derived key."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived1 = 0
            derived2 = 0
            try:
                derived1 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_ECB_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, _DATA_16),
                )
                derived2 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_ECB_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, _DATA_16),
                )
                v1, shape1 = _read_pair_value(
                    rs,
                    derived1,
                    leg="output 1",
                    label="CKM_AES_ECB_ENCRYPT_DATA:deterministic outputs",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                )
                v2, shape2 = _read_pair_value(
                    rs,
                    derived2,
                    leg="output 2",
                    label="CKM_AES_ECB_ENCRYPT_DATA:deterministic outputs",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                )
                _check_derived_pair(
                    (v1, v2),
                    shape_records=(shape1, shape2),
                    relation="equal",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                    label="CKM_AES_ECB_ENCRYPT_DATA:deterministic outputs",
                )
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_different_data(self, p11_raw_session: Any) -> None:
        """Different input data produces different derived keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived1 = 0
            derived2 = 0
            try:
                derived1 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_ECB_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, _DATA_16),
                )
                derived2 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_ECB_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, _ALT_DATA_16),
                )
                v1, shape1 = _read_pair_value(
                    rs,
                    derived1,
                    leg="output 1",
                    label="CKM_AES_ECB_ENCRYPT_DATA:different-data outputs",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                )
                v2, shape2 = _read_pair_value(
                    rs,
                    derived2,
                    leg="output 2",
                    label="CKM_AES_ECB_ENCRYPT_DATA:different-data outputs",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                )
                _check_derived_pair(
                    (v1, v2),
                    shape_records=(shape1, shape2),
                    relation="different",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                    label="CKM_AES_ECB_ENCRYPT_DATA:different-data outputs",
                )
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_32_byte_data(self, p11_raw_session: Any) -> None:
        """Derive a 256-bit key from 32 bytes of input data."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_AES_ECB_ENCRYPT_DATA,
                attrs=_DERIVE_ATTRS_32,
                mech_param=mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, _DATA_32),
            )
            try:
                okm = _read_derived_value(
                    rs,
                    derived,
                    label="CKM_AES_ECB_ENCRYPT_DATA:32-byte derived CKA_VALUE",
                )
                if okm is MISSING_ATTRIBUTE:
                    return
                _check_derived_value(
                    okm,
                    leg="derived",
                    label="CKM_AES_ECB_ENCRYPT_DATA:32-byte derived CKA_VALUE",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                    expected_length=32,
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)


class TestAESCBCEncryptData:
    """CKM_AES_CBC_ENCRYPT_DATA - derive keys by AES-CBC encrypting data."""

    def test_derive_basic(self, p11_raw_session: Any) -> None:
        """Derive an AES key via CBC encryption and verify it is non-empty."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_AES_CBC_ENCRYPT_DATA,
                attrs=_DERIVE_ATTRS,
                mech_param=_mech_cbc_encrypt_data(_IV, _DATA_16),
            )
            try:
                okm = _read_derived_value(
                    rs,
                    derived,
                    label="CKM_AES_CBC_ENCRYPT_DATA:derived CKA_VALUE",
                )
                if okm is MISSING_ATTRIBUTE:
                    return
                _check_derived_value(
                    okm,
                    leg="derived",
                    label="CKM_AES_CBC_ENCRYPT_DATA:derived CKA_VALUE",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                    expected_length=16,
                )
                zero_record = _derived_value_zero_record(
                    okm,
                    leg="derived",
                    label="CKM_AES_CBC_ENCRYPT_DATA:derived CKA_VALUE",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                if zero_record is not None:
                    C.raise_for_record(zero_record)
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        """Same base key + same IV + same data produces the same derived key."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived1 = 0
            derived2 = 0
            try:
                derived1 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_CBC_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=_mech_cbc_encrypt_data(_IV, _DATA_16),
                )
                derived2 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_CBC_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=_mech_cbc_encrypt_data(_IV, _DATA_16),
                )
                v1, shape1 = _read_pair_value(
                    rs,
                    derived1,
                    leg="output 1",
                    label="CKM_AES_CBC_ENCRYPT_DATA:deterministic outputs",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                v2, shape2 = _read_pair_value(
                    rs,
                    derived2,
                    leg="output 2",
                    label="CKM_AES_CBC_ENCRYPT_DATA:deterministic outputs",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                _check_derived_pair(
                    (v1, v2),
                    shape_records=(shape1, shape2),
                    relation="equal",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                    label="CKM_AES_CBC_ENCRYPT_DATA:deterministic outputs",
                )
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_different_data(self, p11_raw_session: Any) -> None:
        """Different input data produces different derived keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived1 = 0
            derived2 = 0
            try:
                derived1 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_CBC_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=_mech_cbc_encrypt_data(_IV, _DATA_16),
                )
                derived2 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_CBC_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=_mech_cbc_encrypt_data(_IV, _ALT_DATA_16),
                )
                v1, shape1 = _read_pair_value(
                    rs,
                    derived1,
                    leg="output 1",
                    label="CKM_AES_CBC_ENCRYPT_DATA:different-data outputs",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                v2, shape2 = _read_pair_value(
                    rs,
                    derived2,
                    leg="output 2",
                    label="CKM_AES_CBC_ENCRYPT_DATA:different-data outputs",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                _check_derived_pair(
                    (v1, v2),
                    shape_records=(shape1, shape2),
                    relation="different",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                    label="CKM_AES_CBC_ENCRYPT_DATA:different-data outputs",
                )
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_different_iv(self, p11_raw_session: Any) -> None:
        """Different IVs with same data produce different derived keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        alt_iv = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

        base_key = _create_base_key(rs)
        try:
            derived1 = 0
            derived2 = 0
            try:
                derived1 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_CBC_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=_mech_cbc_encrypt_data(_IV, _DATA_16),
                )
                derived2 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_AES_CBC_ENCRYPT_DATA,
                    attrs=_DERIVE_ATTRS,
                    mech_param=_mech_cbc_encrypt_data(alt_iv, _DATA_16),
                )
                v1, shape1 = _read_pair_value(
                    rs,
                    derived1,
                    leg="output 1",
                    label="CKM_AES_CBC_ENCRYPT_DATA:different-IV outputs",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                v2, shape2 = _read_pair_value(
                    rs,
                    derived2,
                    leg="output 2",
                    label="CKM_AES_CBC_ENCRYPT_DATA:different-IV outputs",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                )
                _check_derived_pair(
                    (v1, v2),
                    shape_records=(shape1, shape2),
                    relation="different",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                    label="CKM_AES_CBC_ENCRYPT_DATA:different-IV outputs",
                )
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_32_byte_data(self, p11_raw_session: Any) -> None:
        """Derive a 256-bit key from 32 bytes of input data."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")

        base_key = _create_base_key(rs)
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_AES_CBC_ENCRYPT_DATA,
                attrs=_DERIVE_ATTRS_32,
                mech_param=_mech_cbc_encrypt_data(_IV, _DATA_32),
            )
            try:
                okm = _read_derived_value(
                    rs,
                    derived,
                    label="CKM_AES_CBC_ENCRYPT_DATA:32-byte derived CKA_VALUE",
                )
                if okm is MISSING_ATTRIBUTE:
                    return
                _check_derived_value(
                    okm,
                    leg="derived",
                    label="CKM_AES_CBC_ENCRYPT_DATA:32-byte derived CKA_VALUE",
                    mechanism="CKM_AES_CBC_ENCRYPT_DATA",
                    expected_length=32,
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
