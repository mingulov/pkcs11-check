"""Tests for AES key derivation by data encryption.

Covers CKM_AES_ECB_ENCRYPT_DATA and CKM_AES_CBC_ENCRYPT_DATA - mechanisms
that derive new keys by encrypting supplied data with a base key.

OASIS spec: key_derivation_by_data_encryption_aes-des.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_string_data
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_secret_key,
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

pytestmark = pytest.mark.keymgmt

# 32-byte AES key for base key creation
_BASE_KEY_BYTES = bytes(range(32))

# Data inputs must be multiples of 16 bytes (AES block size)
_DATA_16 = b"derive__test__01"  # 16 bytes
_DATA_32 = b"derive__test__01derive__test__02"  # 32 bytes
_ALT_DATA_16 = b"alt_derive_data!"  # 16 bytes, different content

# 16-byte IV for CBC mode
_IV = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"


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
    return import_secret_key(
        rs.raw,
        rs.sh,
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
                okm = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(okm, bytes)
                assert len(okm) == 16, f"Expected 16-byte derived key, got {len(okm)}"
                assert okm != b"\x00" * 16, "Derived key is all zeros"
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
            try:
                v1 = read_attributes(rs.raw, rs.sh, derived1, [CKA_VALUE])[CKA_VALUE]
                v2 = read_attributes(rs.raw, rs.sh, derived2, [CKA_VALUE])[CKA_VALUE]
                assert v1 == v2
            finally:
                destroy_quietly(rs.raw, rs.sh, derived2)
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
            try:
                v1 = read_attributes(rs.raw, rs.sh, derived1, [CKA_VALUE])[CKA_VALUE]
                v2 = read_attributes(rs.raw, rs.sh, derived2, [CKA_VALUE])[CKA_VALUE]
                assert v1 != v2
            finally:
                destroy_quietly(rs.raw, rs.sh, derived2)
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
                okm = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(okm, bytes)
                assert len(okm) == 32, f"Expected 32-byte derived key, got {len(okm)}"
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
                okm = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(okm, bytes)
                assert len(okm) == 16, f"Expected 16-byte derived key, got {len(okm)}"
                assert okm != b"\x00" * 16, "Derived key is all zeros"
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
            try:
                v1 = read_attributes(rs.raw, rs.sh, derived1, [CKA_VALUE])[CKA_VALUE]
                v2 = read_attributes(rs.raw, rs.sh, derived2, [CKA_VALUE])[CKA_VALUE]
                assert v1 == v2
            finally:
                destroy_quietly(rs.raw, rs.sh, derived2)
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
            try:
                v1 = read_attributes(rs.raw, rs.sh, derived1, [CKA_VALUE])[CKA_VALUE]
                v2 = read_attributes(rs.raw, rs.sh, derived2, [CKA_VALUE])[CKA_VALUE]
                assert v1 != v2
            finally:
                destroy_quietly(rs.raw, rs.sh, derived2)
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
            try:
                v1 = read_attributes(rs.raw, rs.sh, derived1, [CKA_VALUE])[CKA_VALUE]
                v2 = read_attributes(rs.raw, rs.sh, derived2, [CKA_VALUE])[CKA_VALUE]
                assert v1 != v2
            finally:
                destroy_quietly(rs.raw, rs.sh, derived2)
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
                okm = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(okm, bytes)
                assert len(okm) == 32, f"Expected 32-byte derived key, got {len(okm)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
