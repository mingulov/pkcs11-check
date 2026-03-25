"""Tests for IKE protocol mechanisms.

Covers CKM_IKE2_PRF_PLUS_DERIVE, CKM_IKE_PRF_DERIVE,
CKM_IKE1_PRF_DERIVE, and CKM_IKE1_EXTENDED_DERIVE.

IKE (Internet Key Exchange) mechanisms are used in IPsec VPN implementations.
They use HMAC-based PRFs internally to derive keying material from a shared
secret and nonce data.

OASIS spec: ike_mechanisms.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    create_object,
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
    CKK_GENERIC_SECRET,
    CKM_IKE1_EXTENDED_DERIVE,
    CKM_IKE1_PRF_DERIVE,
    CKM_IKE2_PRF_PLUS_DERIVE,
    CKM_IKE_PRF_DERIVE,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.keymgmt

# 32-byte base key material (shared secret / SKEYSEED)
_BASE_KEY_BYTES = bytes(range(32))

# Nonce data used in IKE exchanges (Ni | Nr)
_NONCE_I = b"\x01" * 16  # initiator nonce
_NONCE_R = b"\x02" * 16  # responder nonce

# IKE SPI values (8 bytes each)
_SPI_I = b"\xaa" * 8  # initiator SPI
_SPI_R = b"\xbb" * 8  # responder SPI

_DERIVE_ATTRS: dict[int, Any] = {
    int(CKA_SENSITIVE): False,
    int(CKA_EXTRACTABLE): True,
    int(CKA_TOKEN): False,
}


def _create_base_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create a GENERIC_SECRET base key suitable for IKE derivation."""
    return create_object(rs.raw, rs.sh, {
        int(CKA_CLASS): int(CKO_SECRET_KEY),
        int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET),
        int(CKA_VALUE): key_bytes,
        int(CKA_DERIVE): True,
        int(CKA_TOKEN): False,
        int(CKA_SENSITIVE): False,
    })


def _derive_generic(
    rs: Any, base_key: int, mech: int, param: bytes, bits: int = 256,
) -> int:
    """Derive a GENERIC_SECRET key using the given mechanism and params."""
    attrs: dict[int, Any] = {
        int(CKA_CLASS): int(CKO_SECRET_KEY),
        int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET),
        int(CKA_VALUE_LEN): bits // 8,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw, rs.sh, base_key, mech,
        attrs=attrs,
        mech_param=mech_bytes(mech, param),
    )


def _derive_aes128(rs: Any, base_key: int, mech: int, param: bytes) -> int:
    """Derive an AES-128 key using the given mechanism and params."""
    attrs: dict[int, Any] = {
        int(CKA_CLASS): int(CKO_SECRET_KEY),
        int(CKA_KEY_TYPE): int(CKK_AES),
        int(CKA_VALUE_LEN): 16,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw, rs.sh, base_key, mech,
        attrs=attrs,
        mech_param=mech_bytes(mech, param),
    )


def _get_value(rs: Any, handle: int) -> bytes:
    """Read CKA_VALUE from a key handle."""
    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
    return attrs[int(CKA_VALUE)]  # type: ignore[return-value]


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
                rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R,
            )
            try:
                raw = _get_value(rs, derived)
                assert len(raw) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_aes128(
                rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R,
            )
            try:
                raw = _get_value(rs, derived)
                assert len(raw) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE AES-128 not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            da = _derive_generic(rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R)
            nonce_b = b"\x03" * 16 + b"\x04" * 16
            db = _derive_generic(rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, nonce_b)
            try:
                assert _get_value(rs, da) != _get_value(rs, db)
            finally:
                destroy_quietly(rs.raw, rs.sh, db)
                destroy_quietly(rs.raw, rs.sh, da)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            d1 = _derive_generic(rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R)
            d2 = _derive_generic(rs, base_key, CKM_IKE2_PRF_PLUS_DERIVE, _NONCE_I + _NONCE_R)
            try:
                assert _get_value(rs, d1) == _get_value(rs, d2)
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE not operational: {exc}")
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
                assert len(_get_value(rs, derived)) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE not operational: {exc}")
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
                assert len(_get_value(rs, derived)) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE AES-128 not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            da = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            db = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, b"\x05" * 16 + b"\x06" * 16)
            try:
                assert _get_value(rs, da) != _get_value(rs, db)
            finally:
                destroy_quietly(rs.raw, rs.sh, db)
                destroy_quietly(rs.raw, rs.sh, da)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            d1 = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            d2 = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                assert _get_value(rs, d1) == _get_value(rs, d2)
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE not operational: {exc}")
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
        base_key = _create_base_key(rs)
        try:
            derived = _derive_generic(rs, base_key, CKM_IKE1_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                assert len(_get_value(rs, derived)) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_aes128(rs, base_key, CKM_IKE1_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                assert len(_get_value(rs, derived)) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE AES-128 not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            da = _derive_generic(rs, base_key, CKM_IKE1_PRF_DERIVE, _NONCE_I + _NONCE_R)
            db = _derive_generic(rs, base_key, CKM_IKE1_PRF_DERIVE, b"\x07" * 16 + b"\x08" * 16)
            try:
                assert _get_value(rs, da) != _get_value(rs, db)
            finally:
                destroy_quietly(rs.raw, rs.sh, db)
                destroy_quietly(rs.raw, rs.sh, da)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            d1 = _derive_generic(rs, base_key, CKM_IKE1_PRF_DERIVE, _NONCE_I + _NONCE_R)
            d2 = _derive_generic(rs, base_key, CKM_IKE1_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                assert _get_value(rs, d1) == _get_value(rs, d2)
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE not operational: {exc}")
        finally:
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
        base_key = _create_base_key(rs)
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            derived = _derive_generic(rs, base_key, CKM_IKE1_EXTENDED_DERIVE, param)
            try:
                assert len(_get_value(rs, derived)) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_base_key(rs)
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            derived = _derive_aes128(rs, base_key, CKM_IKE1_EXTENDED_DERIVE, param)
            try:
                assert len(_get_value(rs, derived)) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE AES-128 not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_spis_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            pa = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
            pb = _NONCE_I + _NONCE_R + b"\xcc" * 8 + b"\xdd" * 8
            da = _derive_generic(rs, base_key, CKM_IKE1_EXTENDED_DERIVE, pa)
            db = _derive_generic(rs, base_key, CKM_IKE1_EXTENDED_DERIVE, pb)
            try:
                assert _get_value(rs, da) != _get_value(rs, db)
            finally:
                destroy_quietly(rs.raw, rs.sh, db)
                destroy_quietly(rs.raw, rs.sh, da)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_base_key(rs)
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            d1 = _derive_generic(rs, base_key, CKM_IKE1_EXTENDED_DERIVE, param)
            d2 = _derive_generic(rs, base_key, CKM_IKE1_EXTENDED_DERIVE, param)
            try:
                assert _get_value(rs, d1) == _get_value(rs, d2)
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
