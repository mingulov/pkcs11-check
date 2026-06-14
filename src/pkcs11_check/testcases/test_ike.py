"""Tests for IKE protocol mechanisms.

Covers CKM_IKE2_PRF_PLUS_DERIVE, CKM_IKE_PRF_DERIVE,
CKM_IKE1_PRF_DERIVE, and CKM_IKE1_EXTENDED_DERIVE.

IKE (Internet Key Exchange) mechanisms are used in IPsec VPN implementations.
They use HMAC-based PRFs internally to derive keying material from a shared
secret and nonce data.

OASIS spec: ike_mechanisms.md
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    mech_bytes,
    mech_ike1_extended_derive,
    mech_ike1_prf_derive,
    mech_ike2_prf_plus_derive,
    mech_ike_prf_derive,
)
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
    CKK_SHA256_HMAC,
    CKM_AES_ECB,
    CKM_IKE1_EXTENDED_DERIVE,
    CKM_IKE1_PRF_DERIVE,
    CKM_IKE2_PRF_PLUS_DERIVE,
    CKM_IKE_PRF_DERIVE,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    reject_or_classify,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_DERIVE_ERROR_CKRS = (
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_DEVICE_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
)
_INVALID_PRF_REJECT_RVS = (CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID)
_INVALID_PRF_MECHANISM = int(CKM_AES_ECB)
_IKE_PRF_REKEY_DATA_AS_KEY_REJECT_RVS = (CKR_ARGUMENTS_BAD,)

# 32-byte base key material (shared secret / SKEYSEED)
_BASE_KEY_BYTES = bytes(range(32))
_IKE1_KEYGXY_BYTES = bytes(range(32, 64))

# Nonce data used in IKE exchanges (Ni | Nr)
_NONCE_I = b"\x01" * 16  # initiator nonce
_NONCE_R = b"\x02" * 16  # responder nonce

# IKE SPI values (8 bytes each)
_SPI_I = b"\xaa" * 8  # initiator SPI
_SPI_R = b"\xbb" * 8  # responder SPI

_DERIVE_ATTRS: dict[int, Any] = {
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}


def _create_base_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create a GENERIC_SECRET base key suitable for IKE derivation."""
    return create_object(
        rs.raw,
        rs.sh,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: key_bytes,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        },
    )


def _create_sha256_hmac_derive_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create a SHA256-HMAC base key suitable for typed IKE2 PRF+ derivation."""
    return create_object(
        rs.raw,
        rs.sh,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_SHA256_HMAC,
            CKA_VALUE: key_bytes,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


def _create_ike1_keygxy_key(rs: Any, key_bytes: bytes = _IKE1_KEYGXY_BYTES) -> int:
    """Create the generic-secret g^xy input key used by IKEv1 derivation."""
    return create_object(
        rs.raw,
        rs.sh,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: key_bytes,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


def _derive_generic(
    rs: Any,
    base_key: int,
    mech: int,
    param: bytes,
    bits: int = 256,
) -> int:
    """Derive a GENERIC_SECRET key using the given mechanism and params."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: bits // 8,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        mech,
        attrs=attrs,
        mech_param=_ike_mech_param(mech, param),
    )


def _derive_aes128(rs: Any, base_key: int, mech: int, param: bytes) -> int:
    """Derive an AES-128 key using the given mechanism and params."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_VALUE_LEN: 16,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        mech,
        attrs=attrs,
        mech_param=_ike_mech_param(mech, param),
    )


def _classify_invalid_prf_derive(
    rs: Any,
    base_key: int,
    mech: int,
    mech_param: Any,
    *,
    label: str,
    value_len: int = 32,
    key_type: int = CKK_GENERIC_SECRET,
) -> None:
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: value_len,
        **_DERIVE_ATTRS,
    }
    derived = 0
    try:
        exc: AssertionError | None = None
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                mech,
                attrs=attrs,
                mech_param=mech_param,
            )
        except AssertionError as caught:
            exc = caught
        reject_or_classify(exc, _INVALID_PRF_REJECT_RVS, label=label)
    finally:
        if derived:
            destroy_quietly(rs.raw, rs.sh, derived)


def _derive_ike1_prf(
    rs: Any,
    base_key: int,
    keygxy_key: int,
    *,
    initiator_cookie: bytes = _NONCE_I,
    responder_cookie: bytes = _NONCE_R,
    key_number: int = 0,
    previous_key_handle: int = 0,
    value_len: int = 32,
    key_type: int = CKK_GENERIC_SECRET,
) -> int:
    """Derive a key with typed CK_IKE1_PRF_DERIVE_PARAMS."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: value_len,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_IKE1_PRF_DERIVE,
        attrs=attrs,
        mech_param=mech_ike1_prf_derive(
            CKM_IKE1_PRF_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            keygxy_handle=keygxy_key,
            initiator_cookie=initiator_cookie,
            responder_cookie=responder_cookie,
            key_number=key_number,
            previous_key_handle=previous_key_handle,
        ),
    )


def _derive_ike1_extended(
    rs: Any,
    base_key: int,
    *,
    keygxy_key: int = 0,
    extra_data: bytes = b"",
    value_len: int = 32,
    key_type: int = CKK_GENERIC_SECRET,
) -> int:
    """Derive a key with typed CK_IKE1_EXTENDED_DERIVE_PARAMS."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE_LEN: value_len,
        **_DERIVE_ATTRS,
    }
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_IKE1_EXTENDED_DERIVE,
        attrs=attrs,
        mech_param=mech_ike1_extended_derive(
            CKM_IKE1_EXTENDED_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            keygxy_handle=keygxy_key,
            extra_data=extra_data,
        ),
    )


def _get_value(rs: Any, handle: int) -> bytes:
    """Read CKA_VALUE from a key handle."""
    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
    value = attrs[CKA_VALUE]
    assert isinstance(value, bytes)
    return value


def _ike_mech_param(mech: int, param: bytes) -> Any:
    """Build typed IKE mechanism params where the PKCS#11 shape is clear."""
    if mech == CKM_IKE_PRF_DERIVE:
        half = len(param) // 2
        return mech_ike_prf_derive(
            CKM_IKE_PRF_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            initiator_nonce=param[:half],
            responder_nonce=param[half:],
            data_as_key=True,
        )
    if mech == CKM_IKE2_PRF_PLUS_DERIVE:
        return mech_ike2_prf_plus_derive(
            CKM_IKE2_PRF_PLUS_DERIVE,
            prf_mechanism=CKM_SHA256_HMAC,
            seed_data=param,
        )
    return mech_bytes(mech, param)


def _ike_prf_hmac_sha256_reference(
    base_key: bytes,
    initiator_nonce: bytes,
    responder_nonce: bytes,
    *,
    data_as_key: bool,
) -> bytes:
    """Compute the OASIS CKM_IKE_PRF_DERIVE HMAC-SHA256 reference value."""
    nonce_data = initiator_nonce + responder_nonce
    if data_as_key:
        return hmac.new(nonce_data, base_key, hashlib.sha256).digest()
    return hmac.new(base_key, nonce_data, hashlib.sha256).digest()


def _ike2_prf_plus_hmac_sha256_reference(
    base_key: bytes,
    seed: bytes,
    output_len: int,
) -> bytes:
    """Compute the OASIS CKM_IKE2_PRF_PLUS_DERIVE HMAC-SHA256 reference value."""
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    if output_len > 255 * hashlib.sha256().digest_size:
        raise ValueError("output_len exceeds IKE2 PRF+ counter capacity")
    result = b""
    previous = b""
    counter = 1
    while len(result) < output_len:
        previous = hmac.new(base_key, previous + seed + bytes([counter]), hashlib.sha256).digest()
        result += previous
        counter += 1
    return result[:output_len]


def _ike1_prf_hmac_sha256_reference(
    base_key: bytes,
    keygxy: bytes,
    initiator_cookie: bytes,
    responder_cookie: bytes,
    *,
    key_number: int,
    previous_key: bytes | None = None,
) -> bytes:
    """Compute the OASIS CKM_IKE1_PRF_DERIVE HMAC-SHA256 reference value."""
    if not 0 <= key_number <= 0xFF:
        raise ValueError("key_number must fit in one byte")
    prefix = b"" if previous_key is None else previous_key
    data = prefix + keygxy + initiator_cookie + responder_cookie + bytes([key_number])
    return hmac.new(base_key, data, hashlib.sha256).digest()


def _ike1_extended_hmac_sha256_reference(
    base_key: bytes,
    keygxy: bytes | None,
    extra_data: bytes,
    output_len: int,
) -> bytes:
    """Compute the OASIS CKM_IKE1_EXTENDED_DERIVE HMAC-SHA256 reference value."""
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    if keygxy is None and not extra_data and output_len <= len(base_key):
        return base_key[:output_len]
    seed = (keygxy or b"") + extra_data
    result = b""
    previous = b""
    while len(result) < output_len:
        message = previous + seed if previous else seed or b"\x00"
        previous = hmac.new(base_key, message, hashlib.sha256).digest()
        result += previous
    return result[:output_len]


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
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
            )
            try:
                raw = _get_value(rs, derived)
                assert len(raw) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE2_PRF_PLUS_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_plus_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE2_PRF_PLUS_DERIVE follows OASIS prf+(baseKey, seedData)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            expected = _ike2_prf_plus_hmac_sha256_reference(
                _BASE_KEY_BYTES,
                _NONCE_I + _NONCE_R,
                32,
            )
            derived = _derive_generic(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
            )
            try:
                assert_correct(
                    actual=_get_value(rs, derived),
                    expected=expected,
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE2_PRF_PLUS_DERIVE HMAC-SHA256 exact vector not operational",
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_plus_hmac_sha256_multiblock_exact_vector(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_IKE2_PRF_PLUS_DERIVE follows OASIS prf+ across HMAC blocks."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            expected = _ike2_prf_plus_hmac_sha256_reference(
                _BASE_KEY_BYTES,
                _NONCE_I + _NONCE_R,
                48,
            )
            derived = _derive_generic(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
                bits=384,
            )
            try:
                assert_correct(
                    actual=_get_value(rs, derived),
                    expected=expected,
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey KAT (HMAC-SHA256 multiblock)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE2_PRF_PLUS_DERIVE HMAC-SHA256 multiblock exact vector not operational",
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = _create_base_key(rs)
        try:
            derived = _derive_aes128(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                _NONCE_I + _NONCE_R,
            )
            try:
                raw = _get_value(rs, derived)
                assert len(raw) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_CKRS, "CKM_IKE2_PRF_PLUS_DERIVE AES-128 not operational"
            )
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
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE2_PRF_PLUS_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_base_key_affects_output(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key_a = _create_base_key(rs)
        base_key_b: int | None = None
        try:
            base_key_b = _create_base_key(rs, bytes(reversed(_BASE_KEY_BYTES)))
            derived_a: int | None = None
            derived_b: int | None = None
            try:
                derived_a = _derive_generic(
                    rs,
                    base_key_a,
                    CKM_IKE2_PRF_PLUS_DERIVE,
                    _NONCE_I + _NONCE_R,
                )
                derived_b = _derive_generic(
                    rs,
                    base_key_b,
                    CKM_IKE2_PRF_PLUS_DERIVE,
                    _NONCE_I + _NONCE_R,
                )
                assert _get_value(rs, derived_a) != _get_value(rs, derived_b), (
                    "IKE2 PRF+ base key change did not affect derived output"
                )
            finally:
                if derived_b is not None:
                    destroy_quietly(rs.raw, rs.sh, derived_b)
                if derived_a is not None:
                    destroy_quietly(rs.raw, rs.sh, derived_a)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE2_PRF_PLUS_DERIVE not operational")
        finally:
            if base_key_b is not None:
                destroy_quietly(rs.raw, rs.sh, base_key_b)
            destroy_quietly(rs.raw, rs.sh, base_key_a)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE2_PRF_PLUS_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE2_PRF_PLUS_DERIVE,
                mech_ike2_prf_plus_derive(
                    CKM_IKE2_PRF_PLUS_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    seed_data=_NONCE_I + _NONCE_R,
                ),
                label="IKE2 PRF+ invalid PRF mechanism",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE2_PRF_PLUS_DERIVE invalid PRF setup not operational",
            )
        finally:
            if base_key:
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
                assert_correct(
                    actual=_get_value(rs, d1),
                    expected=_get_value(rs, d2),
                    label="CKM_IKE2_PRF_PLUS_DERIVE:C_DeriveKey determinism",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE2_PRF_PLUS_DERIVE not operational")
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
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE_PRF_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_data_as_key_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE_PRF_DERIVE case 1 follows OASIS prf(Ni|Nr, baseKey)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = _create_base_key(rs)
        expected = _ike_prf_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _NONCE_I,
            _NONCE_R,
            data_as_key=True,
        )
        try:
            derived = _derive_generic(rs, base_key, CKM_IKE_PRF_DERIVE, _NONCE_I + _NONCE_R)
            try:
                assert_correct(
                    actual=_get_value(rs, derived),
                    expected=expected,
                    label="CKM_IKE_PRF_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE_PRF_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE_PRF_DERIVE HMAC-SHA256 exact vector not operational",
            )
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
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_CKRS, "CKM_IKE_PRF_DERIVE AES-128 not operational"
            )
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
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE_PRF_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_base_key_affects_output(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key_a = _create_base_key(rs)
        base_key_b: int | None = None
        try:
            base_key_b = _create_base_key(rs, bytes(reversed(_BASE_KEY_BYTES)))
            derived_a: int | None = None
            derived_b: int | None = None
            try:
                derived_a = _derive_generic(
                    rs,
                    base_key_a,
                    CKM_IKE_PRF_DERIVE,
                    _NONCE_I + _NONCE_R,
                )
                derived_b = _derive_generic(
                    rs,
                    base_key_b,
                    CKM_IKE_PRF_DERIVE,
                    _NONCE_I + _NONCE_R,
                )
                assert _get_value(rs, derived_a) != _get_value(rs, derived_b), (
                    "IKE PRF base key change did not affect derived output"
                )
            finally:
                if derived_b is not None:
                    destroy_quietly(rs.raw, rs.sh, derived_b)
                if derived_a is not None:
                    destroy_quietly(rs.raw, rs.sh, derived_a)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE_PRF_DERIVE not operational")
        finally:
            if base_key_b is not None:
                destroy_quietly(rs.raw, rs.sh, base_key_b)
            destroy_quietly(rs.raw, rs.sh, base_key_a)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE_PRF_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = 0
        try:
            base_key = _create_base_key(rs)
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE_PRF_DERIVE,
                mech_ike_prf_derive(
                    CKM_IKE_PRF_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    initiator_nonce=_NONCE_I,
                    responder_nonce=_NONCE_R,
                    data_as_key=True,
                ),
                label="IKE PRF invalid PRF mechanism",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE_PRF_DERIVE invalid PRF setup not operational",
            )
        finally:
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_rejects_data_as_key_rekey_combination(self, p11_raw_session: Any) -> None:
        """CKM_IKE_PRF_DERIVE rejects the disallowed bDataAsKey+bRekey pair."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")
        base_key = 0
        rekey_key = 0
        derived = 0
        try:
            base_key = _create_base_key(rs)
            rekey_key = _create_base_key(rs, bytes(reversed(_BASE_KEY_BYTES)))
            attrs: dict[int, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: 32,
                **_DERIVE_ATTRS,
            }
            exc: AssertionError | None = None
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    CKM_IKE_PRF_DERIVE,
                    attrs=attrs,
                    mech_param=mech_ike_prf_derive(
                        CKM_IKE_PRF_DERIVE,
                        prf_mechanism=CKM_SHA256_HMAC,
                        initiator_nonce=_NONCE_I,
                        responder_nonce=_NONCE_R,
                        data_as_key=True,
                        rekey=True,
                        new_key_handle=rekey_key,
                    ),
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(
                exc,
                _IKE_PRF_REKEY_DATA_AS_KEY_REJECT_RVS,
                label="IKE PRF data-as-key rekey combination",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE_PRF_DERIVE data-as-key rekey setup not operational",
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if rekey_key:
                destroy_quietly(rs.raw, rs.sh, rekey_key)
            if base_key:
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
                assert_correct(
                    actual=_get_value(rs, d1),
                    expected=_get_value(rs, d2),
                    label="CKM_IKE_PRF_DERIVE:C_DeriveKey determinism",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE_PRF_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE_PRF_DERIVE not operational")
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
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        try:
            derived = _derive_ike1_prf(rs, base_key, keygxy_key)
            try:
                assert len(_get_value(rs, derived)) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_PRF_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_prf_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_PRF_DERIVE follows OASIS prf(SKEYID, g^xy|CKYi|CKYr|n)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        expected = _ike1_prf_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _IKE1_KEYGXY_BYTES,
            _NONCE_I,
            _NONCE_R,
            key_number=0,
        )
        try:
            derived = _derive_ike1_prf(rs, base_key, keygxy_key, key_number=0)
            try:
                assert_correct(
                    actual=_get_value(rs, derived),
                    expected=expected,
                    label="CKM_IKE1_PRF_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_PRF_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE1_PRF_DERIVE HMAC-SHA256 exact vector not operational",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        try:
            derived = _derive_ike1_prf(
                rs,
                base_key,
                keygxy_key,
                value_len=16,
                key_type=CKK_AES,
            )
            try:
                assert len(_get_value(rs, derived)) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_PRF_DERIVE AES-128 not operational"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_nonces_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        try:
            da = _derive_ike1_prf(rs, base_key, keygxy_key)
            db = _derive_ike1_prf(
                rs,
                base_key,
                keygxy_key,
                initiator_cookie=b"\x07" * 16,
                responder_cookie=b"\x08" * 16,
            )
            try:
                assert _get_value(rs, da) != _get_value(rs, db)
            finally:
                destroy_quietly(rs.raw, rs.sh, db)
                destroy_quietly(rs.raw, rs.sh, da)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_PRF_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_PRF_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = 0
        keygxy_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            keygxy_key = _create_ike1_keygxy_key(rs)
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE1_PRF_DERIVE,
                mech_ike1_prf_derive(
                    CKM_IKE1_PRF_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    keygxy_handle=keygxy_key,
                    initiator_cookie=_NONCE_I,
                    responder_cookie=_NONCE_R,
                    key_number=0,
                ),
                label="IKE1 PRF invalid PRF mechanism",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE1_PRF_DERIVE invalid PRF setup not operational",
            )
        finally:
            if keygxy_key:
                destroy_quietly(rs.raw, rs.sh, keygxy_key)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        try:
            d1 = _derive_ike1_prf(rs, base_key, keygxy_key)
            d2 = _derive_ike1_prf(rs, base_key, keygxy_key)
            try:
                assert_correct(
                    actual=_get_value(rs, d1),
                    expected=_get_value(rs, d2),
                    label="CKM_IKE1_PRF_DERIVE:C_DeriveKey determinism",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_PRF_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_PRF_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
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
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            derived = _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=param)
            try:
                assert len(_get_value(rs, derived)) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_EXTENDED_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_extended_hmac_sha256_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_EXTENDED_DERIVE follows OASIS prf(SKEYID, g^xy|extraData)."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        extra_data = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        expected = _ike1_extended_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _IKE1_KEYGXY_BYTES,
            extra_data,
            32,
        )
        try:
            derived = _derive_ike1_extended(
                rs,
                base_key,
                keygxy_key=keygxy_key,
                extra_data=extra_data,
            )
            try:
                assert_correct(
                    actual=_get_value(rs, derived),
                    expected=expected,
                    label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey KAT (HMAC-SHA256)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE1_EXTENDED_DERIVE HMAC-SHA256 exact vector not operational",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_extended_hmac_sha256_multiblock_exact_vector(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_IKE1_EXTENDED_DERIVE follows OASIS recurrence across HMAC blocks."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        extra_data = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        expected = _ike1_extended_hmac_sha256_reference(
            _BASE_KEY_BYTES,
            _IKE1_KEYGXY_BYTES,
            extra_data,
            48,
        )
        try:
            derived = _derive_ike1_extended(
                rs,
                base_key,
                keygxy_key=keygxy_key,
                extra_data=extra_data,
                value_len=48,
            )
            try:
                assert_correct(
                    actual=_get_value(rs, derived),
                    expected=expected,
                    label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey KAT (HMAC-SHA256 multiblock)",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE1_EXTENDED_DERIVE HMAC-SHA256 multiblock exact vector not operational",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            derived = _derive_ike1_extended(
                rs,
                base_key,
                keygxy_key=keygxy_key,
                extra_data=param,
                value_len=16,
                key_type=CKK_AES,
            )
            try:
                assert len(_get_value(rs, derived)) == 16
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_EXTENDED_DERIVE AES-128 not operational"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_different_spis_produce_different_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        try:
            pa = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
            pb = _NONCE_I + _NONCE_R + b"\xcc" * 8 + b"\xdd" * 8
            da = _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=pa)
            db = _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=pb)
            try:
                assert _get_value(rs, da) != _get_value(rs, db)
            finally:
                destroy_quietly(rs.raw, rs.sh, db)
                destroy_quietly(rs.raw, rs.sh, da)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_EXTENDED_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_rejects_invalid_prf_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_IKE1_EXTENDED_DERIVE rejects a non-MAC nested prfMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = 0
        keygxy_key = 0
        try:
            base_key = _create_sha256_hmac_derive_key(rs)
            keygxy_key = _create_ike1_keygxy_key(rs)
            _classify_invalid_prf_derive(
                rs,
                base_key,
                CKM_IKE1_EXTENDED_DERIVE,
                mech_ike1_extended_derive(
                    CKM_IKE1_EXTENDED_DERIVE,
                    prf_mechanism=_INVALID_PRF_MECHANISM,
                    keygxy_handle=keygxy_key,
                    extra_data=_NONCE_I + _NONCE_R + _SPI_I + _SPI_R,
                ),
                label="IKE1 extended invalid PRF mechanism",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_CKRS,
                "CKM_IKE1_EXTENDED_DERIVE invalid PRF setup not operational",
            )
        finally:
            if keygxy_key:
                destroy_quietly(rs.raw, rs.sh, keygxy_key)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")
        base_key = _create_sha256_hmac_derive_key(rs)
        keygxy_key = _create_ike1_keygxy_key(rs)
        param = _NONCE_I + _NONCE_R + _SPI_I + _SPI_R
        try:
            d1 = _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=param)
            d2 = _derive_ike1_extended(rs, base_key, keygxy_key=keygxy_key, extra_data=param)
            try:
                assert_correct(
                    actual=_get_value(rs, d1),
                    expected=_get_value(rs, d2),
                    label="CKM_IKE1_EXTENDED_DERIVE:C_DeriveKey determinism",
                    operation="C_DeriveKey",
                    mechanism="CKM_IKE1_EXTENDED_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, d2)
                destroy_quietly(rs.raw, rs.sh, d1)
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_CKRS, "CKM_IKE1_EXTENDED_DERIVE not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, keygxy_key)
            destroy_quietly(rs.raw, rs.sh, base_key)
