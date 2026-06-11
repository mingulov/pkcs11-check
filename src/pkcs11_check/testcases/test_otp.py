"""OTP and CT-KIP mechanism tests - HOTP, SecurID, ACTI, CT-KIP.

Covers OTP key generation and OTP value generation via sign operations:
- CKM_HOTP_KEY_GEN / CKM_HOTP
- CKM_SECURID_KEY_GEN / CKM_SECURID
- CKM_ACTI_KEY_GEN / CKM_ACTI

Also covers CT-KIP key derivation/wrapping/MAC mechanisms:
- CKM_KIP_DERIVE
- CKM_KIP_WRAP
- CKM_KIP_MAC

These mechanisms are rarely supported by software HSMs. All tests check
mechanism availability and skip cleanly when not supported.

OASIS spec: otp_mechanisms.md, ct-kip.md
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.pack import PackedMechanism, _mech_struct, mech_simple
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    gen_aes_key,
    sign_single,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CK_KIP_PARAMS,
    CK_VOID_PTR,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_ACTI,
    CKK_GENERIC_SECRET,
    CKK_HOTP,
    CKK_SECURID,
    CKM_ACTI,
    CKM_ACTI_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_HOTP,
    CKM_HOTP_KEY_GEN,
    CKM_KIP_DERIVE,
    CKM_KIP_MAC,
    CKM_KIP_WRAP,
    CKM_SECURID,
    CKM_SECURID_KEY_GEN,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = pytest.mark.full

_OTP_OPERATIONAL_ERROR_CKRS = (
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
)

_KIP_OPERATIONAL_ERROR_CKRS = (
    *_OTP_OPERATIONAL_ERROR_CKRS,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
)


def _xfail_otp_reject(exc: AssertionError, msg: str) -> None:
    xfail_if_known_ckr(exc, _OTP_OPERATIONAL_ERROR_CKRS, msg)
    raise exc


def _xfail_kip_reject(exc: AssertionError, msg: str) -> None:
    xfail_if_known_ckr(exc, _KIP_OPERATIONAL_ERROR_CKRS, msg)
    raise exc


def _gen_otp_key(rs: Any, key_type: int, mechanism: int) -> int:
    """Generate an OTP key with minimal template."""
    return gen_aes_key(
        rs.raw,
        rs.sh,
        0,
        attrs={
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: key_type,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_SIGN: True,
        },
        mechanism=mechanism,
    )


def _bytes_pointer(data: bytes | None, keepalive: list[Any]) -> tuple[Any, int]:
    if data is None:
        return None, 0
    if data:
        storage = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    else:
        storage = (ctypes.c_ubyte * 0)()
    keepalive.append(storage)
    return ctypes.cast(storage, CK_VOID_PTR), len(data)


def _mech_kip(
    mechanism: int,
    *,
    underlying_mechanism: int,
    h_key: int = 0,
    seed: bytes | None = None,
) -> PackedMechanism:
    keepalive: list[Any] = []
    underlying = mech_simple(underlying_mechanism)
    params = CK_KIP_PARAMS()
    params.pMechanism = ctypes.cast(ctypes.pointer(underlying.ck), CK_VOID_PTR)
    params.hKey = h_key
    params.pSeed, params.ulSeedLen = _bytes_pointer(seed, keepalive)
    packed = _mech_struct(
        mechanism,
        params,
        "mech_kip",
        keepalive,
        sub_mechanisms={"underlying": int(underlying_mechanism)},
    )
    packed._keepalive.append(underlying)
    return packed


def _create_kip_secret_key(
    rs: Any,
    *,
    derive: bool = False,
    wrap: bool = False,
    sign: bool = False,
    verify: bool = False,
    extractable: bool = True,
    value: bytes = b"pkcs11-check-ct-kip-secret-0001",
) -> int:
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE: value,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: extractable,
    }
    if derive:
        attrs[CKA_DERIVE] = True
    if wrap:
        attrs[CKA_WRAP] = True
    if sign:
        attrs[CKA_SIGN] = True
    if verify:
        attrs[CKA_VERIFY] = True
    return create_object(rs.raw, rs.sh, attrs)


def _create_kip_aes_wrap_key(rs: Any) -> int:
    return gen_aes_key(
        rs.raw,
        rs.sh,
        128,
        attrs={
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_WRAP: True,
        },
    )


def _kip_derive_attrs() -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: 32,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
    }


def _destroy_all(rs: Any, *handles: int) -> None:
    for handle in handles:
        if handle:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestHOTP:
    """Tests for CKM_HOTP_KEY_GEN and CKM_HOTP."""

    def test_hotp_key_gen(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_HOTP, CKM_HOTP_KEY_GEN)
            assert key != 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_HOTP_KEY_GEN advertised but keygen rejected")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_hotp_generate_otp(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        if not rs.has_mechanism("HOTP"):
            pytest.skip("CKM_HOTP not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_HOTP, CKM_HOTP_KEY_GEN)
            otp = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_HOTP advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_hotp_two_otps_differ(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        if not rs.has_mechanism("HOTP"):
            pytest.skip("CKM_HOTP not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_HOTP, CKM_HOTP_KEY_GEN)
            otp1 = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            otp2 = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            assert otp1 != otp2, "Consecutive HOTP values must differ"
        except AssertionError as exc:
            if "Consecutive" in str(exc):
                raise
            _xfail_otp_reject(exc, "CKM_HOTP advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestSecurID:
    """Tests for CKM_SECURID_KEY_GEN and CKM_SECURID."""

    def test_securid_key_gen(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SECURID_KEY_GEN"):
            pytest.skip("CKM_SECURID_KEY_GEN not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_SECURID, CKM_SECURID_KEY_GEN)
            assert key != 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_SECURID_KEY_GEN advertised but keygen rejected")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_securid_generate_otp(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SECURID_KEY_GEN"):
            pytest.skip("CKM_SECURID_KEY_GEN not supported")
        if not rs.has_mechanism("SECURID"):
            pytest.skip("CKM_SECURID not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_SECURID, CKM_SECURID_KEY_GEN)
            otp = sign_single(rs.raw, rs.sh, key, CKM_SECURID, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_SECURID advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestACTI:
    """Tests for CKM_ACTI_KEY_GEN and CKM_ACTI."""

    def test_acti_key_gen(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ACTI_KEY_GEN"):
            pytest.skip("CKM_ACTI_KEY_GEN not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_ACTI, CKM_ACTI_KEY_GEN)
            assert key != 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_ACTI_KEY_GEN advertised but keygen rejected")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_acti_generate_otp(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ACTI_KEY_GEN"):
            pytest.skip("CKM_ACTI_KEY_GEN not supported")
        if not rs.has_mechanism("ACTI"):
            pytest.skip("CKM_ACTI not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_ACTI, CKM_ACTI_KEY_GEN)
            otp = sign_single(rs.raw, rs.sh, key, CKM_ACTI, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_ACTI advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestCTKIP:
    """Tests for CT-KIP mechanisms: CKM_KIP_DERIVE, CKM_KIP_WRAP, CKM_KIP_MAC."""

    def test_kip_derive_derives_generic_secret(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_DERIVE"):
            pytest.skip("CKM_KIP_DERIVE not supported")
        base_key = 0
        entropy_key = 0
        derived = 0
        try:
            base_key = _create_kip_secret_key(rs, derive=True)
            entropy_key = _create_kip_secret_key(rs)
            mech_param = _mech_kip(
                CKM_KIP_DERIVE,
                underlying_mechanism=CKM_SHA256,
                h_key=entropy_key,
                seed=b"pkcs11-check-ct-kip-derive-seed",
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_KIP_DERIVE,
                attrs=_kip_derive_attrs(),
                mech_param=mech_param,
            )
            assert derived != 0
        except AssertionError as exc:
            _xfail_kip_reject(exc, "CKM_KIP_DERIVE advertised but derive is not operational")
        finally:
            _destroy_all(rs, derived, base_key, entropy_key)

    def test_kip_wrap_wraps_generic_secret(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_WRAP"):
            pytest.skip("CKM_KIP_WRAP not supported")
        wrapping_key = 0
        target_key = 0
        try:
            wrapping_key = _create_kip_aes_wrap_key(rs)
            target_key = _create_kip_secret_key(rs)
            mech_param = _mech_kip(
                CKM_KIP_WRAP,
                underlying_mechanism=CKM_AES_KEY_WRAP,
                seed=b"pkcs11-check-ct-kip-wrap-seed",
            )
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                target_key,
                CKM_KIP_WRAP,
                mech_param=mech_param,
                output_size_hint=128,
            )
            assert len(wrapped) > 0
        except AssertionError as exc:
            _xfail_kip_reject(exc, "CKM_KIP_WRAP advertised but wrap is not operational")
        finally:
            _destroy_all(rs, wrapping_key, target_key)

    def test_kip_mac_signs_and_verifies(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        key = 0
        try:
            key = _create_kip_secret_key(rs, sign=True, verify=True)
            sign_param = _mech_kip(
                CKM_KIP_MAC,
                underlying_mechanism=CKM_SHA256_HMAC,
                h_key=key,
                seed=None,
            )
            data = b"pkcs11-check-ct-kip-mac"
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_KIP_MAC,
                data,
                mech_param=sign_param,
                output_size_hint=64,
            )
            assert len(mac) > 0

            verify_param = _mech_kip(
                CKM_KIP_MAC,
                underlying_mechanism=CKM_SHA256_HMAC,
                h_key=key,
                seed=None,
            )
            assert verify_single(
                rs.raw,
                rs.sh,
                key,
                CKM_KIP_MAC,
                data,
                mac,
                mech_param=verify_param,
            )
        except AssertionError as exc:
            _xfail_kip_reject(exc, "CKM_KIP_MAC advertised but sign/verify is not operational")
        finally:
            _destroy_all(rs, key)
