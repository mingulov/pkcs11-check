"""Tests for password-based encryption and key derivation mechanisms.

Covers CKM_PBE_SHA1_DES3_EDE_CBC, CKM_PBE_SHA1_DES2_EDE_CBC,
CKM_PBA_SHA1_WITH_SHA1_HMAC, and CKM_PKCS5_PBKD2.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import LengthArg, PackedMechanism, PointerArg, mech_pbkdf2
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PBE_PARAMS,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_DES2,
    CKK_DES3,
    CKK_GENERIC_SECRET,
    CKK_SHA_1_HMAC,
    CKM_PBA_SHA1_WITH_SHA1_HMAC,
    CKM_PBE_SHA1_DES2_EDE_CBC,
    CKM_PBE_SHA1_DES3_EDE_CBC,
    CKM_PKCS5_PBKD2,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA1,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)

pytestmark = pytest.mark.keymgmt

# Acceptable CKR codes for PBE operations
_PBE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
}

# Test password and salt
_PASSWORD = b"TestPassword123!"
_SALT = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
_ITERATIONS = 1024


# ---------------------------------------------------------------------------
# CK_PBE_PARAMS builder
# ---------------------------------------------------------------------------


def _build_pbe_mech(
    mech_type: int,
    password: bytes,
    salt: bytes,
    iterations: int,
    iv_len: int = 8,
) -> tuple[PackedMechanism, list[Any]]:
    """Build a PBE mechanism with CK_PBE_PARAMS. Returns (mech, keepalive)."""
    keepalive: list[Any] = []

    iv_buf = (ctypes.c_ubyte * iv_len)()
    keepalive.append(iv_buf)

    pw_arr = (ctypes.c_ubyte * len(password))(*password)
    keepalive.append(pw_arr)

    salt_arr = (ctypes.c_ubyte * len(salt))(*salt)
    keepalive.append(salt_arr)

    params = CK_PBE_PARAMS()
    params.pInitVector = ctypes.cast(iv_buf, ctypes.c_void_p)
    params.pPassword = ctypes.cast(pw_arr, ctypes.c_void_p)
    params.ulPasswordLen = len(password)
    params.pSalt = ctypes.cast(salt_arr, ctypes.c_void_p)
    params.ulSaltLen = len(salt)
    params.ulIteration = iterations
    keepalive.append(params)

    pointer_arg = PointerArg.to_storage(params, origin="pbe_params")
    length_arg = LengthArg.native(ctypes.sizeof(params))
    pm = PackedMechanism(
        CK_MECHANISM(mech_type, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    pm._keepalive.extend(keepalive)
    return pm, keepalive


def _pbe_gen_key(
    rs: Any,
    mech_type: int,
    key_type: int,
    key_bits: int,
    password: bytes,
    salt: bytes,
    iterations: int,
    iv_len: int = 8,
    extra_attrs: dict[int, Any] | None = None,
) -> int | None:
    """Generate a key via PBE mechanism. Returns handle or None on PBE error."""
    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    packed = [
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
    ]
    if extra_attrs:
        for k, v in extra_attrs.items():
            if isinstance(v, bool):
                packed.append(attr_bool(k, v))
            else:
                packed.append(attr_ulong(k, v))
    tmpl = template(*packed)

    pm, _ka = _build_pbe_mech(mech_type, password, salt, iterations, iv_len)
    key_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, pm.byref(), tmpl.ptr, tmpl.count, byref(key_h))
    if rv != CKR_OK:
        if rv in _PBE_ERROR_RVS:
            return None
        from pkcs11_check.raw.rv import ckr_name

        raise AssertionError(f"Unexpected CKR from PBE keygen: {ckr_name(rv)}")
    return key_h.value


def _pbkdf2_gen_key(
    rs: Any,
    key_type: int,
    key_bits: int,
    password: bytes,
    salt: bytes,
    iterations: int,
    prf: int,
    extra_attrs: dict[int, Any] | None = None,
) -> int | None:
    """Generate a key via CKM_PKCS5_PBKD2. Returns handle or None on error."""
    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    packed = [
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_ulong(CKA_VALUE_LEN, key_bits // 8),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
    ]
    if extra_attrs:
        for k, v in extra_attrs.items():
            if isinstance(v, bool):
                packed.append(attr_bool(k, v))
            else:
                packed.append(attr_ulong(k, v))
    tmpl = template(*packed)

    mp = mech_pbkdf2(
        CKM_PKCS5_PBKD2,
        salt=salt,
        iterations=iterations,
        prf=prf,
        password=password,
    )

    key_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mp.byref(), tmpl.ptr, tmpl.count, byref(key_h))
    if rv != CKR_OK:
        if rv in _PBE_ERROR_RVS:
            return None
        from pkcs11_check.raw.rv import ckr_name

        raise AssertionError(f"Unexpected CKR from PBKDF2 keygen: {ckr_name(rv)}")
    return key_h.value


class TestPBESHA1DES3:
    """CKM_PBE_SHA1_DES3_EDE_CBC - SHA-1 + 3-key Triple-DES PBE key generation."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

    def test_generate_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")
        handle = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        if handle is None:
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not operational")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_DES3
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_generate_key_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")
        h1 = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        h2 = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        if h1 is None or h2 is None:
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not operational")
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2, "PBE_SHA1_DES3_EDE_CBC must be deterministic"
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)

    def test_different_salt_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")
        ha = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            b"\x00" * 8,
            _ITERATIONS,
        )
        hb = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            b"\xff" * 8,
            _ITERATIONS,
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb, "Different salts must produce different keys"
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)

    def test_different_password_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")
        ha = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            b"PasswordAlpha",
            _SALT,
            _ITERATIONS,
        )
        hb = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            b"PasswordBravo",
            _SALT,
            _ITERATIONS,
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb, "Different passwords must produce different keys"
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)


class TestPBESHA1DES2:
    """CKM_PBE_SHA1_DES2_EDE_CBC - SHA-1 + 2-key Triple-DES PBE key generation."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")

    def test_generate_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")
        handle = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        if handle is None:
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not operational")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_DES2
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_generate_key_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")
        h1 = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        h2 = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        if h1 is None or h2 is None:
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not operational")
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2, "PBE_SHA1_DES2_EDE_CBC must be deterministic"
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)

    def test_different_password_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")
        ha = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            b"PasswordAlpha",
            _SALT,
            _ITERATIONS,
        )
        hb = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            b"PasswordBravo",
            _SALT,
            _ITERATIONS,
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)


class TestPBASHA1:
    """CKM_PBA_SHA1_WITH_SHA1_HMAC - password-based SHA-1 HMAC key generation."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")

    def test_generate_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")
        handle = _pbe_gen_key(
            rs,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKK_SHA_1_HMAC,
            160,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            iv_len=20,
            extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
        )
        if handle is None:
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not operational")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_SHA_1_HMAC
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_generate_key_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")
        h1 = _pbe_gen_key(
            rs,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKK_SHA_1_HMAC,
            160,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            iv_len=20,
            extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
        )
        h2 = _pbe_gen_key(
            rs,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKK_SHA_1_HMAC,
            160,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            iv_len=20,
            extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
        )
        if h1 is None or h2 is None:
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not operational")
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)

    def test_different_salt_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")
        ha = _pbe_gen_key(
            rs,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKK_SHA_1_HMAC,
            160,
            _PASSWORD,
            b"\x00" * 8,
            _ITERATIONS,
            iv_len=20,
            extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
        )
        hb = _pbe_gen_key(
            rs,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKK_SHA_1_HMAC,
            160,
            _PASSWORD,
            b"\xff" * 8,
            _ITERATIONS,
            iv_len=20,
            extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)


class TestPKCS5PBKD2:
    """CKM_PKCS5_PBKD2 - PKCS#5 v2 password-based key derivation (PBKDF2)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

    def test_derive_generic_secret_sha256(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        handle = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        if handle is None:
            pytest.skip("CKM_PKCS5_PBKD2 (HMAC-SHA256) not operational")
        try:
            val = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 32
            assert val != bytes(32), "Derived key must not be all zeros"
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_derive_generic_secret_sha1(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        handle = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            160,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA1,
        )
        if handle is None:
            pytest.skip("CKM_PKCS5_PBKD2 (HMAC-SHA1) not operational")
        try:
            val = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 20
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        h1 = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        h2 = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        if h1 is None or h2 is None:
            pytest.skip("CKM_PKCS5_PBKD2 not operational")
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2, "PBKDF2 must be deterministic"
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)

    def test_different_salt_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        ha = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            b"\x00" * 16,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        hb = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            b"\xff" * 16,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PKCS5_PBKD2 not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)

    def test_different_password_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        ha = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            b"PasswordAlpha",
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        hb = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            b"PasswordBravo",
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PKCS5_PBKD2 not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)

    def test_more_iterations_produces_different_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        ha = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            _SALT,
            1000,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        hb = _pbkdf2_gen_key(
            rs,
            CKK_GENERIC_SECRET,
            256,
            _PASSWORD,
            _SALT,
            2000,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
        )
        if ha is None or hb is None:
            pytest.skip("CKM_PKCS5_PBKD2 not operational")
        try:
            va = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])[CKA_VALUE]
            assert va != vb
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)

    def test_derive_aes_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        handle = _pbkdf2_gen_key(
            rs,
            CKK_AES,
            256,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            CKP_PKCS5_PBKD2_HMAC_SHA256,
            extra_attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        if handle is None:
            pytest.skip("CKM_PKCS5_PBKD2 AES key derivation not operational")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE, CKA_VALUE])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
            assert len(attrs[CKA_VALUE]) == 32
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
