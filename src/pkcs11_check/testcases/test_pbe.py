"""Tests for password-based encryption and key derivation mechanisms.

Covers CKM_PBE_SHA1_DES3_EDE_CBC, CKM_PBE_SHA1_DES2_EDE_CBC,
CKM_PBA_SHA1_WITH_SHA1_HMAC, and CKM_PKCS5_PBKD2.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from ctypes import byref
from dataclasses import dataclass
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import PackedMechanism, mech_pbe, mech_pbkdf2
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
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
    CKK_CAST,
    CKK_CAST3,
    CKK_CAST128,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_GENERIC_SECRET,
    CKK_RC2,
    CKK_RC4,
    CKK_SHA_1_HMAC,
    CKM_PBA_SHA1_WITH_SHA1_HMAC,
    CKM_PBE_MD2_DES_CBC,
    CKM_PBE_MD5_CAST3_CBC,
    CKM_PBE_MD5_CAST128_CBC,
    CKM_PBE_MD5_CAST_CBC,
    CKM_PBE_MD5_DES_CBC,
    CKM_PBE_SHA1_CAST128_CBC,
    CKM_PBE_SHA1_DES2_EDE_CBC,
    CKM_PBE_SHA1_DES3_EDE_CBC,
    CKM_PBE_SHA1_RC2_40_CBC,
    CKM_PBE_SHA1_RC2_128_CBC,
    CKM_PBE_SHA1_RC4_40,
    CKM_PBE_SHA1_RC4_128,
    CKM_PKCS5_PBKD2,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA1,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
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
from pkcs11_check.testcases.conftest import assert_correct

# CKK_GENERIC_SECRET is the raw integer value 0x10; CKK_SHA_1_HMAC is 0x28.
# Some modules (NSS) return CKK_GENERIC_SECRET for CKM_PBA_SHA1_WITH_SHA1_HMAC keys
# instead of CKK_SHA_1_HMAC, as they do not distinguish HMAC key types.
_CKK_GENERIC_SECRET_INT = int(CKK_GENERIC_SECRET)

pytestmark = pytest.mark.keymgmt

# Runtime rejects for advertised PBE operations. These are visible xfail findings, not passes.
_PBE_ERROR_RVS = {
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
}

_PBE_MECH_NAMES: dict[int, str] = {
    int(CKM_PBE_MD2_DES_CBC): "CKM_PBE_MD2_DES_CBC",
    int(CKM_PBE_MD5_DES_CBC): "CKM_PBE_MD5_DES_CBC",
    int(CKM_PBE_MD5_CAST_CBC): "CKM_PBE_MD5_CAST_CBC",
    int(CKM_PBE_MD5_CAST3_CBC): "CKM_PBE_MD5_CAST3_CBC",
    int(CKM_PBE_MD5_CAST128_CBC): "CKM_PBE_MD5_CAST128_CBC",
    int(CKM_PBE_SHA1_CAST128_CBC): "CKM_PBE_SHA1_CAST128_CBC",
    int(CKM_PBE_SHA1_RC4_128): "CKM_PBE_SHA1_RC4_128",
    int(CKM_PBE_SHA1_RC4_40): "CKM_PBE_SHA1_RC4_40",
    int(CKM_PBE_SHA1_DES3_EDE_CBC): "CKM_PBE_SHA1_DES3_EDE_CBC",
    int(CKM_PBE_SHA1_DES2_EDE_CBC): "CKM_PBE_SHA1_DES2_EDE_CBC",
    int(CKM_PBE_SHA1_RC2_128_CBC): "CKM_PBE_SHA1_RC2_128_CBC",
    int(CKM_PBE_SHA1_RC2_40_CBC): "CKM_PBE_SHA1_RC2_40_CBC",
    int(CKM_PBA_SHA1_WITH_SHA1_HMAC): "CKM_PBA_SHA1_WITH_SHA1_HMAC",
    int(CKM_PKCS5_PBKD2): "CKM_PKCS5_PBKD2",
}


def _expect_pbe_gen_key_rv(rv: int, mech_type: int) -> None:
    mech_name = _PBE_MECH_NAMES[int(mech_type)]
    if rv in _PBE_ERROR_RVS:
        classify(
            "not_operational",
            label=f"{mech_name}:C_GenerateKey",
            operation="C_GenerateKey",
            mechanism=mech_name,
            actual=rv,
            summary=f"{mech_name} advertised but C_GenerateKey is not operational: {ckr_name(rv)}",
        )
    expect_rv(rv, CKR_OK, context=f"{mech_name} C_GenerateKey")


# Test password and salt
_PASSWORD = b"TestPassword123!"
_SALT = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
_ITERATIONS = 1024


@dataclass(frozen=True)
class _LegacyPBECase:
    mechanism: int
    mechanism_name: str
    key_type: int
    key_bits: int
    iv_len: int | None

    @property
    def mechanism_short_name(self) -> str:
        return self.mechanism_name.removeprefix("CKM_")


_LEGACY_PBE_CASES = (
    _LegacyPBECase(CKM_PBE_MD2_DES_CBC, "CKM_PBE_MD2_DES_CBC", CKK_DES, 64, 8),
    _LegacyPBECase(CKM_PBE_MD5_DES_CBC, "CKM_PBE_MD5_DES_CBC", CKK_DES, 64, 8),
    _LegacyPBECase(CKM_PBE_MD5_CAST_CBC, "CKM_PBE_MD5_CAST_CBC", CKK_CAST, 40, 8),
    _LegacyPBECase(CKM_PBE_MD5_CAST3_CBC, "CKM_PBE_MD5_CAST3_CBC", CKK_CAST3, 80, 8),
    _LegacyPBECase(CKM_PBE_MD5_CAST128_CBC, "CKM_PBE_MD5_CAST128_CBC", CKK_CAST128, 128, 8),
    _LegacyPBECase(
        CKM_PBE_SHA1_CAST128_CBC,
        "CKM_PBE_SHA1_CAST128_CBC",
        CKK_CAST128,
        128,
        8,
    ),
    _LegacyPBECase(CKM_PBE_SHA1_RC4_128, "CKM_PBE_SHA1_RC4_128", CKK_RC4, 128, None),
    _LegacyPBECase(CKM_PBE_SHA1_RC4_40, "CKM_PBE_SHA1_RC4_40", CKK_RC4, 40, None),
    _LegacyPBECase(CKM_PBE_SHA1_RC2_128_CBC, "CKM_PBE_SHA1_RC2_128_CBC", CKK_RC2, 128, 8),
    _LegacyPBECase(CKM_PBE_SHA1_RC2_40_CBC, "CKM_PBE_SHA1_RC2_40_CBC", CKK_RC2, 40, 8),
)


# ---------------------------------------------------------------------------
# CK_PBE_PARAMS builder
# ---------------------------------------------------------------------------


def _build_pbe_mech(
    mech_type: int,
    password: bytes,
    salt: bytes,
    iterations: int,
    iv_len: int | None = 8,
) -> PackedMechanism:
    """Build CK_PBE_PARAMS using the public raw packer."""
    return mech_pbe(
        mech_type,
        password=password,
        salt=salt,
        iteration=iterations,
        iv_len=iv_len,
    )


def _pbe_gen_key(
    rs: Any,
    mech_type: int,
    key_type: int,
    key_bits: int,
    password: bytes,
    salt: bytes,
    iterations: int,
    iv_len: int | None = 8,
    extra_attrs: dict[int, Any] | None = None,
) -> tuple[int, PackedMechanism]:
    """Generate a PBE key.

    Returns ``(handle, packed_mechanism)``. Callers that only need the handle
    index with ``[0]``; callers that want to inspect the mechanism's output
    buffers (e.g. ``pm.buffer_bytes("init_vector")``) destructure the tuple.
    Advertised-but-rejected PBE paths become xfail findings for specific CKRs;
    any other CKR raises AssertionError via ``expect_rv``.
    """
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

    pm = _build_pbe_mech(mech_type, password, salt, iterations, iv_len)
    key_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, pm.byref(), tmpl.ptr, tmpl.count, byref(key_h))
    _expect_pbe_gen_key_rv(rv, mech_type)
    return key_h.value, pm


def _pbkdf2_gen_key(
    rs: Any,
    key_type: int,
    key_bits: int,
    password: bytes,
    salt: bytes,
    iterations: int,
    prf: int,
    extra_attrs: dict[int, Any] | None = None,
) -> int:
    """Generate a key via CKM_PKCS5_PBKD2. Returns handle on success."""
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
    _expect_pbe_gen_key_rv(rv, CKM_PKCS5_PBKD2)
    return key_h.value


class TestLegacyPBEVariants:
    """Obsolete PKCS#5/PKCS#12 PBE mechanisms still get semantic coverage."""

    @pytest.mark.parametrize("case", _LEGACY_PBE_CASES, ids=lambda case: case.mechanism_name)
    def test_generate_key(self, p11_raw_session: Any, case: _LegacyPBECase) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.mechanism_short_name):
            pytest.skip(f"{case.mechanism_name} not supported")

        extra_attrs: dict[int, Any] = {}
        if case.key_type in {CKK_CAST, CKK_CAST3, CKK_CAST128, CKK_RC2, CKK_RC4}:
            extra_attrs[CKA_VALUE_LEN] = case.key_bits // 8

        handle, mech = _pbe_gen_key(
            rs,
            case.mechanism,
            case.key_type,
            case.key_bits,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            iv_len=case.iv_len,
            extra_attrs=extra_attrs,
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert_correct(
                actual=attrs[CKA_KEY_TYPE],
                expected=case.key_type,
                label=f"{case.mechanism_name}:CKA_KEY_TYPE readback",
                operation="C_GenerateKey",
                mechanism=case.mechanism_name,
                kind="metadata",
            )
            if case.iv_len is not None:
                iv = mech.buffer_bytes("init_vector")
                assert len(iv) == case.iv_len
                assert iv != b"\x00" * case.iv_len, (
                    f"{case.mechanism_name} accepted CK_PBE_PARAMS but did not write pInitVector"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)


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
        )[0]
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert_correct(
                actual=attrs[CKA_KEY_TYPE],
                expected=CKK_DES3,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:CKA_KEY_TYPE readback",
                operation="C_GenerateKey",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
                kind="metadata",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_generate_key_writes_init_vector(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

        handle, mech = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        try:
            iv = mech.buffer_bytes("init_vector")
            assert len(iv) == 8
            assert iv != b"\x00" * 8, (
                "C_GenerateKey accepted CK_PBE_PARAMS but did not write pInitVector"
            )
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
        )[0]
        h2 = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )[0]
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:C_GenerateKey determinism",
                operation="C_GenerateKey",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
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
        )[0]
        hb = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            _PASSWORD,
            b"\xff" * 8,
            _ITERATIONS,
        )[0]
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
        )[0]
        hb = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKK_DES3,
            192,
            b"PasswordBravo",
            _SALT,
            _ITERATIONS,
        )[0]
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
        )[0]
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert_correct(
                actual=attrs[CKA_KEY_TYPE],
                expected=CKK_DES2,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:CKA_KEY_TYPE readback",
                operation="C_GenerateKey",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
                kind="metadata",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_generate_key_writes_init_vector(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")

        handle, mech = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )
        try:
            iv = mech.buffer_bytes("init_vector")
            assert len(iv) == 8
            assert iv != b"\x00" * 8, (
                "C_GenerateKey accepted CK_PBE_PARAMS but did not write pInitVector"
            )
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
        )[0]
        h2 = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            _PASSWORD,
            _SALT,
            _ITERATIONS,
        )[0]
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:C_GenerateKey determinism",
                operation="C_GenerateKey",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
            )
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
        )[0]
        hb = _pbe_gen_key(
            rs,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKK_DES2,
            128,
            b"PasswordBravo",
            _SALT,
            _ITERATIONS,
        )[0]
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
        """CKM_PBA_SHA1_WITH_SHA1_HMAC generates a key with CKA_KEY_TYPE=CKK_SHA_1_HMAC.

        NSS deviation: NSS generates a key with CKA_KEY_TYPE=CKK_GENERIC_SECRET (0x10)
        instead of CKK_SHA_1_HMAC (0x28) for CKM_PBA_SHA1_WITH_SHA1_HMAC -- NSS does
        not differentiate HMAC key types and uses the generic secret key type.
        Tracked in docs/module-issues.md under NSS.
        """
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
        )[0]
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            actual_key_type = int(attrs[CKA_KEY_TYPE])
            if actual_key_type == _CKK_GENERIC_SECRET_INT:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"CKM_PBA_SHA1_WITH_SHA1_HMAC generated CKK_GENERIC_SECRET "
                    f"(0x{actual_key_type:02x}) instead of CKK_SHA_1_HMAC (0x28) -- "
                    f"module does not distinguish HMAC key types",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec CKM_PBA_SHA1_WITH_SHA1_HMAC, CKK_SHA_1_HMAC",
                )
                classify(
                    "honest_deviation",
                    kind="metadata",
                    label="CKM_PBA_SHA1_WITH_SHA1_HMAC:CKA_KEY_TYPE",
                    operation="C_GenerateKey",
                    mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
                    summary=(
                        f"Module returns CKK_GENERIC_SECRET (0x{actual_key_type:02x}) instead of "
                        f"CKK_SHA_1_HMAC (0x28) for CKM_PBA_SHA1_WITH_SHA1_HMAC key generation"
                    ),
                )
            assert_correct(
                actual=attrs[CKA_KEY_TYPE],
                expected=CKK_SHA_1_HMAC,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:CKA_KEY_TYPE readback",
                operation="C_GenerateKey",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
                kind="metadata",
            )
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
        )[0]
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
        )[0]
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:C_GenerateKey determinism",
                operation="C_GenerateKey",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
            )
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
        )[0]
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
        )[0]
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
        try:
            v1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_PKCS5_PBKD2:C_GenerateKey determinism",
                operation="C_GenerateKey",
                mechanism="CKM_PKCS5_PBKD2",
            )
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
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE, CKA_VALUE])
            assert_correct(
                actual=attrs[CKA_KEY_TYPE],
                expected=CKK_AES,
                label="CKM_PKCS5_PBKD2:CKA_KEY_TYPE readback",
                operation="C_GenerateKey",
                mechanism="CKM_PKCS5_PBKD2",
                kind="metadata",
            )
            assert len(attrs[CKA_VALUE]) == 32
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
