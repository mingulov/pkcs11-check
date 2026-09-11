"""Tests for password-based encryption and key derivation mechanisms.

Covers CKM_PBE_SHA1_DES3_EDE_CBC, CKM_PBE_SHA1_DES2_EDE_CBC,
CKM_PBA_SHA1_WITH_SHA1_HMAC, and CKM_PKCS5_PBKD2.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from collections.abc import Callable
from ctypes import byref
from dataclasses import dataclass
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
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
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

# CKK_GENERIC_SECRET is the raw integer value 0x10; CKK_SHA_1_HMAC is 0x28.
# Some modules return CKK_GENERIC_SECRET for CKM_PBA_SHA1_WITH_SHA1_HMAC keys
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
        C.classify(
            "not_operational",
            label=f"{mech_name}:C_GenerateKey",
            operation="C_GenerateKey",
            mechanism=mech_name,
            actual=rv,
            summary=f"{mech_name} advertised but C_GenerateKey is not operational: {ckr_name(rv)}",
        )
    expect_rv(rv, CKR_OK, context=f"{mech_name} C_GenerateKey")


_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _record_attribute_mismatch(
    *,
    label: str,
    expected: str,
    actual: str,
    kind: str,
    mechanism: str,
) -> C.Classification:
    """Record a provider-value mismatch without interpreting values as CKR codes."""
    return C.record_as(
        "wrong_result",
        kind=kind,
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual}; expected {expected}",
        detail={
            "attribute": {
                "expected": expected,
                "actual": actual,
            }
        },
    )


def _record_parameter_mismatch(
    *,
    label: str,
    expected: str,
    actual: str,
    mechanism: str,
) -> C.Classification:
    """Record a wrong mechanism-parameter output without fabricating CKR evidence."""
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_GenerateKey",
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual}; expected {expected}",
        detail={
            "parameter": {
                "name": "pInitVector",
                "expected": expected,
                "actual": actual,
            }
        },
    )


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest recorded hard result after all cleanup has completed."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            _KIND_PRIORITY.get(record.kind or "", 0),
            _SEVERITY_PRIORITY.get(record.severity, 0),
        ),
    )
    C.raise_for_record(strongest)


def _read_attribute(
    attrs: dict[Any, Any],
    attr: Any,
    *,
    label: str,
    mechanism: str,
) -> Any:
    """Read one provider attribute while retaining structured absence evidence."""
    return attr_or_record(
        attrs,
        attr,
        label=f"{label} (producer_mechanism={mechanism})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )


def _acquire_second_or_cleanup(
    rs: Any,
    first_handle: int,
    acquire: Callable[[], int],
) -> int:
    """Acquire a paired handle without leaking the first if the second acquisition fails."""
    try:
        return acquire()
    except BaseException:
        destroy_quietly(rs.raw, rs.sh, first_handle)
        raise


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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            key_type = _read_attribute(
                attrs,
                CKA_KEY_TYPE,
                label=f"{case.mechanism_name}:CKA_KEY_TYPE readback",
                mechanism=case.mechanism_name,
            )
            if key_type is not MISSING_ATTRIBUTE and key_type != case.key_type:
                hard_results.append(
                    _record_attribute_mismatch(
                        label=f"{case.mechanism_name}:CKA_KEY_TYPE readback",
                        expected=f"{case.key_type!r}",
                        actual=f"{key_type!r}",
                        kind="metadata",
                        mechanism=case.mechanism_name,
                    )
                )
            if case.iv_len is not None:
                iv = mech.buffer_bytes("init_vector")
                if iv == b"\x00" * case.iv_len:
                    hard_results.append(
                        _record_parameter_mismatch(
                            label=f"{case.mechanism_name}:pInitVector",
                            expected="non-zero IV",
                            actual=f"{iv!r}",
                            mechanism=case.mechanism_name,
                        )
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)


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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            key_type = _read_attribute(
                attrs,
                CKA_KEY_TYPE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:CKA_KEY_TYPE readback",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            if key_type is not MISSING_ATTRIBUTE and key_type != CKK_DES3:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES3_EDE_CBC:CKA_KEY_TYPE readback",
                        expected=f"{CKK_DES3!r}",
                        actual=f"{key_type!r}",
                        kind="metadata",
                        mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        hard_results: list[C.Classification] = []
        try:
            iv = mech.buffer_bytes("init_vector")
            if iv == b"\x00" * 8:
                hard_results.append(
                    _record_parameter_mismatch(
                        label="CKM_PBE_SHA1_DES3_EDE_CBC:pInitVector",
                        expected="non-zero IV",
                        actual=f"{iv!r}",
                        mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        h2 = _acquire_second_or_cleanup(
            rs,
            h1,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBE_SHA1_DES3_EDE_CBC,
                CKK_DES3,
                192,
                _PASSWORD,
                _SALT,
                _ITERATIONS,
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])
            v1 = _read_attribute(
                attrs_1,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:C_GenerateKey determinism:first",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            attrs_2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])
            v2 = _read_attribute(
                attrs_2,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:C_GenerateKey determinism:second",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            if v1 is not MISSING_ATTRIBUTE and v2 is not MISSING_ATTRIBUTE and v1 != v2:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES3_EDE_CBC:C_GenerateKey determinism",
                        expected=f"{v2!r}",
                        actual=f"{v1!r}",
                        kind="crypto",
                        mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBE_SHA1_DES3_EDE_CBC,
                CKK_DES3,
                192,
                _PASSWORD,
                b"\xff" * 8,
                _ITERATIONS,
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:different-salt:first",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:different-salt:second",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES3_EDE_CBC:different-salt",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBE_SHA1_DES3_EDE_CBC,
                CKK_DES3,
                192,
                b"PasswordBravo",
                _SALT,
                _ITERATIONS,
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:different-password:first",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES3_EDE_CBC:different-password:second",
                mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES3_EDE_CBC:different-password",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PBE_SHA1_DES3_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)


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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            key_type = _read_attribute(
                attrs,
                CKA_KEY_TYPE,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:CKA_KEY_TYPE readback",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
            )
            if key_type is not MISSING_ATTRIBUTE and key_type != CKK_DES2:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES2_EDE_CBC:CKA_KEY_TYPE readback",
                        expected=f"{CKK_DES2!r}",
                        actual=f"{key_type!r}",
                        kind="metadata",
                        mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        hard_results: list[C.Classification] = []
        try:
            iv = mech.buffer_bytes("init_vector")
            if iv == b"\x00" * 8:
                hard_results.append(
                    _record_parameter_mismatch(
                        label="CKM_PBE_SHA1_DES2_EDE_CBC:pInitVector",
                        expected="non-zero IV",
                        actual=f"{iv!r}",
                        mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        h2 = _acquire_second_or_cleanup(
            rs,
            h1,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBE_SHA1_DES2_EDE_CBC,
                CKK_DES2,
                128,
                _PASSWORD,
                _SALT,
                _ITERATIONS,
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])
            v1 = _read_attribute(
                attrs_1,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:C_GenerateKey determinism:first",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
            )
            attrs_2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])
            v2 = _read_attribute(
                attrs_2,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:C_GenerateKey determinism:second",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
            )
            if v1 is not MISSING_ATTRIBUTE and v2 is not MISSING_ATTRIBUTE and v1 != v2:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES2_EDE_CBC:C_GenerateKey determinism",
                        expected=f"{v2!r}",
                        actual=f"{v1!r}",
                        kind="crypto",
                        mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBE_SHA1_DES2_EDE_CBC,
                CKK_DES2,
                128,
                b"PasswordBravo",
                _SALT,
                _ITERATIONS,
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:different-password:first",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PBE_SHA1_DES2_EDE_CBC:different-password:second",
                mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBE_SHA1_DES2_EDE_CBC:different-password",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PBE_SHA1_DES2_EDE_CBC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)


class TestPBASHA1:
    """CKM_PBA_SHA1_WITH_SHA1_HMAC - password-based SHA-1 HMAC key generation."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")

    def test_generate_key(self, p11_raw_session: Any) -> None:
        """CKM_PBA_SHA1_WITH_SHA1_HMAC generates a key with CKA_KEY_TYPE=CKK_SHA_1_HMAC.

        Some modules generate a key with CKA_KEY_TYPE=CKK_GENERIC_SECRET (0x10)
        instead of CKK_SHA_1_HMAC (0x28) for CKM_PBA_SHA1_WITH_SHA1_HMAC -- they do
        not differentiate HMAC key types and use the generic secret key type.
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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            key_type = _read_attribute(
                attrs,
                CKA_KEY_TYPE,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:CKA_KEY_TYPE readback",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
            )
            if key_type is not MISSING_ATTRIBUTE and key_type == _CKK_GENERIC_SECRET_INT:
                actual_key_type = int(key_type)
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"CKM_PBA_SHA1_WITH_SHA1_HMAC generated CKK_GENERIC_SECRET "
                    f"(0x{actual_key_type:02x}) instead of CKK_SHA_1_HMAC (0x28) -- "
                    f"module does not distinguish HMAC key types",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec CKM_PBA_SHA1_WITH_SHA1_HMAC, CKK_SHA_1_HMAC",
                )
                C.classify(
                    "honest_deviation",
                    kind="metadata",
                    label="CKM_PBA_SHA1_WITH_SHA1_HMAC:CKA_KEY_TYPE",
                    operation="C_GenerateKey",
                    mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
                    summary=(
                        f"Module returns CKK_GENERIC_SECRET (0x{actual_key_type:02x}) instead of "
                        f"CKK_SHA_1_HMAC (0x28) for CKM_PBA_SHA1_WITH_SHA1_HMAC key generation"
                    ),
                    detail={
                        "attribute": {
                            "expected": repr(CKK_SHA_1_HMAC),
                            "actual": repr(key_type),
                        }
                    },
                )
            if key_type is not MISSING_ATTRIBUTE and key_type != CKK_SHA_1_HMAC:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBA_SHA1_WITH_SHA1_HMAC:CKA_KEY_TYPE readback",
                        expected=f"{CKK_SHA_1_HMAC!r}",
                        actual=f"{key_type!r}",
                        kind="metadata",
                        mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        h2 = _acquire_second_or_cleanup(
            rs,
            h1,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBA_SHA1_WITH_SHA1_HMAC,
                CKK_SHA_1_HMAC,
                160,
                _PASSWORD,
                _SALT,
                _ITERATIONS,
                iv_len=20,
                extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])
            v1 = _read_attribute(
                attrs_1,
                CKA_VALUE,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:C_GenerateKey determinism:first",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
            )
            attrs_2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])
            v2 = _read_attribute(
                attrs_2,
                CKA_VALUE,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:C_GenerateKey determinism:second",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
            )
            if v1 is not MISSING_ATTRIBUTE and v2 is not MISSING_ATTRIBUTE and v1 != v2:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBA_SHA1_WITH_SHA1_HMAC:C_GenerateKey determinism",
                        expected=f"{v2!r}",
                        actual=f"{v1!r}",
                        kind="crypto",
                        mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbe_gen_key(
                rs,
                CKM_PBA_SHA1_WITH_SHA1_HMAC,
                CKK_SHA_1_HMAC,
                160,
                _PASSWORD,
                b"\xff" * 8,
                _ITERATIONS,
                iv_len=20,
                extra_attrs={CKA_SIGN: True, CKA_VERIFY: True},
            )[0],
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:different-salt:first",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PBA_SHA1_WITH_SHA1_HMAC:different-salt:second",
                mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PBA_SHA1_WITH_SHA1_HMAC:different-salt",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PBA_SHA1_WITH_SHA1_HMAC",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)


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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
            val = _read_attribute(
                attrs,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:CKA_VALUE SHA-256 readback",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if val is not MISSING_ATTRIBUTE and (val.__class__ is not bytes or val.__len__() != 32):
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:CKA_VALUE SHA-256 readback",
                        expected="32-byte bytes",
                        actual=f"{val!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
            elif val is not MISSING_ATTRIBUTE and val == bytes(32):
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:CKA_VALUE SHA-256 readback",
                        expected="non-zero 32-byte key",
                        actual=f"{val!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
            val = _read_attribute(
                attrs,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:CKA_VALUE SHA-1 readback",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if val is not MISSING_ATTRIBUTE and (val.__class__ is not bytes or val.__len__() != 20):
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:CKA_VALUE SHA-1 readback",
                        expected="20-byte bytes",
                        actual=f"{val!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)

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
        h2 = _acquire_second_or_cleanup(
            rs,
            h1,
            lambda: _pbkdf2_gen_key(
                rs,
                CKK_GENERIC_SECRET,
                256,
                _PASSWORD,
                _SALT,
                _ITERATIONS,
                CKP_PKCS5_PBKD2_HMAC_SHA256,
            ),
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_1 = read_attributes(rs.raw, rs.sh, h1, [CKA_VALUE])
            v1 = _read_attribute(
                attrs_1,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:C_GenerateKey determinism:first",
                mechanism="CKM_PKCS5_PBKD2",
            )
            attrs_2 = read_attributes(rs.raw, rs.sh, h2, [CKA_VALUE])
            v2 = _read_attribute(
                attrs_2,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:C_GenerateKey determinism:second",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if v1 is not MISSING_ATTRIBUTE and v2 is not MISSING_ATTRIBUTE and v1 != v2:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:C_GenerateKey determinism",
                        expected=f"{v2!r}",
                        actual=f"{v1!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, h1)
            destroy_quietly(rs.raw, rs.sh, h2)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbkdf2_gen_key(
                rs,
                CKK_GENERIC_SECRET,
                256,
                _PASSWORD,
                b"\xff" * 16,
                _ITERATIONS,
                CKP_PKCS5_PBKD2_HMAC_SHA256,
            ),
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:different-salt:first",
                mechanism="CKM_PKCS5_PBKD2",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:different-salt:second",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:different-salt",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbkdf2_gen_key(
                rs,
                CKK_GENERIC_SECRET,
                256,
                b"PasswordBravo",
                _SALT,
                _ITERATIONS,
                CKP_PKCS5_PBKD2_HMAC_SHA256,
            ),
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:different-password:first",
                mechanism="CKM_PKCS5_PBKD2",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:different-password:second",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:different-password",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)

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
        hb = _acquire_second_or_cleanup(
            rs,
            ha,
            lambda: _pbkdf2_gen_key(
                rs,
                CKK_GENERIC_SECRET,
                256,
                _PASSWORD,
                _SALT,
                2000,
                CKP_PKCS5_PBKD2_HMAC_SHA256,
            ),
        )
        hard_results: list[C.Classification] = []
        try:
            attrs_a = read_attributes(rs.raw, rs.sh, ha, [CKA_VALUE])
            va = _read_attribute(
                attrs_a,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:different-iterations:first",
                mechanism="CKM_PKCS5_PBKD2",
            )
            attrs_b = read_attributes(rs.raw, rs.sh, hb, [CKA_VALUE])
            vb = _read_attribute(
                attrs_b,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:different-iterations:second",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if va is not MISSING_ATTRIBUTE and vb is not MISSING_ATTRIBUTE and va == vb:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:different-iterations",
                        expected="different derived values",
                        actual=f"{va!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, ha)
            destroy_quietly(rs.raw, rs.sh, hb)
        _raise_strongest(hard_results)

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
        hard_results: list[C.Classification] = []
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE, CKA_VALUE])
            key_type = _read_attribute(
                attrs,
                CKA_KEY_TYPE,
                label="CKM_PKCS5_PBKD2:CKA_KEY_TYPE readback",
                mechanism="CKM_PKCS5_PBKD2",
            )
            value = _read_attribute(
                attrs,
                CKA_VALUE,
                label="CKM_PKCS5_PBKD2:CKA_VALUE readback",
                mechanism="CKM_PKCS5_PBKD2",
            )
            if key_type is not MISSING_ATTRIBUTE and key_type != CKK_AES:
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:CKA_KEY_TYPE readback",
                        expected=f"{CKK_AES!r}",
                        actual=f"{key_type!r}",
                        kind="metadata",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
            if value is not MISSING_ATTRIBUTE and (
                value.__class__ is not bytes or value.__len__() != 32
            ):
                hard_results.append(
                    _record_attribute_mismatch(
                        label="CKM_PKCS5_PBKD2:CKA_VALUE readback",
                        expected="32-byte bytes",
                        actual=f"{value!r}",
                        kind="crypto",
                        mechanism="CKM_PKCS5_PBKD2",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)
        _raise_strongest(hard_results)
