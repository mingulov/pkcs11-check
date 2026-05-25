"""Tests for extended HKDF mechanisms.

Covers CKM_HKDF_DATA and CKM_HKDF_KEY_GEN.
CKM_HKDF_DERIVE is tested in test_kdf.py.

OASIS spec: hkdf_mechanisms.md

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_hkdf, mech_simple
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKM_HKDF_DATA,
    CKM_HKDF_DERIVE,
    CKM_HKDF_KEY_GEN,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
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
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

pytestmark = pytest.mark.keymgmt

# Common derive error RVs
_DERIVE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
}

# Keygen error RVs
_KEYGEN_ERROR_RVS = {
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
}


def _gen_hkdf_key(rs: Any, key_type: int, bits: int = 256) -> int:
    """Generate a key via CKM_HKDF_KEY_GEN."""
    from ctypes import byref

    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    packed = [
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_ulong(CKA_VALUE_LEN, bits // 8),
        attr_bool(CKA_DERIVE, True),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_TOKEN, False),
    ]
    tmpl = template(*packed)
    mech = mech_simple(CKM_HKDF_KEY_GEN)
    key_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
    expect_rv(rv, CKR_OK, context="CKM_HKDF_KEY_GEN C_GenerateKey")
    return key_h.value


def _create_base_key(rs: Any) -> int:
    """Create a GENERIC_SECRET key suitable for HKDF derivation."""
    ikm = bytes(range(32))
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_GENERIC_SECRET,
        ikm,
        attrs={
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        },
    )


def _hkdf_derive(rs: Any, base_key: int, salt: bytes, info: bytes) -> int:
    """Derive a GENERIC_SECRET key via HKDF."""
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_HKDF_DERIVE,
        attrs={
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_TOKEN: False,
        },
        mech_param=mech_hkdf(
            CKM_HKDF_DERIVE,
            hash_mech=CKM_SHA256,
            extract=True,
            expand=True,
            salt=salt,
            info=info,
        ),
    )


def _hkdf_data_derive(rs: Any, base_key: int, salt: bytes, info: bytes) -> int:
    """Derive a GENERIC_SECRET key via CKM_HKDF_DATA."""
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        CKM_HKDF_DATA,
        attrs={
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_TOKEN: False,
        },
        mech_param=mech_hkdf(
            CKM_HKDF_DATA,
            hash_mech=CKM_SHA256,
            extract=True,
            expand=True,
            salt=salt,
            info=info,
        ),
    )


@pytest.mark.requires_v30
class TestHKDFKeyGen:
    """CKM_HKDF_KEY_GEN tests - generate keys for HKDF input keying material."""

    @pytest.mark.parametrize(
        "key_type",
        [
            CKK_HKDF,
            pytest.param(
                CKK_GENERIC_SECRET,
                marks=pytest.mark.xfail(
                    reason="CKM_HKDF_KEY_GEN should produce CKK_HKDF per spec",
                ),
            ),
        ],
        ids=["CKK_HKDF", "CKK_GENERIC_SECRET"],
    )
    def test_hkdf_key_gen_basic(
        self,
        p11_raw_session: Any,
        key_type: int,
    ) -> None:
        """Generate a key via CKM_HKDF_KEY_GEN with the given key type."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")

        handle = 0
        try:
            handle = _gen_hkdf_key(rs, key_type, 256)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _KEYGEN_ERROR_RVS,
                f"CKM_HKDF_KEY_GEN advertised but key_type={key_type:#x} keygen rejected",
            )
        try:
            assert handle != 0
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                handle,
                [CKA_KEY_TYPE, CKA_VALUE, CKA_DERIVE],
            )
            assert attrs[CKA_KEY_TYPE] == key_type
            value = attrs[CKA_VALUE]
            assert len(value) == 32  # 256 bits = 32 bytes
            assert attrs[CKA_DERIVE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_hkdf_key_gen_usable_for_derive(self, p11_raw_session: Any) -> None:
        """Key generated via CKM_HKDF_KEY_GEN can be used with CKM_HKDF_DERIVE."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")

        # Try CKK_HKDF first, then CKK_GENERIC_SECRET
        base_key: int | None = None
        rejects: list[str] = []
        for kt in (CKK_HKDF, CKK_GENERIC_SECRET):
            try:
                base_key = _gen_hkdf_key(rs, kt, 256)
                break
            except AssertionError as exc:
                if not is_known_error(exc, _KEYGEN_ERROR_RVS):
                    raise
                rejects.append(str(exc))
        if base_key is None:
            pytest.xfail(
                "CKM_HKDF_KEY_GEN advertised but no tested key type is operational: "
                + "; ".join(rejects)
            )

        derived = 0
        try:
            derived = _hkdf_derive(rs, base_key, b"salt-value", b"info-value")
            okm = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(okm) == 32
        except (AssertionError, Exception) as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "HKDF_DERIVE with HKDF_KEY_GEN key failed")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)


@pytest.mark.requires_v30
class TestHKDFData:
    """CKM_HKDF_DATA tests - derive data objects via HKDF."""

    def test_hkdf_data_derive(self, p11_raw_session: Any) -> None:
        """Derive data/key using CKM_HKDF_DATA mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = _create_base_key(rs)
        derived = 0
        try:
            derived = _hkdf_data_derive(rs, base_key, b"salt", b"info")
            value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(value) == 32  # 256 bits = 32 bytes
            assert value != bytes(32), "Derived value should not be all zeros"
        except (AssertionError, Exception) as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "HKDF_DATA derive failed")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_hkdf_data_deterministic(self, p11_raw_session: Any) -> None:
        """Same HKDF_DATA inputs produce identical output."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = _create_base_key(rs)
        derived_1 = 0
        derived_2 = 0
        try:
            derived_1 = _hkdf_data_derive(rs, base_key, b"det-salt", b"det-info")
            derived_2 = _hkdf_data_derive(rs, base_key, b"det-salt", b"det-info")
            val_1 = read_attributes(rs.raw, rs.sh, derived_1, [CKA_VALUE])[CKA_VALUE]
            val_2 = read_attributes(rs.raw, rs.sh, derived_2, [CKA_VALUE])[CKA_VALUE]
            assert val_1 == val_2, "HKDF_DATA must be deterministic"
        except (AssertionError, Exception) as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "HKDF_DATA derive failed")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived_1:
                destroy_quietly(rs.raw, rs.sh, derived_1)
            if derived_2:
                destroy_quietly(rs.raw, rs.sh, derived_2)

    def test_hkdf_data_different_info_different_output(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Different 'info' values produce different HKDF_DATA output."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = _create_base_key(rs)
        derived_a = 0
        derived_b = 0
        try:
            derived_a = _hkdf_data_derive(rs, base_key, b"salt", b"info-alpha")
            derived_b = _hkdf_data_derive(rs, base_key, b"salt", b"info-bravo")
            val_a = read_attributes(rs.raw, rs.sh, derived_a, [CKA_VALUE])[CKA_VALUE]
            val_b = read_attributes(rs.raw, rs.sh, derived_b, [CKA_VALUE])[CKA_VALUE]
            assert val_a != val_b, "Different info strings must produce different output"
        except (AssertionError, Exception) as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "HKDF_DATA derive failed")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived_a:
                destroy_quietly(rs.raw, rs.sh, derived_a)
            if derived_b:
                destroy_quietly(rs.raw, rs.sh, derived_b)
