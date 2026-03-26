"""Tests for the pkcs11_check.raw package and helpers."""

from __future__ import annotations

import ctypes

import pytest


def test_raw_package_exports_core_symbols() -> None:
    from pkcs11_check.raw import CK_ATTRIBUTE, CK_MECHANISM, CKR_OK, RawPKCS11
    from pkcs11_check.raw.api import RawPKCS11 as ApiRawPKCS11

    assert RawPKCS11 is not None
    assert RawPKCS11 is ApiRawPKCS11
    assert CK_MECHANISM is not None
    assert CK_ATTRIBUTE is not None
    assert CKR_OK == 0


def test_cktemplate_builds_array_and_keeps_native_lengths() -> None:
    from pkcs11_check.raw import CK_ATTRIBUTE
    from pkcs11_check.raw.pack import TemplateArg, attr_bool, attr_bytes, attr_ulong

    template = TemplateArg(
        attr_ulong(0x0000, 4),
        attr_bool(0x0104, True),
        attr_bytes(0x0011, b"abc"),
    )

    assert template.count == 3
    assert isinstance(template.array[0], CK_ATTRIBUTE)
    assert template.array[0].type == 0x0000
    assert template.array[0].ulValueLen == ctypes.sizeof(ctypes.c_ulong)
    assert template.array[1].ulValueLen == ctypes.sizeof(ctypes.c_ubyte)
    assert template.array[2].ulValueLen == 3
    assert template.ptr is not None


def test_mech_simple_sets_null_parameter() -> None:
    from pkcs11_check.raw import CK_MECHANISM
    from pkcs11_check.raw.pack import mech_simple

    mech = mech_simple(0x1080)

    assert isinstance(mech.ck, CK_MECHANISM)
    assert mech.ck.mechanism == 0x1080
    assert mech.ck.pParameter is None
    assert mech.ck.ulParameterLen == 0


def test_expect_rv_allows_expected_values() -> None:
    from pkcs11_check.raw.rv import expect_rv

    assert expect_rv(0x00000000, 0x00000000) == 0x00000000
    assert expect_rv(0x00000007, 0x00000000, 0x00000007) == 0x00000007


def test_expect_rv_raises_for_unexpected_value() -> None:
    from pkcs11_check.raw.rv import expect_rv

    with pytest.raises(AssertionError, match="CKR_ARGUMENTS_BAD"):
        expect_rv(0x00000007, 0x00000000)
