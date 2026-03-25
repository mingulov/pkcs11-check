"""Tests for the pkcs11_check.raw package and helpers."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from unittest.mock import patch

import pytest


def test_raw_package_exports_core_symbols() -> None:
    from pkcs11_check.raw import CK_ATTRIBUTE, CK_MECHANISM, CKR_OK, RawPKCS11
    from pkcs11_check.raw.api import RawPKCS11 as ApiRawPKCS11

    assert RawPKCS11 is not None
    assert RawPKCS11 is ApiRawPKCS11
    assert CK_MECHANISM is not None
    assert CK_ATTRIBUTE is not None
    assert CKR_OK == 0


def test_raw_from_lib_uses_all_available_funclists() -> None:
    from pkcs11_check.raw import RawPKCS11
    from pkcs11_check.raw.bridge import raw_from_lib

    lib = SimpleNamespace(
        _raw_funclist_ptr=101,
        _raw_funclist3_ptr=202,
        _raw_funclist32_ptr=303,
    )

    with patch.object(RawPKCS11, "__init__", return_value=None) as init_mock:
        raw = raw_from_lib(lib)

    assert isinstance(raw, RawPKCS11)
    init_mock.assert_called_once_with(101, funclist3_ptr=202, funclist32_ptr=303)


def test_raw_from_module_uses_module_lib() -> None:
    from pkcs11_check.raw import RawPKCS11
    from pkcs11_check.raw.bridge import raw_from_module

    lib = SimpleNamespace(
        _raw_funclist_ptr=11,
        _raw_funclist3_ptr=22,
        _raw_funclist32_ptr=33,
    )
    module = SimpleNamespace(lib=lib)

    with patch.object(RawPKCS11, "__init__", return_value=None) as init_mock:
        raw = raw_from_module(module)

    assert isinstance(raw, RawPKCS11)
    init_mock.assert_called_once_with(11, funclist3_ptr=22, funclist32_ptr=33)


def test_cktemplate_builds_array_and_keeps_native_lengths() -> None:
    from pkcs11_check.raw import CK_ATTRIBUTE
    from pkcs11_check.raw.template import CKTemplate, attr_bool, attr_bytes, attr_ulong

    template = CKTemplate(
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
    from pkcs11_check.raw.mechanism import mech_simple

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


def test_ckr_is_ok_returns_true_for_ok() -> None:
    from pkcs11_check.raw.rv import ckr_is_ok

    assert ckr_is_ok(0x00000000) is True


def test_ckr_is_ok_returns_false_for_error() -> None:
    from pkcs11_check.raw.rv import ckr_is_ok

    assert ckr_is_ok(0x00000007) is False  # CKR_ARGUMENTS_BAD


def test_ckr_in_matches_acceptable() -> None:
    from pkcs11_check.raw.rv import ckr_in

    assert ckr_in(0x00000000, 0x00000000, 0x00000007) is True
    assert ckr_in(0x00000007, 0x00000000, 0x00000007) is True


def test_ckr_in_rejects_unacceptable() -> None:
    from pkcs11_check.raw.rv import ckr_in

    assert ckr_in(0x00000005, 0x00000000, 0x00000007) is False
