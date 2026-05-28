"""Classification meta-tests for symmetric-cipher *_or_xfail legs (Phase 5 P1b).

The produce-leg helpers (``_encrypt_or_xfail`` / ``_sign_or_xfail`` etc.) used to
xfail only on CKR_MECHANISM_INVALID. A module that advertises the mechanism may
return *other* clean runtime-reject codes (e.g. CKR_FUNCTION_NOT_SUPPORTED,
CKR_KEY_TYPE_INCONSISTENT) at the use site -> those are advertised-but-not-
operational -> ``xfail``. A non-CKR (Python) error still propagates as a real
failure.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import (
    test_aria,
    test_blowfish,
    test_camellia,
    test_des,
    test_salsa20,
    test_twofish,
)

_CKR_EXC = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))


def _patch_encrypt(
    monkeypatch: pytest.MonkeyPatch, module: Any, *, raise_exc: BaseException
) -> None:
    def _raise(*_a: Any, **_k: Any) -> bytes:
        raise raise_exc

    monkeypatch.setattr(module, "encrypt_single", _raise)


@pytest.mark.parametrize(
    "module",
    [test_camellia, test_aria, test_twofish, test_blowfish],
)
def test_encrypt_other_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch, module: Any) -> None:
    _patch_encrypt(monkeypatch, module, raise_exc=_CKR_EXC)
    with pytest.raises(pytest.xfail.Exception):
        module._encrypt_or_xfail(object(), 1, 2, 0x1234, b"data")


@pytest.mark.parametrize(
    "module",
    [test_camellia, test_aria, test_twofish, test_blowfish],
)
def test_encrypt_non_ckr_error_propagates(monkeypatch: pytest.MonkeyPatch, module: Any) -> None:
    _patch_encrypt(monkeypatch, module, raise_exc=ValueError("harness bug"))
    with pytest.raises(ValueError, match="harness bug"):
        module._encrypt_or_xfail(object(), 1, 2, 0x1234, b"data")


def test_des_encrypt_other_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_encrypt(monkeypatch, test_des, raise_exc=_CKR_EXC)
    with pytest.raises(pytest.xfail.Exception):
        test_des._encrypt_or_xfail(object(), 1, 2, 0x1234, b"data")


def test_salsa20_encrypt_other_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_encrypt(monkeypatch, test_salsa20, raise_exc=_CKR_EXC)
    with pytest.raises(pytest.xfail.Exception):
        test_salsa20._salsa20_encrypt_or_xfail(object(), 1, 2, b"data", mech_param=b"\x00" * 8)
