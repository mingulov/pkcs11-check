"""Regression tests for padding-oracle setup validation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT
from pkcs11_check.testcases.security import test_padding_oracle


def test_rsa_public_numbers_guard_xfails_empty_modulus(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = SimpleNamespace(raw=object(), sh=1)
    monkeypatch.setattr(
        test_padding_oracle,
        "read_attributes",
        lambda *_args: {CKA_MODULUS: b"", CKA_PUBLIC_EXPONENT: b"\x01\x00\x01"},
    )

    with pytest.raises(pytest.xfail.Exception, match="unusable RSA public modulus"):
        test_padding_oracle._read_rsa_public_numbers_or_xfail(rs, 10)


def test_rsa_public_numbers_guard_xfails_tiny_modulus(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = SimpleNamespace(raw=object(), sh=1)
    monkeypatch.setattr(
        test_padding_oracle,
        "read_attributes",
        lambda *_args: {CKA_MODULUS: b"\x03", CKA_PUBLIC_EXPONENT: b"\x03"},
    )

    with pytest.raises(pytest.xfail.Exception, match="unusable RSA public modulus"):
        test_padding_oracle._read_rsa_public_numbers_or_xfail(rs, 10)


def test_rsa_public_numbers_guard_returns_valid_modulus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(raw=object(), sh=1)
    modulus = (2**2048 - 159).to_bytes(256, "big")
    monkeypatch.setattr(
        test_padding_oracle,
        "read_attributes",
        lambda *_args: {CKA_MODULUS: modulus, CKA_PUBLIC_EXPONENT: b"\x01\x00\x01"},
    )

    n, e, k = test_padding_oracle._read_rsa_public_numbers_or_xfail(rs, 10)

    assert n == int.from_bytes(modulus, "big")
    assert e == 65537
    assert k == 256
