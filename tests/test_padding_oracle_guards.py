"""Regression tests for padding-oracle setup validation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

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


@pytest.mark.parametrize(
    ("label", "mechanism"),
    [
        ("RSA PKCS#1 invalid", "CKM_RSA_PKCS"),
        ("RSA OAEP invalid cat-2", "CKM_RSA_PKCS_OAEP"),
    ],
)
def test_structured_invalid_decrypt_success_is_a_finding(label: str, mechanism: str) -> None:
    with pytest.raises(Failed, match="deliberately invalid encoding"):
        test_padding_oracle._record_invalid_decrypt_outcome(
            set(), b"garbage", None, label=label, mechanism=mechanism
        )


def test_oaep_cat1_success_is_compared_as_an_observable_outcome() -> None:
    outcomes: set[str] = set()
    test_padding_oracle._record_invalid_decrypt_outcome(
        outcomes,
        b"plaintext",
        None,
        label="RSA OAEP cat-1",
        mechanism="CKM_RSA_PKCS_OAEP",
        must_reject=False,
    )
    assert outcomes == {"CKR_OK"}
