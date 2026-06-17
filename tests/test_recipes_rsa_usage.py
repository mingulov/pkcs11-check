"""RSA keypair usage/purpose modelling (single-purpose-capable gen_rsa_keypair).

Cloud-KMS-class providers (kmsp11) back single-purpose keys: a CryptoKey is
ASYMMETRIC_SIGN xor ASYMMETRIC_DECRYPT, never both. The legacy multi-purpose
default (CKA_SIGN+CKA_DECRYPT / CKA_VERIFY+CKA_ENCRYPT) is unsatisfiable there
and is correctly rejected with CKR_TEMPLATE_INCONSISTENT. Purpose is a
crypto-visible attribute, so it must be *declared* by the caller, never silently
negotiated away. These tests pin the explicit-usage API.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.raw import recipes
from pkcs11_check.raw.recipes import RSAUsage, gen_rsa_keypair, rsa_usage_attrs
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_VERIFY,
)
from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail


def test_rsa_usage_attrs_sign_only_has_no_decrypt() -> None:
    pub, priv = rsa_usage_attrs(RSAUsage.SIGN)
    assert priv == {CKA_SIGN: True}
    assert pub == {CKA_VERIFY: True}
    assert CKA_DECRYPT not in priv
    assert CKA_ENCRYPT not in pub


def test_rsa_usage_attrs_decrypt_only_has_no_sign() -> None:
    pub, priv = rsa_usage_attrs(RSAUsage.DECRYPT)
    assert priv == {CKA_DECRYPT: True}
    assert pub == {CKA_ENCRYPT: True}
    assert CKA_SIGN not in priv
    assert CKA_VERIFY not in pub


def test_rsa_usage_attrs_multipurpose_has_all_four() -> None:
    pub, priv = rsa_usage_attrs(RSAUsage.SIGN | RSAUsage.DECRYPT)
    assert priv == {CKA_SIGN: True, CKA_DECRYPT: True}
    assert pub == {CKA_VERIFY: True, CKA_ENCRYPT: True}


def _capture_gen_keypair(monkeypatch: Any) -> dict[str, Any]:
    """Replace recipes.gen_keypair with a capture stub; return the captured kwargs."""
    captured: dict[str, Any] = {}

    def fake_gen_keypair(
        raw: Any,
        session: int,
        mechanism: int,
        *,
        pub_base: Any,
        priv_base: Any,
        public_attrs: Any,
        private_attrs: Any,
        pub_skip: Any = None,
    ) -> tuple[int, int]:
        captured["public_attrs"] = dict(public_attrs)
        captured["private_attrs"] = dict(private_attrs)
        return (101, 102)

    monkeypatch.setattr(recipes, "gen_keypair", fake_gen_keypair)
    return captured


def test_gen_rsa_keypair_sign_usage_omits_decrypt(monkeypatch: Any) -> None:
    captured = _capture_gen_keypair(monkeypatch)
    pub_h, priv_h = gen_rsa_keypair(SimpleNamespace(), 7, usage=RSAUsage.SIGN)
    assert (pub_h, priv_h) == (101, 102)
    assert captured["private_attrs"].get(CKA_SIGN) is True
    assert CKA_DECRYPT not in captured["private_attrs"]
    assert captured["public_attrs"].get(CKA_VERIFY) is True
    assert CKA_ENCRYPT not in captured["public_attrs"]
    # public exponent is always present (65537, NSS requires it)
    assert captured["public_attrs"][CKA_PUBLIC_EXPONENT] == b"\x01\x00\x01"


def test_gen_rsa_keypair_default_stays_multipurpose(monkeypatch: Any) -> None:
    captured = _capture_gen_keypair(monkeypatch)
    gen_rsa_keypair(SimpleNamespace(), 7)
    # back-compat: unchanged callers still get a sign+decrypt / verify+encrypt key
    assert captured["private_attrs"].get(CKA_SIGN) is True
    assert captured["private_attrs"].get(CKA_DECRYPT) is True
    assert captured["public_attrs"].get(CKA_VERIFY) is True
    assert captured["public_attrs"].get(CKA_ENCRYPT) is True
    assert captured["public_attrs"][CKA_PUBLIC_EXPONENT] == b"\x01\x00\x01"


def test_gen_rsa_keypair_explicit_attrs_still_override(monkeypatch: Any) -> None:
    captured = _capture_gen_keypair(monkeypatch)
    gen_rsa_keypair(
        SimpleNamespace(),
        7,
        usage=RSAUsage.SIGN,
        private_attrs={CKA_DECRYPT: True},
    )
    # caller's explicit escape hatch wins over the usage-derived caps
    assert captured["private_attrs"].get(CKA_SIGN) is True
    assert captured["private_attrs"].get(CKA_DECRYPT) is True


def _capture_gen_rsa_keypair(monkeypatch: Any) -> dict[str, Any]:
    """Replace recipes.gen_rsa_keypair with a capture stub; return captured kwargs."""
    captured: dict[str, Any] = {}

    def fake_gen_rsa_keypair(
        raw: Any,
        session: int,
        bits: int = 2048,
        *,
        usage: Any = None,
        public_attrs: Any = None,
        private_attrs: Any = None,
    ) -> tuple[int, int]:
        captured["usage"] = usage
        return (1, 2)

    monkeypatch.setattr(recipes, "gen_rsa_keypair", fake_gen_rsa_keypair)
    return captured


def _fake_rs() -> SimpleNamespace:
    return SimpleNamespace(raw=SimpleNamespace(), sh=7, has_mechanism=lambda _m: True)


def test_gen_rsa_keypair_or_xfail_forwards_sign_usage(monkeypatch: Any) -> None:
    captured = _capture_gen_rsa_keypair(monkeypatch)
    pub, priv = gen_rsa_keypair_or_xfail(_fake_rs(), usage=RSAUsage.SIGN)
    assert (pub, priv) == (1, 2)
    assert captured["usage"] == RSAUsage.SIGN


def test_gen_rsa_keypair_or_xfail_default_usage_is_multipurpose(monkeypatch: Any) -> None:
    captured = _capture_gen_rsa_keypair(monkeypatch)
    gen_rsa_keypair_or_xfail(_fake_rs())
    assert captured["usage"] == RSAUsage.SIGN | RSAUsage.DECRYPT
