"""Regression tests for ACVP ECDH runtime/setup classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKA_EC_POINT
from pkcs11_check.testcases.acvp import test_acvp_ecdh


def test_generated_ec_point_decode_error_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
    )
    generated = iter([(1, 2), (3, 4)])

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        test_acvp_ecdh,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: b"\x04\xff\xff"},
    )
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="malformed CKA_EC_POINT"):
        test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-521")
