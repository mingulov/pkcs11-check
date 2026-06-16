"""Regression tests for object-test setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_object


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_session_object_skips_missing_aes_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Session object rows should not call AES setup without AES_KEY_GEN."""

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(raw_recipes, "gen_aes_key", _unexpected_keygen)

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_object.TestSessionObjects().test_create_secret_key_with_label(_session())


def test_session_object_aes_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised-but-rejected AES setup is visible xfail evidence."""

    def _keygen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(raw_recipes, "gen_aes_key", _keygen_reject)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_object.TestSessionObjects().test_create_secret_key_with_label(_session("AES_KEY_GEN"))


def test_ec_keypair_attributes_skip_missing_ec_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EC attribute rows should skip when no EC key-generation mechanism is advertised."""

    def _unexpected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("EC keypair generation should have been guarded")

    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _unexpected_keypair)

    with pytest.raises(pytest.skip.Exception, match="EC_KEY_PAIR_GEN not supported"):
        test_object.TestKeyPairAttributes().test_ec_keypair_attributes(_session())


def test_imported_key_verifies_signature_skips_missing_rsa_sign_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA import/sign rows should skip before setup when SHA256_RSA_PKCS is absent."""

    def _unexpected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("RSA keypair generation should have been guarded")

    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _unexpected_keypair)
    monkeypatch.setattr(
        test_object, "skip_unless_create_object_supported", lambda *_a, **_k: None
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_object.TestKeyImportExport().test_imported_key_verifies_signature(
            _session("RSA_PKCS_KEY_PAIR_GEN")
        )


def test_import_rsa_public_key_xfails_malformed_generated_attrs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Import-copy rows should classify malformed generated RSA attrs as setup evidence."""

    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(
        test_object,
        "read_attributes",
        lambda *_args, **_kwargs: {
            CKA_MODULUS: b"",
            CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
        },
    )
    monkeypatch.setattr(test_object, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_object, "skip_unless_create_object_supported", lambda *_a, **_k: None
    )

    with pytest.raises(pytest.xfail.Exception, match="generated RSA public key"):
        test_object.TestKeyImportExport().test_import_rsa_public_key(
            _session("RSA_PKCS_KEY_PAIR_GEN")
        )


def test_import_rsa_public_key_import_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider rejecting RSA public import is setup/import xfail evidence."""

    attrs = {
        CKA_MODULUS: (2**2048 - 159).to_bytes(256, "big"),
        CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
    }

    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(test_object, "read_attributes", lambda *_args, **_kwargs: attrs)
    monkeypatch.setattr(test_object, "create_object", _import_reject)
    monkeypatch.setattr(test_object, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_object, "skip_unless_create_object_supported", lambda *_a, **_k: None
    )

    with pytest.raises(pytest.xfail.Exception, match="RSA public key import not operational"):
        test_object.TestKeyImportExport().test_import_rsa_public_key(
            _session("RSA_PKCS_KEY_PAIR_GEN")
        )
