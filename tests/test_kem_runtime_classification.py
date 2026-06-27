"""Regression tests for ML-KEM runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKR_GENERAL_ERROR,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_kem


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_decapsulate_aes_key_sizes_request_value_len(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_attrs: list[dict[int, Any]] = []

    def _encapsulate(*_args: Any, attrs: dict[int, Any], **_kwargs: Any) -> tuple[int, bytes]:
        captured_attrs.append(attrs)
        return 101, b"ciphertext"

    def _decapsulate(*_args: Any, attrs: dict[int, Any], **_kwargs: Any) -> int:
        captured_attrs.append(attrs)
        return 102

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", _encapsulate)
    monkeypatch.setattr(test_kem, "decapsulate_key", _decapsulate)
    monkeypatch.setattr(
        test_kem,
        "read_attributes",
        lambda _raw, _sh, _handle, _attrs: {CKA_VALUE: b"x" * 24},
    )
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    test_kem.TestMLKEMDecapsulation().test_decapsulate_aes_key_sizes(
        _session("ML_KEM"),
        24,
    )

    assert len(captured_attrs) == 2
    assert all(attrs[CKA_VALUE_LEN] == 24 for attrs in captured_attrs)


def test_decapsulate_aes_key_sizes_template_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encapsulate(*_args: Any, **_kwargs: Any) -> tuple[int, bytes]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", _encapsulate)
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM.*not operational"):
        test_kem.TestMLKEMDecapsulation().test_decapsulate_aes_key_sizes(
            _session("ML_KEM"),
            16,
        )


def test_encapsulate_returns_ciphertext_template_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encapsulate(*_args: Any, **_kwargs: Any) -> tuple[int, bytes]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", _encapsulate)
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM.*not operational"):
        test_kem.TestMLKEMEncapsulateDecapsulate().test_encapsulate_returns_ciphertext_and_key(
            _session("ML_KEM"),
        )


def test_decapsulate_generic_secret_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encapsulate(*_args: Any, **_kwargs: Any) -> tuple[int, bytes]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", _encapsulate)
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM.*not operational"):
        test_kem.TestMLKEMDecapsulation().test_decapsulate_generic_secret(
            _session("ML_KEM"),
        )


def test_decapsulate_invalid_ciphertext_generic_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = SimpleNamespace(C_DecapsulateKey=lambda *_args: CKR_GENERAL_ERROR)

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", lambda *_args, **_kwargs: (3, b"ciphertext"))
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM invalid ciphertext length"):
        test_kem.TestMLKEMNegative().test_decapsulate_invalid_ciphertext_length(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name == "ML_KEM"),
        )


def test_decapsulate_invalid_ciphertext_accepted_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    # Task 4z: the local _xfail_if_kem_negative_rv + bare assert was retired onto
    # the shared classify_negative_rv. A truncated ciphertext that decapsulates
    # cleanly (CKR_OK) is a crypto-correctness break -> fail.
    from _pytest.outcomes import Failed, XFailed

    raw = SimpleNamespace(C_DecapsulateKey=lambda *_args: test_kem.CKR_OK)

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", lambda *_args, **_kwargs: (3, b"ciphertext"))
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(Failed, match="accepted invalid") as excinfo:
        test_kem.TestMLKEMNegative().test_decapsulate_invalid_ciphertext_length(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name == "ML_KEM"),
        )
    assert not isinstance(excinfo.value, XFailed)


def test_decapsulate_invalid_template_success_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    # Phase 3 crypto: accepting CKA_VALUE in the decapsulation template lets the
    # caller dictate the derived key's secret bytes -- a crypto-correctness break
    # -> fail (was previously hidden as xfail).
    from _pytest.outcomes import Failed, XFailed

    raw = SimpleNamespace(C_DecapsulateKey=lambda *_args: test_kem.CKR_OK)

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", lambda *_args, **_kwargs: (3, b"ciphertext"))
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(Failed, match="inject CKA_VALUE") as excinfo:
        test_kem.TestMLKEMNegative().test_decapsulate_with_invalid_attributes_in_template(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name == "ML_KEM"),
        )
    assert not isinstance(excinfo.value, XFailed)


def test_wrong_key_type_object_handle_invalid_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = SimpleNamespace(C_EncapsulateKey=lambda *_args: CKR_OBJECT_HANDLE_INVALID)

    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_aes_key", lambda *_args, **_kwargs: 9)
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM wrong-key-type reject"):
        test_kem.TestMLKEMNegative().test_kem_mechanisms_with_wrong_key_type(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name == "ML_KEM"),
        )


def test_wrong_key_decapsulate_generic_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _decapsulate(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_kem, "encapsulate_key", lambda *_args, **_kwargs: (3, b"ciphertext"))
    monkeypatch.setattr(test_kem, "decapsulate_key", _decapsulate)
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM wrong-key decapsulate"):
        test_kem.TestMLKEMEncapsulateDecapsulate().test_decapsulate_with_wrong_key_fails_or_differs(
            _session("ML_KEM"),
        )
