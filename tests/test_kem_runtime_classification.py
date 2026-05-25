"""Regression tests for ML-KEM runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_VALUE, CKA_VALUE_LEN, CKR_TEMPLATE_INCONSISTENT
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
