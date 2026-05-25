"""Regression tests for Wycheproof ECDH guards."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdh as ecdh


class _EcdhSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ECDH1_DERIVE"


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def _read_zeros(_raw: Any, _session: int, _obj: int, attrs: list[int]) -> dict[int, bytes]:
    return {attr: b"\x00" * 32 for attr in attrs}


def test_invalid_ecdh_without_shared_secret_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid ECDH public points must fail if a provider derives anyway."""
    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(ecdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    vec = next(
        vec
        for vec_id, vec in ecdh._ALL_ECDH_VECTORS
        if vec_id == "ecdh_secp256r1_ecpoint_test.json:tc332-invalid"
    )

    with pytest.raises(pytest.fail.Exception, match="Invalid ECDH vector"):
        ecdh.test_ecdh(_EcdhSession(), "ecdh_secp256r1_ecpoint_test.json:tc332-invalid", vec)
