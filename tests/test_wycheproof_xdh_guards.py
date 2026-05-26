"""Regression tests for Wycheproof X25519/X448 guards."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_x25519 as xdh


class _XdhSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ECDH1_DERIVE"


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached after invalid public-key decode")


def _fail_if_duplicate_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached for duplicate XDH vector")


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def _read_zeros(_raw: Any, _session: int, _obj: int, attrs: list[int]) -> dict[int, bytes]:
    return {attr: b"\x00" * 56 for attr in attrs}


def test_duplicate_xdh_container_vector_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASN/PEM/JWK duplicates should not rerun identical PKCS#11 inputs."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _fail_if_duplicate_called)
    vec_id = "x25519_asn_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 XDH operation input"):
        xdh.test_xdh(_XdhSession(), vec_id, vec)


def test_invalid_xdh_public_decode_is_accepted_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed invalid public vectors should not become capability skips."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _fail_if_called)
    vec = next(
        vec
        for vec_id, vec in xdh._ALL_XDH_VECTORS
        if vec_id == "x25519_jwk_test.json:tc528-invalid"
    )

    try:
        xdh.test_xdh(_XdhSession(), "x25519_jwk_test.json:tc528-invalid", vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"invalid XDH public-key decode was skipped: {exc}")


def test_invalid_xdh_public_length_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed public bytes must fail if a provider derives anyway."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _handle)
    monkeypatch.setattr(xdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec = next(
        vec
        for vec_id, vec in xdh._ALL_XDH_VECTORS
        if vec_id == "x448_test.json:tc76-invalid"
    )

    with pytest.raises(pytest.fail.Exception, match="Invalid X25519/X448 vector"):
        xdh.test_xdh(_XdhSession(), "x448_test.json:tc76-invalid", vec)
