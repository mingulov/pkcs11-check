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
