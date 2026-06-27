"""Regression tests for Wycheproof HMAC invalid-vector classification.

Phase-2 V2: HMAC invalid vectors were exercised as *produce* (C_Sign + compare)
operations, so a fresh correct tag never matched the modified expected tag and
rejection was never tested. Re-framed to verify-and-reject: a module that
verifies an invalid (forged) HMAC tag as valid is a crypto-correctness break
(crypto -> fail). A valid MAC that the module rejects (e.g. an unsupported
truncated tag length) is an honest deviation -> xfail.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_hmac as hmac


def _first(result: str) -> tuple[str, dict[str, Any]]:
    hit = next(((cid, v) for cid, v in hmac._ALL_HMAC_VECTORS if v["result"] == result), None)
    if hit is None:
        pytest.skip(
            "Wycheproof HMAC vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    return hit


class _HmacSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "SHA_1_HMAC"


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def test_hmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid HMAC tag that verifies must fail (forged tag accepted)."""
    vec_id, vec = _first("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)


def test_hmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid HMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)


def test_hmac_valid_vector_rejected_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid HMAC vector the module fails to verify is an honest deviation (xfail)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception, match="did not verify a valid HMAC tag"):
        hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)
