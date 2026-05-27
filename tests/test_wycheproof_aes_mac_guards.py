"""Regression tests for Wycheproof AES MAC/AEAD/keywrap invalid-vector classification.

Phase-2 V2: these families were exercised as *produce* operations
(sign/encrypt/wrap), so a fresh correct output never matched the modified
expected output and rejection of invalid vectors was never tested. They are
re-framed to the verify/decrypt/unwrap direction; a module that ACCEPTS an
invalid vector is a crypto-correctness break (Type A -> fail).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes


def _vec(vecs: list[tuple[str, dict[str, Any]]], vec_id: str) -> dict[str, Any]:
    return next(v for cid, v in vecs if cid == vec_id)


def _first(vecs: list[tuple[str, dict[str, Any]]], result: str) -> tuple[str, dict[str, Any]]:
    return next((cid, v) for cid, v in vecs if v["result"] == result)


class _AesSession:
    raw = object()
    sh = 1

    def __init__(self, mech: str) -> None:
        self._mech = mech

    def has_mechanism(self, name: str) -> bool:
        return name == self._mech


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


# --- AES-CMAC (Task 2d) ---


def test_cmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid CMAC tag that verifies must fail (forged-tag accepted)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_valid_vector_rejected_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CMAC vector that does not verify is a finding (fail)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="valid CMAC vector"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


# --- AES-GMAC (Task 2e) ---


def test_gmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid GMAC tag that verifies must fail (forged-tag accepted)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid GMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_valid_vector_rejected_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid GMAC vector that does not verify is a finding (fail)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="valid GMAC vector"):
        aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)
