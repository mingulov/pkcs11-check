"""Regression tests for Wycheproof ChaCha20-Poly1305 invalid-vector classification.

Phase-2 V2: ChaCha20-Poly1305 invalid vectors were exercised as *encrypt*
operations, so a fresh correct ciphertext never matched the modified expected
output and rejection was never tested. Re-framed to decrypt-and-reject: a
module that decrypts a forged/modified ciphertext or tag is a crypto-correctness
break (Type A -> fail).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_chacha as chacha


def _first(result: str) -> tuple[str, dict[str, Any]]:
    hit = next(((cid, v) for cid, v in chacha._CHACHA_VECTORS if v["result"] == result), None)
    if hit is None:
        pytest.skip(
            "Wycheproof ChaCha vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    return hit


class _ChaChaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "CHACHA20_POLY1305"


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def test_chacha_invalid_vector_decrypt_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid ChaCha20-Poly1305 vector that decrypts must fail (forged accepted)."""
    vec_id, vec = _first("invalid")
    monkeypatch.setattr(chacha, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(chacha, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(chacha, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        chacha.test_chacha20_poly1305(_ChaChaSession(), vec_id, vec)


def test_chacha_valid_vector_decrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid ChaCha20-Poly1305 vector that decrypts to the expected plaintext passes."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(chacha, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(chacha, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(chacha, "destroy_quietly", lambda *_a: None)

    chacha.test_chacha20_poly1305(_ChaChaSession(), vec_id, vec)


def test_chacha_valid_vector_wrong_plaintext_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid ChaCha20-Poly1305 vector that decrypts to wrong plaintext is a finding (fail)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(chacha, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(chacha, "decrypt_single", lambda *_a, **_k: b"\xde\xad\xbe\xef")
    monkeypatch.setattr(chacha, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="plaintext mismatch"):
        chacha.test_chacha20_poly1305(_ChaChaSession(), vec_id, vec)
