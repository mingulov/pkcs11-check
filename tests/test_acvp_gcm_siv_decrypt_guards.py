"""Regression tests for ACVP AES-GCM-SIV decrypt invalid-vector classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp.aes import test_gcm as gcm


class _GcmSivSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "AES_GCM_SIV"


def _wrong_plaintext(*_args: Any, **_kwargs: Any) -> bytes:
    return b"\x00" * 16


def test_gcm_siv_decrypt_invalid_vector_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged GCM-SIV vector that decrypts must fail (auth break, Type A).

    Phase-2 V1: the decrypt-success path previously had no ``else: fail`` for
    ``test_passed is False``, so a module that returned plaintext for a
    tampered ciphertext/tag was accepted silently.
    """
    vec_id, vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is False
    )

    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "decrypt_single", _wrong_plaintext)
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="invalid GCM-SIV"):
        gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), vec_id, vec)
