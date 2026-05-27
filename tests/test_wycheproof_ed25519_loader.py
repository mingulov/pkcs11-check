"""Regression tests for Wycheproof Ed25519 vector adaptation."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_ed25519 as ed25519


class _EdDsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "EDDSA"


def test_wycheproof_ed25519_import_uses_raw_rfc8032_public_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKK_EC_EDWARDS CKA_EC_POINT is raw public-key bytes, not DER wrapped."""
    vec_id, vec = next(
        (candidate_id, candidate_vec)
        for candidate_id, candidate_vec in ed25519._ED25519_VECTORS
        if candidate_vec["result"] == "valid"
    )
    pk_bytes = bytes.fromhex(vec["_pk"]["pk"])
    captured: dict[str, bytes] = {}

    def fake_import_eddsa_public_key(
        raw: object,
        session: int,
        *,
        ec_params: bytes,
        public_key: bytes,
        attrs: dict[int, Any],
    ) -> int:
        captured["ec_point"] = public_key
        return 1

    monkeypatch.setattr(ed25519, "select_eddsa_public_key_encoding", lambda *args, **kwargs: "raw")
    monkeypatch.setattr(
        ed25519,
        "import_eddsa_public_key_with_supported_encoding",
        fake_import_eddsa_public_key,
    )
    monkeypatch.setattr(
        ed25519,
        "verify_eddsa_signature_with_supported_params",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(ed25519, "destroy_quietly", lambda *args: None)

    ed25519.test_ed25519_wycheproof(_EdDsaSession(), vec_id, vec)

    assert captured["ec_point"] == pk_bytes
    assert len(captured["ec_point"]) == 32


def test_wycheproof_ed448_import_uses_raw_rfc8032_public_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKK_EC_EDWARDS CKA_EC_POINT is raw public-key bytes, not DER wrapped."""
    vec_id, vec = next(
        (candidate_id, candidate_vec)
        for candidate_id, candidate_vec in ed25519._ED448_VECTORS
        if candidate_vec["result"] == "valid"
    )
    pk_bytes = bytes.fromhex(vec["_pk"]["pk"])
    captured: dict[str, bytes] = {}

    def fake_import_eddsa_public_key(
        raw: object,
        session: int,
        *,
        ec_params: bytes,
        public_key: bytes,
        attrs: dict[int, Any],
    ) -> int:
        captured["ec_point"] = public_key
        return 1

    monkeypatch.setattr(ed25519, "select_eddsa_public_key_encoding", lambda *args, **kwargs: "raw")
    monkeypatch.setattr(
        ed25519,
        "import_eddsa_public_key_with_supported_encoding",
        fake_import_eddsa_public_key,
    )
    monkeypatch.setattr(
        ed25519,
        "verify_eddsa_signature_with_supported_params",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(ed25519, "destroy_quietly", lambda *args: None)

    ed25519.test_ed448_wycheproof(_EdDsaSession(), vec_id, vec)

    assert captured["ec_point"] == pk_bytes
    assert len(captured["ec_point"]) == 57
