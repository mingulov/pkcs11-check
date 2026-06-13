"""Regression: Wycheproof loader stamps _source and _vector_id on every vector."""

from __future__ import annotations

from pkcs11_check.testcases.wycheproof.wycheproof_loader import load_vectors


def test_vectors_carry_source_and_vector_id() -> None:
    vs = load_vectors("aes_gcm_test.json")
    assert vs and vs[0]["_source"] == "wycheproof:aes_gcm_test.json"
    assert vs[0]["_vector_id"] == f"tcId={vs[0]['tcId']}"
