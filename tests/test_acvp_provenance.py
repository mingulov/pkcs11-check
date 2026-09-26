"""Regression: ACVP loader stamps _source and _vector_id on every merged vector."""

from __future__ import annotations

import pytest

from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

_ALGORITHM = "ACVP-AES-CBC-1.0"


def test_vectors_carry_source_and_vector_id() -> None:
    if not ACVP_AVAILABLE:
        pytest.skip("ACVP vectors not cloned")
    vs = load_acvp_vectors(_ALGORITHM)
    assert vs, f"no vectors loaded for {_ALGORITHM!r}"
    assert vs[0]["_source"] == f"acvp:{_ALGORITHM}"
    assert vs[0]["_vector_id"].startswith("tcId=")


def test_base_loader_preserves_source_and_vector_id() -> None:
    """Normalized AES dicts keep _source/_vector_id (issue #20 correction)."""
    if not ACVP_AVAILABLE:
        pytest.skip("ACVP vectors not cloned")
    from pkcs11_check.testcases.acvp.aes.base_loader import _load_vectors

    enc, dec = _load_vectors(
        _ALGORITHM,
        {"key": "key", "pt": "pt", "ct_expected": "ct"},
        {"key": "key", "ct": "ct", "pt_expected": "pt"},
    )
    assert enc and dec
    for _vec_id, vec in enc + dec:
        assert vec["_source"] == f"acvp:{_ALGORITHM}", _vec_id
        assert vec["_vector_id"] == f"tcId={vec['tc_id']}", _vec_id


def test_ecma_normalized_vectors_carry_exact_provenance() -> None:
    """Normalized ECMA reports carry source=acvp:ACVP-AES-CCM-ECMA-1.0."""
    if not ACVP_AVAILABLE:
        pytest.skip("ACVP vectors not cloned")
    from pkcs11_check.testcases.acvp.aes.test_ccm import _load_ccm_ecma_vectors

    enc, dec = _load_ccm_ecma_vectors()
    assert len(enc) == 44
    assert len(dec) == 44
    for _vec_id, vec in enc + dec:
        assert vec["_source"] == "acvp:ACVP-AES-CCM-ECMA-1.0", _vec_id
        assert vec["_vector_id"] == f"tcId={vec['tc_id']}", _vec_id
