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
