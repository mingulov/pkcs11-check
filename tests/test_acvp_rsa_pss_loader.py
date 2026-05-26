"""Regression tests for ACVP RSA-PSS vector filtering."""

from __future__ import annotations

from pkcs11_check.testcases.acvp.rsa.base_loader import load_sigver_pss_vectors


def test_sigver_pss_skips_shake_mask_function_vectors() -> None:
    """PKCS#11 RSA-PSS params cannot express ACVP shake-* maskFunction rows."""
    vectors = load_sigver_pss_vectors()
    vector_ids = {vec_id for vec_id, _ in vectors}

    assert "SigVer-pss-ver-SHA3-256-tc199" not in vector_ids
    assert "SigVer-pss-ver-SHA3-256-tc209" not in vector_ids
    assert "SigVer-pss-ver-SHA3-256-tc255" not in vector_ids
    assert any(vec["hash_alg"] == "SHA3-256" for _, vec in vectors)
