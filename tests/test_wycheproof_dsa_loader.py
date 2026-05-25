"""Regression tests for Wycheproof DSA vector adaptation."""

from __future__ import annotations

from pkcs11_check.testcases.wycheproof import test_wycheproof_dsa as dsa


def test_der_dsa_vectors_have_pkcs11_p1363_signature() -> None:
    """Valid DER DSA signatures are converted to raw r||s for C_Verify."""
    _vec_id, vec = next(
        (vec_id, item)
        for vec_id, item in dsa._ALL_DSA_VECTORS
        if not item["_is_p1363"] and item["result"] == "valid"
    )
    q = int.from_bytes(bytes.fromhex(vec["_group"]["publicKey"]["q"]), "big")
    q_len = (q.bit_length() + 7) // 8
    sig = bytes.fromhex(vec.get("_pkcs11_sig", ""))

    assert len(sig) == 2 * q_len
    assert sig[0] != 0x30
