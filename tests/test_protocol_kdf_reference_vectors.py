"""Reference-vector tests for protocol KDF assertions."""

from __future__ import annotations

from pkcs11_check.testcases import test_sp800_108_kdf, test_tls12


def test_sp800_108_counter_reference_vector() -> None:
    assert (
        test_sp800_108_kdf._sp800_108_counter_hmac_sha256_reference(
            test_sp800_108_kdf._BASE_KEY_BYTES,
            test_sp800_108_kdf._LABEL,
            test_sp800_108_kdf._CONTEXT,
            128,
        ).hex()
        == "caff7a6a35ca9b35afcc64fa658d8bc2"
    )
    assert (
        test_sp800_108_kdf._sp800_108_counter_hmac_sha256_reference(
            test_sp800_108_kdf._BASE_KEY_BYTES,
            test_sp800_108_kdf._LABEL,
            test_sp800_108_kdf._CONTEXT,
            256,
        ).hex()
        == "b88f2b0575ec7271d57a76d5dc05355edbb56652e0a19e1788661f2b473e35a3"
    )


def test_tls12_prf_sha256_reference_vector() -> None:
    assert (
        test_tls12._tls12_prf_sha256(
            test_tls12._PRE_MASTER_SECRET,
            b"key expansion",
            test_tls12._CLIENT_RANDOM,
            test_tls12._SERVER_RANDOM,
            32,
        ).hex()
        == "4ac38c4d46e5ff44538c63cd6644009fd1aa1b19a81b76452615cb3f94ce61ea"
    )
