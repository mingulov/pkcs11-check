"""Reference-vector tests for protocol KDF assertions."""

from __future__ import annotations

from pkcs11_check.testcases import test_ike, test_sp800_108_kdf, test_tls12


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


def test_ike_prf_data_as_key_hmac_sha256_reference_vector() -> None:
    assert (
        test_ike._ike_prf_hmac_sha256_reference(
            test_ike._BASE_KEY_BYTES,
            test_ike._NONCE_I,
            test_ike._NONCE_R,
            data_as_key=True,
        ).hex()
        == "909be39279fec3ad8b16546a956974ee435bb4acfa8f0c9167f0f019ff977f45"
    )


def test_ike2_prf_plus_hmac_sha256_reference_vector() -> None:
    assert (
        test_ike._ike2_prf_plus_hmac_sha256_reference(
            test_ike._BASE_KEY_BYTES,
            test_ike._NONCE_I + test_ike._NONCE_R,
            32,
        ).hex()
        == "e3703ee905295e6c0141c98f382e17e9df07a5d0e7fb5d1d5eb45e117022cbb1"
    )


def test_ike1_prf_hmac_sha256_reference_vector() -> None:
    assert (
        test_ike._ike1_prf_hmac_sha256_reference(
            test_ike._BASE_KEY_BYTES,
            test_ike._IKE1_KEYGXY_BYTES,
            test_ike._NONCE_I,
            test_ike._NONCE_R,
            key_number=0,
        ).hex()
        == "eb8c20534feb1be5d11d3c71f12056e677b6d7122f7183348ce353614de363be"
    )


def test_ike1_extended_hmac_sha256_reference_vector() -> None:
    assert (
        test_ike._ike1_extended_hmac_sha256_reference(
            test_ike._BASE_KEY_BYTES,
            test_ike._IKE1_KEYGXY_BYTES,
            test_ike._NONCE_I + test_ike._NONCE_R + test_ike._SPI_I + test_ike._SPI_R,
            32,
        ).hex()
        == "9672b961d4f0556b9bbfdf40707ff9494c6b95f1c916653575420a7b657d863d"
    )
