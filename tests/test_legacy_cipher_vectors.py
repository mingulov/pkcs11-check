"""Coverage guardrails for legacy cipher known-answer vectors."""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import (
    CKM_BLOWFISH_CBC,
    CKM_CAST128_CBC,
    CKM_CAST128_ECB,
    CKM_RC2_CBC,
    CKM_RC2_ECB,
    CKM_RC4,
    CKM_RC5_CBC,
    CKM_RC5_ECB,
)
from pkcs11_check.testcases.mechanism_helpers import build_params_from_vector
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY
from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors


def test_cast128_encrypt_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_CAST128_ECB): "cast128_ecb.json",
        int(CKM_CAST128_CBC): "cast128_cbc.json",
    }

    for mech_id, vector_file in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["key_hex"]
            assert vec["plaintext_hex"]
            assert vec["ciphertext_hex"]


def test_rc2_encrypt_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_RC2_ECB): "rc2_ecb.json",
        int(CKM_RC2_CBC): "rc2_cbc.json",
    }

    for mech_id, vector_file in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["key_hex"]
            assert vec["plaintext_hex"]
            assert vec["ciphertext_hex"]
            assert vec["params"]["effective_bits"] == 128


def test_rc2_cbc_vector_params_replay_effective_bits_and_iv() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC2_CBC)]
    vec = load_positive_vectors("rc2_cbc.json")[0]

    params = build_params_from_vector(int(CKM_RC2_CBC), config.param_recipe, vec)

    assert params.params.ulEffectiveBits == vec["params"]["effective_bits"]
    assert bytes(params.params.iv) == bytes.fromhex(vec["params"]["iv_hex"])


def test_rc5_encrypt_mechanisms_have_rfc2040_kat_vectors() -> None:
    expected = {
        int(CKM_RC5_ECB): "rc5_ecb.json",
        int(CKM_RC5_CBC): "rc5_cbc.json",
    }

    for mech_id, vector_file in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["key_hex"]
            assert vec["plaintext_hex"]
            assert vec["ciphertext_hex"]
            assert vec["params"]["source"] == "RFC 2040 section 9.3"
            assert vec["params"]["word_bits"] == 32
            assert vec["params"]["rounds"] in {8, 12, 16}


def test_rc5_cbc_vector_params_replay_rounds_word_bits_and_iv() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC5_CBC)]
    vec = load_positive_vectors("rc5_cbc.json")[0]

    params = build_params_from_vector(int(CKM_RC5_CBC), config.param_recipe, vec)

    assert params.params.ulWordsize == vec["params"]["word_bits"]
    assert params.params.ulRounds == vec["params"]["rounds"]
    assert ctypes.string_at(params.params.pIv, params.params.ulIvLen) == bytes.fromhex(
        vec["params"]["iv_hex"]
    )


def test_rc4_encrypt_mechanism_has_rfc6229_kat_vectors() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC4)]
    assert config.vector_file == "rc4.json"

    vectors = load_positive_vectors("rc4.json")
    assert vectors, "rc4.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["key_hex"]
        assert vec["plaintext_hex"] == "00" * 32
        assert vec["ciphertext_hex"]
        assert vec["params"]["source"] == "RFC 6229 section 2"
        assert vec["params"]["offset"] == 0


def test_blowfish_cbc_encrypt_mechanism_has_schneier_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_BLOWFISH_CBC)]
    assert config.vector_file == "blowfish_cbc.json"

    vectors = load_positive_vectors("blowfish_cbc.json")
    assert vectors, "blowfish_cbc.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["key_hex"] == "0000000000000000"
        assert vec["plaintext_hex"] == "0000000000000000"
        assert vec["ciphertext_hex"] == "4ef997456198dd78"
        assert vec["params"]["iv_hex"] == "0000000000000000"
        assert vec["params"]["source"] == (
            "Bruce Schneier Blowfish ECB test data, replayed as single-block CBC with zero IV"
        )
