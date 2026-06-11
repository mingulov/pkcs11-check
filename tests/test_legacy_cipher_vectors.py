"""Coverage guardrails for legacy cipher known-answer vectors."""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import (
    CKM_BLOWFISH_CBC,
    CKM_CAST128_CBC,
    CKM_CAST128_ECB,
    CKM_CAST128_MAC_GENERAL,
    CKM_IDEA_CBC,
    CKM_IDEA_ECB,
    CKM_IDEA_MAC_GENERAL,
    CKM_RC2_CBC,
    CKM_RC2_ECB,
    CKM_RC4,
    CKM_RC5_CBC,
    CKM_RC5_ECB,
    CKM_RC5_MAC_GENERAL,
    CKM_TWOFISH_CBC,
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


def test_rc5_mac_general_mechanism_has_rfc2040_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC5_MAC_GENERAL)]
    assert config.vector_file == "rc5_mac_general.json"

    vectors = load_positive_vectors("rc5_mac_general.json")
    assert vectors, "rc5_mac_general.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["mechanism_name"] == "CKM_RC5_MAC_GENERAL"
        assert vec["key_hex"] == "0102030405060708"
        assert vec["input_hex"] == "ffffffffffffffff"
        assert vec["mac_hex"] == "e493f1c1bb4d6e8c"
        assert vec["params"]["source"] == (
            "RFC 2040 section 9.3; one-block CBC-MAC with zero IV equals RC5-ECB"
        )
        assert vec["params"]["word_bits"] == 32
        assert vec["params"]["rounds"] == 12
        assert vec["params"]["mac_len"] == 8


def test_rc5_mac_general_vector_params_replay_length_rounds_and_word_bits() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC5_MAC_GENERAL)]
    vector = next(
        vec
        for vec in load_positive_vectors("rc5_mac_general.json")
        if vec["mechanism_name"] == "CKM_RC5_MAC_GENERAL"
    )

    params = build_params_from_vector(int(CKM_RC5_MAC_GENERAL), config.param_recipe, vector)

    assert params.params.ulWordsize == vector["params"]["word_bits"]
    assert params.params.ulRounds == vector["params"]["rounds"]
    assert params.params.ulMacLength == vector["params"]["mac_len"]


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


def test_idea_encrypt_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_IDEA_ECB): "idea_ecb.json",
        int(CKM_IDEA_CBC): "idea_cbc.json",
    }

    for mech_id, vector_file in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["key_bits"] == 128
            assert vec["key_hex"]
            assert vec["plaintext_hex"]
            assert vec["ciphertext_hex"]
            assert vec["params"]["source"] in {
                "NESSIE IDEA verified test vectors via pyca cryptography",
                "pyca cryptography IDEA CBC vectors generated with OpenSSL and verified with Botan",
            }


def test_idea_cbc_vector_params_replay_iv() -> None:
    config = MECHANISM_REGISTRY[int(CKM_IDEA_CBC)]
    vec = load_positive_vectors("idea_cbc.json")[0]

    params = build_params_from_vector(int(CKM_IDEA_CBC), config.param_recipe, vec)

    assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen) == bytes.fromhex(
        vec["params"]["iv_hex"]
    )


def test_idea_mac_general_mechanism_has_nessie_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_IDEA_MAC_GENERAL)]
    assert config.vector_file == "idea_mac_general.json"

    vectors = load_positive_vectors("idea_mac_general.json")
    assert vectors, "idea_mac_general.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["mechanism_name"] == "CKM_IDEA_MAC_GENERAL"
        assert vec["key_hex"] == "80000000000000000000000000000000"
        assert vec["input_hex"] == "0000000000000000"
        assert vec["mac_hex"] == "b1f5f7f87901370f"
        assert vec["params"]["source"] == (
            "NESSIE IDEA verified test vectors via pyca cryptography; "
            "one-block CBC-MAC with zero IV equals IDEA-ECB"
        )
        assert vec["params"]["mac_len"] == 8


def test_cast128_mac_general_mechanism_has_rfc2144_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_CAST128_MAC_GENERAL)]
    assert config.vector_file == "cast128_mac_general.json"

    vectors = load_positive_vectors("cast128_mac_general.json")
    assert vectors, "cast128_mac_general.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["mechanism_name"] == "CKM_CAST128_MAC_GENERAL"
        assert vec["key_hex"] == "0123456712345678234567893456789a"
        assert vec["input_hex"] == "0123456789abcdef"
        assert vec["mac_hex"] == "238b4fe5847e44b2"
        assert vec["params"]["source"] == (
            "RFC 2144 appendix B.1; one-block CBC-MAC with zero IV equals CAST-128 ECB"
        )
        assert vec["params"]["mac_len"] == 8


def test_twofish_cbc_encrypt_mechanism_has_schneier_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_TWOFISH_CBC)]
    assert config.vector_file == "twofish_cbc.json"

    vectors = load_positive_vectors("twofish_cbc.json")
    assert vectors, "twofish_cbc.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["key_bits"] == 128
        assert vec["key_hex"] == "00000000000000000000000000000000"
        assert vec["plaintext_hex"] == "00000000000000000000000000000000"
        assert vec["ciphertext_hex"] == "9f589f5cf6122c32b6bfec2f2ae8c35a"
        assert vec["params"]["iv_hex"] == "00000000000000000000000000000000"
        assert vec["params"]["source"] == (
            "Bruce Schneier Twofish ECB intermediate value test, "
            "replayed as single-block CBC with zero IV"
        )
