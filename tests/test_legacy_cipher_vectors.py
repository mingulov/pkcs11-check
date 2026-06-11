"""Coverage guardrails for legacy cipher known-answer vectors."""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import (
    CKM_ARIA_CBC_PAD,
    CKM_BLOWFISH_CBC,
    CKM_BLOWFISH_CBC_PAD,
    CKM_CAMELLIA_CBC_PAD,
    CKM_CAST128_CBC,
    CKM_CAST128_CBC_PAD,
    CKM_CAST128_ECB,
    CKM_CAST128_MAC_GENERAL,
    CKM_DES3_CBC_PAD,
    CKM_DES_CBC_PAD,
    CKM_IDEA_CBC,
    CKM_IDEA_CBC_PAD,
    CKM_IDEA_ECB,
    CKM_IDEA_MAC_GENERAL,
    CKM_RC2_CBC,
    CKM_RC2_CBC_PAD,
    CKM_RC2_ECB,
    CKM_RC2_MAC_GENERAL,
    CKM_RC4,
    CKM_RC5_CBC,
    CKM_RC5_CBC_PAD,
    CKM_RC5_ECB,
    CKM_RC5_MAC_GENERAL,
    CKM_SEED_CBC_PAD,
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


def test_legacy_cbc_pad_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_RC2_CBC_PAD): (
            "rc2_cbc_pad.json",
            "CKM_RC2_CBC_PAD",
            8,
            "5dc06db7afa1896ad38fbfa9fe215ab3",
        ),
        int(CKM_CAST128_CBC_PAD): (
            "cast128_cbc_pad.json",
            "CKM_CAST128_CBC_PAD",
            8,
            "c5aa82a2a6c97d5ce48c18e4fbda3d5d",
        ),
        int(CKM_IDEA_CBC_PAD): (
            "idea_cbc_pad.json",
            "CKM_IDEA_CBC_PAD",
            8,
            "2cb10d22ac22a37555032f85bc5d3806",
        ),
        int(CKM_BLOWFISH_CBC_PAD): (
            "blowfish_cbc_pad.json",
            "CKM_BLOWFISH_CBC_PAD",
            8,
            "64ed065757511fa7",
        ),
        int(CKM_RC5_CBC_PAD): (
            "rc5_cbc_pad.json",
            "CKM_RC5_CBC_PAD",
            8,
            "7875dbf6738c64787cb3f1df34f948117fd1a023a5bba217",
        ),
    }

    for mech_id, (vector_file, mechanism_name, block_size, expected_ciphertext) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            plaintext = bytes.fromhex(vec["plaintext_hex"])
            ciphertext = bytes.fromhex(vec["ciphertext_hex"])
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"]
            assert len(plaintext) % block_size != 0
            assert len(ciphertext) % block_size == 0
            assert len(ciphertext) > len(plaintext)
            assert vec["ciphertext_hex"] == expected_ciphertext
            assert vec["params"]["iv_hex"]
            assert "PKCS#7" in vec["params"]["source"]
            if mechanism_name == "CKM_RC5_CBC_PAD":
                assert "RFC 2040 section 9.3" in vec["params"]["source"]
                assert vec["params"]["source_url"] == "https://www.rfc-editor.org/rfc/rfc2040"


def test_block_cipher_cbc_pad_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_DES_CBC_PAD): (
            "des_cbc_pad.json",
            "CKM_DES_CBC_PAD",
            8,
            1,
            "ccfec8fe28d5828e52340c1aa445fc61",
        ),
        int(CKM_DES3_CBC_PAD): (
            "des3_cbc_pad.json",
            "CKM_DES3_CBC_PAD",
            8,
            1,
            "cc980b0548d718e43f2ff326e3d40ae7",
        ),
        int(CKM_CAMELLIA_CBC_PAD): (
            "camellia_cbc_pad.json",
            "CKM_CAMELLIA_CBC_PAD",
            16,
            3,
            "ae50cb70c6d2d1cf3290031f682a3f9768cf559ddd170006ed70a040b0aea425",
        ),
        int(CKM_ARIA_CBC_PAD): (
            "aria_cbc_pad.json",
            "CKM_ARIA_CBC_PAD",
            16,
            3,
            "798ad766758dd2b0249dbddae0055eb7e30b5138c669e1c158594a92ec01bb99",
        ),
        int(CKM_SEED_CBC_PAD): (
            "seed_cbc_pad.json",
            "CKM_SEED_CBC_PAD",
            16,
            1,
            "199ca42dab518bf9f9605f892c3d567a",
        ),
    }

    for mech_id, (
        vector_file,
        mechanism_name,
        block_size,
        expected_count,
        first_ciphertext,
    ) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert len(vectors) == expected_count
        assert vectors[0]["ciphertext_hex"] == first_ciphertext
        for vec in vectors:
            plaintext = bytes.fromhex(vec["plaintext_hex"])
            ciphertext = bytes.fromhex(vec["ciphertext_hex"])
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"]
            assert len(plaintext) % block_size != 0
            assert len(ciphertext) % block_size == 0
            assert len(ciphertext) > len(plaintext)
            assert vec["params"]["iv_hex"]
            assert "PKCS#7" in vec["params"]["source"]


def test_legacy_cbc_pad_vector_params_replay_iv_and_effective_bits() -> None:
    expected = {
        int(CKM_RC2_CBC_PAD): "rc2_cbc_pad.json",
        int(CKM_CAST128_CBC_PAD): "cast128_cbc_pad.json",
        int(CKM_IDEA_CBC_PAD): "idea_cbc_pad.json",
        int(CKM_BLOWFISH_CBC_PAD): "blowfish_cbc_pad.json",
        int(CKM_RC5_CBC_PAD): "rc5_cbc_pad.json",
    }

    for mech_id, vector_file in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        vector = load_positive_vectors(vector_file)[0]
        params = build_params_from_vector(mech_id, config.param_recipe, vector)

        if mech_id == int(CKM_RC2_CBC_PAD):
            assert params.params.ulEffectiveBits == vector["params"]["effective_bits"]
            assert bytes(params.params.iv) == bytes.fromhex(vector["params"]["iv_hex"])
        elif mech_id == int(CKM_RC5_CBC_PAD):
            assert params.params.ulWordsize == vector["params"]["word_bits"]
            assert params.params.ulRounds == vector["params"]["rounds"]
            assert ctypes.string_at(params.params.pIv, params.params.ulIvLen) == bytes.fromhex(
                vector["params"]["iv_hex"]
            )
        else:
            assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen) == (
                bytes.fromhex(vector["params"]["iv_hex"])
            )


def test_rc2_mac_general_mechanism_has_openssl_legacy_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC2_MAC_GENERAL)]
    assert config.vector_file == "rc2_mac_general.json"

    vectors = load_positive_vectors("rc2_mac_general.json")
    assert vectors, "rc2_mac_general.json must contain positive vectors"
    for vec in vectors:
        assert vec["type"] == "positive"
        assert vec["mechanism_name"] == "CKM_RC2_MAC_GENERAL"
        assert vec["key_hex"] == "000102030405060708090a0b0c0d0e0f"
        assert vec["input_hex"] == "0123456789abcdef"
        assert vec["mac_hex"] == "c1de66972a5efb2b"
        assert vec["params"]["source"] == (
            "OpenSSL legacy RC2 vector; one-block CBC-MAC with zero IV equals RC2-ECB"
        )
        assert vec["params"]["effective_bits"] == 128
        assert vec["params"]["mac_len"] == 8


def test_rc2_mac_general_vector_params_replay_effective_bits_and_length() -> None:
    config = MECHANISM_REGISTRY[int(CKM_RC2_MAC_GENERAL)]
    vector = load_positive_vectors("rc2_mac_general.json")[0]

    params = build_params_from_vector(int(CKM_RC2_MAC_GENERAL), config.param_recipe, vector)

    assert params.params.ulEffectiveBits == vector["params"]["effective_bits"]
    assert params.params.ulMacLength == vector["params"]["mac_len"]


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
