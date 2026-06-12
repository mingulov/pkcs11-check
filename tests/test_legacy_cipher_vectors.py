"""Coverage guardrails for legacy cipher known-answer vectors."""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import (
    CKM_ARIA_CBC_PAD,
    CKM_ARIA_MAC,
    CKM_ARIA_MAC_GENERAL,
    CKM_BLOWFISH_CBC,
    CKM_BLOWFISH_CBC_PAD,
    CKM_CAMELLIA_CBC_PAD,
    CKM_CAMELLIA_MAC,
    CKM_CAMELLIA_MAC_GENERAL,
    CKM_CAST3_CBC,
    CKM_CAST3_CBC_PAD,
    CKM_CAST3_ECB,
    CKM_CAST3_MAC,
    CKM_CAST3_MAC_GENERAL,
    CKM_CAST128_CBC,
    CKM_CAST128_CBC_PAD,
    CKM_CAST128_ECB,
    CKM_CAST128_MAC,
    CKM_CAST128_MAC_GENERAL,
    CKM_CAST_CBC,
    CKM_CAST_CBC_PAD,
    CKM_CAST_ECB,
    CKM_CAST_MAC,
    CKM_CAST_MAC_GENERAL,
    CKM_CDMF_CBC,
    CKM_CDMF_CBC_PAD,
    CKM_CDMF_ECB,
    CKM_CDMF_MAC,
    CKM_CDMF_MAC_GENERAL,
    CKM_DES3_CBC_PAD,
    CKM_DES3_CMAC,
    CKM_DES3_CMAC_GENERAL,
    CKM_DES3_MAC,
    CKM_DES3_MAC_GENERAL,
    CKM_DES_CBC_PAD,
    CKM_DES_MAC,
    CKM_DES_MAC_GENERAL,
    CKM_GOST28147,
    CKM_IDEA_CBC,
    CKM_IDEA_CBC_PAD,
    CKM_IDEA_ECB,
    CKM_IDEA_MAC,
    CKM_IDEA_MAC_GENERAL,
    CKM_RC2_CBC,
    CKM_RC2_CBC_PAD,
    CKM_RC2_ECB,
    CKM_RC2_MAC,
    CKM_RC2_MAC_GENERAL,
    CKM_RC4,
    CKM_RC5_CBC,
    CKM_RC5_CBC_PAD,
    CKM_RC5_ECB,
    CKM_RC5_MAC,
    CKM_RC5_MAC_GENERAL,
    CKM_SEED_CBC_PAD,
    CKM_SEED_MAC,
    CKM_SEED_MAC_GENERAL,
    CKM_SKIPJACK_CBC64,
    CKM_SKIPJACK_CFB64,
    CKM_SKIPJACK_ECB64,
    CKM_SKIPJACK_OFB64,
    CKM_TWOFISH_CBC,
    CKM_TWOFISH_CBC_PAD,
)
from pkcs11_check.testcases.mechanism_helpers import build_params_from_vector, build_test_params
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


def test_cast_encrypt_mechanisms_have_rfc2144_kat_vectors() -> None:
    expected = {
        int(CKM_CAST_ECB): (
            "cast_ecb.json",
            "CKM_CAST_ECB",
            "0123456712",
            "7ac816d16e9b302e",
            None,
        ),
        int(CKM_CAST3_ECB): (
            "cast3_ecb.json",
            "CKM_CAST3_ECB",
            "01234567123456782345",
            "eb6a711a2c02271b",
            None,
        ),
        int(CKM_CAST_CBC): (
            "cast_cbc.json",
            "CKM_CAST_CBC",
            "0123456712",
            "7ac816d16e9b302e",
            "0000000000000000",
        ),
        int(CKM_CAST3_CBC): (
            "cast3_cbc.json",
            "CKM_CAST3_CBC",
            "01234567123456782345",
            "eb6a711a2c02271b",
            "0000000000000000",
        ),
    }

    for mech_id, (vector_file, mechanism_name, key_hex, ciphertext_hex, iv_hex) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"] == key_hex
            assert vec["plaintext_hex"] == "0123456789abcdef"
            assert vec["ciphertext_hex"] == ciphertext_hex
            assert vec["params"]["source"].startswith("RFC 2144 appendix B.1")
            if iv_hex is None:
                assert "iv_hex" not in vec["params"]
            else:
                assert vec["params"]["iv_hex"] == iv_hex


def test_cast_cbc_vector_params_replay_iv() -> None:
    for mech_id, vector_file in {
        int(CKM_CAST_CBC): "cast_cbc.json",
        int(CKM_CAST3_CBC): "cast3_cbc.json",
    }.items():
        config = MECHANISM_REGISTRY[mech_id]
        vec = load_positive_vectors(vector_file)[0]

        params = build_params_from_vector(mech_id, config.param_recipe, vec)

        assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen) == bytes.fromhex(
            vec["params"]["iv_hex"]
        )


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


def test_cdmf_encrypt_mechanisms_have_ibm_derived_kat_vectors() -> None:
    expected = {
        int(CKM_CDMF_ECB): ("cdmf_ecb.json", "CKM_CDMF_ECB"),
        int(CKM_CDMF_CBC): ("cdmf_cbc.json", "CKM_CDMF_CBC"),
    }

    for mech_id, (vector_file, mechanism_name) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_bits"] == 64
            assert vec["key_hex"] == "0123456789abcdef"
            assert vec["plaintext_hex"] == "0123456789abcdef"
            assert vec["ciphertext_hex"] == "230d53ce98eb0939"
            assert vec["params"]["source"].startswith(
                "IBM CDMF key-shortening algorithm"
            )
            assert vec["params"]["derived_des_key_hex"] == "1fb26b1a81089f12"


def test_cdmf_cbc_vector_params_replay_iv() -> None:
    config = MECHANISM_REGISTRY[int(CKM_CDMF_CBC)]
    vec = load_positive_vectors("cdmf_cbc.json")[0]

    params = build_params_from_vector(int(CKM_CDMF_CBC), config.param_recipe, vec)

    assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen) == bytes.fromhex(
        vec["params"]["iv_hex"]
    )


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
        int(CKM_CAST_CBC_PAD): (
            "cast_cbc_pad.json",
            "CKM_CAST_CBC_PAD",
            8,
            "7ac816d16e9b302e849d0f944d28e9d9",
        ),
        int(CKM_CAST3_CBC_PAD): (
            "cast3_cbc_pad.json",
            "CKM_CAST3_CBC_PAD",
            8,
            "eb6a711a2c02271bea91f7857df6373b",
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
        int(CKM_CDMF_CBC_PAD): (
            "cdmf_cbc_pad.json",
            "CKM_CDMF_CBC_PAD",
            8,
            "b01eb29905bb02a0",
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
        int(CKM_CAST_CBC_PAD): "cast_cbc_pad.json",
        int(CKM_CAST3_CBC_PAD): "cast3_cbc_pad.json",
        int(CKM_CAST128_CBC_PAD): "cast128_cbc_pad.json",
        int(CKM_IDEA_CBC_PAD): "idea_cbc_pad.json",
        int(CKM_BLOWFISH_CBC_PAD): "blowfish_cbc_pad.json",
        int(CKM_RC5_CBC_PAD): "rc5_cbc_pad.json",
        int(CKM_TWOFISH_CBC_PAD): "twofish_cbc_pad.json",
        int(CKM_CDMF_CBC_PAD): "cdmf_cbc_pad.json",
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


def test_cdmf_mac_mechanisms_have_ibm_derived_kat_vectors() -> None:
    expected = {
        int(CKM_CDMF_MAC_GENERAL): (
            "cdmf_mac_general.json",
            "CKM_CDMF_MAC_GENERAL",
            "230d53ce98eb0939",
            8,
        ),
        int(CKM_CDMF_MAC): (
            "cdmf_mac.json",
            "CKM_CDMF_MAC",
            "230d53ce",
            4,
        ),
    }

    for mech_id, (vector_file, mechanism_name, mac_hex, mac_len) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"] == "0123456789abcdef"
            assert vec["input_hex"] == "0123456789abcdef"
            assert vec["mac_hex"] == mac_hex
            assert vec["params"]["mac_len"] == mac_len
            assert vec["params"]["source"].startswith(
                "IBM CDMF key-shortening algorithm"
            )


def test_cdmf_mac_general_vector_params_replay_length() -> None:
    config = MECHANISM_REGISTRY[int(CKM_CDMF_MAC_GENERAL)]
    vector = load_positive_vectors("cdmf_mac_general.json")[0]

    params = build_params_from_vector(int(CKM_CDMF_MAC_GENERAL), config.param_recipe, vector)

    assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen) == (
        vector["params"]["mac_len"].to_bytes(8, "little")
    )


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


def test_skipjack_ecb64_mechanism_has_sp800_17_kat_vectors() -> None:
    config = MECHANISM_REGISTRY[int(CKM_SKIPJACK_ECB64)]
    assert config.vector_file == "skipjack_ecb64.json"

    vectors = load_positive_vectors("skipjack_ecb64.json")
    assert {vec["id"] for vec in vectors} == {
        "skipjack_ecb64_sp800_17_table5_round_01",
        "skipjack_ecb64_sp800_17_table6_round_10",
    }

    expected = {
        "skipjack_ecb64_sp800_17_table5_round_01": (
            "00000000000000000000",
            "4000000000000000",
            "cc6843598c732bbe",
            "table 5 round 01",
        ),
        "skipjack_ecb64_sp800_17_table6_round_10": (
            "00200000000000000000",
            "0000000000000000",
            "f4108b099b047040",
            "table 6 round 10",
        ),
    }

    for vec in vectors:
        key_hex, plaintext_hex, ciphertext_hex, table_ref = expected[vec["id"]]
        assert vec["type"] == "positive"
        assert vec["mechanism_name"] == "CKM_SKIPJACK_ECB64"
        assert vec["key_bits"] == 80
        assert vec["key_hex"] == key_hex
        assert vec["plaintext_hex"] == plaintext_hex
        assert vec["ciphertext_hex"] == ciphertext_hex
        assert vec["params"]["source"] == f"NIST SP 800-17 appendix B {table_ref}"
        assert vec["params"]["source_url"] == (
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/"
            "nistspecialpublication800-17.pdf"
        )


def test_skipjack_iv_modes_remain_source_first_until_pkcs11_iv_mapping_is_reconciled() -> None:
    for mech_id in (
        int(CKM_SKIPJACK_CBC64),
        int(CKM_SKIPJACK_OFB64),
        int(CKM_SKIPJACK_CFB64),
    ):
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file is None
        assert config.param_recipe.style == "iv"
        assert config.param_recipe.defaults["iv_len"] == 24


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


def test_cast_mac_general_mechanisms_have_rfc2144_kat_vectors() -> None:
    expected = {
        int(CKM_CAST_MAC_GENERAL): (
            "cast_mac_general.json",
            "CKM_CAST_MAC_GENERAL",
            "0123456712",
            "7ac816d16e9b302e",
        ),
        int(CKM_CAST3_MAC_GENERAL): (
            "cast3_mac_general.json",
            "CKM_CAST3_MAC_GENERAL",
            "01234567123456782345",
            "eb6a711a2c02271b",
        ),
    }

    for mech_id, (vector_file, mechanism_name, key_hex, expected_mac) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"] == key_hex
            assert vec["input_hex"] == "0123456789abcdef"
            assert vec["mac_hex"] == expected_mac
            assert vec["params"]["source"].startswith("RFC 2144 appendix B.1")
            assert vec["params"]["mac_len"] == 8


def test_block_cipher_mac_general_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_DES_MAC_GENERAL): (
            "des_mac_general.json",
            "CKM_DES_MAC_GENERAL",
            8,
            "795b284fe8a85625",
        ),
        int(CKM_DES3_MAC_GENERAL): (
            "des3_mac_general.json",
            "CKM_DES3_MAC_GENERAL",
            8,
            "2bc46d1df3349c3b",
        ),
        int(CKM_CAMELLIA_MAC_GENERAL): (
            "camellia_mac_general.json",
            "CKM_CAMELLIA_MAC_GENERAL",
            16,
            "f96073b123ee5bdd75675f790362a798",
        ),
        int(CKM_ARIA_MAC_GENERAL): (
            "aria_mac_general.json",
            "CKM_ARIA_MAC_GENERAL",
            16,
            "b5c11c1494615dc7d4bcd3aecf6852e4",
        ),
        int(CKM_SEED_MAC_GENERAL): (
            "seed_mac_general.json",
            "CKM_SEED_MAC_GENERAL",
            16,
            "f353f89ce52d7929a1df5e2a37fdbf5b",
        ),
    }

    for mech_id, (vector_file, mechanism_name, mac_len, expected_mac) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"]
            assert len(bytes.fromhex(vec["input_hex"])) == mac_len
            assert vec["mac_hex"] == expected_mac
            assert vec["params"]["mac_len"] == mac_len
            assert "one-block CBC-MAC with zero IV equals" in vec["params"]["source"]


def test_des_family_fixed_mac_mechanisms_have_half_block_kat_vectors() -> None:
    expected = {
        int(CKM_DES_MAC): (
            "des_mac.json",
            "CKM_DES_MAC",
            "ae7a5bff9a66ccd4",
            "6614a40c7202bad0",
            "795b284f",
        ),
        int(CKM_DES3_MAC): (
            "des3_mac.json",
            "CKM_DES3_MAC",
            "96dea09d832e4609742ccd800a8958caecdb70730c27d8b1",
            "0cb1c9965ea202b0",
            "2bc46d1d",
        ),
    }

    for mech_id, (
        vector_file,
        mechanism_name,
        key_hex,
        input_hex,
        expected_mac,
    ) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"] == key_hex
            assert vec["input_hex"] == input_hex
            assert vec["mac_hex"] == expected_mac
            assert len(bytes.fromhex(vec["mac_hex"])) == 4
            assert "FIPS PUB 113" in vec["params"]["source"]
            assert "special case" in vec["params"]["source"]
            assert "half the block size" in vec["params"]["source"]
            assert "mac_len" not in vec["params"]


def test_half_block_cipher_mac_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_CAMELLIA_MAC): (
            "camellia_mac.json",
            "CKM_CAMELLIA_MAC",
            "f96073b123ee5bdd",
        ),
        int(CKM_ARIA_MAC): (
            "aria_mac.json",
            "CKM_ARIA_MAC",
            "b5c11c1494615dc7",
        ),
        int(CKM_SEED_MAC): (
            "seed_mac.json",
            "CKM_SEED_MAC",
            "f353f89ce52d7929",
        ),
    }

    for mech_id, (vector_file, mechanism_name, expected_mac) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"]
            assert len(bytes.fromhex(vec["input_hex"])) == 16
            assert vec["mac_hex"] == expected_mac
            assert len(bytes.fromhex(vec["mac_hex"])) == 8
            assert "special case" in vec["params"]["source"]
            assert "half the block size" in vec["params"]["source"]


def test_legacy_fixed_mac_mechanisms_have_half_block_kat_vectors() -> None:
    expected = {
        int(CKM_RC2_MAC): (
            "rc2_mac.json",
            "CKM_RC2_MAC",
            "000102030405060708090a0b0c0d0e0f",
            "0123456789abcdef",
            "c1de6697",
            {"effective_bits": 128},
        ),
        int(CKM_RC5_MAC): (
            "rc5_mac.json",
            "CKM_RC5_MAC",
            "0102030405060708",
            "ffffffffffffffff",
            "e493f1c1",
            {"word_bits": 32, "rounds": 12},
        ),
        int(CKM_CAST128_MAC): (
            "cast128_mac.json",
            "CKM_CAST128_MAC",
            "0123456712345678234567893456789a",
            "0123456789abcdef",
            "238b4fe5",
            {},
        ),
        int(CKM_CAST_MAC): (
            "cast_mac.json",
            "CKM_CAST_MAC",
            "0123456712",
            "0123456789abcdef",
            "7ac816d1",
            {},
        ),
        int(CKM_CAST3_MAC): (
            "cast3_mac.json",
            "CKM_CAST3_MAC",
            "01234567123456782345",
            "0123456789abcdef",
            "eb6a711a",
            {},
        ),
        int(CKM_IDEA_MAC): (
            "idea_mac.json",
            "CKM_IDEA_MAC",
            "80000000000000000000000000000000",
            "0000000000000000",
            "b1f5f7f8",
            {},
        ),
    }

    for mech_id, (
        vector_file,
        mechanism_name,
        key_hex,
        input_hex,
        expected_mac,
        expected_params,
    ) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"] == key_hex
            assert vec["input_hex"] == input_hex
            assert vec["mac_hex"] == expected_mac
            assert len(bytes.fromhex(vec["mac_hex"])) == 4
            assert "special case" in vec["params"]["source"]
            assert "half the block size" in vec["params"]["source"]
            assert "mac_len" not in vec["params"]
            for key, value in expected_params.items():
                assert vec["params"][key] == value


def test_des3_cmac_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_DES3_CMAC): (
            "des3_cmac.json",
            "CKM_DES3_CMAC",
            "c0e7032f42c24c81",
            None,
        ),
        int(CKM_DES3_CMAC_GENERAL): (
            "des3_cmac_general.json",
            "CKM_DES3_CMAC_GENERAL",
            "c0e7032f42c24c81",
            8,
        ),
    }

    for mech_id, (vector_file, mechanism_name, expected_mac, mac_len) in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["mechanism_name"] == mechanism_name
            assert vec["key_hex"] == "96dea09d832e4609742ccd800a8958caecdb70730c27d8b1"
            assert vec["input_hex"] == "0546f43bf28360e17bdeb5648f3ab9ab94424219eca9da"
            assert vec["mac_hex"] == expected_mac
            assert len(bytes.fromhex(vec["mac_hex"])) == 8
            assert "NIST SP 800-38B CMAC" in vec["params"]["source"]
            assert "PKCS#11 DES3-CMAC" in vec["params"]["source"]
            if mac_len is None:
                assert "mac_len" not in vec["params"]
            else:
                assert vec["params"]["mac_len"] == mac_len


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


def test_twofish_cbc_pad_mechanism_has_reference_generated_kat_vector() -> None:
    config = MECHANISM_REGISTRY[int(CKM_TWOFISH_CBC_PAD)]
    assert config.vector_file == "twofish_cbc_pad.json"

    vectors = load_positive_vectors("twofish_cbc_pad.json")
    assert vectors, "twofish_cbc_pad.json must contain positive vectors"
    for vec in vectors:
        plaintext = bytes.fromhex(vec["plaintext_hex"])
        ciphertext = bytes.fromhex(vec["ciphertext_hex"])
        assert vec["type"] == "positive"
        assert vec["mechanism_name"] == "CKM_TWOFISH_CBC_PAD"
        assert vec["key_bits"] == 128
        assert vec["key_hex"] == "00000000000000000000000000000000"
        assert plaintext == bytes(16)
        assert len(ciphertext) == 32
        assert vec["ciphertext_hex"] == (
            "9f589f5cf6122c32b6bfec2f2ae8c35a"
            "a645c0dafebc6d6dcf4fc0fa33e78ac5"
        )
        assert vec["params"]["iv_hex"] == "00000000000000000000000000000000"
        assert "Bruce Schneier Twofish reference C implementation" in vec["params"]["source"]
        assert "PKCS#7 padded" in vec["params"]["source"]


def test_gost28147_registry_replays_oasis_iv_parameter_shape() -> None:
    """CKM_GOST28147 generic tests must build the OASIS 8-byte IV parameter."""
    config = MECHANISM_REGISTRY[int(CKM_GOST28147)]

    assert config.param_required is True
    assert config.param_recipe.style == "iv"
    assert config.param_recipe.defaults["iv_len"] == 8

    params = build_test_params(int(CKM_GOST28147), config.param_recipe)

    assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen)
    assert params.ck.ulParameterLen == 8
