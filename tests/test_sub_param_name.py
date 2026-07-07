"""sub_param_name renders integer mechanism params as numbers, not colliding constants."""

from __future__ import annotations

from pkcs11_check.raw.api import constant_name, sub_param_name


def test_integer_params_render_as_numbers_not_ckm() -> None:
    # value 16 == CKM_DSA_KEY_PAIR_GEN; an integer param must NOT decode to it
    for key in ("tagBits", "macLen", "nonceLen", "generatedIvBytes", "phFlag", "aes_key_bits"):
        assert sub_param_name(key, 16) == "16", key


def test_mechanism_valued_params_decode_to_ckm() -> None:
    from pkcs11_check.raw.api import ckm_name

    val = 0x00000041  # some real CKM value
    for key in ("hashAlg", "prf", "prfHashMechanism", "prfMechanism"):
        assert sub_param_name(key, val) == ckm_name(val), key


def test_prefix_unknown_value_is_hex_not_colliding_ckm() -> None:
    # mgf=16 is not a valid CKG_; must render hex, never CKM_DSA_KEY_PAIR_GEN
    assert constant_name(16, "CKG_") == "0x00000010"
    assert sub_param_name("mgf", 16) == "0x00000010"
