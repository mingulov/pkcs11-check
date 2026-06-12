"""Legacy cipher mechanism family registry entries.

Covers RC2, RC4, RC5, IDEA, CAST, CAST3, CAST128/CAST5, CDMF, Skipjack,
Baton, Juniper, Blowfish, and Twofish -- approximately 80 mechanisms.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DERIVE,
    CKF_DIGEST,
    CKF_ENCRYPT,
    CKF_GENERATE,
    CKF_SIGN,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_WRAP,
    CKK_BATON,
    CKK_BLOWFISH,
    CKK_CAST,
    CKK_CAST3,
    CKK_CAST128,
    CKK_CDMF,
    CKK_GOST28147,
    CKK_IDEA,
    CKK_JUNIPER,
    CKK_RC2,
    CKK_RC4,
    CKK_RC5,
    CKK_SKIPJACK,
    CKK_TWOFISH,
    CKM_BATON_CBC128,
    CKM_BATON_COUNTER,
    CKM_BATON_ECB96,
    CKM_BATON_ECB128,
    CKM_BATON_KEY_GEN,
    CKM_BATON_SHUFFLE,
    CKM_BATON_WRAP,
    CKM_BLOWFISH_CBC,
    CKM_BLOWFISH_CBC_PAD,
    CKM_BLOWFISH_KEY_GEN,
    CKM_CAST3_CBC,
    CKM_CAST3_CBC_PAD,
    CKM_CAST3_ECB,
    CKM_CAST3_KEY_GEN,
    CKM_CAST3_MAC,
    CKM_CAST3_MAC_GENERAL,
    CKM_CAST128_CBC,
    CKM_CAST128_CBC_PAD,
    CKM_CAST128_ECB,
    CKM_CAST128_KEY_GEN,
    CKM_CAST128_MAC,
    CKM_CAST128_MAC_GENERAL,
    CKM_CAST_CBC,
    CKM_CAST_CBC_PAD,
    CKM_CAST_ECB,
    CKM_CAST_KEY_GEN,
    CKM_CAST_MAC,
    CKM_CAST_MAC_GENERAL,
    CKM_CDMF_CBC,
    CKM_CDMF_CBC_PAD,
    CKM_CDMF_ECB,
    CKM_CDMF_KEY_GEN,
    CKM_CDMF_MAC,
    CKM_CDMF_MAC_GENERAL,
    CKM_FASTHASH,
    CKM_GOST28147,
    CKM_GOST28147_ECB,
    CKM_GOST28147_KEY_GEN,
    CKM_GOST28147_KEY_WRAP,
    CKM_GOST28147_MAC,
    CKM_IDEA_CBC,
    CKM_IDEA_CBC_PAD,
    CKM_IDEA_ECB,
    CKM_IDEA_KEY_GEN,
    CKM_IDEA_MAC,
    CKM_IDEA_MAC_GENERAL,
    CKM_JUNIPER_CBC128,
    CKM_JUNIPER_COUNTER,
    CKM_JUNIPER_ECB128,
    CKM_JUNIPER_KEY_GEN,
    CKM_JUNIPER_SHUFFLE,
    CKM_JUNIPER_WRAP,
    CKM_KEY_WRAP_LYNKS,
    CKM_KEY_WRAP_SET_OAEP,
    CKM_RC2_CBC,
    CKM_RC2_CBC_PAD,
    CKM_RC2_ECB,
    CKM_RC2_KEY_GEN,
    CKM_RC2_MAC,
    CKM_RC2_MAC_GENERAL,
    CKM_RC4,
    CKM_RC4_KEY_GEN,
    CKM_RC5_CBC,
    CKM_RC5_CBC_PAD,
    CKM_RC5_ECB,
    CKM_RC5_KEY_GEN,
    CKM_RC5_MAC,
    CKM_RC5_MAC_GENERAL,
    CKM_SKIPJACK_CBC64,
    CKM_SKIPJACK_CFB8,
    CKM_SKIPJACK_CFB16,
    CKM_SKIPJACK_CFB32,
    CKM_SKIPJACK_CFB64,
    CKM_SKIPJACK_ECB64,
    CKM_SKIPJACK_KEY_GEN,
    CKM_SKIPJACK_OFB64,
    CKM_SKIPJACK_PRIVATE_WRAP,
    CKM_SKIPJACK_RELAYX,
    CKM_SKIPJACK_WRAP,
    CKM_TWOFISH_CBC,
    CKM_TWOFISH_CBC_PAD,
    CKM_TWOFISH_KEY_GEN,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_ENC_DEC = CKF_ENCRYPT | CKF_DECRYPT
_SIG_VER = CKF_SIGN | CKF_VERIFY

_RC2_SIZES = (40, 64, 128)
_RC4_SIZES = (40, 128, 256)
_RC5_SIZES = (128, 256)
_IDEA_SIZES = (128,)
_CAST_SIZES = (40, 128)
_CAST3_SIZES = (40, 128)
_CAST128_SIZES = (40, 128)
_CDMF_SIZES = (40,)
_SKIPJACK_SIZES = (80,)
_BATON_SIZES = (320,)
_JUNIPER_SIZES = (128,)
_BLOWFISH_SIZES = (128, 256, 448)
_TWOFISH_SIZES = (128, 192, 256)

_sym = KeygenRecipe("symmetric")
_fixed = KeygenRecipe("fixed_length")
_iv8 = ParamRecipe("iv", {"iv_len": 8})
_iv16 = ParamRecipe("iv", {"iv_len": 16})
_mac_general = ParamRecipe("mac_general", {"mac_len": 8})
_rc2 = ParamRecipe("rc2", {"effective_bits": 128})
_rc2_cbc = ParamRecipe("rc2_cbc", {"effective_bits": 128})
_rc2_mac_general = ParamRecipe("rc2_mac_general", {"effective_bits": 128, "mac_len": 8})
_rc5 = ParamRecipe("rc5", {"word_bits": 32, "rounds": 12})
_rc5_cbc = ParamRecipe("rc5_cbc", {"word_bits": 32, "rounds": 12})
_rc5_mac_general = ParamRecipe("rc5_mac_general", {"word_bits": 32, "rounds": 12, "mac_len": 8})


def populate(registry: dict[int, MechConfig]) -> None:
    """Add legacy cipher mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # RC2 mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_RC2_KEY_GEN] = MechConfig(
        key_type=CKK_RC2,
        keygen_mech=CKM_RC2_KEY_GEN,
        key_sizes=_RC2_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="RC2 key generation (variable key size 40-128 bits)",
    )

    registry[CKM_RC2_ECB] = MechConfig(
        key_type=CKK_RC2,
        keygen_mech=CKM_RC2_KEY_GEN,
        key_sizes=_RC2_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_rc2,
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="rc2_ecb.json",
        notes="RC2-ECB: 8-byte block, no padding, requires CK_RC2_PARAMS (effective key bits)",
    )

    registry[CKM_RC2_CBC] = MechConfig(
        key_type=CKK_RC2,
        keygen_mech=CKM_RC2_KEY_GEN,
        key_sizes=_RC2_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_rc2_cbc,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="rc2_cbc.json",
        notes="RC2-CBC: 8-byte block, requires CK_RC2_CBC_PARAMS (effective bits + 8-byte IV)",
    )

    registry[CKM_RC2_CBC_PAD] = MechConfig(
        key_type=CKK_RC2,
        keygen_mech=CKM_RC2_KEY_GEN,
        key_sizes=_RC2_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_rc2_cbc,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="rc2_cbc_pad.json",
        notes="RC2-CBC with PKCS#7 padding: any-length plaintext, requires CK_RC2_CBC_PARAMS",
    )

    registry[CKM_RC2_MAC] = MechConfig(
        key_type=CKK_RC2,
        keygen_mech=CKM_RC2_KEY_GEN,
        key_sizes=_RC2_SIZES,
        param_required=True,
        param_recipe=_rc2,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="rc2_mac.json",
        notes="RC2-MAC: CBC-MAC with fixed output, requires CK_RC2_PARAMS (effective key bits)",
    )

    registry[CKM_RC2_MAC_GENERAL] = MechConfig(
        key_type=CKK_RC2,
        keygen_mech=CKM_RC2_KEY_GEN,
        key_sizes=_RC2_SIZES,
        param_required=True,
        param_recipe=_rc2_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="rc2_mac_general.json",
        notes="RC2-MAC-GENERAL: variable-length MAC, requires CK_RC2_MAC_GENERAL_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # RC4 mechanisms (stream cipher)
    # ---------------------------------------------------------------------------

    registry[CKM_RC4_KEY_GEN] = MechConfig(
        key_type=CKK_RC4,
        keygen_mech=CKM_RC4_KEY_GEN,
        key_sizes=_RC4_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="RC4 key generation (variable key size 40-256 bits)",
    )

    registry[CKM_RC4] = MechConfig(
        key_type=CKK_RC4,
        keygen_mech=CKM_RC4_KEY_GEN,
        key_sizes=_RC4_SIZES,
        block_size=None,
        input_constraint="any",
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC,
        vector_file="rc4.json",
        notes="RC4 stream cipher: no IV or params needed, stateful (never reuse key+nonce)",
    )

    # ---------------------------------------------------------------------------
    # RC5 mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_RC5_KEY_GEN] = MechConfig(
        key_type=CKK_RC5,
        keygen_mech=CKM_RC5_KEY_GEN,
        key_sizes=_RC5_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="RC5 key generation (128/256-bit keys)",
    )

    registry[CKM_RC5_ECB] = MechConfig(
        key_type=CKK_RC5,
        keygen_mech=CKM_RC5_KEY_GEN,
        key_sizes=_RC5_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_rc5,
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="rc5_ecb.json",
        notes="RC5-ECB: variable block size, requires CK_RC5_PARAMS (wordsize, rounds)",
    )

    registry[CKM_RC5_CBC] = MechConfig(
        key_type=CKK_RC5,
        keygen_mech=CKM_RC5_KEY_GEN,
        key_sizes=_RC5_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_rc5_cbc,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="rc5_cbc.json",
        notes="RC5-CBC: requires CK_RC5_CBC_PARAMS (wordsize, rounds, IV)",
    )

    registry[CKM_RC5_CBC_PAD] = MechConfig(
        key_type=CKK_RC5,
        keygen_mech=CKM_RC5_KEY_GEN,
        key_sizes=_RC5_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_rc5_cbc,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="rc5_cbc_pad.json",
        notes="RC5-CBC with PKCS#7 padding: any-length plaintext, requires CK_RC5_CBC_PARAMS",
    )

    registry[CKM_RC5_MAC] = MechConfig(
        key_type=CKK_RC5,
        keygen_mech=CKM_RC5_KEY_GEN,
        key_sizes=_RC5_SIZES,
        param_required=True,
        param_recipe=_rc5,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="rc5_mac.json",
        notes="RC5-MAC: CBC-MAC with fixed output, requires CK_RC5_PARAMS",
    )

    registry[CKM_RC5_MAC_GENERAL] = MechConfig(
        key_type=CKK_RC5,
        keygen_mech=CKM_RC5_KEY_GEN,
        key_sizes=_RC5_SIZES,
        param_required=True,
        param_recipe=_rc5_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="rc5_mac_general.json",
        notes="RC5-MAC-GENERAL: variable-length MAC, requires CK_RC5_MAC_GENERAL_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # IDEA mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_IDEA_KEY_GEN] = MechConfig(
        key_type=CKK_IDEA,
        keygen_mech=CKM_IDEA_KEY_GEN,
        key_sizes=_IDEA_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="IDEA key generation (128-bit fixed key size)",
    )

    registry[CKM_IDEA_ECB] = MechConfig(
        key_type=CKK_IDEA,
        keygen_mech=CKM_IDEA_KEY_GEN,
        key_sizes=_IDEA_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="idea_ecb.json",
        notes="IDEA-ECB: 8-byte block, no padding, deterministic",
    )

    registry[CKM_IDEA_CBC] = MechConfig(
        key_type=CKK_IDEA,
        keygen_mech=CKM_IDEA_KEY_GEN,
        key_sizes=_IDEA_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="idea_cbc.json",
        notes="IDEA-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_IDEA_CBC_PAD] = MechConfig(
        key_type=CKK_IDEA,
        keygen_mech=CKM_IDEA_KEY_GEN,
        key_sizes=_IDEA_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="idea_cbc_pad.json",
        notes="IDEA-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    registry[CKM_IDEA_MAC] = MechConfig(
        key_type=CKK_IDEA,
        keygen_mech=CKM_IDEA_KEY_GEN,
        key_sizes=_IDEA_SIZES,
        keygen_recipe=_fixed,
        expected_flags=_SIG_VER,
        vector_file="idea_mac.json",
        notes="IDEA-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_IDEA_MAC_GENERAL] = MechConfig(
        key_type=CKK_IDEA,
        keygen_mech=CKM_IDEA_KEY_GEN,
        key_sizes=_IDEA_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_fixed,
        expected_flags=_SIG_VER,
        vector_file="idea_mac_general.json",
        notes="IDEA-MAC-GENERAL: variable-length MAC (CK_MAC_GENERAL_PARAMS)",
    )

    # ---------------------------------------------------------------------------
    # CAST mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_CAST_KEY_GEN] = MechConfig(
        key_type=CKK_CAST,
        keygen_mech=CKM_CAST_KEY_GEN,
        key_sizes=_CAST_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="CAST key generation (40-128 bit variable key size)",
    )

    registry[CKM_CAST_ECB] = MechConfig(
        key_type=CKK_CAST,
        keygen_mech=CKM_CAST_KEY_GEN,
        key_sizes=_CAST_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast_ecb.json",
        notes="CAST-ECB: 8-byte block, no padding, deterministic",
    )

    registry[CKM_CAST_CBC] = MechConfig(
        key_type=CKK_CAST,
        keygen_mech=CKM_CAST_KEY_GEN,
        key_sizes=_CAST_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast_cbc.json",
        notes="CAST-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_CAST_CBC_PAD] = MechConfig(
        key_type=CKK_CAST,
        keygen_mech=CKM_CAST_KEY_GEN,
        key_sizes=_CAST_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast_cbc_pad.json",
        notes="CAST-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    registry[CKM_CAST_MAC] = MechConfig(
        key_type=CKK_CAST,
        keygen_mech=CKM_CAST_KEY_GEN,
        key_sizes=_CAST_SIZES,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="cast_mac.json",
        notes="CAST-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_CAST_MAC_GENERAL] = MechConfig(
        key_type=CKK_CAST,
        keygen_mech=CKM_CAST_KEY_GEN,
        key_sizes=_CAST_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="cast_mac_general.json",
        notes="CAST-MAC-GENERAL: variable-length MAC (CK_MAC_GENERAL_PARAMS)",
    )

    # ---------------------------------------------------------------------------
    # CAST3 mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_CAST3_KEY_GEN] = MechConfig(
        key_type=CKK_CAST3,
        keygen_mech=CKM_CAST3_KEY_GEN,
        key_sizes=_CAST3_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="CAST3 key generation (40-128 bit variable key size)",
    )

    registry[CKM_CAST3_ECB] = MechConfig(
        key_type=CKK_CAST3,
        keygen_mech=CKM_CAST3_KEY_GEN,
        key_sizes=_CAST3_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast3_ecb.json",
        notes="CAST3-ECB: 8-byte block, no padding, deterministic",
    )

    registry[CKM_CAST3_CBC] = MechConfig(
        key_type=CKK_CAST3,
        keygen_mech=CKM_CAST3_KEY_GEN,
        key_sizes=_CAST3_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast3_cbc.json",
        notes="CAST3-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_CAST3_CBC_PAD] = MechConfig(
        key_type=CKK_CAST3,
        keygen_mech=CKM_CAST3_KEY_GEN,
        key_sizes=_CAST3_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast3_cbc_pad.json",
        notes="CAST3-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    registry[CKM_CAST3_MAC] = MechConfig(
        key_type=CKK_CAST3,
        keygen_mech=CKM_CAST3_KEY_GEN,
        key_sizes=_CAST3_SIZES,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="cast3_mac.json",
        notes="CAST3-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_CAST3_MAC_GENERAL] = MechConfig(
        key_type=CKK_CAST3,
        keygen_mech=CKM_CAST3_KEY_GEN,
        key_sizes=_CAST3_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="cast3_mac_general.json",
        notes="CAST3-MAC-GENERAL: variable-length MAC (CK_MAC_GENERAL_PARAMS)",
    )

    # ---------------------------------------------------------------------------
    # CAST128 / CAST5 mechanisms (aliases -- register under CAST128 names only)
    # ---------------------------------------------------------------------------

    registry[CKM_CAST128_KEY_GEN] = MechConfig(
        key_type=CKK_CAST128,
        keygen_mech=CKM_CAST128_KEY_GEN,
        key_sizes=_CAST128_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="CAST128/CAST5 key generation (40-128 bit); CKM_CAST5_KEY_GEN is an alias",
    )

    registry[CKM_CAST128_ECB] = MechConfig(
        key_type=CKK_CAST128,
        keygen_mech=CKM_CAST128_KEY_GEN,
        key_sizes=_CAST128_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast128_ecb.json",
        notes="CAST128-ECB: 8-byte block, no padding; CKM_CAST5_ECB is an alias",
    )

    registry[CKM_CAST128_CBC] = MechConfig(
        key_type=CKK_CAST128,
        keygen_mech=CKM_CAST128_KEY_GEN,
        key_sizes=_CAST128_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast128_cbc.json",
        notes="CAST128-CBC: 8-byte block, requires 8-byte IV; CKM_CAST5_CBC is an alias",
    )

    registry[CKM_CAST128_CBC_PAD] = MechConfig(
        key_type=CKK_CAST128,
        keygen_mech=CKM_CAST128_KEY_GEN,
        key_sizes=_CAST128_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="cast128_cbc_pad.json",
        notes="CAST128-CBC with PKCS#7 padding; CKM_CAST5_CBC_PAD is an alias",
    )

    registry[CKM_CAST128_MAC] = MechConfig(
        key_type=CKK_CAST128,
        keygen_mech=CKM_CAST128_KEY_GEN,
        key_sizes=_CAST128_SIZES,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="cast128_mac.json",
        notes="CAST128-MAC: CBC-MAC fixed output; CKM_CAST5_MAC is an alias",
    )

    registry[CKM_CAST128_MAC_GENERAL] = MechConfig(
        key_type=CKK_CAST128,
        keygen_mech=CKM_CAST128_KEY_GEN,
        key_sizes=_CAST128_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="cast128_mac_general.json",
        notes="CAST128-MAC-GENERAL: variable-length MAC; CKM_CAST5_MAC_GENERAL is an alias",
    )

    # ---------------------------------------------------------------------------
    # CDMF mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_CDMF_KEY_GEN] = MechConfig(
        key_type=CKK_CDMF,
        keygen_mech=CKM_CDMF_KEY_GEN,
        key_sizes=_CDMF_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="CDMF key generation (Content Data Masking Facility, 40-bit key)",
    )

    registry[CKM_CDMF_ECB] = MechConfig(
        key_type=CKK_CDMF,
        keygen_mech=CKM_CDMF_KEY_GEN,
        key_sizes=_CDMF_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        notes="CDMF-ECB: 8-byte block, no padding, deterministic",
    )

    registry[CKM_CDMF_CBC] = MechConfig(
        key_type=CKK_CDMF,
        keygen_mech=CKM_CDMF_KEY_GEN,
        key_sizes=_CDMF_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        notes="CDMF-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_CDMF_CBC_PAD] = MechConfig(
        key_type=CKK_CDMF,
        keygen_mech=CKM_CDMF_KEY_GEN,
        key_sizes=_CDMF_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        notes="CDMF-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    registry[CKM_CDMF_MAC] = MechConfig(
        key_type=CKK_CDMF,
        keygen_mech=CKM_CDMF_KEY_GEN,
        key_sizes=_CDMF_SIZES,
        keygen_recipe=_fixed,
        expected_flags=_SIG_VER,
        notes="CDMF-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_CDMF_MAC_GENERAL] = MechConfig(
        key_type=CKK_CDMF,
        keygen_mech=CKM_CDMF_KEY_GEN,
        key_sizes=_CDMF_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_fixed,
        expected_flags=_SIG_VER,
        notes="CDMF-MAC-GENERAL: variable-length MAC (CK_MAC_GENERAL_PARAMS)",
    )

    # ---------------------------------------------------------------------------
    # Skipjack mechanisms (NSA Fortezza/Capstone)
    # ---------------------------------------------------------------------------

    registry[CKM_SKIPJACK_KEY_GEN] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="Skipjack key generation (80-bit NSA Fortezza cipher)",
    )

    registry[CKM_SKIPJACK_ECB64] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        vector_file="skipjack_ecb64.json",
        notes="Skipjack-ECB64: 8-byte block ECB mode",
    )

    registry[CKM_SKIPJACK_CBC64] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        vector_file="skipjack_cbc64.json",
        notes="Skipjack-CBC64: 8-byte block CBC mode, requires 8-byte IV",
    )

    registry[CKM_SKIPJACK_OFB64] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Skipjack-OFB64: 64-bit output feedback stream mode",
    )

    registry[CKM_SKIPJACK_CFB64] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Skipjack-CFB64: 64-bit cipher feedback stream mode",
    )

    registry[CKM_SKIPJACK_CFB32] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Skipjack-CFB32: 32-bit cipher feedback stream mode",
    )

    registry[CKM_SKIPJACK_CFB16] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Skipjack-CFB16: 16-bit cipher feedback stream mode",
    )

    registry[CKM_SKIPJACK_CFB8] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Skipjack-CFB8: 8-bit cipher feedback stream mode",
    )

    registry[CKM_SKIPJACK_WRAP] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="Skipjack key wrapping (MEK exchange)",
    )

    registry[CKM_SKIPJACK_PRIVATE_WRAP] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="Skipjack private-key wrapping",
    )

    registry[CKM_SKIPJACK_RELAYX] = MechConfig(
        key_type=CKK_SKIPJACK,
        keygen_mech=CKM_SKIPJACK_KEY_GEN,
        key_sizes=_SKIPJACK_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="Skipjack RELAYX: re-wrapping with new key (Fortezza relay exchange)",
    )

    # ---------------------------------------------------------------------------
    # Baton mechanisms (NSA Type I classified cipher)
    # ---------------------------------------------------------------------------

    registry[CKM_BATON_KEY_GEN] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="Baton key generation (320-bit NSA Type I cipher key)",
    )

    registry[CKM_BATON_ECB128] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Baton-ECB128: 128-bit (16-byte) block ECB mode",
    )

    registry[CKM_BATON_ECB96] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        block_size=12,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Baton-ECB96: 96-bit (12-byte) block ECB mode",
    )

    registry[CKM_BATON_CBC128] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Baton-CBC128: 128-bit block CBC mode",
    )

    registry[CKM_BATON_COUNTER] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        block_size=None,
        input_constraint="any",
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Baton counter mode stream cipher",
    )

    registry[CKM_BATON_SHUFFLE] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        block_size=None,
        input_constraint="any",
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Baton shuffle mode",
    )

    registry[CKM_BATON_WRAP] = MechConfig(
        key_type=CKK_BATON,
        keygen_mech=CKM_BATON_KEY_GEN,
        key_sizes=_BATON_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="Baton key wrapping",
    )

    # ---------------------------------------------------------------------------
    # Juniper mechanisms (NSA/NIST Type I classified cipher)
    # ---------------------------------------------------------------------------

    registry[CKM_JUNIPER_KEY_GEN] = MechConfig(
        key_type=CKK_JUNIPER,
        keygen_mech=CKM_JUNIPER_KEY_GEN,
        key_sizes=_JUNIPER_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="Juniper key generation (128-bit NSA/NIST Type I cipher)",
    )

    registry[CKM_JUNIPER_ECB128] = MechConfig(
        key_type=CKK_JUNIPER,
        keygen_mech=CKM_JUNIPER_KEY_GEN,
        key_sizes=_JUNIPER_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Juniper-ECB128: 128-bit (16-byte) block ECB mode",
    )

    registry[CKM_JUNIPER_CBC128] = MechConfig(
        key_type=CKK_JUNIPER,
        keygen_mech=CKM_JUNIPER_KEY_GEN,
        key_sizes=_JUNIPER_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Juniper-CBC128: 128-bit block CBC mode, requires 16-byte IV",
    )

    registry[CKM_JUNIPER_COUNTER] = MechConfig(
        key_type=CKK_JUNIPER,
        keygen_mech=CKM_JUNIPER_KEY_GEN,
        key_sizes=_JUNIPER_SIZES,
        block_size=None,
        input_constraint="any",
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Juniper counter mode stream cipher",
    )

    registry[CKM_JUNIPER_SHUFFLE] = MechConfig(
        key_type=CKK_JUNIPER,
        keygen_mech=CKM_JUNIPER_KEY_GEN,
        key_sizes=_JUNIPER_SIZES,
        block_size=None,
        input_constraint="any",
        keygen_recipe=_fixed,
        expected_flags=_ENC_DEC,
        notes="Juniper shuffle mode",
    )

    registry[CKM_JUNIPER_WRAP] = MechConfig(
        key_type=CKK_JUNIPER,
        keygen_mech=CKM_JUNIPER_KEY_GEN,
        key_sizes=_JUNIPER_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="Juniper key wrapping",
    )

    # ---------------------------------------------------------------------------
    # Blowfish mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_BLOWFISH_KEY_GEN] = MechConfig(
        key_type=CKK_BLOWFISH,
        keygen_mech=CKM_BLOWFISH_KEY_GEN,
        key_sizes=_BLOWFISH_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="Blowfish key generation (128/256/448-bit variable key size)",
    )

    registry[CKM_BLOWFISH_CBC] = MechConfig(
        key_type=CKK_BLOWFISH,
        keygen_mech=CKM_BLOWFISH_KEY_GEN,
        key_sizes=_BLOWFISH_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="blowfish_cbc.json",
        notes="Blowfish-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_BLOWFISH_CBC_PAD] = MechConfig(
        key_type=CKK_BLOWFISH,
        keygen_mech=CKM_BLOWFISH_KEY_GEN,
        key_sizes=_BLOWFISH_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="blowfish_cbc_pad.json",
        notes="Blowfish-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    # ---------------------------------------------------------------------------
    # Twofish mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_TWOFISH_KEY_GEN] = MechConfig(
        key_type=CKK_TWOFISH,
        keygen_mech=CKM_TWOFISH_KEY_GEN,
        key_sizes=_TWOFISH_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="Twofish key generation (128/192/256-bit variable key size)",
    )

    registry[CKM_TWOFISH_CBC] = MechConfig(
        key_type=CKK_TWOFISH,
        keygen_mech=CKM_TWOFISH_KEY_GEN,
        key_sizes=_TWOFISH_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        vector_file="twofish_cbc.json",
        notes="Twofish-CBC: 16-byte block, requires 16-byte IV param",
    )

    registry[CKM_TWOFISH_CBC_PAD] = MechConfig(
        key_type=CKK_TWOFISH,
        keygen_mech=CKM_TWOFISH_KEY_GEN,
        key_sizes=_TWOFISH_SIZES,
        block_size=16,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ENC_DEC | CKF_WRAP | CKF_UNWRAP,
        notes="Twofish-CBC with PKCS#7 padding: any-length plaintext, requires 16-byte IV",
    )

    # ---------------------------------------------------------------------------
    # Legacy key wrap mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_KEY_WRAP_LYNKS] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="Lynks key wrap (legacy proprietary key wrapping scheme)",
    )

    registry[CKM_KEY_WRAP_SET_OAEP] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        expected_flags=CKF_WRAP | CKF_UNWRAP,
        notes="SET OAEP key wrap (legacy SET protocol key wrapping)",
    )

    # ---------------------------------------------------------------------------
    # FASTHASH (legacy digest)
    # ---------------------------------------------------------------------------

    registry[CKM_FASTHASH] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="any",
        multi_part_supported=True,
        expected_flags=CKF_DIGEST,
        notes="FASTHASH: legacy fast digest mechanism",
    )

    # ---------------------------------------------------------------------------
    # GOST 28147-89 mechanisms (Soviet/Russian symmetric cipher)
    # ---------------------------------------------------------------------------

    _gost28147 = KeygenRecipe("fixed_length")

    registry[CKM_GOST28147_KEY_GEN] = MechConfig(
        key_type=CKK_GOST28147,
        keygen_mech=CKM_GOST28147_KEY_GEN,
        key_sizes=(256,),
        keygen_recipe=_gost28147,
        expected_flags=CKF_GENERATE,
        notes="GOST 28147-89 key generation (256-bit key)",
    )

    registry[CKM_GOST28147_ECB] = MechConfig(
        key_type=CKK_GOST28147,
        keygen_mech=CKM_GOST28147_KEY_GEN,
        key_sizes=(256,),
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_gost28147,
        expected_flags=_ENC_DEC,
        notes="GOST 28147-89 ECB mode: 8-byte block, no padding",
    )

    registry[CKM_GOST28147] = MechConfig(
        key_type=CKK_GOST28147,
        keygen_mech=CKM_GOST28147_KEY_GEN,
        key_sizes=(256,),
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_gost28147,
        expected_flags=_ENC_DEC,
        notes="GOST 28147-89 non-ECB mode: 8-byte IV mechanism param",
    )

    registry[CKM_GOST28147_MAC] = MechConfig(
        key_type=CKK_GOST28147,
        keygen_mech=CKM_GOST28147_KEY_GEN,
        key_sizes=(256,),
        keygen_recipe=_gost28147,
        expected_flags=CKF_SIGN | CKF_VERIFY,
        notes="GOST 28147-89 MAC (imitovstavka): 32-bit output",
    )

    registry[CKM_GOST28147_KEY_WRAP] = MechConfig(
        key_type=CKK_GOST28147,
        keygen_mech=CKM_GOST28147_KEY_GEN,
        key_sizes=(256,),
        keygen_recipe=_gost28147,
        expected_flags=CKF_WRAP | CKF_UNWRAP | CKF_DERIVE,
        notes="GOST 28147-89 key wrapping for key export/import",
    )
