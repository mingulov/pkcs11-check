"""ChaCha20, Salsa20, Poly1305, Camellia, ARIA, and SEED mechanism family registry entries."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DERIVE,
    CKF_ENCRYPT,
    CKF_GENERATE,
    CKF_SIGN,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_WRAP,
    CKK_ARIA,
    CKK_CAMELLIA,
    CKK_CHACHA20,
    CKK_POLY1305,
    CKK_SALSA20,
    CKK_SEED,
    CKM_ARIA_CBC,
    CKM_ARIA_CBC_ENCRYPT_DATA,
    CKM_ARIA_CBC_PAD,
    CKM_ARIA_ECB,
    CKM_ARIA_ECB_ENCRYPT_DATA,
    CKM_ARIA_KEY_GEN,
    CKM_ARIA_MAC,
    CKM_ARIA_MAC_GENERAL,
    CKM_CAMELLIA_CBC,
    CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    CKM_CAMELLIA_CBC_PAD,
    CKM_CAMELLIA_CTR,
    CKM_CAMELLIA_ECB,
    CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    CKM_CAMELLIA_KEY_GEN,
    CKM_CAMELLIA_MAC,
    CKM_CAMELLIA_MAC_GENERAL,
    CKM_CHACHA20,
    CKM_CHACHA20_KEY_GEN,
    CKM_CHACHA20_POLY1305,
    CKM_POLY1305,
    CKM_POLY1305_KEY_GEN,
    CKM_SALSA20,
    CKM_SALSA20_KEY_GEN,
    CKM_SALSA20_POLY1305,
    CKM_SEED_CBC,
    CKM_SEED_CBC_ENCRYPT_DATA,
    CKM_SEED_CBC_PAD,
    CKM_SEED_ECB,
    CKM_SEED_ECB_ENCRYPT_DATA,
    CKM_SEED_KEY_GEN,
    CKM_SEED_MAC,
    CKM_SEED_MAC_GENERAL,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_ENC_DEC = CKF_ENCRYPT | CKF_DECRYPT
_CAMELLIA_SIZES = (128, 192, 256)
_CAMELLIA_ENC = CKF_ENCRYPT | CKF_DECRYPT
_CAMELLIA_SIG = CKF_SIGN | CKF_VERIFY
_ARIA_SIZES = (128, 192, 256)
_ARIA_ENC = CKF_ENCRYPT | CKF_DECRYPT
_ARIA_SIG = CKF_SIGN | CKF_VERIFY
_SEED_ENC = CKF_ENCRYPT | CKF_DECRYPT
_SEED_SIG = CKF_SIGN | CKF_VERIFY
_SIG_VER = CKF_SIGN | CKF_VERIFY

_sym = KeygenRecipe("symmetric")
_fixed = KeygenRecipe("fixed_length")
_iv16 = ParamRecipe("iv", {"iv_len": 16})
_mac_general = ParamRecipe("mac_general", {"mac_len": 8})
_string_data = ParamRecipe("string_data")


def populate(registry: dict[int, MechConfig]) -> None:
    """Add ChaCha20, Salsa20, Poly1305, Camellia, ARIA, and SEED entries to the registry."""

    # ---------------------------------------------------------------------------
    # ChaCha20 / Salsa20 / Poly1305
    # ---------------------------------------------------------------------------

    registry[CKM_CHACHA20_KEY_GEN] = MechConfig(
        key_type=CKK_CHACHA20,
        keygen_mech=CKM_CHACHA20_KEY_GEN,
        key_sizes=(256,),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="ChaCha20 key generation (256-bit key)",
    )

    registry[CKM_CHACHA20] = MechConfig(
        key_type=CKK_CHACHA20,
        keygen_mech=CKM_CHACHA20_KEY_GEN,
        key_sizes=(256,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_ENC_DEC,
        notes="ChaCha20 stream cipher: requires CK_CHACHA20_PARAMS (nonce + counter)",
    )

    registry[CKM_CHACHA20_POLY1305] = MechConfig(
        key_type=CKK_CHACHA20,
        keygen_mech=CKM_CHACHA20_KEY_GEN,
        key_sizes=(256,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        multi_part_supported=False,
        auth_tag_included=True,
        deterministic=False,
        expected_flags=_ENC_DEC,
        notes="ChaCha20-Poly1305 AEAD: auth tag appended, requires CK_CHACHA20_POLY1305_PARAMS",
    )

    registry[CKM_SALSA20_KEY_GEN] = MechConfig(
        key_type=CKK_SALSA20,
        keygen_mech=CKM_SALSA20_KEY_GEN,
        key_sizes=(256,),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="Salsa20 key generation (256-bit key)",
    )

    registry[CKM_SALSA20] = MechConfig(
        key_type=CKK_SALSA20,
        keygen_mech=CKM_SALSA20_KEY_GEN,
        key_sizes=(256,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_ENC_DEC,
        notes="Salsa20 stream cipher: requires CK_SALSA20_PARAMS (nonce + counter)",
    )

    registry[CKM_SALSA20_POLY1305] = MechConfig(
        key_type=CKK_SALSA20,
        keygen_mech=CKM_SALSA20_KEY_GEN,
        key_sizes=(256,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        multi_part_supported=False,
        auth_tag_included=True,
        deterministic=False,
        expected_flags=_ENC_DEC,
        notes="Salsa20-Poly1305 AEAD: auth tag appended, requires CK_SALSA20_POLY1305_PARAMS",
    )

    registry[CKM_POLY1305_KEY_GEN] = MechConfig(
        key_type=CKK_POLY1305,
        keygen_mech=CKM_POLY1305_KEY_GEN,
        key_sizes=(256,),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="Poly1305 authenticator key generation (256-bit key, CKK_POLY1305)",
    )

    registry[CKM_POLY1305] = MechConfig(
        key_type=CKK_POLY1305,
        keygen_mech=CKM_POLY1305_KEY_GEN,
        key_sizes=(256,),
        param_required=True,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="Poly1305 one-time MAC: sign/verify, requires nonce param",
    )

    # ---------------------------------------------------------------------------
    # Camellia mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_CAMELLIA_KEY_GEN] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="Camellia key generation (128/192/256-bit)",
    )

    registry[CKM_CAMELLIA_ECB] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_CAMELLIA_ENC | CKF_WRAP | CKF_UNWRAP,
        vector_file="camellia_ecb.json",
        notes="Camellia-ECB: 16-byte block, no padding, deterministic",
    )

    registry[CKM_CAMELLIA_CBC] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_CAMELLIA_ENC | CKF_WRAP | CKF_UNWRAP,
        vector_file="camellia_cbc.json",
        notes="Camellia-CBC: 16-byte block, requires 16-byte IV param",
    )

    registry[CKM_CAMELLIA_CBC_PAD] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        block_size=16,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_CAMELLIA_ENC | CKF_WRAP | CKF_UNWRAP,
        notes="Camellia-CBC with PKCS#7 padding: any-length plaintext, requires 16-byte IV",
    )

    registry[CKM_CAMELLIA_CTR] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_CAMELLIA_ENC,
        notes="Camellia-CTR: counter mode stream cipher, requires counter block param",
    )

    registry[CKM_CAMELLIA_MAC] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        keygen_recipe=_sym,
        expected_flags=_CAMELLIA_SIG,
        notes="Camellia-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_CAMELLIA_MAC_GENERAL] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_CAMELLIA_SIG,
        notes="Camellia-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_CAMELLIA_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        input_constraint="block_aligned",
        param_recipe=_string_data,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="Camellia-ECB key derivation: derive key by Camellia-ECB encrypting data",
    )

    registry[CKM_CAMELLIA_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_CAMELLIA,
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_sizes=_CAMELLIA_SIZES,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_string_data,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="Camellia-CBC key derivation: derive key by Camellia-CBC encrypting data",
    )

    # ---------------------------------------------------------------------------
    # ARIA mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_ARIA_KEY_GEN] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="ARIA key generation (128/192/256-bit, Korean standard KS X 1213)",
    )

    registry[CKM_ARIA_ECB] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_sym,
        expected_flags=_ARIA_ENC | CKF_WRAP | CKF_UNWRAP,
        vector_file="aria_ecb.json",
        notes="ARIA-ECB: 16-byte block, no padding, deterministic",
    )

    registry[CKM_ARIA_CBC] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ARIA_ENC | CKF_WRAP | CKF_UNWRAP,
        vector_file="aria_cbc.json",
        notes="ARIA-CBC: 16-byte block, requires 16-byte IV param",
    )

    registry[CKM_ARIA_CBC_PAD] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        block_size=16,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_sym,
        expected_flags=_ARIA_ENC | CKF_WRAP | CKF_UNWRAP,
        notes="ARIA-CBC with PKCS#7 padding: any-length plaintext, requires 16-byte IV",
    )

    registry[CKM_ARIA_MAC] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        keygen_recipe=_sym,
        expected_flags=_ARIA_SIG,
        notes="ARIA-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_ARIA_MAC_GENERAL] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_ARIA_SIG,
        notes="ARIA-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_ARIA_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        input_constraint="block_aligned",
        param_recipe=_string_data,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="ARIA-ECB key derivation: derive key by ARIA-ECB encrypting data",
    )

    registry[CKM_ARIA_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_ARIA,
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_sizes=_ARIA_SIZES,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_string_data,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="ARIA-CBC key derivation: derive key by ARIA-CBC encrypting data",
    )

    # ---------------------------------------------------------------------------
    # SEED mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_SEED_KEY_GEN] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="SEED key generation (128-bit, Korean standard TTAS.KO-12.0004)",
    )

    registry[CKM_SEED_ECB] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        block_size=16,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_SEED_ENC | CKF_WRAP | CKF_UNWRAP,
        vector_file="seed_ecb.json",
        notes="SEED-ECB: 16-byte block, no padding, deterministic",
    )

    registry[CKM_SEED_CBC] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_SEED_ENC | CKF_WRAP | CKF_UNWRAP,
        vector_file="seed_cbc.json",
        notes="SEED-CBC: 16-byte block, requires 16-byte IV param",
    )

    registry[CKM_SEED_CBC_PAD] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        block_size=16,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv16,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_SEED_ENC | CKF_WRAP | CKF_UNWRAP,
        notes="SEED-CBC with PKCS#7 padding: any-length plaintext, requires 16-byte IV",
    )

    registry[CKM_SEED_MAC] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        keygen_recipe=_fixed,
        expected_flags=_SEED_SIG,
        notes="SEED-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_SEED_MAC_GENERAL] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_fixed,
        expected_flags=_SEED_SIG,
        notes="SEED-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_SEED_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        input_constraint="block_aligned",
        param_recipe=_string_data,
        keygen_recipe=_fixed,
        expected_flags=CKF_DERIVE,
        notes="SEED-ECB key derivation: derive key by SEED-ECB encrypting data",
    )

    registry[CKM_SEED_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_SEED,
        keygen_mech=CKM_SEED_KEY_GEN,
        key_sizes=(128,),
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_string_data,
        keygen_recipe=_fixed,
        expected_flags=CKF_DERIVE,
        notes="SEED-CBC key derivation: derive key by SEED-CBC encrypting data",
    )
