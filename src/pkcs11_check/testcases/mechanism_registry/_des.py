"""DES and Triple-DES mechanism family registry entries."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DERIVE,
    CKF_ENCRYPT,
    CKF_GENERATE,
    CKF_SIGN,
    CKF_VERIFY,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKM_DES2_KEY_GEN,
    CKM_DES3_CBC,
    CKM_DES3_CBC_ENCRYPT_DATA,
    CKM_DES3_CBC_PAD,
    CKM_DES3_CMAC,
    CKM_DES3_CMAC_GENERAL,
    CKM_DES3_ECB,
    CKM_DES3_ECB_ENCRYPT_DATA,
    CKM_DES3_KEY_GEN,
    CKM_DES3_MAC,
    CKM_DES3_MAC_GENERAL,
    CKM_DES_CBC,
    CKM_DES_CBC_ENCRYPT_DATA,
    CKM_DES_CBC_PAD,
    CKM_DES_CFB8,
    CKM_DES_CFB64,
    CKM_DES_ECB,
    CKM_DES_ECB_ENCRYPT_DATA,
    CKM_DES_KEY_GEN,
    CKM_DES_MAC,
    CKM_DES_MAC_GENERAL,
    CKM_DES_OFB8,
    CKM_DES_OFB64,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_DES_ENC = CKF_ENCRYPT | CKF_DECRYPT
_DES_SIG = CKF_SIGN | CKF_VERIFY

# OASIS spec lists WRP&UWRP for DES/3DES block ciphers, but this is an optional
# capability -- modules may implement encrypt/decrypt without wrap.  Only the
# minimum required flags (CKF_ENCRYPT | CKF_DECRYPT) are recorded as expected.
_DES3_SIZES = (128, 192)  # DES2 (2-key 3DES) and DES3 (3-key 3DES)

_fixed = KeygenRecipe("fixed_length")
_iv8 = ParamRecipe("iv", {"iv_len": 8})
_mac_general = ParamRecipe("mac_general", {"mac_len": 8})
_string_data = ParamRecipe("string_data")


def populate(registry: dict[int, MechConfig]) -> None:
    """Add DES and Triple-DES mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # DES mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_DES_KEY_GEN] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="DES single key generation (56-bit effective, 64-bit with parity)",
    )

    registry[CKM_DES_ECB] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        vector_file="des_ecb.json",
        notes="DES-ECB: 8-byte block, no padding, deterministic",
    )

    registry[CKM_DES_CBC] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        vector_file="des_cbc.json",
        notes="DES-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_DES_CBC_PAD] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        vector_file="des_cbc_pad.json",
        notes="DES-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    registry[CKM_DES_MAC] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        keygen_recipe=_fixed,
        expected_flags=_DES_SIG,
        notes="DES-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_DES_MAC_GENERAL] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_fixed,
        expected_flags=_DES_SIG,
        vector_file="des_mac_general.json",
        notes="DES-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_DES_OFB64] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        notes="DES-OFB64: 64-bit output feedback stream mode, requires 8-byte IV",
    )

    registry[CKM_DES_OFB8] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        notes="DES-OFB8: 8-bit output feedback stream mode, requires 8-byte IV",
    )

    registry[CKM_DES_CFB64] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        notes="DES-CFB64: 64-bit cipher feedback stream mode, requires 8-byte IV",
    )

    registry[CKM_DES_CFB8] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        notes="DES-CFB8: 8-bit cipher feedback stream mode, requires 8-byte IV",
    )

    registry[CKM_DES_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        input_constraint="block_aligned",
        param_recipe=_string_data,
        keygen_recipe=_fixed,
        expected_flags=CKF_DERIVE,
        notes="DES-ECB key derivation: derive key by DES-ECB encrypting data",
    )

    registry[CKM_DES_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_DES,
        keygen_mech=CKM_DES_KEY_GEN,
        key_sizes=(64,),
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_string_data,
        keygen_recipe=_fixed,
        expected_flags=CKF_DERIVE,
        notes="DES-CBC key derivation: derive key by DES-CBC encrypting data",
    )

    registry[CKM_DES2_KEY_GEN] = MechConfig(
        key_type=CKK_DES2,
        keygen_mech=CKM_DES2_KEY_GEN,
        key_sizes=(128,),
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="2-key Triple-DES key generation (CKK_DES2, 128-bit)",
    )

    # ---------------------------------------------------------------------------
    # DES3 (Triple-DES) mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_DES3_KEY_GEN] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        keygen_recipe=_fixed,
        expected_flags=CKF_GENERATE,
        notes="Triple-DES key generation (CKK_DES3): 128-bit (2-key) or 192-bit (3-key)",
    )

    registry[CKM_DES3_ECB] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        deterministic=True,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        vector_file="des3_ecb.json",
        notes="3DES-ECB: 8-byte block, no padding, deterministic",
    )

    registry[CKM_DES3_CBC] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        block_size=8,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        vector_file="des3_cbc.json",
        notes="3DES-CBC: 8-byte block, requires 8-byte IV param",
    )

    registry[CKM_DES3_CBC_PAD] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=True,
        param_recipe=_iv8,
        deterministic=False,
        keygen_recipe=_fixed,
        expected_flags=_DES_ENC,
        vector_file="des3_cbc_pad.json",
        notes="3DES-CBC with PKCS#7 padding: any-length plaintext, requires 8-byte IV",
    )

    registry[CKM_DES3_MAC] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        keygen_recipe=_fixed,
        expected_flags=_DES_SIG,
        notes="3DES-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_DES3_MAC_GENERAL] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_fixed,
        expected_flags=_DES_SIG,
        vector_file="des3_mac_general.json",
        notes="3DES-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_DES3_CMAC] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        keygen_recipe=_fixed,
        expected_flags=_DES_SIG,
        notes="3DES-CMAC: NIST SP 800-38B CMAC, fixed 64-bit output",
    )

    registry[CKM_DES3_CMAC_GENERAL] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_fixed,
        expected_flags=_DES_SIG,
        notes="3DES-CMAC-GENERAL: CMAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_DES3_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        input_constraint="block_aligned",
        param_recipe=_string_data,
        keygen_recipe=_fixed,
        expected_flags=CKF_DERIVE,
        notes="3DES-ECB key derivation: derive key by 3DES-ECB encrypting data",
    )

    registry[CKM_DES3_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_DES3,
        keygen_mech=CKM_DES3_KEY_GEN,
        key_sizes=_DES3_SIZES,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=_string_data,
        keygen_recipe=_fixed,
        expected_flags=CKF_DERIVE,
        notes="3DES-CBC key derivation: derive key by 3DES-CBC encrypting data",
    )
