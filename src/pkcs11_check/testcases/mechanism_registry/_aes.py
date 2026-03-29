"""AES mechanism family registry entries."""

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
    CKK_AES,
    CKK_AES_XTS,
    CKM_AES_CBC,
    CKM_AES_CBC_ENCRYPT_DATA,
    CKM_AES_CBC_PAD,
    CKM_AES_CCM,
    CKM_AES_CFB1,
    CKM_AES_CFB8,
    CKM_AES_CFB64,
    CKM_AES_CFB128,
    CKM_AES_CMAC,
    CKM_AES_CMAC_GENERAL,
    CKM_AES_CTR,
    CKM_AES_CTS,
    CKM_AES_ECB,
    CKM_AES_ECB_ENCRYPT_DATA,
    CKM_AES_GCM,
    CKM_AES_GMAC,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKM_AES_KEY_WRAP_PAD,
    CKM_AES_KEY_WRAP_PKCS7,
    CKM_AES_MAC,
    CKM_AES_MAC_GENERAL,
    CKM_AES_OFB,
    CKM_AES_XCBC_MAC,
    CKM_AES_XCBC_MAC_96,
    CKM_AES_XTS,
    CKM_AES_XTS_KEY_GEN,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_AES_SIZES = (128, 192, 256)
_AES_ENC = CKF_ENCRYPT | CKF_DECRYPT
_AES_WRP = CKF_WRAP | CKF_UNWRAP
_AES_SIG = CKF_SIGN | CKF_VERIFY

# OASIS PKCS#11 spec lists WRP&UWRP for AES block/stream ciphers, but this is
# an optional capability — modules may implement encrypt/decrypt without wrap.
# Only dedicated key-wrap mechanisms (CKM_AES_KEY_WRAP*) are required to
# advertise CKF_WRAP | CKF_UNWRAP.  For all other AES cipher modes the minimum
# required flag set is CKF_ENCRYPT | CKF_DECRYPT.


def populate(registry: dict[int, MechConfig]) -> None:
    """Add AES mechanism entries to the registry."""

    _sym = KeygenRecipe("symmetric")

    # -- Key generation ----------------------------------------------------------

    registry[CKM_AES_KEY_GEN] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="AES secret key generation",
    )

    registry[CKM_AES_XTS_KEY_GEN] = MechConfig(
        key_type=CKK_AES_XTS,
        keygen_mech=CKM_AES_XTS_KEY_GEN,
        key_sizes=(256, 512),  # XTS uses double-length keys: 2×128 or 2×256
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="AES-XTS double-length key generation (CKK_AES_XTS)",
    )

    # -- Block cipher modes — encrypt/decrypt + wrap/unwrap ----------------------

    registry[CKM_AES_ECB] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        deterministic=True,
        expected_flags=_AES_ENC,
        vector_file="aes_ecb.json",
        notes="AES-ECB: block-aligned, no params, deterministic",
    )

    registry[CKM_AES_CBC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=16,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_cbc.json",
        notes="AES-CBC: block-aligned, requires 16-byte IV param",
    )

    registry[CKM_AES_CBC_PAD] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=16,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_cbc_pad.json",
        notes="AES-CBC with PKCS#7 padding: any-length plaintext, requires IV param",
    )

    registry[CKM_AES_OFB] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_ofb.json",
        notes="AES-OFB: stream mode, any length, requires IV param",
    )

    registry[CKM_AES_CFB8] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_cfb8.json",
        notes="AES-CFB8: 8-bit CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CFB64] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        notes="AES-CFB64: 64-bit CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CFB128] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_cfb128.json",
        notes="AES-CFB128: 128-bit CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CFB1] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        notes="AES-CFB1: bit-level CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CTS] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=16,
        input_constraint="any",  # any length >= 1 block
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,  # wrap/unwrap not typically advertised
        notes="AES-CTS: ciphertext stealing, min 1 block, requires IV param",
    )

    registry[CKM_AES_CTR] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("ctr", {"counter_bits": 128}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_ctr.json",
        notes="AES-CTR: counter mode, requires CK_AES_CTR_PARAMS (counter bits + IV)",
    )

    # -- AEAD --------------------------------------------------------------------

    registry[CKM_AES_GCM] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("gcm", {"iv_len": 12, "tag_bits": 128}),
        keygen_recipe=_sym,
        multi_part_supported=False,
        auth_tag_included=True,
        deterministic=False,
        message_based=True,
        expected_flags=_AES_ENC,
        vector_file="aes_gcm.json",
        notes="AES-GCM: AEAD, auth tag appended to ciphertext, NOT multi-part, v3.0 message-based",
    )

    registry[CKM_AES_CCM] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("ccm", {"nonce_len": 7, "data_len": 32, "mac_len": 16}),
        keygen_recipe=_sym,
        multi_part_supported=False,
        auth_tag_included=True,
        deterministic=False,
        message_based=True,
        expected_flags=_AES_ENC,
        vector_file="aes_ccm.json",
        notes="AES-CCM: AEAD, auth tag appended to ciphertext, NOT multi-part, v3.0 message-based",
    )

    registry[CKM_AES_GMAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("gcm", {"iv_len": 12, "tag_bits": 128}),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-GMAC: GMAC authentication only (sign/verify), no plaintext encryption",
    )

    # -- XTS ---------------------------------------------------------------------

    registry[CKM_AES_XTS] = MechConfig(
        key_type=CKK_AES_XTS,
        keygen_mech=CKM_AES_XTS_KEY_GEN,
        key_sizes=(256, 512),  # double-length keys: 2×128 or 2×256
        block_size=16,
        input_constraint="any",
        param_required=True,
        param_recipe=ParamRecipe("iv", {"iv_len": 16}),
        keygen_recipe=_sym,
        deterministic=False,
        expected_flags=_AES_ENC,
        vector_file="aes_xts.json",
        notes="AES-XTS: requires tweak (IV) and CKK_AES_XTS double-length key",
    )

    # -- MAC ---------------------------------------------------------------------

    registry[CKM_AES_MAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_AES_MAC_GENERAL] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        param_required=True,
        param_recipe=ParamRecipe("mac_general", {"mac_len": 8}),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_AES_CMAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-CMAC: NIST SP 800-38B CMAC, fixed 128-bit output",
    )

    registry[CKM_AES_CMAC_GENERAL] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        param_required=True,
        param_recipe=ParamRecipe("mac_general", {"mac_len": 8}),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-CMAC-GENERAL: CMAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_AES_XCBC_MAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=(128,),  # 128-bit keys only per spec
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-XCBC-MAC: RFC 3566, 128-bit key only, 128-bit output",
    )

    registry[CKM_AES_XCBC_MAC_96] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=(128,),  # 128-bit keys only per spec
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        expected_flags=_AES_SIG,
        notes="AES-XCBC-MAC-96: RFC 3566, 128-bit key only, 96-bit output",
    )

    # -- Key wrap ----------------------------------------------------------------

    registry[CKM_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=8,  # RFC 3394: operates on 64-bit blocks
        input_constraint="block_aligned",
        param_required=False,  # optional 8-byte IV param (default IV used if absent)
        param_recipe=ParamRecipe("none"),  # key-wrap-only, skip for data operations
        keygen_recipe=_sym,
        multi_part_supported=False,
        expected_flags=_AES_WRP,
        notes="AES Key Wrap (RFC 3394): optional 8-byte IV, wraps 128/192/256-bit keys",
    )

    registry[CKM_AES_KEY_WRAP_PAD] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=8,
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        multi_part_supported=False,
        expected_flags=_AES_WRP,
        notes="AES Key Wrap with Padding (DEPRECATED in PKCS#11 v3.x — use KWP instead)",
    )

    registry[CKM_AES_KEY_WRAP_KWP] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=8,
        input_constraint="any",
        param_required=False,  # optional 4-byte semi-fixed header
        param_recipe=ParamRecipe("none"),  # key-wrap-only, skip for data operations
        keygen_recipe=_sym,
        multi_part_supported=False,
        expected_flags=_AES_WRP,
        notes="AES Key Wrap with Padding (RFC 5649): optional 4-byte IV, any-length data",
    )

    registry[CKM_AES_KEY_WRAP_PKCS7] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=8,
        input_constraint="any",
        param_recipe=ParamRecipe("none"),
        keygen_recipe=_sym,
        multi_part_supported=False,
        expected_flags=_AES_WRP,
        notes="AES Key Wrap with PKCS#7 padding",
    )

    # -- Key derivation ----------------------------------------------------------

    registry[CKM_AES_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        input_constraint="block_aligned",
        param_recipe=ParamRecipe("string_data"),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="AES-ECB key derivation: derive key by AES-ECB encrypting data",
    )

    registry[CKM_AES_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        input_constraint="block_aligned",
        param_required=True,
        param_recipe=ParamRecipe("string_data"),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="AES-CBC key derivation: derive key by AES-CBC encrypting data",
    )
