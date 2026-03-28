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
from pkcs11_check.testcases.mechanism_registry import MechConfig

_AES_SIZES = (128, 192, 256)
_AES_ENC = CKF_ENCRYPT | CKF_DECRYPT
_AES_WRP = CKF_WRAP | CKF_UNWRAP
_AES_SIG = CKF_SIGN | CKF_VERIFY


def populate(registry: dict[int, MechConfig]) -> None:
    """Add AES mechanism entries to the registry."""

    # -- Key generation ----------------------------------------------------------

    registry[CKM_AES_KEY_GEN] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        expected_flags=CKF_GENERATE,
        notes="AES secret key generation",
    )

    registry[CKM_AES_XTS_KEY_GEN] = MechConfig(
        key_type=CKK_AES_XTS,
        keygen_mech=CKM_AES_XTS_KEY_GEN,
        key_sizes=(256, 512),  # XTS uses double-length keys: 2×128 or 2×256
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
        deterministic=True,
        expected_flags=_AES_ENC | _AES_WRP,
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
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
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
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-CBC with PKCS#7 padding: any-length plaintext, requires IV param",
    )

    registry[CKM_AES_OFB] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-OFB: stream mode, any length, requires IV param",
    )

    registry[CKM_AES_CFB8] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-CFB8: 8-bit CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CFB64] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-CFB64: 64-bit CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CFB128] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-CFB128: 128-bit CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CFB1] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-CFB1: bit-level CFB stream mode, requires IV param",
    )

    registry[CKM_AES_CTS] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=16,
        input_constraint="any",  # any length >= 1 block
        param_required=True,
        param_packer="pack_aes_iv",
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
        param_packer="pack_aes_ctr",
        deterministic=False,
        expected_flags=_AES_ENC | _AES_WRP,
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
        param_packer="pack_aes_gcm",
        multi_part_supported=False,
        auth_tag_included=True,
        deterministic=False,
        message_based=True,
        expected_flags=_AES_ENC | _AES_WRP,
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
        param_packer="pack_aes_ccm",
        multi_part_supported=False,
        auth_tag_included=True,
        deterministic=False,
        message_based=True,
        expected_flags=_AES_ENC | _AES_WRP,
        notes="AES-CCM: AEAD, auth tag appended to ciphertext, NOT multi-part, v3.0 message-based",
    )

    registry[CKM_AES_GMAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=None,
        input_constraint="any",
        param_required=True,
        param_packer="pack_aes_gcm",
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
        param_packer="pack_aes_iv",
        deterministic=False,
        expected_flags=_AES_ENC,
        notes="AES-XTS: requires tweak (IV) and CKK_AES_XTS double-length key",
    )

    # -- MAC ---------------------------------------------------------------------

    registry[CKM_AES_MAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        expected_flags=_AES_SIG,
        notes="AES-MAC: CBC-MAC with fixed output length",
    )

    registry[CKM_AES_MAC_GENERAL] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        param_required=True,
        param_packer="pack_mac_general",
        expected_flags=_AES_SIG,
        notes="AES-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_AES_CMAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        expected_flags=_AES_SIG,
        notes="AES-CMAC: NIST SP 800-38B CMAC, fixed 128-bit output",
    )

    registry[CKM_AES_CMAC_GENERAL] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        param_required=True,
        param_packer="pack_mac_general",
        expected_flags=_AES_SIG,
        notes="AES-CMAC-GENERAL: CMAC with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_AES_XCBC_MAC] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=(128,),  # 128-bit keys only per spec
        expected_flags=_AES_SIG,
        notes="AES-XCBC-MAC: RFC 3566, 128-bit key only, 128-bit output",
    )

    registry[CKM_AES_XCBC_MAC_96] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=(128,),  # 128-bit keys only per spec
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
        param_packer="pack_aes_key_wrap_iv",
        expected_flags=_AES_WRP,
        notes="AES Key Wrap (RFC 3394): optional 8-byte IV, wraps 128/192/256-bit keys",
    )

    registry[CKM_AES_KEY_WRAP_PAD] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=8,
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
        param_packer="pack_aes_key_wrap_kwp",
        expected_flags=_AES_WRP,
        notes="AES Key Wrap with Padding (RFC 5649): optional 4-byte IV, any-length data",
    )

    registry[CKM_AES_KEY_WRAP_PKCS7] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        block_size=8,
        input_constraint="any",
        expected_flags=_AES_WRP,
        notes="AES Key Wrap with PKCS#7 padding",
    )

    # -- Key derivation ----------------------------------------------------------

    registry[CKM_AES_ECB_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        input_constraint="block_aligned",
        expected_flags=CKF_DERIVE,
        notes="AES-ECB key derivation: derive key by AES-ECB encrypting data",
    )

    registry[CKM_AES_CBC_ENCRYPT_DATA] = MechConfig(
        key_type=CKK_AES,
        keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES,
        input_constraint="block_aligned",
        param_required=True,
        param_packer="pack_aes_cbc_encrypt_data",
        expected_flags=CKF_DERIVE,
        notes="AES-CBC key derivation: derive key by AES-CBC encrypting data",
    )
