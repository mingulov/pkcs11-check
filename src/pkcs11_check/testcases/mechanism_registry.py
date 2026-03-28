"""Mechanism registry for mechanism-driven parametrized tests.

Maps CKM_* mechanism IDs to test configurations. Covers all 480 mechanisms
from the OASIS PKCS#11 v3.2 standard. Each entry describes how to test
a mechanism: what key type it needs, what key sizes, what parameter packer,
whether it supports multi-part, etc.

Usage:
    from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY, get_config
    config = get_config(CKM_AES_GCM)
    if config and config.key_type == CKK_AES:
        ...
"""
from __future__ import annotations

from dataclasses import dataclass

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DERIVE,
    CKF_DIGEST,
    CKF_ENCRYPT,
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
    CKF_SIGN,
    CKF_SIGN_RECOVER,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_VERIFY_RECOVER,
    CKF_WRAP,
    CKK_AES,
    CKK_AES_XTS,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKK_HSS,
    CKK_ML_DSA,
    CKK_ML_KEM,
    CKK_RSA,
    CKK_SHA3_224_HMAC,
    CKK_SHA3_256_HMAC,
    CKK_SHA3_384_HMAC,
    CKK_SHA3_512_HMAC,
    CKK_SHA224_HMAC,
    CKK_SHA256_HMAC,
    CKK_SHA384_HMAC,
    CKK_SHA512_224_HMAC,
    CKK_SHA512_256_HMAC,
    CKK_SHA512_HMAC,
    CKK_SHA512_T_HMAC,
    CKK_SHA_1_HMAC,
    CKK_SLH_DSA,
    CKK_XMSS,
    CKK_XMSSMT,
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
    CKM_BLAKE2B_160,
    CKM_BLAKE2B_160_HMAC,
    CKM_BLAKE2B_160_HMAC_GENERAL,
    CKM_BLAKE2B_160_KEY_DERIVE,
    CKM_BLAKE2B_160_KEY_GEN,
    CKM_BLAKE2B_256,
    CKM_BLAKE2B_256_HMAC,
    CKM_BLAKE2B_256_HMAC_GENERAL,
    CKM_BLAKE2B_256_KEY_DERIVE,
    CKM_BLAKE2B_256_KEY_GEN,
    CKM_BLAKE2B_384,
    CKM_BLAKE2B_384_HMAC,
    CKM_BLAKE2B_384_HMAC_GENERAL,
    CKM_BLAKE2B_384_KEY_DERIVE,
    CKM_BLAKE2B_384_KEY_GEN,
    CKM_BLAKE2B_512,
    CKM_BLAKE2B_512_HMAC,
    CKM_BLAKE2B_512_HMAC_GENERAL,
    CKM_BLAKE2B_512_KEY_DERIVE,
    CKM_BLAKE2B_512_KEY_GEN,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_DATA_AND_BASE,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ECDH1_COFACTOR_DERIVE,
    CKM_ECDH1_DERIVE,
    CKM_ECDH_AES_KEY_WRAP,
    CKM_ECDH_COF_AES_KEY_WRAP,
    CKM_ECDH_X_AES_KEY_WRAP,
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA3_224,
    CKM_ECDSA_SHA3_256,
    CKM_ECDSA_SHA3_384,
    CKM_ECDSA_SHA3_512,
    CKM_ECDSA_SHA224,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_ECMQV_DERIVE,
    CKM_EDDSA,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_HASH_ML_DSA,
    CKM_HASH_ML_DSA_SHA3_224,
    CKM_HASH_ML_DSA_SHA3_256,
    CKM_HASH_ML_DSA_SHA3_384,
    CKM_HASH_ML_DSA_SHA3_512,
    CKM_HASH_ML_DSA_SHA224,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_ML_DSA_SHA384,
    CKM_HASH_ML_DSA_SHA512,
    CKM_HASH_ML_DSA_SHAKE128,
    CKM_HASH_ML_DSA_SHAKE256,
    CKM_HASH_SLH_DSA,
    CKM_HASH_SLH_DSA_SHA3_224,
    CKM_HASH_SLH_DSA_SHA3_256,
    CKM_HASH_SLH_DSA_SHA3_384,
    CKM_HASH_SLH_DSA_SHA3_512,
    CKM_HASH_SLH_DSA_SHA224,
    CKM_HASH_SLH_DSA_SHA256,
    CKM_HASH_SLH_DSA_SHA384,
    CKM_HASH_SLH_DSA_SHA512,
    CKM_HASH_SLH_DSA_SHAKE128,
    CKM_HASH_SLH_DSA_SHAKE256,
    CKM_HKDF_DATA,
    CKM_HKDF_DERIVE,
    CKM_HKDF_KEY_GEN,
    CKM_HSS,
    CKM_HSS_KEY_PAIR_GEN,
    CKM_IKE1_EXTENDED_DERIVE,
    CKM_IKE1_PRF_DERIVE,
    CKM_IKE2_PRF_PLUS_DERIVE,
    CKM_IKE_PRF_DERIVE,
    CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_NULL,
    CKM_PKCS5_PBKD2,
    CKM_PUB_KEY_FROM_PRIV_KEY,
    CKM_RIPEMD128,
    CKM_RIPEMD128_HMAC,
    CKM_RIPEMD128_HMAC_GENERAL,
    CKM_RIPEMD160,
    CKM_RIPEMD160_HMAC,
    CKM_RIPEMD160_HMAC_GENERAL,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_OAEP_TPM_1_1,
    CKM_RSA_PKCS_PSS,
    CKM_RSA_PKCS_TPM_1_1,
    CKM_RSA_X9_31,
    CKM_RSA_X9_31_KEY_PAIR_GEN,
    CKM_RSA_X_509,
    CKM_SHA1_KEY_DERIVATION,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA3_224,
    CKM_SHA3_224_HMAC,
    CKM_SHA3_224_HMAC_GENERAL,
    CKM_SHA3_224_KEY_DERIVATION,
    CKM_SHA3_224_KEY_GEN,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_256_HMAC_GENERAL,
    CKM_SHA3_256_KEY_DERIVATION,
    CKM_SHA3_256_KEY_GEN,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384,
    CKM_SHA3_384_HMAC,
    CKM_SHA3_384_HMAC_GENERAL,
    CKM_SHA3_384_KEY_DERIVATION,
    CKM_SHA3_384_KEY_GEN,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512,
    CKM_SHA3_512_HMAC,
    CKM_SHA3_512_HMAC_GENERAL,
    CKM_SHA3_512_KEY_DERIVATION,
    CKM_SHA3_512_KEY_GEN,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS_PSS,
    CKM_SHA224,
    CKM_SHA224_HMAC,
    CKM_SHA224_HMAC_GENERAL,
    CKM_SHA224_KEY_DERIVATION,
    CKM_SHA224_KEY_GEN,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_HMAC_GENERAL,
    CKM_SHA256_KEY_DERIVATION,
    CKM_SHA256_KEY_GEN,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384,
    CKM_SHA384_HMAC,
    CKM_SHA384_HMAC_GENERAL,
    CKM_SHA384_KEY_DERIVATION,
    CKM_SHA384_KEY_GEN,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512,
    CKM_SHA512_224,
    CKM_SHA512_224_HMAC,
    CKM_SHA512_224_HMAC_GENERAL,
    CKM_SHA512_224_KEY_DERIVATION,
    CKM_SHA512_224_KEY_GEN,
    CKM_SHA512_256,
    CKM_SHA512_256_HMAC,
    CKM_SHA512_256_HMAC_GENERAL,
    CKM_SHA512_256_KEY_DERIVATION,
    CKM_SHA512_256_KEY_GEN,
    CKM_SHA512_HMAC,
    CKM_SHA512_HMAC_GENERAL,
    CKM_SHA512_KEY_DERIVATION,
    CKM_SHA512_KEY_GEN,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA512_T,
    CKM_SHA512_T_HMAC,
    CKM_SHA512_T_HMAC_GENERAL,
    CKM_SHA512_T_KEY_DERIVATION,
    CKM_SHA512_T_KEY_GEN,
    CKM_SHA_1,
    CKM_SHA_1_HMAC,
    CKM_SHA_1_HMAC_GENERAL,
    CKM_SHA_1_KEY_GEN,
    CKM_SHAKE_128_KEY_DERIVATION,
    CKM_SHAKE_256_KEY_DERIVATION,
    CKM_SLH_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKM_SP800_108_COUNTER_KDF,
    CKM_SP800_108_DOUBLE_PIPELINE_KDF,
    CKM_SP800_108_FEEDBACK_KDF,
    CKM_SSL3_KEY_AND_MAC_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKM_SSL3_PRE_MASTER_KEY_GEN,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
    CKM_TLS12_KDF,
    CKM_TLS12_KEY_AND_MAC_DERIVE,
    CKM_TLS12_KEY_SAFE_DERIVE,
    CKM_TLS12_MAC,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKM_TLS12_MASTER_KEY_DERIVE_DH,
    CKM_TLS_KDF,
    CKM_TLS_MAC,
    CKM_TLS_PRE_MASTER_KEY_GEN,
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    CKM_WTLS_PRE_MASTER_KEY_GEN,
    CKM_WTLS_PRF,
    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    CKM_X2RATCHET_INITIALIZE,
    CKM_X2RATCHET_RESPOND,
    CKM_X3DH_INITIALIZE,
    CKM_X3DH_RESPOND,
    CKM_XEDDSA,
    CKM_XMSS,
    CKM_XMSS_KEY_PAIR_GEN,
    CKM_XMSSMT,
    CKM_XMSSMT_KEY_PAIR_GEN,
    CKM_XOR_BASE_AND_DATA,
)


@dataclass(frozen=True)
class MechConfig:
    """Configuration for testing a specific PKCS#11 mechanism.

    Fields:
        key_type: CKK_* constant (None for digest-only mechanisms)
        keygen_mech: CKM_* constant for generating the right key (None for digest)
        key_sizes: Valid key sizes in bits. () for digest or curve-based
        is_keypair: True for asymmetric (uses C_GenerateKeyPair)
        is_param_gen: True for domain parameter generation (DSA/DH param gen)
        param_packer: Name of packer function in pack_mechanisms.py
        param_factory: Name of function that creates default test params
        block_size: Block size in bytes (16 for AES block modes, None for stream)
        vector_file: Path to JSON vectors file (relative to data/mechanism_vectors/)
        input_constraint: "block_aligned", "any", "digest_only", "none"
        multi_part_supported: False for AEAD (GCM/CCM), raw ECDSA, etc.
        param_required: True if C_*Init needs non-NULL mechanism params
        auth_tag_included: True for GCM/CCM (ciphertext includes auth tag)
        deterministic: False for CBC with random IV, RSA-OAEP, etc.
        message_based: True if v3.0 C_Message* APIs supported
        expected_flags: Expected CKF_* flags from C_GetMechanismInfo
        notes: Human-readable notes about the mechanism
    """

    key_type: int | None = None
    keygen_mech: int | None = None
    key_sizes: tuple[int, ...] = ()
    is_keypair: bool = False
    is_param_gen: bool = False
    param_packer: str | None = None
    param_factory: str | None = None
    block_size: int | None = None
    vector_file: str | None = None
    input_constraint: str = "any"
    multi_part_supported: bool = True
    param_required: bool = False
    auth_tag_included: bool = False
    deterministic: bool = True
    message_based: bool = False
    expected_flags: int = 0
    notes: str = ""


# ---------------------------------------------------------------------------
# Shared flag combinations
# ---------------------------------------------------------------------------
_AES_SIZES = (128, 192, 256)
_AES_ENC = CKF_ENCRYPT | CKF_DECRYPT
_AES_WRP = CKF_WRAP | CKF_UNWRAP
_AES_SIG = CKF_SIGN | CKF_VERIFY

_RSA_SIZES = (2048, 3072, 4096)
_SIG_VER = CKF_SIGN | CKF_VERIFY
_SIG_VER_REC = CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER
_ENC_DEC = CKF_ENCRYPT | CKF_DECRYPT
_WRP_UWRP = CKF_WRAP | CKF_UNWRAP


# Registry: CKM int value → MechConfig
# Populated incrementally by Tasks 2-4
MECHANISM_REGISTRY: dict[int, MechConfig] = {}


# ---------------------------------------------------------------------------
# AES mechanisms (28 entries)
# ---------------------------------------------------------------------------

# -- Key generation ----------------------------------------------------------

MECHANISM_REGISTRY[CKM_AES_KEY_GEN] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    expected_flags=CKF_GENERATE,
    notes="AES secret key generation",
)

MECHANISM_REGISTRY[CKM_AES_XTS_KEY_GEN] = MechConfig(
    key_type=CKK_AES_XTS,
    keygen_mech=CKM_AES_XTS_KEY_GEN,
    key_sizes=(256, 512),  # XTS uses double-length keys: 2×128 or 2×256
    expected_flags=CKF_GENERATE,
    notes="AES-XTS double-length key generation (CKK_AES_XTS)",
)

# -- Block cipher modes — encrypt/decrypt + wrap/unwrap ----------------------

MECHANISM_REGISTRY[CKM_AES_ECB] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CBC] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CBC_PAD] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_OFB] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CFB8] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CFB64] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CFB128] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CFB1] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CTS] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CTR] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_GCM] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_CCM] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_GMAC] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_XTS] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_MAC] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    expected_flags=_AES_SIG,
    notes="AES-MAC: CBC-MAC with fixed output length",
)

MECHANISM_REGISTRY[CKM_AES_MAC_GENERAL] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_AES_SIG,
    notes="AES-MAC-GENERAL: CBC-MAC with variable output length (CK_MAC_GENERAL_PARAMS)",
)

MECHANISM_REGISTRY[CKM_AES_CMAC] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    expected_flags=_AES_SIG,
    notes="AES-CMAC: NIST SP 800-38B CMAC, fixed 128-bit output",
)

MECHANISM_REGISTRY[CKM_AES_CMAC_GENERAL] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_AES_SIG,
    notes="AES-CMAC-GENERAL: CMAC with variable output length (CK_MAC_GENERAL_PARAMS)",
)

MECHANISM_REGISTRY[CKM_AES_XCBC_MAC] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=(128,),  # 128-bit keys only per spec
    expected_flags=_AES_SIG,
    notes="AES-XCBC-MAC: RFC 3566, 128-bit key only, 128-bit output",
)

MECHANISM_REGISTRY[CKM_AES_XCBC_MAC_96] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=(128,),  # 128-bit keys only per spec
    expected_flags=_AES_SIG,
    notes="AES-XCBC-MAC-96: RFC 3566, 128-bit key only, 96-bit output",
)

# -- Key wrap ----------------------------------------------------------------

MECHANISM_REGISTRY[CKM_AES_KEY_WRAP] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_KEY_WRAP_PAD] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    block_size=8,
    expected_flags=_AES_WRP,
    notes="AES Key Wrap with Padding (DEPRECATED in PKCS#11 v3.x — use KWP instead)",
)

MECHANISM_REGISTRY[CKM_AES_KEY_WRAP_KWP] = MechConfig(
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

MECHANISM_REGISTRY[CKM_AES_KEY_WRAP_PKCS7] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    block_size=8,
    input_constraint="any",
    expected_flags=_AES_WRP,
    notes="AES Key Wrap with PKCS#7 padding",
)

# -- Key derivation ----------------------------------------------------------

MECHANISM_REGISTRY[CKM_AES_ECB_ENCRYPT_DATA] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    input_constraint="block_aligned",
    expected_flags=CKF_DERIVE,
    notes="AES-ECB key derivation: derive key by AES-ECB encrypting data",
)

MECHANISM_REGISTRY[CKM_AES_CBC_ENCRYPT_DATA] = MechConfig(
    key_type=CKK_AES,
    keygen_mech=CKM_AES_KEY_GEN,
    key_sizes=_AES_SIZES,
    input_constraint="block_aligned",
    param_required=True,
    param_packer="pack_aes_cbc_encrypt_data",
    expected_flags=CKF_DERIVE,
    notes="AES-CBC key derivation: derive key by AES-CBC encrypting data",
)


# ---------------------------------------------------------------------------
# RSA mechanisms (~30 entries)
# ---------------------------------------------------------------------------

# -- Key generation ----------------------------------------------------------

MECHANISM_REGISTRY[CKM_RSA_PKCS_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="RSA key pair generation",
)

MECHANISM_REGISTRY[CKM_RSA_X9_31_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_X9_31_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="RSA X9.31 key pair generation",
)

# -- Raw RSA -----------------------------------------------------------------

MECHANISM_REGISTRY[CKM_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_ENC_DEC | _SIG_VER_REC | _WRP_UWRP,
    notes="RSA PKCS#1 v1.5 padding: encrypt/decrypt, sign/verify, wrap/unwrap",
)

MECHANISM_REGISTRY[CKM_RSA_PKCS_OAEP] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    param_packer="mech_oaep",
    param_required=True,
    expected_flags=_ENC_DEC | _WRP_UWRP,
    notes="RSA OAEP encryption/wrap: requires CK_RSA_PKCS_OAEP_PARAMS",
)

MECHANISM_REGISTRY[CKM_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="RSA PSS sign/verify with pre-hash: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_RSA_X_509] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_ENC_DEC | _SIG_VER_REC,
    notes="Raw RSA (no padding): X.509 format",
)

MECHANISM_REGISTRY[CKM_RSA_X9_31] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_SIG_VER,
    notes="RSA X9.31 sign/verify with pre-hash",
)

# -- Hash-and-sign: SHA-1 through SHA-512 ------------------------------------

MECHANISM_REGISTRY[CKM_SHA1_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA-1 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA224_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA-224 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA256_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    vector_file="rsa_pkcs1_sha256.json",
    notes="SHA-256 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA384_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA-384 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA512_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA-512 + RSA PKCS#1 v1.5 sign/verify",
)

# -- Hash-and-sign PSS: SHA-1 through SHA-512 --------------------------------

MECHANISM_REGISTRY[CKM_SHA1_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA-1 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA224_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA-224 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA256_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    vector_file="rsa_pss_sha256.json",
    notes="SHA-256 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA384_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA-384 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA512_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA-512 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

# -- Hash-and-sign: SHA3 variants --------------------------------------------

MECHANISM_REGISTRY[CKM_SHA3_224_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA3-224 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA3_256_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA3-256 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA3_384_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA3-384 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA3_512_RSA_PKCS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SHA3-512 + RSA PKCS#1 v1.5 sign/verify",
)

MECHANISM_REGISTRY[CKM_SHA3_224_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA3-224 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_256_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA3-256 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_384_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA3-384 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_512_RSA_PKCS_PSS] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_pss",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="SHA3-512 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
)

# -- Hybrid wrap / TPM variants ----------------------------------------------

MECHANISM_REGISTRY[CKM_RSA_AES_KEY_WRAP] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    param_packer="mech_oaep",
    param_required=True,
    expected_flags=_WRP_UWRP,
    notes="RSA-AES hybrid key wrap: OAEP wraps AES key, AES wraps target key",
)

MECHANISM_REGISTRY[CKM_RSA_PKCS_TPM_1_1] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_WRP_UWRP,
    notes="RSA PKCS#1 v1.5 TPM 1.1 variant for key unwrapping",
)

MECHANISM_REGISTRY[CKM_RSA_PKCS_OAEP_TPM_1_1] = MechConfig(
    key_type=CKK_RSA,
    keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
    key_sizes=_RSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_WRP_UWRP,
    notes="RSA OAEP TPM 1.1 variant for key unwrapping",
)


# ---------------------------------------------------------------------------
# EC — Weierstrass (CKK_EC, ~18 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_EC_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),  # curve-dependent, not bit sizes
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="EC (Weierstrass) key pair generation; alias CKM_ECDSA_KEY_PAIR_GEN",
)

# Alias: same value as CKM_EC_KEY_PAIR_GEN — only one entry in registry
# (CKM_ECDSA_KEY_PAIR_GEN == CKM_EC_KEY_PAIR_GEN == 0x1040)

MECHANISM_REGISTRY[CKM_ECDSA] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_SIG_VER,
    notes="Raw ECDSA sign/verify: pre-hashed input only, single-part",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA1] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA-1 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA224] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA-224 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA256] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    vector_file="ecdsa_sha256.json",
    notes="ECDSA with SHA-256 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA384] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA-384 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA512] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA-512 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA3_224] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA3-224 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA3_256] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA3-256 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA3_384] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA3-384 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDSA_SHA3_512] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ECDSA with SHA3-512 hash-and-sign",
)

MECHANISM_REGISTRY[CKM_ECDH1_DERIVE] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_packer="mech_ecdh",
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="ECDH1 key derivation: requires CK_ECDH1_DERIVE_PARAMS with peer public key",
)

MECHANISM_REGISTRY[CKM_ECDH1_COFACTOR_DERIVE] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_packer="mech_ecdh",
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="ECDH1 cofactor key derivation: requires CK_ECDH1_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_ECMQV_DERIVE] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="ECMQV key derivation: MQV protocol, requires CK_ECMQV_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_ECDH_AES_KEY_WRAP] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=_WRP_UWRP,
    notes="ECDH-AES hybrid key wrap (deprecated in v3.x)",
)

MECHANISM_REGISTRY[CKM_ECDH_COF_AES_KEY_WRAP] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=_WRP_UWRP,
    notes="ECDH cofactor + AES hybrid key wrap",
)

MECHANISM_REGISTRY[CKM_ECDH_X_AES_KEY_WRAP] = MechConfig(
    key_type=CKK_EC_MONTGOMERY,
    keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=_WRP_UWRP,
    notes="ECDH-X (Montgomery) + AES hybrid key wrap",
)


# ---------------------------------------------------------------------------
# EC — Edwards (CKK_EC_EDWARDS, 3 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_EC_EDWARDS_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_EC_EDWARDS,
    keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="Edwards-curve key pair generation (Ed25519 / Ed448)",
)

MECHANISM_REGISTRY[CKM_EDDSA] = MechConfig(
    key_type=CKK_EC_EDWARDS,
    keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_packer="mech_eddsa",
    param_required=True,
    expected_flags=_SIG_VER,
    notes="EdDSA sign/verify: requires CK_EDDSA_PARAMS specifying curve",
)

MECHANISM_REGISTRY[CKM_XEDDSA] = MechConfig(
    key_type=CKK_EC_EDWARDS,
    keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="XEdDSA sign/verify (Signal protocol)",
)


# ---------------------------------------------------------------------------
# EC — Montgomery (CKK_EC_MONTGOMERY, 1 entry)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_EC_MONTGOMERY_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_EC_MONTGOMERY,
    keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="Montgomery-curve key pair generation (X25519 / X448)",
)


# ---------------------------------------------------------------------------
# Hash/digest mechanisms (~20 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SHA_1] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    vector_file="sha1.json",
    notes="SHA-1 digest",
)

MECHANISM_REGISTRY[CKM_SHA224] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA-224 digest",
)

MECHANISM_REGISTRY[CKM_SHA256] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    vector_file="sha256.json",
    notes="SHA-256 digest",
)

MECHANISM_REGISTRY[CKM_SHA384] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA-384 digest",
)

MECHANISM_REGISTRY[CKM_SHA512] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA-512 digest",
)

MECHANISM_REGISTRY[CKM_SHA512_224] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA-512/224 truncated digest",
)

MECHANISM_REGISTRY[CKM_SHA512_256] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA-512/256 truncated digest",
)

MECHANISM_REGISTRY[CKM_SHA512_T] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    param_required=True,
    expected_flags=CKF_DIGEST,
    notes="SHA-512/t truncated digest: requires t (output length) parameter",
)

MECHANISM_REGISTRY[CKM_SHA3_224] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA3-224 digest",
)

MECHANISM_REGISTRY[CKM_SHA3_256] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA3-256 digest",
)

MECHANISM_REGISTRY[CKM_SHA3_384] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA3-384 digest",
)

MECHANISM_REGISTRY[CKM_SHA3_512] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHA3-512 digest",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_160] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="BLAKE2b-160 digest",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_256] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="BLAKE2b-256 digest",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_384] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="BLAKE2b-384 digest",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_512] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="BLAKE2b-512 digest",
)

# CKM_SHAKE_128 = 0x00000418, CKM_SHAKE_256 = 0x00000419
# Not yet exported from types_std.py (XOF requires C_DigestXof* v3.1 functions)
MECHANISM_REGISTRY[0x00000418] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHAKE-128 XOF: extendable-output function, requires C_DigestXof* (v3.1)",
)

MECHANISM_REGISTRY[0x00000419] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="SHAKE-256 XOF: extendable-output function, requires C_DigestXof* (v3.1)",
)

MECHANISM_REGISTRY[CKM_RIPEMD128] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="RIPEMD-128 digest",
)

MECHANISM_REGISTRY[CKM_RIPEMD160] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    input_constraint="digest_only",
    expected_flags=CKF_DIGEST,
    notes="RIPEMD-160 digest",
)


# ---------------------------------------------------------------------------
# HMAC mechanisms — standard (12 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SHA_1_HMAC] = MechConfig(
    key_type=CKK_SHA_1_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-1",
)

MECHANISM_REGISTRY[CKM_SHA224_HMAC] = MechConfig(
    key_type=CKK_SHA224_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-224",
)

MECHANISM_REGISTRY[CKM_SHA256_HMAC] = MechConfig(
    key_type=CKK_SHA256_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    vector_file="hmac_sha256.json",
    notes="HMAC-SHA-256",
)

MECHANISM_REGISTRY[CKM_SHA384_HMAC] = MechConfig(
    key_type=CKK_SHA384_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-384",
)

MECHANISM_REGISTRY[CKM_SHA512_HMAC] = MechConfig(
    key_type=CKK_SHA512_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512",
)

MECHANISM_REGISTRY[CKM_SHA512_224_HMAC] = MechConfig(
    key_type=CKK_SHA512_224_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512/224",
)

MECHANISM_REGISTRY[CKM_SHA512_256_HMAC] = MechConfig(
    key_type=CKK_SHA512_256_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512/256",
)

MECHANISM_REGISTRY[CKM_SHA3_224_HMAC] = MechConfig(
    key_type=CKK_SHA3_224_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-224",
)

MECHANISM_REGISTRY[CKM_SHA3_256_HMAC] = MechConfig(
    key_type=CKK_SHA3_256_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-256",
)

MECHANISM_REGISTRY[CKM_SHA3_384_HMAC] = MechConfig(
    key_type=CKK_SHA3_384_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-384",
)

MECHANISM_REGISTRY[CKM_SHA3_512_HMAC] = MechConfig(
    key_type=CKK_SHA3_512_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-512",
)

MECHANISM_REGISTRY[CKM_RIPEMD128_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-RIPEMD-128",
)

MECHANISM_REGISTRY[CKM_RIPEMD160_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-RIPEMD-160",
)

MECHANISM_REGISTRY[CKM_SHA512_T_HMAC] = MechConfig(
    key_type=CKK_SHA512_T_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512/t",
)


# ---------------------------------------------------------------------------
# HMAC_GENERAL variants — variable-length output (12 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SHA_1_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA_1_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-1-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA224_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA224_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-224-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA256_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA256_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA384_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA384_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-384-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA512_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA512_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA512_224_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA512_224_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512/224-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA512_256_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA512_256_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512/256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_224_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA3_224_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-224-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_256_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA3_256_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_384_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA3_384_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-384-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA3_512_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA3_512_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA3-512-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_RIPEMD128_HMAC_GENERAL] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-RIPEMD-128-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_RIPEMD160_HMAC_GENERAL] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-RIPEMD-160-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_SHA512_T_HMAC_GENERAL] = MechConfig(
    key_type=CKK_SHA512_T_HMAC,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-SHA-512/t-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)


# ---------------------------------------------------------------------------
# HMAC key generation (~13 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_GENERIC_SECRET_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="Generic secret key generation (used for HMAC and derivation keys)",
)

MECHANISM_REGISTRY[CKM_SHA_1_KEY_GEN] = MechConfig(
    key_type=CKK_SHA_1_HMAC,
    keygen_mech=CKM_SHA_1_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-1 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA224_KEY_GEN] = MechConfig(
    key_type=CKK_SHA224_HMAC,
    keygen_mech=CKM_SHA224_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-224 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA256_KEY_GEN] = MechConfig(
    key_type=CKK_SHA256_HMAC,
    keygen_mech=CKM_SHA256_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-256 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA384_KEY_GEN] = MechConfig(
    key_type=CKK_SHA384_HMAC,
    keygen_mech=CKM_SHA384_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-384 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA512_KEY_GEN] = MechConfig(
    key_type=CKK_SHA512_HMAC,
    keygen_mech=CKM_SHA512_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-512 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA512_224_KEY_GEN] = MechConfig(
    key_type=CKK_SHA512_224_HMAC,
    keygen_mech=CKM_SHA512_224_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-512/224 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA512_256_KEY_GEN] = MechConfig(
    key_type=CKK_SHA512_256_HMAC,
    keygen_mech=CKM_SHA512_256_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-512/256 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA512_T_KEY_GEN] = MechConfig(
    key_type=CKK_SHA512_T_HMAC,
    keygen_mech=CKM_SHA512_T_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA-512/t HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA3_224_KEY_GEN] = MechConfig(
    key_type=CKK_SHA3_224_HMAC,
    keygen_mech=CKM_SHA3_224_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA3-224 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA3_256_KEY_GEN] = MechConfig(
    key_type=CKK_SHA3_256_HMAC,
    keygen_mech=CKM_SHA3_256_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA3-256 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA3_384_KEY_GEN] = MechConfig(
    key_type=CKK_SHA3_384_HMAC,
    keygen_mech=CKM_SHA3_384_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA3-384 HMAC key generation",
)

MECHANISM_REGISTRY[CKM_SHA3_512_KEY_GEN] = MechConfig(
    key_type=CKK_SHA3_512_HMAC,
    keygen_mech=CKM_SHA3_512_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="SHA3-512 HMAC key generation",
)


# ---------------------------------------------------------------------------
# Key derivation by hash (~14 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SHA1_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-1 key derivation: derive symmetric key by hashing base key value",
)

MECHANISM_REGISTRY[CKM_SHA224_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-224 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA256_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-256 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA384_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-384 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA512_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-512 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA512_224_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-512/224 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA512_256_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-512/256 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA512_T_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA-512/t key derivation",
)

MECHANISM_REGISTRY[CKM_SHA3_224_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA3-224 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA3_256_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA3-256 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA3_384_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA3-384 key derivation",
)

MECHANISM_REGISTRY[CKM_SHA3_512_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHA3-512 key derivation",
)

MECHANISM_REGISTRY[CKM_SHAKE_128_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHAKE-128 key derivation (XOF-based)",
)

MECHANISM_REGISTRY[CKM_SHAKE_256_KEY_DERIVATION] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="SHAKE-256 key derivation (XOF-based)",
)


# ---------------------------------------------------------------------------
# BLAKE2b HMAC and key gen/derivation (~16 entries)
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_BLAKE2B_160_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-160",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_160_HMAC_GENERAL] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-160-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_160_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="BLAKE2b-160 key generation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_160_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="BLAKE2b-160 key derivation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_256_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-256",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_256_HMAC_GENERAL] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_256_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="BLAKE2b-256 key generation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_256_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="BLAKE2b-256 key derivation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_384_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-384",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_384_HMAC_GENERAL] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-384-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_384_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="BLAKE2b-384 key generation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_384_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="BLAKE2b-384 key derivation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_512_HMAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
    key_sizes=(),
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-512",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_512_HMAC_GENERAL] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
    key_sizes=(),
    param_required=True,
    param_packer="pack_mac_general",
    expected_flags=_SIG_VER,
    notes="HMAC-BLAKE2b-512-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_512_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="BLAKE2b-512 key generation",
)

MECHANISM_REGISTRY[CKM_BLAKE2B_512_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_DERIVE,
    notes="BLAKE2b-512 key derivation",
)


# ---------------------------------------------------------------------------
# PQC — ML-KEM (CRYSTALS-Kyber, FIPS 203) — 2 entries
# ---------------------------------------------------------------------------

_ML_KEM_SIZES = (512, 768, 1024)  # security levels (not raw bit sizes)

MECHANISM_REGISTRY[CKM_ML_KEM_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_ML_KEM,
    keygen_mech=CKM_ML_KEM_KEY_PAIR_GEN,
    key_sizes=_ML_KEM_SIZES,
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="ML-KEM key pair generation (FIPS 203): parameter sets 512/768/1024",
)

MECHANISM_REGISTRY[CKM_ML_KEM] = MechConfig(
    key_type=CKK_ML_KEM,
    keygen_mech=CKM_ML_KEM_KEY_PAIR_GEN,
    key_sizes=_ML_KEM_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=CKF_DERIVE,
    notes="ML-KEM encapsulation/decapsulation KEM (FIPS 203): CKF_DERIVE via C_DeriveKey",
)


# ---------------------------------------------------------------------------
# PQC — ML-DSA (CRYSTALS-Dilithium, FIPS 204) — 14 entries
# ---------------------------------------------------------------------------

_ML_DSA_SIZES = (44, 65, 87)  # security level params (not raw bit sizes)

MECHANISM_REGISTRY[CKM_ML_DSA_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="ML-DSA key pair generation (FIPS 204): parameter sets 44/65/87",
)

MECHANISM_REGISTRY[CKM_ML_DSA] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="ML-DSA sign/verify (FIPS 204): pure ML-DSA, context optional",
)

# CKM_ML_DSA_EXTERNAL_MU_GEN = 0x0000001e (gaps in types_std.py around ML_DSA=0x1d)
MECHANISM_REGISTRY[0x0000001E] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    param_required=True,
    expected_flags=CKF_DIGEST,
    notes="ML-DSA ExternalMu generation (FIPS 204): digest op producing mu for EXTERNAL_MU",
)

# CKM_ML_DSA_EXTERNAL_MU = 0x00000022 (gap between DH_PKCS_DERIVE=0x21 and HASH_ML_DSA_SHA224=0x23)
MECHANISM_REGISTRY[0x00000022] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    multi_part_supported=False,
    expected_flags=_SIG_VER,
    notes="ML-DSA ExternalMu sign/verify (FIPS 204): pre-computed mu input",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    param_required=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA sign/verify (FIPS 204): hash-then-sign, requires hash alg param",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA224] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA-224 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA256] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA-256 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA384] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA-384 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA512] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA-512 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA3_224] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA3-224 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA3_256] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA3-256 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA3_384] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA3-384 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHA3_512] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHA3-512 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHAKE128] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHAKE-128 (FIPS 204)",
)

MECHANISM_REGISTRY[CKM_HASH_ML_DSA_SHAKE256] = MechConfig(
    key_type=CKK_ML_DSA,
    keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
    key_sizes=_ML_DSA_SIZES,
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashML-DSA with SHAKE-256 (FIPS 204)",
)


# ---------------------------------------------------------------------------
# PQC — SLH-DSA (SPHINCS+, FIPS 205) — 13 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SLH_DSA_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),  # parameter set embedded in key (SLH-DSA-SHA2-128s etc.)
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="SLH-DSA key pair generation (FIPS 205): parameter set from CKA_PARAMETER_SET",
)

MECHANISM_REGISTRY[CKM_SLH_DSA] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="SLH-DSA sign/verify (FIPS 205): pure SLH-DSA, optional context",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA sign/verify (FIPS 205): hash-then-sign, requires hash alg param",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA224] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA-224 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA256] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA-256 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA384] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA-384 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA512] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA-512 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA3_224] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA3-224 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA3_256] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA3-256 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA3_384] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA3-384 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHA3_512] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHA3-512 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHAKE128] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHAKE-128 (FIPS 205)",
)

MECHANISM_REGISTRY[CKM_HASH_SLH_DSA_SHAKE256] = MechConfig(
    key_type=CKK_SLH_DSA,
    keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HashSLH-DSA with SHAKE-256 (FIPS 205)",
)


# ---------------------------------------------------------------------------
# PQC — HSS / XMSS / XMSSMT (hash-based signatures) — 6 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_HSS_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_HSS,
    keygen_mech=CKM_HSS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="HSS (Hierarchical Signature System, SP 800-208) key pair generation",
)

MECHANISM_REGISTRY[CKM_HSS] = MechConfig(
    key_type=CKK_HSS,
    keygen_mech=CKM_HSS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="HSS sign/verify (SP 800-208): stateful hash-based signature",
)

MECHANISM_REGISTRY[CKM_XMSS_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_XMSS,
    keygen_mech=CKM_XMSS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="XMSS (RFC 8391) key pair generation: stateful hash-based signature",
)

MECHANISM_REGISTRY[CKM_XMSS] = MechConfig(
    key_type=CKK_XMSS,
    keygen_mech=CKM_XMSS_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="XMSS sign/verify (RFC 8391): stateful hash-based signature",
)

MECHANISM_REGISTRY[CKM_XMSSMT_KEY_PAIR_GEN] = MechConfig(
    key_type=CKK_XMSSMT,
    keygen_mech=CKM_XMSSMT_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=CKF_GENERATE_KEY_PAIR,
    notes="XMSS^MT (RFC 8391) multi-tree key pair generation: stateful hash-based signature",
)

MECHANISM_REGISTRY[CKM_XMSSMT] = MechConfig(
    key_type=CKK_XMSSMT,
    keygen_mech=CKM_XMSSMT_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    expected_flags=_SIG_VER,
    notes="XMSS^MT sign/verify (RFC 8391): stateful hash-based multi-tree signature",
)


# ---------------------------------------------------------------------------
# KDF — HKDF (RFC 5869) — 3 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_HKDF_KEY_GEN] = MechConfig(
    key_type=CKK_HKDF,
    keygen_mech=CKM_HKDF_KEY_GEN,
    key_sizes=(),
    expected_flags=CKF_GENERATE,
    notes="HKDF key generation: generate raw IKM (input keying material) key",
)

MECHANISM_REGISTRY[CKM_HKDF_DERIVE] = MechConfig(
    key_type=CKK_HKDF,
    keygen_mech=CKM_HKDF_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="HKDF key derivation (RFC 5869): extract-and-expand, requires CK_HKDF_PARAMS",
)

MECHANISM_REGISTRY[CKM_HKDF_DATA] = MechConfig(
    key_type=CKK_HKDF,
    keygen_mech=CKM_HKDF_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="HKDF data derivation (RFC 5869): produces raw data output rather than key object",
)


# ---------------------------------------------------------------------------
# KDF — PBKDF2 (RFC 2898) — 1 entry
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_PKCS5_PBKD2] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_PKCS5_PBKD2,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_GENERATE,
    notes="PBKDF2 (RFC 2898): password-based key derivation, requires CK_PKCS5_PBKD2_PARAMS",
)


# ---------------------------------------------------------------------------
# KDF — SP800-108 counter/feedback/pipeline KDFs — 3 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SP800_108_COUNTER_KDF] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="SP800-108 counter-mode KDF: requires CK_SP800_108_KDF_PARAMS",
)

MECHANISM_REGISTRY[CKM_SP800_108_FEEDBACK_KDF] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="SP800-108 feedback-mode KDF: requires CK_SP800_108_KDF_PARAMS",
)

MECHANISM_REGISTRY[CKM_SP800_108_DOUBLE_PIPELINE_KDF] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="SP800-108 double-pipeline KDF: requires CK_SP800_108_KDF_PARAMS",
)


# ---------------------------------------------------------------------------
# TLS 1.2 protocol mechanisms — 9 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_TLS_PRE_MASTER_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_TLS_PRE_MASTER_KEY_GEN,
    key_sizes=(384,),  # 48-byte pre-master secret
    param_required=True,
    expected_flags=CKF_GENERATE,
    notes="TLS pre-master secret generation: requires TLS version param",
)

MECHANISM_REGISTRY[CKM_TLS12_MASTER_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 master key derivation: requires CK_TLS12_MASTER_KEY_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_TLS12_MASTER_KEY_DERIVE_DH] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 master key derivation (DH): requires CK_TLS12_MASTER_KEY_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_TLS12_KEY_AND_MAC_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 key and MAC material derivation: requires CK_TLS12_KEY_MAT_PARAMS",
)

MECHANISM_REGISTRY[CKM_TLS12_KEY_SAFE_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 safe key derivation: same as KEY_AND_MAC_DERIVE but SENSITIVE flag preserved",
)

MECHANISM_REGISTRY[CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 extended master secret (RFC 7627): requires session hash param",
)

MECHANISM_REGISTRY[CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 extended master secret DH variant (RFC 7627)",
)

MECHANISM_REGISTRY[CKM_TLS_MAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=_SIG_VER,
    notes="TLS MAC: requires CK_TLS_MAC_PARAMS (hash alg + label)",
)

MECHANISM_REGISTRY[CKM_TLS_KDF] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS KDF (generic PRF): requires CK_TLS_KDF_PARAMS",
)

MECHANISM_REGISTRY[CKM_TLS12_MAC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=_SIG_VER,
    notes="TLS 1.2 MAC: requires hash algorithm parameter",
)

MECHANISM_REGISTRY[CKM_TLS12_KDF] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="TLS 1.2 KDF (PRF): requires CK_TLS12_KDF_PARAMS",
)


# ---------------------------------------------------------------------------
# SSL 3.0 protocol mechanisms — 4 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_SSL3_PRE_MASTER_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_SSL3_PRE_MASTER_KEY_GEN,
    key_sizes=(384,),  # 48-byte pre-master secret
    param_required=True,
    expected_flags=CKF_GENERATE,
    notes="SSL 3.0 pre-master secret generation: requires TLS version param",
)

MECHANISM_REGISTRY[CKM_SSL3_MASTER_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="SSL 3.0 master key derivation: requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_SSL3_MASTER_KEY_DERIVE_DH] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="SSL 3.0 master key derivation (DH): requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_SSL3_KEY_AND_MAC_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="SSL 3.0 key and MAC material derivation: requires CK_SSL3_KEY_MAT_PARAMS",
)


# ---------------------------------------------------------------------------
# WTLS (WAP TLS) protocol mechanisms — 6 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_WTLS_PRE_MASTER_KEY_GEN] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_WTLS_PRE_MASTER_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_GENERATE,
    notes="WTLS pre-master secret generation",
)

MECHANISM_REGISTRY[CKM_WTLS_MASTER_KEY_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="WTLS master key derivation: requires CK_WTLS_MASTER_KEY_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="WTLS master key derivation (DH/ECC): requires CK_WTLS_MASTER_KEY_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="WTLS client key and MAC material derivation",
)

MECHANISM_REGISTRY[CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="WTLS server key and MAC material derivation",
)

MECHANISM_REGISTRY[CKM_WTLS_PRF] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="WTLS PRF (pseudo-random function)",
)


# ---------------------------------------------------------------------------
# IKE (IPsec key exchange) KDFs — 4 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_IKE_PRF_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="IKE PRF key derivation: requires CK_IKE_PRF_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_IKE1_PRF_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="IKEv1 PRF key derivation: requires CK_IKE1_PRF_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_IKE1_EXTENDED_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="IKEv1 extended key derivation: requires CK_IKE1_EXTENDED_DERIVE_PARAMS",
)

MECHANISM_REGISTRY[CKM_IKE2_PRF_PLUS_DERIVE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="IKEv2 PRF+ key derivation: requires CK_IKE2_PRF_PLUS_DERIVE_PARAMS",
)


# ---------------------------------------------------------------------------
# Miscellaneous derivation mechanisms — 6 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_CONCATENATE_BASE_AND_KEY] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="Concatenate base key value with another key value to derive new key",
)

MECHANISM_REGISTRY[CKM_CONCATENATE_BASE_AND_DATA] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="Concatenate base key value with data bytes to derive new key",
)

MECHANISM_REGISTRY[CKM_CONCATENATE_DATA_AND_BASE] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="Concatenate data bytes with base key value to derive new key",
)

MECHANISM_REGISTRY[CKM_XOR_BASE_AND_DATA] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="XOR base key value with data bytes to derive new key",
)

MECHANISM_REGISTRY[CKM_EXTRACT_KEY_FROM_KEY] = MechConfig(
    key_type=CKK_GENERIC_SECRET,
    keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
    key_sizes=(),
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="Extract a subset of bytes from key value to create new key",
)

MECHANISM_REGISTRY[CKM_PUB_KEY_FROM_PRIV_KEY] = MechConfig(
    key_type=CKK_EC,
    keygen_mech=CKM_EC_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=False,
    expected_flags=CKF_DERIVE,
    notes="Derive public key object from existing private key: works for EC/EdDSA/Montgomery",
)


# ---------------------------------------------------------------------------
# Signal protocol mechanisms — 4 entries
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_X3DH_INITIALIZE] = MechConfig(
    key_type=CKK_EC_MONTGOMERY,
    keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="X3DH key agreement — initiator side (Signal protocol): requires CK_X3DH_INITIATE_PARAMS",
)

MECHANISM_REGISTRY[CKM_X3DH_RESPOND] = MechConfig(
    key_type=CKK_EC_MONTGOMERY,
    keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="X3DH key agreement — responder side (Signal protocol): requires CK_X3DH_RESPOND_PARAMS",
)

MECHANISM_REGISTRY[CKM_X2RATCHET_INITIALIZE] = MechConfig(
    key_type=CKK_EC_MONTGOMERY,
    keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="Double Ratchet initialization — sender side (Signal protocol)",
)

MECHANISM_REGISTRY[CKM_X2RATCHET_RESPOND] = MechConfig(
    key_type=CKK_EC_MONTGOMERY,
    keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    key_sizes=(),
    is_keypair=True,
    param_required=True,
    expected_flags=CKF_DERIVE,
    notes="Double Ratchet initialization — receiver side (Signal protocol)",
)


# ---------------------------------------------------------------------------
# CKM_NULL — 1 entry
# ---------------------------------------------------------------------------

MECHANISM_REGISTRY[CKM_NULL] = MechConfig(
    key_type=None,
    keygen_mech=None,
    key_sizes=(),
    multi_part_supported=False,
    expected_flags=_SIG_VER,
    notes="CKM_NULL: pass-through mechanism, data signed/verified as-is with no hashing",
)


def get_config(mech_id: int) -> MechConfig | None:
    """Look up mechanism config by CKM_* integer value.

    Returns None for vendor-defined mechanisms not in the registry.
    """
    return MECHANISM_REGISTRY.get(mech_id)
