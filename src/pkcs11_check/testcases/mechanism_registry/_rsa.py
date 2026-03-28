"""RSA mechanism family registry entries."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKF_GENERATE_KEY_PAIR,
    CKF_SIGN,
    CKF_SIGN_RECOVER,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_VERIFY_RECOVER,
    CKF_WRAP,
    CKK_RSA,
    CKM_RIPEMD128_RSA_PKCS,
    CKM_RIPEMD160_RSA_PKCS,
    CKM_RSA_9796,
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
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA1_RSA_X9_31,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS_PSS,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA512_RSA_PKCS_PSS,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_RSA_SIZES = (2048, 3072, 4096)
_SIG_VER = CKF_SIGN | CKF_VERIFY
# OASIS spec lists SIGR&VERR for CKM_RSA_PKCS and CKM_RSA_X_509, but
# sign-with-message-recovery is an optional capability — modules may omit
# CKF_SIGN_RECOVER / CKF_VERIFY_RECOVER without violating the spec.
# _SIG_VER_REC is kept for documentation but not used in expected_flags.
_SIG_VER_REC = CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER
_ENC_DEC = CKF_ENCRYPT | CKF_DECRYPT
_WRP_UWRP = CKF_WRAP | CKF_UNWRAP

_rsa = KeygenRecipe("rsa")
_oaep = ParamRecipe("oaep", {"hash_mech": "CKM_SHA256", "mgf": "CKG_MGF1_SHA256"})

# PSS parameter recipes (one per hash — salt_len matches hash output size)
_pss_sha1 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA_1", "mgf": "CKG_MGF1_SHA1", "salt_len": 20}
)
_pss_sha224 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA224", "mgf": "CKG_MGF1_SHA224", "salt_len": 28}
)
_pss_sha256 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA256", "mgf": "CKG_MGF1_SHA256", "salt_len": 32}
)
_pss_sha384 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA384", "mgf": "CKG_MGF1_SHA384", "salt_len": 48}
)
_pss_sha512 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA512", "mgf": "CKG_MGF1_SHA512", "salt_len": 64}
)
_pss_sha3_224 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA3_224", "mgf": "CKG_MGF1_SHA3_224", "salt_len": 28}
)
_pss_sha3_256 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA3_256", "mgf": "CKG_MGF1_SHA3_256", "salt_len": 32}
)
_pss_sha3_384 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA3_384", "mgf": "CKG_MGF1_SHA3_384", "salt_len": 48}
)
_pss_sha3_512 = ParamRecipe(
    "pss", {"hash_mech": "CKM_SHA3_512", "mgf": "CKG_MGF1_SHA3_512", "salt_len": 64}
)


def populate(registry: dict[int, MechConfig]) -> None:
    """Add RSA mechanism entries to the registry."""

    # -- Key generation ----------------------------------------------------------

    registry[CKM_RSA_PKCS_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="RSA key pair generation",
    )

    registry[CKM_RSA_X9_31_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_X9_31_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="RSA X9.31 key pair generation",
    )

    # -- Raw RSA -----------------------------------------------------------------

    registry[CKM_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_rsa,
        expected_flags=_ENC_DEC | _SIG_VER | _WRP_UWRP,
        notes="RSA PKCS#1 v1.5 padding: encrypt/decrypt, sign/verify, wrap/unwrap",
    )

    registry[CKM_RSA_PKCS_OAEP] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        param_required=True,
        param_recipe=_oaep,
        keygen_recipe=_rsa,
        expected_flags=_ENC_DEC | _WRP_UWRP,
        notes="RSA OAEP encryption/wrap: requires CK_RSA_PKCS_OAEP_PARAMS",
    )

    registry[CKM_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        param_required=True,
        param_recipe=_pss_sha256,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="RSA PSS sign/verify with pre-hash: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_RSA_X_509] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_rsa,
        expected_flags=_ENC_DEC | _SIG_VER,
        notes="Raw RSA (no padding): X.509 format",
    )

    registry[CKM_RSA_X9_31] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="RSA X9.31 sign/verify with pre-hash",
    )

    # -- Hash-and-sign: SHA-1 through SHA-512 ------------------------------------

    registry[CKM_SHA1_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        vector_file="rsa_pkcs1_sha1.json",
        notes="SHA-1 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA224_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA-224 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA256_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        vector_file="rsa_pkcs1_sha256.json",
        notes="SHA-256 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA384_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        vector_file="rsa_pkcs1_sha384.json",
        notes="SHA-384 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA512_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        vector_file="rsa_pkcs1_sha512.json",
        notes="SHA-512 + RSA PKCS#1 v1.5 sign/verify",
    )

    # -- Hash-and-sign PSS: SHA-1 through SHA-512 --------------------------------

    registry[CKM_SHA1_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha1,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA-1 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA224_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha224,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA-224 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA256_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha256,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        vector_file="rsa_pss_sha256.json",
        notes="SHA-256 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA384_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha384,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA-384 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA512_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha512,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA-512 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    # -- Hash-and-sign: SHA3 variants --------------------------------------------

    registry[CKM_SHA3_224_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-224 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_256_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-256 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_384_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-384 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_512_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-512 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_224_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha3_224,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-224 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA3_256_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha3_256,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-256 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA3_384_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha3_384,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-384 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA3_512_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_pss_sha3_512,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA3-512 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    # -- Hybrid wrap / TPM variants ----------------------------------------------

    registry[CKM_RSA_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_required=True,
        param_recipe=_oaep,
        keygen_recipe=_rsa,
        expected_flags=_WRP_UWRP,
        notes="RSA-AES hybrid key wrap: OAEP wraps AES key, AES wraps target key",
    )

    registry[CKM_RSA_PKCS_TPM_1_1] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_rsa,
        expected_flags=_WRP_UWRP,
        notes="RSA PKCS#1 v1.5 TPM 1.1 variant for key unwrapping",
    )

    registry[CKM_RSA_PKCS_OAEP_TPM_1_1] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_rsa,
        expected_flags=_WRP_UWRP,
        notes="RSA OAEP TPM 1.1 variant for key unwrapping",
    )

    # -- Legacy RSA signature mechanisms ----------------------------------------

    registry[CKM_RSA_9796] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="ISO 9796 RSA signature (legacy, single-part)",
    )

    registry[CKM_RIPEMD128_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="RIPEMD-128 + RSA PKCS#1 v1.5 sign/verify (legacy)",
    )

    registry[CKM_RIPEMD160_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="RIPEMD-160 + RSA PKCS#1 v1.5 sign/verify (legacy)",
    )

    registry[CKM_SHA1_RSA_X9_31] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        keygen_recipe=_rsa,
        expected_flags=_SIG_VER,
        notes="SHA-1 + RSA X9.31 hash-and-sign",
    )
