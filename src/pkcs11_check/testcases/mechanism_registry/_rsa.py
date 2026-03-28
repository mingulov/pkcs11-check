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
from pkcs11_check.testcases.mechanism_registry import MechConfig

_RSA_SIZES = (2048, 3072, 4096)
_SIG_VER = CKF_SIGN | CKF_VERIFY
_SIG_VER_REC = CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER
_ENC_DEC = CKF_ENCRYPT | CKF_DECRYPT
_WRP_UWRP = CKF_WRAP | CKF_UNWRAP


def populate(registry: dict[int, MechConfig]) -> None:
    """Add RSA mechanism entries to the registry."""

    # -- Key generation ----------------------------------------------------------

    registry[CKM_RSA_PKCS_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="RSA key pair generation",
    )

    registry[CKM_RSA_X9_31_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_X9_31_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
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
        expected_flags=_ENC_DEC | _SIG_VER_REC | _WRP_UWRP,
        notes="RSA PKCS#1 v1.5 padding: encrypt/decrypt, sign/verify, wrap/unwrap",
    )

    registry[CKM_RSA_PKCS_OAEP] = MechConfig(
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

    registry[CKM_RSA_PKCS_PSS] = MechConfig(
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

    registry[CKM_RSA_X_509] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        expected_flags=_ENC_DEC | _SIG_VER_REC,
        notes="Raw RSA (no padding): X.509 format",
    )

    registry[CKM_RSA_X9_31] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        expected_flags=_SIG_VER,
        notes="RSA X9.31 sign/verify with pre-hash",
    )

    # -- Hash-and-sign: SHA-1 through SHA-512 ------------------------------------

    registry[CKM_SHA1_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA-1 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA224_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA-224 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA256_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        vector_file="rsa_pkcs1_sha256.json",
        notes="SHA-256 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA384_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA-384 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA512_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA-512 + RSA PKCS#1 v1.5 sign/verify",
    )

    # -- Hash-and-sign PSS: SHA-1 through SHA-512 --------------------------------

    registry[CKM_SHA1_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_pss",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="SHA-1 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA224_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_pss",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="SHA-224 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA256_RSA_PKCS_PSS] = MechConfig(
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

    registry[CKM_SHA384_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_pss",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="SHA-384 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA512_RSA_PKCS_PSS] = MechConfig(
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

    registry[CKM_SHA3_224_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA3-224 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_256_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA3-256 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_384_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA3-384 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_512_RSA_PKCS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="SHA3-512 + RSA PKCS#1 v1.5 sign/verify",
    )

    registry[CKM_SHA3_224_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_pss",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="SHA3-224 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA3_256_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_pss",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="SHA3-256 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA3_384_RSA_PKCS_PSS] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_pss",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="SHA3-384 + RSA PSS sign/verify: requires CK_RSA_PKCS_PSS_PARAMS",
    )

    registry[CKM_SHA3_512_RSA_PKCS_PSS] = MechConfig(
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

    registry[CKM_RSA_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        param_packer="mech_oaep",
        param_required=True,
        expected_flags=_WRP_UWRP,
        notes="RSA-AES hybrid key wrap: OAEP wraps AES key, AES wraps target key",
    )

    registry[CKM_RSA_PKCS_TPM_1_1] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        expected_flags=_WRP_UWRP,
        notes="RSA PKCS#1 v1.5 TPM 1.1 variant for key unwrapping",
    )

    registry[CKM_RSA_PKCS_OAEP_TPM_1_1] = MechConfig(
        key_type=CKK_RSA,
        keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN,
        key_sizes=_RSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        expected_flags=_WRP_UWRP,
        notes="RSA OAEP TPM 1.1 variant for key unwrapping",
    )
