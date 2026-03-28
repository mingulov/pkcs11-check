"""DSA and DH mechanism family registry entries."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DERIVE,
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
    CKF_SIGN,
    CKF_VERIFY,
    CKK_DH,
    CKK_DSA,
    CKK_X9_42_DH,
    CKM_DH_PKCS_DERIVE,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DH_PKCS_PARAMETER_GEN,
    CKM_DSA,
    CKM_DSA_FIPS_G_GEN,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_DSA_PARAMETER_GEN,
    CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
    CKM_DSA_SHA1,
    CKM_DSA_SHA3_224,
    CKM_DSA_SHA3_256,
    CKM_DSA_SHA3_384,
    CKM_DSA_SHA3_512,
    CKM_DSA_SHA224,
    CKM_DSA_SHA256,
    CKM_DSA_SHA384,
    CKM_DSA_SHA512,
    CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
    CKM_X9_42_DH_DERIVE,
    CKM_X9_42_DH_HYBRID_DERIVE,
    CKM_X9_42_DH_KEY_PAIR_GEN,
    CKM_X9_42_DH_PARAMETER_GEN,
    CKM_X9_42_MQV_DERIVE,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig

_DSA_SIZES = (2048, 3072)
_DH_SIZES = (2048, 3072)
_SIG_VER = CKF_SIGN | CKF_VERIFY

_dsa = KeygenRecipe("dsa")
_dh = KeygenRecipe("dh")


def populate(registry: dict[int, MechConfig]) -> None:
    """Add DSA and DH mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # DSA mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_DSA_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="DSA key pair generation",
    )

    registry[CKM_DSA_PARAMETER_GEN] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_param_gen=True,
        keygen_recipe=_dsa,
        expected_flags=CKF_GENERATE,
        notes="DSA domain parameter generation (p, q, g)",
    )

    registry[CKM_DSA_PROBABLISTIC_PARAMETER_GEN] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_param_gen=True,
        keygen_recipe=_dsa,
        expected_flags=CKF_GENERATE,
        notes="DSA probabilistic domain parameter generation (FIPS 186-4 A.1.1.2)",
    )

    registry[CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_param_gen=True,
        keygen_recipe=_dsa,
        expected_flags=CKF_GENERATE,
        notes="DSA Shawe-Taylor domain parameter generation (FIPS 186-4 A.1.2.1)",
    )

    registry[CKM_DSA_FIPS_G_GEN] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_param_gen=True,
        keygen_recipe=_dsa,
        expected_flags=CKF_GENERATE,
        notes="DSA FIPS g parameter generation (generator g from p and q)",
    )

    registry[CKM_DSA] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA sign/verify (raw, single-part): requires pre-hashed input",
    )

    registry[CKM_DSA_SHA1] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA-1 hash-and-sign",
    )

    registry[CKM_DSA_SHA224] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA-224 hash-and-sign",
    )

    registry[CKM_DSA_SHA256] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA-256 hash-and-sign",
    )

    registry[CKM_DSA_SHA384] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA-384 hash-and-sign",
    )

    registry[CKM_DSA_SHA512] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA-512 hash-and-sign",
    )

    registry[CKM_DSA_SHA3_224] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA3-224 hash-and-sign",
    )

    registry[CKM_DSA_SHA3_256] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA3-256 hash-and-sign",
    )

    registry[CKM_DSA_SHA3_384] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA3-384 hash-and-sign",
    )

    registry[CKM_DSA_SHA3_512] = MechConfig(
        key_type=CKK_DSA,
        keygen_mech=CKM_DSA_KEY_PAIR_GEN,
        key_sizes=_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_dsa,
        expected_flags=_SIG_VER,
        notes="DSA with SHA3-512 hash-and-sign",
    )

    # ---------------------------------------------------------------------------
    # DH mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_DH_PKCS_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_DH,
        keygen_mech=CKM_DH_PKCS_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_keypair=True,
        keygen_recipe=_dh,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="Diffie-Hellman PKCS key pair generation",
    )

    registry[CKM_DH_PKCS_PARAMETER_GEN] = MechConfig(
        key_type=CKK_DH,
        keygen_mech=CKM_DH_PKCS_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_param_gen=True,
        keygen_recipe=_dh,
        expected_flags=CKF_GENERATE,
        notes="DH PKCS domain parameter generation (p, g)",
    )

    registry[CKM_DH_PKCS_DERIVE] = MechConfig(
        key_type=CKK_DH,
        keygen_mech=CKM_DH_PKCS_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_keypair=True,
        param_required=True,
        keygen_recipe=_dh,
        expected_flags=CKF_DERIVE,
        notes="DH PKCS key agreement: derive shared secret, requires peer public key param",
    )

    registry[CKM_X9_42_DH_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_X9_42_DH,
        keygen_mech=CKM_X9_42_DH_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_keypair=True,
        keygen_recipe=_dh,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="X9.42 DH key pair generation (CKK_X9_42_DH)",
    )

    registry[CKM_X9_42_DH_PARAMETER_GEN] = MechConfig(
        key_type=CKK_X9_42_DH,
        keygen_mech=CKM_X9_42_DH_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_param_gen=True,
        keygen_recipe=_dh,
        expected_flags=CKF_GENERATE,
        notes="X9.42 DH domain parameter generation",
    )

    registry[CKM_X9_42_DH_DERIVE] = MechConfig(
        key_type=CKK_X9_42_DH,
        keygen_mech=CKM_X9_42_DH_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_keypair=True,
        param_required=True,
        keygen_recipe=_dh,
        expected_flags=CKF_DERIVE,
        notes="X9.42 DH key agreement: single-step, requires CK_X9_42_DH1_DERIVE_PARAMS",
    )

    registry[CKM_X9_42_DH_HYBRID_DERIVE] = MechConfig(
        key_type=CKK_X9_42_DH,
        keygen_mech=CKM_X9_42_DH_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_keypair=True,
        param_required=True,
        keygen_recipe=_dh,
        expected_flags=CKF_DERIVE,
        notes="X9.42 DH hybrid key agreement: requires CK_X9_42_DH2_DERIVE_PARAMS",
    )

    registry[CKM_X9_42_MQV_DERIVE] = MechConfig(
        key_type=CKK_X9_42_DH,
        keygen_mech=CKM_X9_42_DH_KEY_PAIR_GEN,
        key_sizes=_DH_SIZES,
        is_keypair=True,
        param_required=True,
        keygen_recipe=_dh,
        expected_flags=CKF_DERIVE,
        notes="X9.42 MQV key agreement: requires CK_X9_42_MQV_DERIVE_PARAMS",
    )
