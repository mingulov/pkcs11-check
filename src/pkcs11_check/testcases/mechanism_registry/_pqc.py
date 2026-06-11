"""PQC mechanism family registry entries.

Covers ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
HSS (SP 800-208), XMSS, and XMSS^MT (RFC 8391).
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DECAPSULATE,
    CKF_DIGEST,
    CKF_ENCAPSULATE,
    CKF_GENERATE_KEY_PAIR,
    CKF_SIGN,
    CKF_VERIFY,
    CKK_HSS,
    CKK_ML_DSA,
    CKK_ML_KEM,
    CKK_SLH_DSA,
    CKK_XMSS,
    CKK_XMSSMT,
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
    CKM_HSS,
    CKM_HSS_KEY_PAIR_GEN,
    CKM_ML_DSA,
    CKM_ML_DSA_EXTERNAL_MU,
    CKM_ML_DSA_EXTERNAL_MU_GEN,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_SLH_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKM_XMSS,
    CKM_XMSS_KEY_PAIR_GEN,
    CKM_XMSSMT,
    CKM_XMSSMT_KEY_PAIR_GEN,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig

_SIG_VER = CKF_SIGN | CKF_VERIFY
_ML_KEM_SIZES = (512, 768, 1024)  # security levels (not raw bit sizes)
_ML_DSA_SIZES = (44, 65, 87)  # security level params (not raw bit sizes)

_ml_kem = KeygenRecipe("pqc", {"parameter_set": "CKP_ML_KEM_768"})
_ml_dsa = KeygenRecipe("pqc", {"parameter_set": "CKP_ML_DSA_65"})
_slh_dsa = KeygenRecipe("pqc", {"parameter_set": "CKP_SLH_DSA_SHA2_128S"})
_hss = KeygenRecipe("pqc", {"parameter_set": "CKP_HSS_LMS_SHA256_M32_H5"})
_xmss = KeygenRecipe("pqc", {"parameter_set": "CKP_XMSS_SHA2_10_256"})
_xmssmt = KeygenRecipe("pqc", {"parameter_set": "CKP_XMSSMT_SHA2_20_2_256"})


def populate(registry: dict[int, MechConfig]) -> None:
    """Add PQC mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # ML-KEM (CRYSTALS-Kyber, FIPS 203)
    # ---------------------------------------------------------------------------

    registry[CKM_ML_KEM_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_ML_KEM,
        keygen_mech=CKM_ML_KEM_KEY_PAIR_GEN,
        key_sizes=_ML_KEM_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_kem,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="ML-KEM key pair generation (FIPS 203): parameter sets 512/768/1024",
    )

    registry[CKM_ML_KEM] = MechConfig(
        key_type=CKK_ML_KEM,
        keygen_mech=CKM_ML_KEM_KEY_PAIR_GEN,
        key_sizes=_ML_KEM_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_ml_kem,
        expected_flags=int(CKF_ENCAPSULATE) | int(CKF_DECAPSULATE),
        notes="ML-KEM (FIPS 203): C_EncapsulateKey / C_DecapsulateKey",
    )

    # ---------------------------------------------------------------------------
    # ML-DSA (CRYSTALS-Dilithium, FIPS 204)
    # ---------------------------------------------------------------------------

    registry[CKM_ML_DSA_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="ML-DSA key pair generation (FIPS 204): parameter sets 44/65/87",
    )

    registry[CKM_ML_DSA] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="ML-DSA sign/verify (FIPS 204): pure ML-DSA, context optional",
    )

    registry[CKM_ML_DSA_EXTERNAL_MU_GEN] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ml_dsa,
        expected_flags=CKF_DIGEST,
        notes="ML-DSA ExternalMu generation (FIPS 204): digest op producing mu for EXTERNAL_MU",
    )

    registry[CKM_ML_DSA_EXTERNAL_MU] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="ML-DSA ExternalMu sign/verify (FIPS 204): pre-computed mu input",
    )

    registry[CKM_HASH_ML_DSA] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA sign/verify (FIPS 204): hash-then-sign, requires hash alg param",
    )

    registry[CKM_HASH_ML_DSA_SHA224] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA-224 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA256] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA-256 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA384] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA-384 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA512] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA-512 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA3_224] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA3-224 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA3_256] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA3-256 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA3_384] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA3-384 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHA3_512] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHA3-512 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHAKE128] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHAKE-128 (FIPS 204)",
    )

    registry[CKM_HASH_ML_DSA_SHAKE256] = MechConfig(
        key_type=CKK_ML_DSA,
        keygen_mech=CKM_ML_DSA_KEY_PAIR_GEN,
        key_sizes=_ML_DSA_SIZES,
        is_keypair=True,
        keygen_recipe=_ml_dsa,
        expected_flags=_SIG_VER,
        notes="HashML-DSA with SHAKE-256 (FIPS 204)",
    )

    # ---------------------------------------------------------------------------
    # SLH-DSA (SPHINCS+, FIPS 205)
    # ---------------------------------------------------------------------------

    registry[CKM_SLH_DSA_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),  # parameter set embedded in key (SLH-DSA-SHA2-128s etc.)
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="SLH-DSA key pair generation (FIPS 205): parameter set from CKA_PARAMETER_SET",
    )

    registry[CKM_SLH_DSA] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="SLH-DSA sign/verify (FIPS 205): pure SLH-DSA, optional context",
    )

    registry[CKM_HASH_SLH_DSA] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA sign/verify (FIPS 205): hash-then-sign, requires hash alg param",
    )

    registry[CKM_HASH_SLH_DSA_SHA224] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA-224 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA256] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA-256 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA384] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA-384 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA512] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA-512 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA3_224] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA3-224 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA3_256] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA3-256 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA3_384] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA3-384 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHA3_512] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHA3-512 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHAKE128] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHAKE-128 (FIPS 205)",
    )

    registry[CKM_HASH_SLH_DSA_SHAKE256] = MechConfig(
        key_type=CKK_SLH_DSA,
        keygen_mech=CKM_SLH_DSA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_slh_dsa,
        expected_flags=_SIG_VER,
        notes="HashSLH-DSA with SHAKE-256 (FIPS 205)",
    )

    # ---------------------------------------------------------------------------
    # HSS / XMSS / XMSSMT (hash-based signatures)
    # ---------------------------------------------------------------------------

    registry[CKM_HSS_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_HSS,
        keygen_mech=CKM_HSS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_hss,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="HSS (Hierarchical Signature System, SP 800-208) key pair generation",
    )

    registry[CKM_HSS] = MechConfig(
        key_type=CKK_HSS,
        keygen_mech=CKM_HSS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_hss,
        expected_flags=_SIG_VER,
        notes="HSS sign/verify (SP 800-208): stateful hash-based signature",
    )

    registry[CKM_XMSS_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_XMSS,
        keygen_mech=CKM_XMSS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_xmss,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="XMSS (RFC 8391) key pair generation: stateful hash-based signature",
    )

    registry[CKM_XMSS] = MechConfig(
        key_type=CKK_XMSS,
        keygen_mech=CKM_XMSS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_xmss,
        expected_flags=_SIG_VER,
        notes="XMSS sign/verify (RFC 8391): stateful hash-based signature",
    )

    registry[CKM_XMSSMT_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_XMSSMT,
        keygen_mech=CKM_XMSSMT_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_xmssmt,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="XMSS^MT (RFC 8391) multi-tree key pair generation: stateful hash-based signature",
    )

    registry[CKM_XMSSMT] = MechConfig(
        key_type=CKK_XMSSMT,
        keygen_mech=CKM_XMSSMT_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_xmssmt,
        expected_flags=_SIG_VER,
        notes="XMSS^MT sign/verify (RFC 8391): stateful hash-based multi-tree signature",
    )
