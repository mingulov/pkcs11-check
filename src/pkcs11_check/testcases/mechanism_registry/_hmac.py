"""HMAC mechanism family registry entries.

Includes: HMAC standard, HMAC_GENERAL variants, HMAC keygen, key derivation
by hash, and BLAKE2b HMAC/keygen/derivation.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DERIVE,
    CKF_GENERATE,
    CKF_SIGN,
    CKF_VERIFY,
    CKK_GENERIC_SECRET,
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
    CKM_BLAKE2B_160_HMAC,
    CKM_BLAKE2B_160_HMAC_GENERAL,
    CKM_BLAKE2B_160_KEY_DERIVE,
    CKM_BLAKE2B_160_KEY_GEN,
    CKM_BLAKE2B_256_HMAC,
    CKM_BLAKE2B_256_HMAC_GENERAL,
    CKM_BLAKE2B_256_KEY_DERIVE,
    CKM_BLAKE2B_256_KEY_GEN,
    CKM_BLAKE2B_384_HMAC,
    CKM_BLAKE2B_384_HMAC_GENERAL,
    CKM_BLAKE2B_384_KEY_DERIVE,
    CKM_BLAKE2B_384_KEY_GEN,
    CKM_BLAKE2B_512_HMAC,
    CKM_BLAKE2B_512_HMAC_GENERAL,
    CKM_BLAKE2B_512_KEY_DERIVE,
    CKM_BLAKE2B_512_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_RIPEMD128_HMAC,
    CKM_RIPEMD128_HMAC_GENERAL,
    CKM_RIPEMD160_HMAC,
    CKM_RIPEMD160_HMAC_GENERAL,
    CKM_SHA1_KEY_DERIVATION,
    CKM_SHA3_224_HMAC,
    CKM_SHA3_224_HMAC_GENERAL,
    CKM_SHA3_224_KEY_DERIVATION,
    CKM_SHA3_224_KEY_GEN,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_256_HMAC_GENERAL,
    CKM_SHA3_256_KEY_DERIVATION,
    CKM_SHA3_256_KEY_GEN,
    CKM_SHA3_384_HMAC,
    CKM_SHA3_384_HMAC_GENERAL,
    CKM_SHA3_384_KEY_DERIVATION,
    CKM_SHA3_384_KEY_GEN,
    CKM_SHA3_512_HMAC,
    CKM_SHA3_512_HMAC_GENERAL,
    CKM_SHA3_512_KEY_DERIVATION,
    CKM_SHA3_512_KEY_GEN,
    CKM_SHA224_HMAC,
    CKM_SHA224_HMAC_GENERAL,
    CKM_SHA224_KEY_DERIVATION,
    CKM_SHA224_KEY_GEN,
    CKM_SHA256_HMAC,
    CKM_SHA256_HMAC_GENERAL,
    CKM_SHA256_KEY_DERIVATION,
    CKM_SHA256_KEY_GEN,
    CKM_SHA384_HMAC,
    CKM_SHA384_HMAC_GENERAL,
    CKM_SHA384_KEY_DERIVATION,
    CKM_SHA384_KEY_GEN,
    CKM_SHA512_224_HMAC,
    CKM_SHA512_224_HMAC_GENERAL,
    CKM_SHA512_224_KEY_DERIVATION,
    CKM_SHA512_224_KEY_GEN,
    CKM_SHA512_256_HMAC,
    CKM_SHA512_256_HMAC_GENERAL,
    CKM_SHA512_256_KEY_DERIVATION,
    CKM_SHA512_256_KEY_GEN,
    CKM_SHA512_HMAC,
    CKM_SHA512_HMAC_GENERAL,
    CKM_SHA512_KEY_DERIVATION,
    CKM_SHA512_KEY_GEN,
    CKM_SHA512_T_HMAC,
    CKM_SHA512_T_HMAC_GENERAL,
    CKM_SHA512_T_KEY_DERIVATION,
    CKM_SHA512_T_KEY_GEN,
    CKM_SHA_1_HMAC,
    CKM_SHA_1_HMAC_GENERAL,
    CKM_SHA_1_KEY_GEN,
    CKM_SHAKE_128_KEY_DERIVATION,
    CKM_SHAKE_256_KEY_DERIVATION,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_SIG_VER = CKF_SIGN | CKF_VERIFY

_sym = KeygenRecipe("symmetric")
_mac_general = ParamRecipe("mac_general", {"mac_len": 8})


def populate(registry: dict[int, MechConfig]) -> None:
    """Add HMAC and key derivation mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # HMAC mechanisms — standard
    # ---------------------------------------------------------------------------

    registry[CKM_SHA_1_HMAC] = MechConfig(
        key_type=CKK_SHA_1_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="hmac_sha1.json",
        notes="HMAC-SHA-1",
    )

    registry[CKM_SHA224_HMAC] = MechConfig(
        key_type=CKK_SHA224_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="hmac_sha224.json",
        notes="HMAC-SHA-224",
    )

    registry[CKM_SHA256_HMAC] = MechConfig(
        key_type=CKK_SHA256_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="hmac_sha256.json",
        notes="HMAC-SHA-256",
    )

    registry[CKM_SHA384_HMAC] = MechConfig(
        key_type=CKK_SHA384_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="hmac_sha384.json",
        notes="HMAC-SHA-384",
    )

    registry[CKM_SHA512_HMAC] = MechConfig(
        key_type=CKK_SHA512_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        vector_file="hmac_sha512.json",
        notes="HMAC-SHA-512",
    )

    registry[CKM_SHA512_224_HMAC] = MechConfig(
        key_type=CKK_SHA512_224_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512/224",
    )

    registry[CKM_SHA512_256_HMAC] = MechConfig(
        key_type=CKK_SHA512_256_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512/256",
    )

    registry[CKM_SHA3_224_HMAC] = MechConfig(
        key_type=CKK_SHA3_224_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-224",
    )

    registry[CKM_SHA3_256_HMAC] = MechConfig(
        key_type=CKK_SHA3_256_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-256",
    )

    registry[CKM_SHA3_384_HMAC] = MechConfig(
        key_type=CKK_SHA3_384_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-384",
    )

    registry[CKM_SHA3_512_HMAC] = MechConfig(
        key_type=CKK_SHA3_512_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-512",
    )

    registry[CKM_RIPEMD128_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-RIPEMD-128",
    )

    registry[CKM_RIPEMD160_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-RIPEMD-160",
    )

    registry[CKM_SHA512_T_HMAC] = MechConfig(
        key_type=CKK_SHA512_T_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512/t",
    )

    # ---------------------------------------------------------------------------
    # HMAC_GENERAL variants — variable-length output
    # ---------------------------------------------------------------------------

    registry[CKM_SHA_1_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA_1_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-1-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA224_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA224_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-224-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA256_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA256_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA384_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA384_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-384-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA512_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA512_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA512_224_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA512_224_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512/224-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA512_256_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA512_256_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512/256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA3_224_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA3_224_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-224-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA3_256_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA3_256_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA3_384_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA3_384_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-384-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA3_512_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA3_512_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA3-512-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_RIPEMD128_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-RIPEMD-128-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_RIPEMD160_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-RIPEMD-160-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_SHA512_T_HMAC_GENERAL] = MechConfig(
        key_type=CKK_SHA512_T_HMAC,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-SHA-512/t-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # HMAC key generation
    # ---------------------------------------------------------------------------

    registry[CKM_GENERIC_SECRET_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="Generic secret key generation (used for HMAC and derivation keys)",
    )

    registry[CKM_SHA_1_KEY_GEN] = MechConfig(
        key_type=CKK_SHA_1_HMAC,
        keygen_mech=CKM_SHA_1_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-1 HMAC key generation",
    )

    registry[CKM_SHA224_KEY_GEN] = MechConfig(
        key_type=CKK_SHA224_HMAC,
        keygen_mech=CKM_SHA224_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-224 HMAC key generation",
    )

    registry[CKM_SHA256_KEY_GEN] = MechConfig(
        key_type=CKK_SHA256_HMAC,
        keygen_mech=CKM_SHA256_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-256 HMAC key generation",
    )

    registry[CKM_SHA384_KEY_GEN] = MechConfig(
        key_type=CKK_SHA384_HMAC,
        keygen_mech=CKM_SHA384_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-384 HMAC key generation",
    )

    registry[CKM_SHA512_KEY_GEN] = MechConfig(
        key_type=CKK_SHA512_HMAC,
        keygen_mech=CKM_SHA512_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-512 HMAC key generation",
    )

    registry[CKM_SHA512_224_KEY_GEN] = MechConfig(
        key_type=CKK_SHA512_224_HMAC,
        keygen_mech=CKM_SHA512_224_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-512/224 HMAC key generation",
    )

    registry[CKM_SHA512_256_KEY_GEN] = MechConfig(
        key_type=CKK_SHA512_256_HMAC,
        keygen_mech=CKM_SHA512_256_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-512/256 HMAC key generation",
    )

    registry[CKM_SHA512_T_KEY_GEN] = MechConfig(
        key_type=CKK_SHA512_T_HMAC,
        keygen_mech=CKM_SHA512_T_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA-512/t HMAC key generation",
    )

    registry[CKM_SHA3_224_KEY_GEN] = MechConfig(
        key_type=CKK_SHA3_224_HMAC,
        keygen_mech=CKM_SHA3_224_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA3-224 HMAC key generation",
    )

    registry[CKM_SHA3_256_KEY_GEN] = MechConfig(
        key_type=CKK_SHA3_256_HMAC,
        keygen_mech=CKM_SHA3_256_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA3-256 HMAC key generation",
    )

    registry[CKM_SHA3_384_KEY_GEN] = MechConfig(
        key_type=CKK_SHA3_384_HMAC,
        keygen_mech=CKM_SHA3_384_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA3-384 HMAC key generation",
    )

    registry[CKM_SHA3_512_KEY_GEN] = MechConfig(
        key_type=CKK_SHA3_512_HMAC,
        keygen_mech=CKM_SHA3_512_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SHA3-512 HMAC key generation",
    )

    # ---------------------------------------------------------------------------
    # Key derivation by hash
    # ---------------------------------------------------------------------------

    registry[CKM_SHA1_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-1 key derivation: derive symmetric key by hashing base key value",
    )

    registry[CKM_SHA224_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-224 key derivation",
    )

    registry[CKM_SHA256_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-256 key derivation",
    )

    registry[CKM_SHA384_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-384 key derivation",
    )

    registry[CKM_SHA512_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-512 key derivation",
    )

    registry[CKM_SHA512_224_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-512/224 key derivation",
    )

    registry[CKM_SHA512_256_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-512/256 key derivation",
    )

    registry[CKM_SHA512_T_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA-512/t key derivation",
    )

    registry[CKM_SHA3_224_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA3-224 key derivation",
    )

    registry[CKM_SHA3_256_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA3-256 key derivation",
    )

    registry[CKM_SHA3_384_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA3-384 key derivation",
    )

    registry[CKM_SHA3_512_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHA3-512 key derivation",
    )

    registry[CKM_SHAKE_128_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHAKE-128 key derivation (XOF-based)",
    )

    registry[CKM_SHAKE_256_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SHAKE-256 key derivation (XOF-based)",
    )

    # ---------------------------------------------------------------------------
    # BLAKE2b HMAC and key gen/derivation
    # ---------------------------------------------------------------------------

    registry[CKM_BLAKE2B_160_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-160",
    )

    registry[CKM_BLAKE2B_160_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-160-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_BLAKE2B_160_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="BLAKE2b-160 key generation",
    )

    registry[CKM_BLAKE2B_160_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_160_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="BLAKE2b-160 key derivation",
    )

    registry[CKM_BLAKE2B_256_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-256",
    )

    registry[CKM_BLAKE2B_256_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-256-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_BLAKE2B_256_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="BLAKE2b-256 key generation",
    )

    registry[CKM_BLAKE2B_256_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_256_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="BLAKE2b-256 key derivation",
    )

    registry[CKM_BLAKE2B_384_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-384",
    )

    registry[CKM_BLAKE2B_384_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-384-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_BLAKE2B_384_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="BLAKE2b-384 key generation",
    )

    registry[CKM_BLAKE2B_384_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_384_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="BLAKE2b-384 key derivation",
    )

    registry[CKM_BLAKE2B_512_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-512",
    )

    registry[CKM_BLAKE2B_512_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="HMAC-BLAKE2b-512-GENERAL: variable output length via CK_MAC_GENERAL_PARAMS",
    )

    registry[CKM_BLAKE2B_512_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="BLAKE2b-512 key generation",
    )

    registry[CKM_BLAKE2B_512_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_BLAKE2B_512_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="BLAKE2b-512 key derivation",
    )
