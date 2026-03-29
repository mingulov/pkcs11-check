"""EC/EdDSA/ECDH mechanism family registry entries."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DERIVE,
    CKF_GENERATE_KEY_PAIR,
    CKF_SIGN,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_WRAP,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS,
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
    CKM_XEDDSA,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_SIG_VER = CKF_SIGN | CKF_VERIFY
_WRP_UWRP = CKF_WRAP | CKF_UNWRAP

_ec = KeygenRecipe("ec", {"curve": "secp256r1"})
_ec_edwards = KeygenRecipe("ec_edwards", {"curve": "Ed25519"})
_ec_montgomery = KeygenRecipe("ec_montgomery", {"curve": "X25519"})
_ecdh = ParamRecipe("ecdh")
_eddsa = ParamRecipe("eddsa")


def populate(registry: dict[int, MechConfig]) -> None:
    """Add EC/EdDSA/ECDH mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # EC — Weierstrass (CKK_EC)
    # ---------------------------------------------------------------------------

    registry[CKM_EC_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),  # curve-dependent, not bit sizes
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="EC (Weierstrass) key pair generation; alias CKM_ECDSA_KEY_PAIR_GEN",
    )

    # Alias: same value as CKM_EC_KEY_PAIR_GEN — only one entry in registry
    # (CKM_ECDSA_KEY_PAIR_GEN == CKM_EC_KEY_PAIR_GEN == 0x1040)

    registry[CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="EC key pair generation with extra random bits (FIPS 186-5 B.4.2)",
    )

    registry[CKM_ECDSA] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_secp256k1.json",
        notes="Raw ECDSA sign/verify: pre-hashed input only, single-part",
    )

    registry[CKM_ECDSA_SHA1] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_sha1.json",
        notes="ECDSA with SHA-1 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA224] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_p224.json",
        notes="ECDSA with SHA-224 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA256] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_sha256.json",
        notes="ECDSA with SHA-256 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA384] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_p384.json",
        notes="ECDSA with SHA-384 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA512] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_p521.json",
        notes="ECDSA with SHA-512 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_224] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-224 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_256] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-256 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_384] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-384 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_512] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-512 hash-and-sign",
    )

    registry[CKM_ECDH1_DERIVE] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        param_recipe=_ecdh,
        keygen_recipe=_ec,
        expected_flags=CKF_DERIVE,
        notes="ECDH1 key derivation: requires CK_ECDH1_DERIVE_PARAMS with peer public key",
    )

    registry[CKM_ECDH1_COFACTOR_DERIVE] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        param_recipe=_ecdh,
        keygen_recipe=_ec,
        expected_flags=CKF_DERIVE,
        notes="ECDH1 cofactor key derivation: requires CK_ECDH1_DERIVE_PARAMS",
    )

    registry[CKM_ECMQV_DERIVE] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec,
        expected_flags=CKF_DERIVE,
        notes="ECMQV key derivation: MQV protocol, requires CK_ECMQV_DERIVE_PARAMS",
    )

    registry[CKM_ECDH_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec,
        expected_flags=_WRP_UWRP,
        notes="ECDH-AES hybrid key wrap (deprecated in v3.x)",
    )

    registry[CKM_ECDH_COF_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec,
        expected_flags=_WRP_UWRP,
        notes="ECDH cofactor + AES hybrid key wrap",
    )

    registry[CKM_ECDH_X_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec_montgomery,
        expected_flags=_WRP_UWRP,
        notes="ECDH-X (Montgomery) + AES hybrid key wrap",
    )

    # ---------------------------------------------------------------------------
    # EC — Edwards (CKK_EC_EDWARDS)
    # ---------------------------------------------------------------------------

    registry[CKM_EC_EDWARDS_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_EC_EDWARDS,
        keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec_edwards,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="Edwards-curve key pair generation (Ed25519 / Ed448)",
    )

    registry[CKM_EDDSA] = MechConfig(
        key_type=CKK_EC_EDWARDS,
        keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        multi_part_supported=False,
        param_required=True,
        param_recipe=_eddsa,
        keygen_recipe=_ec_edwards,
        expected_flags=_SIG_VER,
        vector_file="eddsa.json",
        notes="EdDSA sign/verify: requires CK_EDDSA_PARAMS specifying curve",
    )

    registry[CKM_XEDDSA] = MechConfig(
        key_type=CKK_EC_EDWARDS,
        keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        multi_part_supported=False,
        keygen_recipe=_ec_edwards,
        expected_flags=_SIG_VER,
        vector_file="eddsa.json",
        notes="XEdDSA sign/verify (Signal protocol); uses same EdDSA KAT vectors",
    )

    # ---------------------------------------------------------------------------
    # EC — Montgomery (CKK_EC_MONTGOMERY)
    # ---------------------------------------------------------------------------

    registry[CKM_EC_MONTGOMERY_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_ec_montgomery,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="Montgomery-curve key pair generation (X25519 / X448)",
    )
