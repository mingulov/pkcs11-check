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
from pkcs11_check.testcases.mechanism_registry import MechConfig

_SIG_VER = CKF_SIGN | CKF_VERIFY
_WRP_UWRP = CKF_WRAP | CKF_UNWRAP


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
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="EC (Weierstrass) key pair generation; alias CKM_ECDSA_KEY_PAIR_GEN",
    )

    # Alias: same value as CKM_EC_KEY_PAIR_GEN — only one entry in registry
    # (CKM_ECDSA_KEY_PAIR_GEN == CKM_EC_KEY_PAIR_GEN == 0x1040)

    registry[CKM_ECDSA] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        multi_part_supported=False,
        expected_flags=_SIG_VER,
        notes="Raw ECDSA sign/verify: pre-hashed input only, single-part",
    )

    registry[CKM_ECDSA_SHA1] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA-1 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA224] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA-224 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA256] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        vector_file="ecdsa_sha256.json",
        notes="ECDSA with SHA-256 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA384] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA-384 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA512] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA-512 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_224] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-224 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_256] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-256 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_384] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-384 hash-and-sign",
    )

    registry[CKM_ECDSA_SHA3_512] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="ECDSA with SHA3-512 hash-and-sign",
    )

    registry[CKM_ECDH1_DERIVE] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_packer="mech_ecdh",
        param_required=True,
        expected_flags=CKF_DERIVE,
        notes="ECDH1 key derivation: requires CK_ECDH1_DERIVE_PARAMS with peer public key",
    )

    registry[CKM_ECDH1_COFACTOR_DERIVE] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_packer="mech_ecdh",
        param_required=True,
        expected_flags=CKF_DERIVE,
        notes="ECDH1 cofactor key derivation: requires CK_ECDH1_DERIVE_PARAMS",
    )

    registry[CKM_ECMQV_DERIVE] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        expected_flags=CKF_DERIVE,
        notes="ECMQV key derivation: MQV protocol, requires CK_ECMQV_DERIVE_PARAMS",
    )

    registry[CKM_ECDH_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        expected_flags=_WRP_UWRP,
        notes="ECDH-AES hybrid key wrap (deprecated in v3.x)",
    )

    registry[CKM_ECDH_COF_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        expected_flags=_WRP_UWRP,
        notes="ECDH cofactor + AES hybrid key wrap",
    )

    registry[CKM_ECDH_X_AES_KEY_WRAP] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
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
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="Edwards-curve key pair generation (Ed25519 / Ed448)",
    )

    registry[CKM_EDDSA] = MechConfig(
        key_type=CKK_EC_EDWARDS,
        keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_packer="mech_eddsa",
        param_required=True,
        expected_flags=_SIG_VER,
        notes="EdDSA sign/verify: requires CK_EDDSA_PARAMS specifying curve",
    )

    registry[CKM_XEDDSA] = MechConfig(
        key_type=CKK_EC_EDWARDS,
        keygen_mech=CKM_EC_EDWARDS_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="XEdDSA sign/verify (Signal protocol)",
    )

    # ---------------------------------------------------------------------------
    # EC — Montgomery (CKK_EC_MONTGOMERY)
    # ---------------------------------------------------------------------------

    registry[CKM_EC_MONTGOMERY_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="Montgomery-curve key pair generation (X25519 / X448)",
    )
