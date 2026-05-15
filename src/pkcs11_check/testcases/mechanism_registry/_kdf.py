"""KDF and protocol mechanism family registry entries.

Covers: HKDF (RFC 5869), PBKDF2 (RFC 2898), SP800-108 KDFs,
TLS 1.2, SSL 3.0, WTLS, IKE, miscellaneous derivation,
Signal protocol (X3DH/X2Ratchet), and CKM_NULL.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DERIVE,
    CKF_GENERATE,
    CKF_SIGN,
    CKF_VERIFY,
    CKK_EC,
    CKK_EC_MONTGOMERY,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_DATA_AND_BASE,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_HKDF_DATA,
    CKM_HKDF_DERIVE,
    CKM_HKDF_KEY_GEN,
    CKM_IKE1_EXTENDED_DERIVE,
    CKM_IKE1_PRF_DERIVE,
    CKM_IKE2_PRF_PLUS_DERIVE,
    CKM_IKE_PRF_DERIVE,
    CKM_NULL,
    CKM_PKCS5_PBKD2,
    CKM_PUB_KEY_FROM_PRIV_KEY,
    CKM_SHA3_224_KEY_DERIVE,
    CKM_SHA3_256_KEY_DERIVE,
    CKM_SHA3_384_KEY_DERIVE,
    CKM_SHA3_512_KEY_DERIVE,
    CKM_SHAKE_128_KEY_DERIVE,
    CKM_SHAKE_256_KEY_DERIVE,
    CKM_SP800_108_COUNTER_KDF,
    CKM_SP800_108_DOUBLE_PIPELINE_KDF,
    CKM_SP800_108_FEEDBACK_KDF,
    CKM_SSL3_KEY_AND_MAC_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKM_SSL3_MD5_MAC,
    CKM_SSL3_PRE_MASTER_KEY_GEN,
    CKM_SSL3_SHA1_MAC,
    CKM_TLS10_MAC_CLIENT,
    CKM_TLS10_MAC_SERVER,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
    CKM_TLS12_KDF,
    CKM_TLS12_KEY_AND_MAC_DERIVE,
    CKM_TLS12_KEY_SAFE_DERIVE,
    CKM_TLS12_MAC,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKM_TLS12_MASTER_KEY_DERIVE_DH,
    CKM_TLS_KDF,
    CKM_TLS_KEY_AND_MAC_DERIVE,
    CKM_TLS_MAC,
    CKM_TLS_MASTER_KEY_DERIVE,
    CKM_TLS_MASTER_KEY_DERIVE_DH,
    CKM_TLS_PRE_MASTER_KEY_GEN,
    CKM_TLS_PRF,
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
    CKM_XOR_BASE_AND_DATA,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_SIG_VER = CKF_SIGN | CKF_VERIFY

_sym = KeygenRecipe("symmetric")
_ec = KeygenRecipe("ec", {"curve": "secp256r1"})
_ec_montgomery = KeygenRecipe("ec_montgomery", {"curve": "X25519"})
_hkdf = ParamRecipe("hkdf")


def populate(registry: dict[int, MechConfig]) -> None:
    """Add KDF and protocol mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # HKDF (RFC 5869)
    # ---------------------------------------------------------------------------

    registry[CKM_HKDF_KEY_GEN] = MechConfig(
        key_type=CKK_HKDF,
        keygen_mech=CKM_HKDF_KEY_GEN,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="HKDF key generation: generate raw IKM (input keying material) key",
    )

    registry[CKM_HKDF_DERIVE] = MechConfig(
        key_type=CKK_HKDF,
        keygen_mech=CKM_HKDF_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_hkdf,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="HKDF key derivation (RFC 5869): extract-and-expand, requires CK_HKDF_PARAMS",
    )

    registry[CKM_HKDF_DATA] = MechConfig(
        key_type=CKK_HKDF,
        keygen_mech=CKM_HKDF_KEY_GEN,
        key_sizes=(),
        param_required=True,
        param_recipe=_hkdf,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="HKDF data derivation (RFC 5869): produces raw data output rather than key object",
    )

    # ---------------------------------------------------------------------------
    # PBKDF2 (RFC 2898)
    # ---------------------------------------------------------------------------

    registry[CKM_PKCS5_PBKD2] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_PKCS5_PBKD2,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="PBKDF2 (RFC 2898): password-based key derivation, requires CK_PKCS5_PBKD2_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # SP800-108 counter/feedback/pipeline KDFs
    # ---------------------------------------------------------------------------

    registry[CKM_SP800_108_COUNTER_KDF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SP800-108 counter-mode KDF: requires CK_SP800_108_KDF_PARAMS",
    )

    registry[CKM_SP800_108_FEEDBACK_KDF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SP800-108 feedback-mode KDF: requires CK_SP800_108_KDF_PARAMS",
    )

    registry[CKM_SP800_108_DOUBLE_PIPELINE_KDF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SP800-108 double-pipeline KDF: requires CK_SP800_108_KDF_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # TLS 1.2 protocol mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_TLS_PRE_MASTER_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_TLS_PRE_MASTER_KEY_GEN,
        key_sizes=(384,),  # 48-byte pre-master secret
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="TLS pre-master secret generation: requires TLS version param",
    )

    registry[CKM_TLS12_MASTER_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 master key derivation: requires CK_TLS12_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_TLS12_MASTER_KEY_DERIVE_DH] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 master key derivation (DH): requires CK_TLS12_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_TLS12_KEY_AND_MAC_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 key and MAC material derivation: requires CK_TLS12_KEY_MAT_PARAMS",
    )

    registry[CKM_TLS12_KEY_SAFE_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 safe key derivation: same as KEY_AND_MAC_DERIVE but SENSITIVE preserved",
    )

    registry[CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 extended master secret (RFC 7627): requires session hash param",
    )

    registry[CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 extended master secret DH variant (RFC 7627)",
    )

    registry[CKM_TLS_MAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="TLS MAC: requires CK_TLS_MAC_PARAMS (hash alg + label)",
    )

    registry[CKM_TLS_KDF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS KDF (generic PRF): requires CK_TLS_KDF_PARAMS",
    )

    registry[CKM_TLS12_MAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="TLS 1.2 MAC: requires hash algorithm parameter",
    )

    registry[CKM_TLS12_KDF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.2 KDF (PRF): requires CK_TLS12_KDF_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # SSL 3.0 protocol mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_SSL3_PRE_MASTER_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_SSL3_PRE_MASTER_KEY_GEN,
        key_sizes=(384,),  # 48-byte pre-master secret
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="SSL 3.0 pre-master secret generation: requires TLS version param",
    )

    registry[CKM_SSL3_MASTER_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SSL 3.0 master key derivation: requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_SSL3_MASTER_KEY_DERIVE_DH] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SSL 3.0 master key derivation (DH): requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_SSL3_KEY_AND_MAC_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="SSL 3.0 key and MAC material derivation: requires CK_SSL3_KEY_MAT_PARAMS",
    )

    registry[CKM_SSL3_MD5_MAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="SSL 3.0 MD5 MAC: requires CK_MAC_GENERAL_PARAMS for output length",
    )

    registry[CKM_SSL3_SHA1_MAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="SSL 3.0 SHA-1 MAC: requires CK_MAC_GENERAL_PARAMS for output length",
    )

    # ---------------------------------------------------------------------------
    # TLS 1.0 legacy mechanisms (pre-TLS 1.2)
    # ---------------------------------------------------------------------------

    registry[CKM_TLS_MASTER_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.0 master key derivation (pre-TLS 1.2): CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_TLS_KEY_AND_MAC_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.0 key and MAC material derivation (pre-TLS 1.2): CK_SSL3_KEY_MAT_PARAMS",
    )

    registry[CKM_TLS_MASTER_KEY_DERIVE_DH] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.0 master key derivation DH (pre-TLS 1.2): CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_TLS_PRF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="TLS 1.0 PRF (pseudo-random function): requires CK_TLS_PRF_PARAMS",
    )

    registry[CKM_TLS10_MAC_SERVER] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="TLS 1.0 server MAC computation: requires hash algorithm parameter",
    )

    registry[CKM_TLS10_MAC_CLIENT] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="TLS 1.0 client MAC computation: requires hash algorithm parameter",
    )

    # ---------------------------------------------------------------------------
    # WTLS (WAP TLS) protocol mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_WTLS_PRE_MASTER_KEY_GEN] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_WTLS_PRE_MASTER_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_GENERATE,
        notes="WTLS pre-master secret generation",
    )

    registry[CKM_WTLS_MASTER_KEY_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="WTLS master key derivation: requires CK_WTLS_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="WTLS master key derivation (DH/ECC): requires CK_WTLS_MASTER_KEY_DERIVE_PARAMS",
    )

    registry[CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="WTLS client key and MAC material derivation",
    )

    registry[CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="WTLS server key and MAC material derivation",
    )

    registry[CKM_WTLS_PRF] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="WTLS PRF (pseudo-random function)",
    )

    # ---------------------------------------------------------------------------
    # IKE (IPsec key exchange) KDFs
    # ---------------------------------------------------------------------------

    registry[CKM_IKE_PRF_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="IKE PRF key derivation: requires CK_IKE_PRF_DERIVE_PARAMS",
    )

    registry[CKM_IKE1_PRF_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="IKEv1 PRF key derivation: requires CK_IKE1_PRF_DERIVE_PARAMS",
    )

    registry[CKM_IKE1_EXTENDED_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="IKEv1 extended key derivation: requires CK_IKE1_EXTENDED_DERIVE_PARAMS",
    )

    registry[CKM_IKE2_PRF_PLUS_DERIVE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="IKEv2 PRF+ key derivation: requires CK_IKE2_PRF_PLUS_DERIVE_PARAMS",
    )

    # ---------------------------------------------------------------------------
    # Miscellaneous derivation mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_CONCATENATE_BASE_AND_KEY] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="Concatenate base key value with another key value to derive new key",
    )

    registry[CKM_CONCATENATE_BASE_AND_DATA] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="Concatenate base key value with data bytes to derive new key",
    )

    registry[CKM_CONCATENATE_DATA_AND_BASE] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="Concatenate data bytes with base key value to derive new key",
    )

    registry[CKM_XOR_BASE_AND_DATA] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="XOR base key value with data bytes to derive new key",
    )

    registry[CKM_EXTRACT_KEY_FROM_KEY] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(),
        param_required=True,
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="Extract a subset of bytes from key value to create new key",
    )

    # ---------------------------------------------------------------------------
    # SHA-3 / SHAKE hash-based key derivation
    # ---------------------------------------------------------------------------

    for _ckm, _note in [
        (CKM_SHA3_224_KEY_DERIVE, "SHA3-224 hash-based key derivation"),
        (CKM_SHA3_256_KEY_DERIVE, "SHA3-256 hash-based key derivation"),
        (CKM_SHA3_384_KEY_DERIVE, "SHA3-384 hash-based key derivation"),
        (CKM_SHA3_512_KEY_DERIVE, "SHA3-512 hash-based key derivation"),
        (CKM_SHAKE_128_KEY_DERIVE, "SHAKE-128 hash-based key derivation"),
        (CKM_SHAKE_256_KEY_DERIVE, "SHAKE-256 hash-based key derivation"),
    ]:
        registry[_ckm] = MechConfig(
            key_type=CKK_GENERIC_SECRET,
            keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
            key_sizes=(),
            param_required=True,
            keygen_recipe=_sym,
            expected_flags=CKF_DERIVE,
            notes=_note,
        )

    registry[CKM_PUB_KEY_FROM_PRIV_KEY] = MechConfig(
        key_type=CKK_EC,
        keygen_mech=CKM_EC_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=False,
        keygen_recipe=_ec,
        expected_flags=CKF_DERIVE,
        notes="Derive public key object from existing private key: works for EC/EdDSA/Montgomery",
    )

    # ---------------------------------------------------------------------------
    # Signal protocol mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_X3DH_INITIALIZE] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec_montgomery,
        expected_flags=CKF_DERIVE,
        notes="X3DH key agreement -- initiator side (Signal protocol): CK_X3DH_INITIATE_PARAMS",
    )

    registry[CKM_X3DH_RESPOND] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec_montgomery,
        expected_flags=CKF_DERIVE,
        notes="X3DH key agreement -- responder side (Signal protocol): CK_X3DH_RESPOND_PARAMS",
    )

    registry[CKM_X2RATCHET_INITIALIZE] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec_montgomery,
        expected_flags=CKF_DERIVE,
        notes="Double Ratchet initialization -- sender side (Signal protocol)",
    )

    registry[CKM_X2RATCHET_RESPOND] = MechConfig(
        key_type=CKK_EC_MONTGOMERY,
        keygen_mech=CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        param_required=True,
        keygen_recipe=_ec_montgomery,
        expected_flags=CKF_DERIVE,
        notes="Double Ratchet initialization -- receiver side (Signal protocol)",
    )

    # ---------------------------------------------------------------------------
    # CKM_NULL
    # ---------------------------------------------------------------------------

    registry[CKM_NULL] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        multi_part_supported=False,
        expected_flags=_SIG_VER,
        notes="CKM_NULL: pass-through mechanism, data signed/verified as-is with no hashing",
    )
