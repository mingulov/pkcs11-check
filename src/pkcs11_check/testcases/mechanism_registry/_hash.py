"""Hash/digest mechanism family registry entries."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DIGEST,
    CKM_BLAKE2B_160,
    CKM_BLAKE2B_256,
    CKM_BLAKE2B_384,
    CKM_BLAKE2B_512,
    CKM_RIPEMD128,
    CKM_RIPEMD160,
    CKM_SHA3_224,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA512_224,
    CKM_SHA512_256,
    CKM_SHA512_T,
    CKM_SHA_1,
)
from pkcs11_check.testcases.mechanism_registry import MechConfig


def populate(registry: dict[int, MechConfig]) -> None:
    """Add hash/digest mechanism entries to the registry."""

    registry[CKM_SHA_1] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha.json",
        notes="SHA-1 digest",
    )

    registry[CKM_SHA224] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha.json",
        notes="SHA-224 digest",
    )

    registry[CKM_SHA256] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha.json",
        notes="SHA-256 digest",
    )

    registry[CKM_SHA384] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha.json",
        notes="SHA-384 digest",
    )

    registry[CKM_SHA512] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha.json",
        notes="SHA-512 digest",
    )

    registry[CKM_SHA512_224] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha512_truncated.json",
        notes="SHA-512/224 truncated digest",
    )

    registry[CKM_SHA512_256] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha512_truncated.json",
        notes="SHA-512/256 truncated digest",
    )

    registry[CKM_SHA512_T] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        param_required=True,
        expected_flags=CKF_DIGEST,
        notes="SHA-512/t truncated digest: requires t (output length) parameter",
    )

    registry[CKM_SHA3_224] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha3.json",
        notes="SHA3-224 digest",
    )

    registry[CKM_SHA3_256] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha3.json",
        notes="SHA3-256 digest",
    )

    registry[CKM_SHA3_384] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha3.json",
        notes="SHA3-384 digest",
    )

    registry[CKM_SHA3_512] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        vector_file="sha3.json",
        notes="SHA3-512 digest",
    )

    registry[CKM_BLAKE2B_160] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        notes="BLAKE2b-160 digest",
    )

    registry[CKM_BLAKE2B_256] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        notes="BLAKE2b-256 digest",
    )

    registry[CKM_BLAKE2B_384] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        notes="BLAKE2b-384 digest",
    )

    registry[CKM_BLAKE2B_512] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        notes="BLAKE2b-512 digest",
    )

    # The standalone SHAKE-128/256 digest mechanisms (CKM_SHAKE_128/CKM_SHAKE_256, the
    # extendable-output hash functions used with C_DigestXof*, FIPS PUB 202) are described
    # in the PKCS#11 working draft but are NOT YET ASSIGNED a numeric CKM value in any
    # published or working OASIS header (only the SHAKE *KDF* mechanisms are numbered:
    # CKM_SHAKE_128/256_KEY_DERIVE = 0x039B/0x039C). The former placeholder entries here
    # (registry[0x418]/registry[0x419]) used invented IDs no provider can advertise, so they
    # were dead; they are retired. When the spec assigns real IDs and types_std adds
    # CKM_SHAKE_128/256, register them here and add real XOF support (C_DigestXof*); the
    # standard-digest tests already skip XOF digests by NAME (see test_mech_digest /
    # test_mech_multipart), so they will be handled correctly the moment the mechanism exists.

    registry[CKM_RIPEMD128] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        notes="RIPEMD-128 digest",
    )

    registry[CKM_RIPEMD160] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="digest_only",
        expected_flags=CKF_DIGEST,
        notes="RIPEMD-160 digest",
    )
