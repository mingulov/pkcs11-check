"""Shared key-type choices for registry-driven negative operation tests."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKK_AES,
    CKK_BLAKE2B_160_HMAC,
    CKK_BLAKE2B_256_HMAC,
    CKK_BLAKE2B_384_HMAC,
    CKK_BLAKE2B_512_HMAC,
    CKK_GENERIC_SECRET,
    CKK_MD5_HMAC,
    CKK_RIPEMD128_HMAC,
    CKK_RIPEMD160_HMAC,
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
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry

_TYPED_HMAC_KEY_TYPES = frozenset(
    int(ckk)
    for ckk in (
        CKK_MD5_HMAC,
        CKK_SHA_1_HMAC,
        CKK_RIPEMD128_HMAC,
        CKK_RIPEMD160_HMAC,
        CKK_SHA256_HMAC,
        CKK_SHA384_HMAC,
        CKK_SHA512_HMAC,
        CKK_SHA224_HMAC,
        CKK_SHA3_224_HMAC,
        CKK_SHA3_256_HMAC,
        CKK_SHA3_384_HMAC,
        CKK_SHA3_512_HMAC,
        CKK_BLAKE2B_160_HMAC,
        CKK_BLAKE2B_256_HMAC,
        CKK_BLAKE2B_384_HMAC,
        CKK_BLAKE2B_512_HMAC,
        CKK_SHA512_224_HMAC,
        CKK_SHA512_256_HMAC,
        CKK_SHA512_T_HMAC,
    )
)


def wrong_secret_key_type(entry: MechEntry) -> int:
    """Return a key type that is genuinely incompatible with *entry*.

    Generic-secret keys are legal for BLAKE2 HMAC and ordinary HMAC operations,
    while AES keys are not.  Conversely, generic-secret is the negative control
    for AES, DES, and other non-HMAC secret-key mechanisms.  This selector stays
    pure; callers retain any capability-specific skip policy around it.
    """
    config = entry.config
    assert config is not None
    assert config.key_type is not None
    expected_key_type = int(config.key_type)
    if expected_key_type == int(CKK_GENERIC_SECRET):
        return int(CKK_AES)
    if expected_key_type in _TYPED_HMAC_KEY_TYPES:
        return int(CKK_AES)
    return int(CKK_GENERIC_SECRET)
