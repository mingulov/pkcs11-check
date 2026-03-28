"""Shared helpers for mechanism-driven parametrized tests.

Provides parameter factories, key generators, and test data helpers
used by all test_mech_*.py files. Avoids duplicating logic across files.
"""
from __future__ import annotations

import os
from typing import Any

from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.pack_mechanisms import (
    mech_ccm,
    mech_ctr,
    mech_eddsa,
    mech_gcm,
    mech_oaep,
    mech_pss,
)
from pkcs11_check.raw.recipes import (
    gen_ec_keypair,
    gen_keypair,
    gen_rsa_keypair,
    pack_attrs,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKG_MGF1_SHA256,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_RSA,
    CKK_SEED,
    CKM,
    CKR_OK,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig, ParamRecipe

# Fixed-length symmetric key types: CKA_VALUE_LEN must NOT be set.
FIXED_LENGTH_KEY_TYPES: frozenset[int] = frozenset(
    [int(CKK_DES), int(CKK_DES2), int(CKK_DES3), int(CKK_SEED)]
)

# EC key types that need CKA_EC_PARAMS
EC_KEY_TYPES: frozenset[int] = frozenset(
    [int(CKK_EC), int(CKK_EC_EDWARDS), int(CKK_EC_MONTGOMERY)]
)

# Default curve OIDs
_P256_OID: bytes | None = None
_ED25519_OID: bytes | None = None
_X25519_OID: bytes | None = None


def _get_curve_oids() -> tuple[bytes, bytes, bytes]:
    """Lazy-load curve OIDs (avoids import cost at module level)."""
    global _P256_OID, _ED25519_OID, _X25519_OID
    if _P256_OID is None:
        from pkcs11_check.raw.ec import encode_named_curve_parameters

        _P256_OID = encode_named_curve_parameters("secp256r1")
        _ED25519_OID = encode_named_curve_parameters("ed25519")
        _X25519_OID = encode_named_curve_parameters("x25519")
    assert _P256_OID is not None
    assert _ED25519_OID is not None
    assert _X25519_OID is not None
    return _P256_OID, _ED25519_OID, _X25519_OID


# ---------------------------------------------------------------------------
# Test Data
# ---------------------------------------------------------------------------


def test_plaintext(block_size: int | None = None, length: int = 32) -> bytes:
    """Generate test plaintext, block-aligned if needed."""
    data = os.urandom(length)
    if block_size and len(data) % block_size != 0:
        pad = block_size - (len(data) % block_size)
        data += b"\x00" * pad
    return data


# ---------------------------------------------------------------------------
# Mechanism Parameter Factories
# ---------------------------------------------------------------------------


def make_mech_param(entry: MechEntry) -> Any:
    """Create appropriate mechanism parameters for a MechEntry.

    Returns None for mechanisms that don't need params,
    a PackedMechanism for those that do, or the string "SKIP"
    if params cannot be built generically for this mechanism.
    """
    config = entry.config
    if config is None or not config.param_required:
        return None

    packer = config.param_packer
    if packer is None:
        return None

    mech_id = CKM(entry.mech_id)

    if packer == "pack_aes_gcm":
        return mech_gcm(mech_id, os.urandom(12))

    if packer == "pack_aes_ccm":
        return mech_ccm(mech_id, os.urandom(7), data_len=32, mac_len=16)

    if packer == "pack_aes_ctr":
        return mech_ctr(mech_id, bits=128)

    if packer == "mech_oaep":
        from pkcs11_check.raw.types_std import CKM_SHA256

        return mech_oaep(mech_id, hash_mech=int(CKM_SHA256), mgf=int(CKG_MGF1_SHA256))

    if packer == "mech_pss":
        from pkcs11_check.raw.types_std import CKM_SHA256

        return mech_pss(
            mech_id, hash_mech=int(CKM_SHA256), mgf=int(CKG_MGF1_SHA256), salt_len=32
        )

    if packer == "mech_ecdh":
        # Needs peer public key — handled in derive tests
        return "SKIP"

    if packer == "mech_hkdf":
        # Needs CK_HKDF_PARAMS — handled in derive tests
        return "SKIP"

    if packer in ("pack_aes_iv", "mech_bytes"):
        # IV-based mechanisms (CBC, OFB, CFB, etc.)
        return mech_bytes(mech_id, os.urandom(16))

    if packer == "pack_mac_general":
        import ctypes

        from pkcs11_check.raw.types_std import CK_ULONG

        mac_len = CK_ULONG(8)
        return mech_bytes(
            mech_id,
            bytes(ctypes.string_at(ctypes.addressof(mac_len), ctypes.sizeof(mac_len))),
        )

    if packer in ("pack_aes_key_wrap_iv", "pack_aes_key_wrap_kwp"):
        # Key-wrap-only mechanisms — not usable for data operations
        return "SKIP"

    if packer == "mech_eddsa":
        return mech_eddsa(mech_id)

    # Unknown packer
    return "SKIP"


# ---------------------------------------------------------------------------
# Recipe-based Parameter Builder
# ---------------------------------------------------------------------------


def _resolve_const(name: str) -> int:
    """Resolve a CKM_*/CKG_* constant name to its integer value."""
    from pkcs11_check.raw import types_std

    val = getattr(types_std, name, None)
    if val is not None:
        return int(val)
    raise ValueError(f"Unknown constant: {name}")


def build_test_params(mech_id: int, recipe: ParamRecipe) -> Any:
    """Build mechanism parameters from a ParamRecipe.

    Returns None for "none" style, a PackedMechanism for concrete styles,
    or the string "SKIP" if the recipe needs runtime data (ECDH peer key, etc.)
    """
    style = recipe.style
    d = recipe.defaults

    if style == "none":
        return None
    elif style == "iv":
        iv_len = d.get("iv_len", 16)
        return mech_bytes(CKM(mech_id), os.urandom(iv_len))
    elif style == "gcm":
        return mech_gcm(
            CKM(mech_id),
            iv=os.urandom(d.get("iv_len", 12)),
            tag_bits=d.get("tag_bits", 128),
        )
    elif style == "ccm":
        return mech_ccm(
            CKM(mech_id),
            nonce=os.urandom(d.get("nonce_len", 12)),
            data_len=d.get("data_len", 32),
            mac_len=d.get("mac_len", 16),
        )
    elif style == "ctr":
        return mech_ctr(CKM(mech_id), bits=d.get("counter_bits", 128))
    elif style == "pss":
        return mech_pss(
            CKM(mech_id),
            hash_mech=_resolve_const(d.get("hash_mech", "CKM_SHA256")),
            mgf=_resolve_const(d.get("mgf", "CKG_MGF1_SHA256")),
            salt_len=d.get("salt_len", 32),
        )
    elif style == "oaep":
        return mech_oaep(
            CKM(mech_id),
            hash_mech=_resolve_const(d.get("hash_mech", "CKM_SHA256")),
            mgf=_resolve_const(d.get("mgf", "CKG_MGF1_SHA256")),
        )
    elif style == "eddsa":
        return mech_eddsa(CKM(mech_id))
    elif style == "mac_general":
        mac_len = d.get("mac_len", 8)
        return mech_bytes(CKM(mech_id), mac_len.to_bytes(8, "little"))
    elif style in ("ecdh", "hkdf", "string_data", "pbkdf2", "tls", "sp800_108"):
        return "SKIP"  # Needs runtime data
    # Unknown style
    return "SKIP"


# ---------------------------------------------------------------------------
# Key Size Helpers
# ---------------------------------------------------------------------------


def pick_key_size(entry: MechEntry, config: MechConfig) -> int | None:
    """Pick a key size (bits) within the module's reported range.

    Returns None for fixed-length key types (DES/SEED), curve-based or
    parameter-set types with no bit sizes defined, or when no registry
    size fits the module's reported range.
    """
    if config.key_type is not None and int(config.key_type) in FIXED_LENGTH_KEY_TYPES:
        return None
    if not config.key_sizes:
        return None
    max_size = entry.max_key_size if entry.max_key_size != 0 else 0xFFFFFFFF
    for size in sorted(config.key_sizes):
        if entry.min_key_size <= size <= max_size:
            return size
    # Fallback: use first registry size even if out of module range
    return config.key_sizes[0]


def needs_domain_params(config: MechConfig) -> bool:
    """Return True if this mechanism requires external domain parameters (DSA/DH/KEA/GOSTR)."""
    try:
        from pkcs11_check.raw.types_std import (
            CKK_DH,
            CKK_DSA,
            CKK_GOSTR3410,
            CKK_KEA,
            CKK_X9_42_DH,
        )

        domain_param_types: frozenset[int] = frozenset(
            [int(CKK_DSA), int(CKK_DH), int(CKK_X9_42_DH), int(CKK_KEA), int(CKK_GOSTR3410)]
        )
    except ImportError:
        return False
    return config.key_type is not None and int(config.key_type) in domain_param_types


# ---------------------------------------------------------------------------
# Symmetric Key Generation
# ---------------------------------------------------------------------------


def gen_symmetric_key(
    rs: Any,
    entry: MechEntry,
    config: MechConfig,
    *,
    extra_attrs: dict[int, Any] | None = None,
) -> int:
    """Generate a symmetric (secret) key using the mechanism's keygen.

    Handles both fixed-length (DES, SEED) and variable-length (AES, Camellia)
    key types. Returns the key handle. Asserts CKR_OK.

    Raises pytest.skip if key size cannot be determined.
    """
    from ctypes import byref

    import pytest

    from pkcs11_check.raw.pack import attr_ulong, template

    key_type = config.key_type
    is_fixed = key_type is not None and int(key_type) in FIXED_LENGTH_KEY_TYPES

    attrs: dict[int, Any] = {CKA_TOKEN: False}
    if key_type is not None:
        attrs[CKA_KEY_TYPE] = key_type
    if extra_attrs:
        attrs.update(extra_attrs)

    packed: list[Any] = []
    if not is_fixed:
        key_size = pick_key_size(entry, config)
        if key_size is None:
            pytest.skip(f"{entry.mech_name}: no usable key size in registry")
        packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))

    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    tmpl = template(*packed)
    mech = mech_simple(CKM(entry.mech_id))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(
        rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
    )
    assert rv == CKR_OK, f"C_GenerateKey failed: {rv} for {entry.mech_name}"
    return handle.value


# ---------------------------------------------------------------------------
# Asymmetric Key Generation
# ---------------------------------------------------------------------------


def gen_keypair_for_mech(
    rs: Any,
    entry: MechEntry,
    config: MechConfig,
) -> tuple[int, int]:
    """Generate an asymmetric key pair for the given mechanism.

    Returns (pub_handle, priv_handle). Calls pytest.skip for
    unsupported key types or domain-param mechanisms.
    Uses sensible defaults for key usage flags (sign/verify, encrypt/decrypt).
    """
    import pytest

    from pkcs11_check.raw.pack import attr_ulong

    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    if needs_domain_params(config):
        pytest.skip(
            f"{entry.mech_name}: requires external domain parameters "
            "(DSA/DH/GOSTR/KEA — not covered by this test)"
        )

    kt = int(config.key_type)

    if kt == int(CKK_RSA):
        key_size = pick_key_size(entry, config) or 2048
        return gen_rsa_keypair(
            rs.raw,
            rs.sh,
            key_size,
            public_attrs={CKA_VERIFY: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )

    if kt in EC_KEY_TYPES:
        p256_oid, ed25519_oid, x25519_oid = _get_curve_oids()
        if kt == int(CKK_EC_EDWARDS):
            curve_oid = ed25519_oid
        elif kt == int(CKK_EC_MONTGOMERY):
            curve_oid = x25519_oid
        else:
            curve_oid = p256_oid
        return gen_ec_keypair(
            rs.raw,
            rs.sh,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )

    # PQC key types
    try:
        from pkcs11_check.raw.types_std import (
            CKA_PARAMETER_SET,
            CKK_ML_DSA,
            CKK_ML_KEM,
            CKK_SLH_DSA,
            CKP_ML_DSA_65,
            CKP_ML_KEM_768,
            CKP_SLH_DSA_SHA2_128S,
        )

        if kt == int(CKK_ML_KEM):
            return gen_keypair(
                rs.raw,
                rs.sh,
                entry.mech_id,
                pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768)],
                priv_base=[],
                public_attrs={CKA_TOKEN: False},
                private_attrs={CKA_TOKEN: False},
                pub_skip={CKA_PARAMETER_SET},
            )
        if kt == int(CKK_ML_DSA):
            return gen_keypair(
                rs.raw,
                rs.sh,
                entry.mech_id,
                pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65)],
                priv_base=[],
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                pub_skip={CKA_PARAMETER_SET},
            )
        if kt == int(CKK_SLH_DSA):
            return gen_keypair(
                rs.raw,
                rs.sh,
                entry.mech_id,
                pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_SLH_DSA_SHA2_128S)],
                priv_base=[],
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                pub_skip={CKA_PARAMETER_SET},
            )
    except ImportError:
        pass

    pytest.skip(
        f"{entry.mech_name}: keypair generation for key type {config.key_type!r} "
        "not yet covered"
    )
