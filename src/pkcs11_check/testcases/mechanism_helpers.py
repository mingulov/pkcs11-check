"""Shared helpers for mechanism-driven parametrized tests.

Provides parameter factories, key generators, and test data helpers
used by all test_mech_*.py files. Avoids duplicating logic across files.
"""
from __future__ import annotations

import os
from ctypes import byref
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
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_GENERIC_SECRET,
    CKK_RSA,
    CKK_SEED,
    CKM,
    CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_OK,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig, ParamRecipe

# Optional types that may not exist in all PKCS#11 versions
_CKK_AES_XTS_VAL: int = -1
_CKM_AES_XTS_KEY_GEN_VAL: int = -1
_CKM_RSA_X9_31_KEY_PAIR_GEN_VAL: int = -1
try:
    from pkcs11_check.raw.types_std import CKK_AES_XTS  # noqa: E402

    _CKK_AES_XTS_VAL = int(CKK_AES_XTS)
except ImportError:
    pass
try:
    from pkcs11_check.raw.types_std import CKM_AES_XTS_KEY_GEN  # noqa: E402

    _CKM_AES_XTS_KEY_GEN_VAL = int(CKM_AES_XTS_KEY_GEN)
except ImportError:
    pass
try:
    from pkcs11_check.raw.types_std import CKM_RSA_X9_31_KEY_PAIR_GEN  # noqa: E402

    _CKM_RSA_X9_31_KEY_PAIR_GEN_VAL = int(CKM_RSA_X9_31_KEY_PAIR_GEN)
except ImportError:
    pass

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

    Delegates to build_test_params() using the entry's param_recipe.
    """
    config = entry.config
    if config is None or not config.param_required:
        return None
    return build_test_params(entry.mech_id, config.param_recipe)


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


# ---------------------------------------------------------------------------
# Test Plaintext
# ---------------------------------------------------------------------------


def test_plaintext_bytes() -> bytes:
    """Return 32 bytes of fixed test plaintext for encrypt/sign tests."""
    return b"\xab\xcd\xef\x01" * 8


# ---------------------------------------------------------------------------
# Encrypt Key Generation
# ---------------------------------------------------------------------------

# RSA keygen mechanism IDs (computed at import time)
_RSA_KEYGEN_MECHS: frozenset[int] = frozenset(
    x for x in [int(CKM_RSA_PKCS_KEY_PAIR_GEN), _CKM_RSA_X9_31_KEY_PAIR_GEN_VAL] if x != -1
)


def generate_key_for_encrypt(
    rs: Any,
    entry: MechEntry,
    config: MechConfig,
) -> tuple[int, int | None]:
    """Generate a key suitable for encrypt+decrypt operations.

    Returns (encrypt_key_or_pub, decrypt_key_or_priv).
    For symmetric: both are the same handle, second value is None.
    For asymmetric (RSA): (pub_handle, priv_handle).
    """
    import pytest

    from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    kt = int(config.key_type)

    if config.is_keypair:
        if needs_domain_params(config):
            pytest.skip(
                f"{entry.mech_name}: requires external domain parameters (DSA/DH/KEA/GOSTR)"
            )

        if kt == int(CKK_RSA):
            keygen = config.keygen_mech
            if keygen is None or keygen not in _RSA_KEYGEN_MECHS:
                keygen = int(CKM_RSA_PKCS_KEY_PAIR_GEN)
            key_size = pick_key_size(entry, config) or 2048
            pub, priv = gen_keypair(
                rs.raw,
                rs.sh,
                keygen,
                pub_base=[
                    attr_ulong(CKA_MODULUS_BITS, key_size),
                    attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
                ],
                priv_base=[],
                public_attrs={CKA_VERIFY: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            return pub, priv

        pytest.skip(
            f"{entry.mech_name}: keypair mechanism with key type {config.key_type!r} "
            "not supported for encrypt/decrypt test"
        )

    # Symmetric: AES-XTS needs special double-length key
    if _CKK_AES_XTS_VAL != -1 and kt == _CKK_AES_XTS_VAL:
        keygen = config.keygen_mech or (
            _CKM_AES_XTS_KEY_GEN_VAL if _CKM_AES_XTS_KEY_GEN_VAL != -1 else None
        )
        if keygen is None:
            pytest.skip(f"{entry.mech_name}: no keygen_mech for AES-XTS")
        xts_key_size = pick_key_size(entry, config)
        if xts_key_size is None:
            pytest.skip(f"{entry.mech_name}: no usable key size")
        attrs: dict[int, Any] = {
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
            CKA_KEY_TYPE: config.key_type,
        }
        packed = [attr_ulong(CKA_VALUE_LEN, xts_key_size // 8)]
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
        tmpl = template(*packed)
        mech = mech_simple(CKM(keygen))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
        assert rv == CKR_OK, f"AES-XTS keygen failed: {rv}"
        return handle.value, None

    # Standard symmetric keygen
    keygen_mech = config.keygen_mech
    if keygen_mech is None:
        keygen_mech = int(CKM_AES_KEY_GEN) if kt == int(CKK_AES) else None
    if keygen_mech is None:
        pytest.skip(f"{entry.mech_name}: no keygen_mech in registry config")

    is_fixed = kt in FIXED_LENGTH_KEY_TYPES

    attrs2: dict[int, Any] = {
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
        CKA_TOKEN: False,
        CKA_KEY_TYPE: config.key_type,
    }
    packed2 = []
    if not is_fixed:
        sym_key_size = pick_key_size(entry, config)
        if sym_key_size is None:
            pytest.skip(f"{entry.mech_name}: no usable key size in registry")
        packed2.append(attr_ulong(CKA_VALUE_LEN, sym_key_size // 8))
        packed2.extend(pack_attrs(attrs2, skip={CKA_VALUE_LEN}))
    else:
        packed2.extend(pack_attrs(attrs2))

    tmpl2 = template(*packed2)
    mech2 = mech_simple(CKM(keygen_mech))
    handle2 = CK_OBJECT_HANDLE(0)
    rv2 = rs.raw.C_GenerateKey(rs.sh, mech2.byref(), tmpl2.ptr, tmpl2.count, byref(handle2))
    assert rv2 == CKR_OK, f"C_GenerateKey failed: {rv2} for {entry.mech_name}"
    return handle2.value, None


# ---------------------------------------------------------------------------
# Sign Key Generation
# ---------------------------------------------------------------------------


def generate_key_for_sign(
    rs: Any,
    entry: MechEntry,
    config: MechConfig,
) -> tuple[int, int | None]:
    """Generate key(s) for sign/verify.

    Returns (sign_key, verify_key).
    For symmetric: same handle; verify_key is None.
    For asymmetric: (priv_handle, pub_handle).
    """
    import pytest

    from pkcs11_check.raw.pack import attr_ulong, template
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    if needs_domain_params(config):
        pytest.skip(
            f"{entry.mech_name}: requires external domain parameters (DSA/DH/GOSTR/KEA)"
        )

    if config.is_keypair:
        pub, priv = gen_keypair_for_mech(rs, entry, config)
        return priv, pub  # sign with private, verify with public

    # Symmetric: use keygen_mech from config
    keygen = config.keygen_mech
    if keygen is None:
        kt = int(config.key_type)
        if kt == int(CKK_AES):
            keygen = int(CKM_AES_KEY_GEN)
        else:
            keygen = int(CKM_GENERIC_SECRET_KEY_GEN)

    kt = int(config.key_type)
    is_fixed = kt in FIXED_LENGTH_KEY_TYPES

    attrs: dict[int, Any] = {
        CKA_SIGN: True,
        CKA_VERIFY: True,
        CKA_TOKEN: False,
        CKA_KEY_TYPE: config.key_type,
    }
    packed = []
    key_size = pick_key_size(entry, config)
    if not is_fixed:
        if key_size is None:
            key_size = 256  # For HMAC with no key_sizes, use sensible default
        packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))

    tmpl = template(*packed)
    mech = mech_simple(CKM(keygen))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    assert rv == CKR_OK, f"C_GenerateKey failed: {rv} for {entry.mech_name}"
    return handle.value, None


# ---------------------------------------------------------------------------
# Mechanism Parameter Wrapper (with skip)
# ---------------------------------------------------------------------------


def make_mech_param_or_skip(entry: MechEntry) -> Any:
    """Build mechanism params or skip if not possible.

    Returns None for mechanisms that take no parameters or have no registry config.
    Calls pytest.skip() for param recipes that need runtime data (ECDH peer key, etc.).
    """
    import pytest

    config = entry.config
    if config is None or not config.param_required:
        return None
    result = build_test_params(entry.mech_id, config.param_recipe)
    if result == "SKIP":
        pytest.skip(
            f"{entry.mech_name}: param recipe '{config.param_recipe.style}' needs runtime data"
        )
    return result


# ---------------------------------------------------------------------------
# Generic Secret Key Generation
# ---------------------------------------------------------------------------


def gen_generic_secret(
    rs: Any,
    bits: int = 256,
    extra_attrs: dict[int, Any] | None = None,
) -> int:
    """Generate a generic secret key.

    Creates a CKK_GENERIC_SECRET key of the given bit size. Callers supply
    extra_attrs to set the permissions needed for their use-case, e.g.:
      - sign/verify tests: {CKA_SIGN: True, CKA_VERIFY: True}
      - derive tests:      {CKA_DERIVE: True}

    Base attrs (CKA_KEY_TYPE, CKA_TOKEN, CKA_EXTRACTABLE, CKA_SENSITIVE) are
    always set; extra_attrs override or extend them.

    Returns the key handle. Asserts CKR_OK.
    """
    from pkcs11_check.raw.pack import attr_ulong, template
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_TOKEN: False,
        CKA_EXTRACTABLE: True,
        CKA_SENSITIVE: False,
    }
    if extra_attrs:
        attrs.update(extra_attrs)

    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))

    tmpl = template(*packed)
    mech = mech_simple(CKM(CKM_GENERIC_SECRET_KEY_GEN))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    assert rv == CKR_OK, f"Generic secret key gen failed: {rv}"
    return handle.value
