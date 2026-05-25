"""Shared helpers for mechanism-driven parametrized tests.

Provides parameter factories, key generators, and test data helpers
used by all test_mech_*.py files. Avoids duplicating logic across files.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from ctypes import byref
from typing import Any

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.pack import attr_bytes, mech_bytes, mech_simple
from pkcs11_check.raw.pack_mechanisms import (
    mech_ccm,
    mech_chacha20,
    mech_chacha20_poly1305,
    mech_ctr,
    mech_eddsa,
    mech_gcm,
    mech_oaep,
    mech_pbe,
    mech_pss,
    mech_rc2,
    mech_rc2_cbc,
)
from pkcs11_check.raw.recipes import (
    gen_keypair,
    gen_rsa_keypair,
    pack_attrs,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
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
    CKM_EC_KEY_PAIR_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_PKCS5_PBKD2,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

# Optional types that may not exist in all PKCS#11 versions
_CKK_AES_XTS_VAL: int = -1
_CKM_AES_XTS_KEY_GEN_VAL: int = -1
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

# Fixed-length symmetric key types: CKA_VALUE_LEN must NOT be set.
FIXED_LENGTH_KEY_TYPES: frozenset[int] = frozenset(
    [int(CKK_DES), int(CKK_DES2), int(CKK_DES3), int(CKK_SEED)]
)

# EC key types that need CKA_EC_PARAMS
EC_KEY_TYPES: frozenset[int] = frozenset([int(CKK_EC), int(CKK_EC_EDWARDS), int(CKK_EC_MONTGOMERY)])

_KEYGEN_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_KEYPAIR_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

# Default curve OIDs
_P256_OID: bytes | None = None
_ED25519_OID: bytes | None = None
_X25519_OID: bytes | None = None


def _mechanism_name_variants(mechanism: int) -> tuple[str, ...]:
    name = MECHANISM_NAMES.get(int(mechanism))
    if not name:
        return ()
    if name.startswith("CKM_"):
        return (name, name[4:])
    return (name,)


def _session_has_mechanism(rs: Any, mechanism: int) -> bool:
    has_mechanism = getattr(rs, "has_mechanism", None)
    if not callable(has_mechanism):
        return True
    variants = _mechanism_name_variants(mechanism)
    if not variants:
        return True
    return any(bool(has_mechanism(name)) for name in variants)


def _skip_if_keygen_mechanism_absent(rs: Any, keygen_mech: int, mech_name: str) -> None:
    if _session_has_mechanism(rs, keygen_mech):
        return
    import pytest

    display = MECHANISM_NAMES.get(int(keygen_mech), f"0x{int(keygen_mech):x}")
    if display.startswith("CKM_"):
        display = display[4:]
    pytest.skip(f"{mech_name}: {display} not supported")


def _xfail_if_keygen_runtime_reject(rv: int, mech_name: str) -> None:
    if rv not in _KEYGEN_RUNTIME_REJECT_RVS:
        return
    import pytest

    pytest.xfail(f"{mech_name} keygen rejected at runtime: {ckr_name(rv)}")


def _pbkdf2_keygen_mechanism() -> Any:
    from pkcs11_check.raw.pack_mechanisms import mech_pbkdf2
    from pkcs11_check.raw.types_std import CKP_PKCS5_PBKD2_HMAC_SHA256

    return mech_pbkdf2(
        CKM_PKCS5_PBKD2,
        salt=b"pkcs11-check-test-salt",
        iterations=10000,
        prf=CKP_PKCS5_PBKD2_HMAC_SHA256,
        password=b"test-password",
    )


def _xfail_if_keypair_runtime_reject(exc: AssertionError, mech_name: str) -> None:
    rv = getattr(exc, "rv", None)
    if rv is not None:
        if rv in _KEYPAIR_RUNTIME_REJECT_RVS:
            import pytest

            pytest.xfail(f"{mech_name} keypair rejected at runtime: {ckr_name(rv)}")
        return
    msg = str(exc)
    for candidate in _KEYPAIR_RUNTIME_REJECT_RVS:
        if ckr_name(candidate) in msg:
            import pytest

            pytest.xfail(f"{mech_name} keypair rejected at runtime: {ckr_name(candidate)}")


def _generate_keypair_or_xfail(
    rs: Any,
    entry: MechEntry,
    keygen_mech: int,
    callback: Callable[[], tuple[int, int]],
) -> tuple[int, int]:
    _skip_if_keygen_mechanism_absent(rs, keygen_mech, entry.mech_name)
    try:
        return callback()
    except AssertionError as exc:
        _xfail_if_keypair_runtime_reject(exc, entry.mech_name)
        raise


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
    elif style == "chacha20":
        nonce = os.urandom(12)
        return mech_chacha20(CKM(mech_id), nonce=nonce)
    elif style == "chacha20_poly1305":
        nonce = os.urandom(12)
        return mech_chacha20_poly1305(CKM(mech_id), nonce=nonce)
    elif style == "rc2":
        effective_bits = d.get("effective_bits", 128)
        return mech_rc2(CKM(mech_id), effective_bits=effective_bits)
    elif style == "rc2_cbc":
        effective_bits = d.get("effective_bits", 128)
        iv = os.urandom(8)
        return mech_rc2_cbc(CKM(mech_id), effective_bits=effective_bits, iv=iv)
    elif style == "eddsa":
        return mech_eddsa(CKM(mech_id))
    elif style == "mac_general":
        mac_len = d.get("mac_len", 8)
        return mech_bytes(CKM(mech_id), mac_len.to_bytes(8, "little"))
    elif style == "pbe":
        password = b"test1234"
        salt = os.urandom(8)
        iteration = d.get("iteration", 1000)
        return mech_pbe(CKM(mech_id), password=password, salt=salt, iteration=iteration)
    elif style in ("ecdh", "hkdf", "string_data", "pbkdf2", "tls", "sp800_108"):
        return "SKIP"  # Needs runtime data
    elif style in ("rc2_mac_general", "rc5_mac_general"):
        return "SKIP"  # Needs CK_RC2/RC5_MAC_GENERAL_PARAMS (multi-field struct)
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
            # Some variable-length secret-key generators intentionally leave
            # registry sizes open-ended. Fall back to the mechanism's reported
            # minimum size instead of self-skipping advertised coverage.
            min_bits = entry.min_key_size * 8 if entry.min_key_size > 0 else 0
            key_size = max(256, min_bits)
        packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))

    import pytest

    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    tmpl = template(*packed)
    if int(entry.mech_id) == int(CKM_PKCS5_PBKD2):
        mech = _pbkdf2_keygen_mechanism()
    elif config.param_required:
        mech_param_result = make_mech_param(entry)
        if mech_param_result == "SKIP":
            pytest.skip(f"{entry.mech_name} requires runtime parameters for keygen")
        mech = (
            mech_param_result if mech_param_result is not None else mech_simple(CKM(entry.mech_id))
        )
    else:
        mech = mech_simple(CKM(entry.mech_id))
    _skip_if_keygen_mechanism_absent(rs, int(entry.mech_id), entry.mech_name)
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    _xfail_if_keygen_runtime_reject(int(rv), entry.mech_name)
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
            "(DSA/DH/GOSTR/KEA -- not covered by this test)"
        )

    kt = int(config.key_type)

    if kt == int(CKK_RSA):
        key_size = pick_key_size(entry, config) or 2048
        keygen_mech = (
            int(config.keygen_mech)
            if config.keygen_mech is not None
            else int(CKM_RSA_PKCS_KEY_PAIR_GEN)
        )
        return _generate_keypair_or_xfail(
            rs,
            entry,
            keygen_mech,
            lambda: gen_rsa_keypair(
                rs.raw,
                rs.sh,
                key_size,
                public_attrs={CKA_VERIFY: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            ),
        )

    if kt in EC_KEY_TYPES:
        p256_oid, ed25519_oid, x25519_oid = _get_curve_oids()
        if kt == int(CKK_EC_EDWARDS):
            curve_oid = ed25519_oid
        elif kt == int(CKK_EC_MONTGOMERY):
            curve_oid = x25519_oid
        else:
            curve_oid = p256_oid
        # Use the keygen mechanism from the registry: Weierstrass uses
        # CKM_EC_KEY_PAIR_GEN, Edwards uses CKM_EC_EDWARDS_KEY_PAIR_GEN,
        # Montgomery uses CKM_EC_MONTGOMERY_KEY_PAIR_GEN.
        keygen_mech = (
            int(config.keygen_mech) if config.keygen_mech is not None else int(CKM_EC_KEY_PAIR_GEN)
        )
        return _generate_keypair_or_xfail(
            rs,
            entry,
            keygen_mech,
            lambda: gen_keypair(
                rs.raw,
                rs.sh,
                keygen_mech,
                pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                priv_base=[],
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                pub_skip={int(CKA_EC_PARAMS)},
            ),
        )

    # PQC key types
    try:
        from pkcs11_check.raw.types_std import (
            CKA_PARAMETER_SET,
            CKK_ML_DSA,
            CKK_ML_KEM,
            CKK_SLH_DSA,
            CKM_ML_DSA_KEY_PAIR_GEN,
            CKM_ML_KEM_KEY_PAIR_GEN,
            CKM_SLH_DSA_KEY_PAIR_GEN,
            CKP_ML_DSA_65,
            CKP_ML_KEM_768,
            CKP_SLH_DSA_SHA2_128S,
        )

        if kt == int(CKK_ML_KEM):
            keygen_mech = (
                int(config.keygen_mech)
                if config.keygen_mech is not None
                else int(CKM_ML_KEM_KEY_PAIR_GEN)
            )
            return _generate_keypair_or_xfail(
                rs,
                entry,
                keygen_mech,
                lambda: gen_keypair(
                    rs.raw,
                    rs.sh,
                    keygen_mech,
                    pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768)],
                    priv_base=[],
                    public_attrs={CKA_TOKEN: False},
                    private_attrs={CKA_TOKEN: False},
                    pub_skip={CKA_PARAMETER_SET},
                ),
            )
        if kt == int(CKK_ML_DSA):
            keygen_mech = (
                int(config.keygen_mech)
                if config.keygen_mech is not None
                else int(CKM_ML_DSA_KEY_PAIR_GEN)
            )
            return _generate_keypair_or_xfail(
                rs,
                entry,
                keygen_mech,
                lambda: gen_keypair(
                    rs.raw,
                    rs.sh,
                    keygen_mech,
                    pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65)],
                    priv_base=[],
                    public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                    private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                    pub_skip={CKA_PARAMETER_SET},
                ),
            )
        if kt == int(CKK_SLH_DSA):
            keygen_mech = (
                int(config.keygen_mech)
                if config.keygen_mech is not None
                else int(CKM_SLH_DSA_KEY_PAIR_GEN)
            )
            return _generate_keypair_or_xfail(
                rs,
                entry,
                keygen_mech,
                lambda: gen_keypair(
                    rs.raw,
                    rs.sh,
                    keygen_mech,
                    pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_SLH_DSA_SHA2_128S)],
                    priv_base=[],
                    public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                    private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                    pub_skip={CKA_PARAMETER_SET},
                ),
            )
    except ImportError:
        pass

    pytest.skip(
        f"{entry.mech_name}: keypair generation for key type {config.key_type!r} not yet covered"
    )


# ---------------------------------------------------------------------------
# Test Plaintext
# ---------------------------------------------------------------------------


def get_test_plaintext_bytes() -> bytes:
    """Return 32 bytes of fixed test plaintext for encrypt/sign tests."""
    return b"\xab\xcd\xef\x01" * 8


# ---------------------------------------------------------------------------
# Encrypt Key Generation
# ---------------------------------------------------------------------------


def generate_key_from_recipe(
    rs: Any,
    entry: MechEntry,
    config: MechConfig,
    *,
    extra_attrs: dict[int, Any] | None = None,
) -> tuple[int, int | None]:
    """Generate key(s) using KeygenRecipe style dispatch.

    Returns (key_or_pub, priv_or_None).
    For symmetric/fixed_length/generic: (key_handle, None).
    For asymmetric (rsa/ec/ec_edwards/ec_montgomery/pqc): (pub_handle, priv_handle).

    Raises pytest.skip for:
    - DSA/DH styles (require external domain parameters)
    - Unknown styles
    - Missing keygen_mech for symmetric styles
    """
    import pytest

    from pkcs11_check.raw.pack import attr_ulong, template
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    recipe: KeygenRecipe = config.keygen_recipe
    style = recipe.style

    if style in ("dsa", "dh"):
        pytest.skip(f"{entry.mech_name}: {style} requires external domain parameters")

    if style in ("symmetric", "fixed_length", "generic"):
        if config.key_type is None:
            pytest.skip(f"{entry.mech_name}: no key_type in registry config")
        kt = int(config.key_type)

        keygen_mech = config.keygen_mech
        if keygen_mech is None:
            if kt == int(CKK_AES):
                keygen_mech = int(CKM_AES_KEY_GEN)
            else:
                keygen_mech = int(CKM_GENERIC_SECRET_KEY_GEN)

        is_fixed = style == "fixed_length" or kt in FIXED_LENGTH_KEY_TYPES

        # CKM_GENERIC_SECRET_KEY_GEN only produces CKK_GENERIC_SECRET keys.
        # Module-specific HMAC key types (e.g. CKK_SHA256_HMAC) are correct for
        # import/KAT operations but incompatible with this keygen mechanism --
        # passing them in the template causes CKR_TEMPLATE_INCONSISTENT.
        actual_key_type: Any = config.key_type
        if int(keygen_mech) == int(CKM_GENERIC_SECRET_KEY_GEN):
            actual_key_type = CKK_GENERIC_SECRET

        attrs: dict[int, Any] = {CKA_TOKEN: False, CKA_KEY_TYPE: actual_key_type}
        if extra_attrs:
            attrs.update(extra_attrs)

        packed: list[Any] = []
        if not is_fixed:
            key_size = pick_key_size(entry, config)
            if key_size is None:
                if style in ("symmetric", "generic"):
                    # Use at least the module's reported minimum key size.
                    # entry.min_key_size is in bytes (from CK_MECHANISM_INFO.ulMinKeySize);
                    # convert to bits and take the max with 256 as a floor.
                    min_bits = entry.min_key_size * 8 if entry.min_key_size > 0 else 0
                    key_size = max(256, min_bits)
                else:
                    pytest.skip(f"{entry.mech_name}: no usable key size in registry")
            packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
            packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
        else:
            packed.extend(pack_attrs(attrs))

        tmpl = template(*packed)
        if keygen_mech == CKM_PKCS5_PBKD2:
            mech = _pbkdf2_keygen_mechanism()
        else:
            mech = mech_simple(CKM(keygen_mech))
        _skip_if_keygen_mechanism_absent(rs, int(keygen_mech), entry.mech_name)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
        _xfail_if_keygen_runtime_reject(int(rv), entry.mech_name)
        assert rv == CKR_OK, f"C_GenerateKey failed: {rv} for {entry.mech_name}"
        return handle.value, None

    if style in ("rsa", "ec", "ec_edwards", "ec_montgomery", "pqc"):
        pub, priv = gen_keypair_for_mech(rs, entry, config)
        return pub, priv

    pytest.skip(f"{entry.mech_name}: unknown keygen_recipe style {style!r}")
    return 0, None  # unreachable


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

    from pkcs11_check.raw.pack import attr_ulong, template
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    kt = int(config.key_type)

    # AES-XTS needs a special double-length key via its own keygen mechanism
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
        _skip_if_keygen_mechanism_absent(rs, int(keygen), entry.mech_name)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
        _xfail_if_keygen_runtime_reject(int(rv), entry.mech_name)
        assert rv == CKR_OK, f"AES-XTS keygen failed: {rv}"
        return handle.value, None

    # Delegate all other styles to generate_key_from_recipe
    encrypt_attrs: dict[int, Any] = {CKA_ENCRYPT: True, CKA_DECRYPT: True}
    return generate_key_from_recipe(rs, entry, config, extra_attrs=encrypt_attrs)


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

    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    sign_attrs: dict[int, Any] = {CKA_SIGN: True, CKA_VERIFY: True}
    pub, priv = generate_key_from_recipe(rs, entry, config, extra_attrs=sign_attrs)

    if priv is not None:
        # Asymmetric: sign with private, verify with public
        return priv, pub

    return pub, None


# ---------------------------------------------------------------------------
# Vector-based Parameter Builder
# ---------------------------------------------------------------------------


def build_params_from_vector(mech_id: int, recipe: ParamRecipe, vec: dict[str, Any]) -> Any:
    """Build mechanism parameters from a KAT vector entry.

    Reads the ``params`` sub-dict from *vec* and constructs the PKCS#11
    mechanism parameter struct using values from the vector rather than
    random data.  When a required field is absent from the vector params,
    the function falls back to ``build_test_params`` (random generation).

    Styles handled:
        ``"none"``   -- returns None regardless of vector contents.
        ``"iv"``     -- uses ``params["iv_hex"]`` decoded to bytes.
        ``"gcm"``    -- uses ``iv_hex``, ``aad_hex`` (optional), ``tag_bits``.
        ``"ctr"``    -- uses ``params["iv_hex"]`` as the 16-byte counter block.
        ``"ccm"``    -- uses ``iv_hex`` (nonce), ``aad_hex``, ``tag_bits``, ``data_len``.
        ``"pss"``    -- uses ``params["hash_mech_hex"]`` as CKM constant name.
        ``"oaep"``   -- uses ``params["hash_mech_hex"]`` as CKM constant name.

    For all other styles the function delegates to ``build_test_params``.

    Returns the same types as ``build_test_params``: None, a PackedMechanism,
    or the string ``"SKIP"`` for runtime-data recipes.
    """
    style = recipe.style
    vp: dict[str, Any] = vec.get("params", {})
    d = recipe.defaults

    if style == "none":
        return None

    if style == "iv":
        iv_hex: str | None = vp.get("iv_hex")
        if iv_hex is None:
            return build_test_params(mech_id, recipe)
        return mech_bytes(CKM(mech_id), bytes.fromhex(iv_hex))

    if style == "gcm":
        iv_hex_gcm: str | None = vp.get("iv_hex")
        if iv_hex_gcm is None:
            return build_test_params(mech_id, recipe)
        iv = bytes.fromhex(iv_hex_gcm)
        aad_hex: str | None = vp.get("aad_hex")
        aad: bytes | None = bytes.fromhex(aad_hex) if aad_hex else None
        tag_bits: int = vp.get("tag_bits", d.get("tag_bits", 128))
        return mech_gcm(CKM(mech_id), iv=iv, aad=aad, tag_bits=tag_bits)

    if style == "ctr":
        iv_hex_ctr: str | None = vp.get("iv_hex")
        if iv_hex_ctr is None:
            return build_test_params(mech_id, recipe)
        # Build a CTR PackedMechanism, then overwrite cb with the vector's counter block.
        # mech_ctr always zeroes cb; we patch it afterwards to match the KAT vector.
        pm_ctr = mech_ctr(CKM(mech_id), bits=d.get("counter_bits", 128))
        cb_raw = bytes.fromhex(iv_hex_ctr)
        cb_bytes = (cb_raw[:16]).ljust(16, b"\x00")
        if pm_ctr.params is not None:
            for i, b in enumerate(cb_bytes):
                pm_ctr.params.cb[i] = b
        return pm_ctr

    if style == "ccm":
        iv_hex_ccm: str | None = vp.get("iv_hex")
        if iv_hex_ccm is None:
            return build_test_params(mech_id, recipe)
        nonce = bytes.fromhex(iv_hex_ccm)
        aad_hex_ccm: str | None = vp.get("aad_hex")
        aad_ccm: bytes | None = bytes.fromhex(aad_hex_ccm) if aad_hex_ccm else None
        tag_bits_ccm: int = vp.get("tag_bits", d.get("mac_len", 16) * 8)
        data_len: int = vp.get("data_len", d.get("data_len", 32))
        return mech_ccm(
            CKM(mech_id),
            nonce=nonce,
            data_len=data_len,
            aad=aad_ccm,
            mac_len=tag_bits_ccm // 8,
        )

    if style == "pss":
        hash_mech_name: str | None = vp.get("hash_mech_hex")
        if hash_mech_name is None:
            return build_test_params(mech_id, recipe)
        return mech_pss(
            CKM(mech_id),
            hash_mech=_resolve_const(hash_mech_name),
            mgf=_resolve_const(d.get("mgf", "CKG_MGF1_SHA256")),
            salt_len=d.get("salt_len", 32),
        )

    if style == "oaep":
        hash_mech_name_oaep: str | None = vp.get("hash_mech_hex")
        if hash_mech_name_oaep is None:
            return build_test_params(mech_id, recipe)
        return mech_oaep(
            CKM(mech_id),
            hash_mech=_resolve_const(hash_mech_name_oaep),
            mgf=_resolve_const(d.get("mgf", "CKG_MGF1_SHA256")),
        )

    # All other styles (eddsa, ecdh, hkdf, etc.) delegate to random generation
    return build_test_params(mech_id, recipe)


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
