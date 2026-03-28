"""Mechanism-driven key generation tests.

Parametrized by mech_keygen_entry — tests every keygen mechanism
advertised by the module that also has a registry config.

Key types covered:
- Symmetric variable-length (AES, Camellia, ChaCha20, ARIA, generic):
  uses CKA_VALUE_LEN
- Symmetric fixed-length (DES, DES3, SEED): no CKA_VALUE_LEN, module determines size
- RSA keypairs: CKA_MODULUS_BITS in public template
- EC (Weierstrass / Edwards / Montgomery) keypairs: CKA_EC_PARAMS (P-256 default)
- PQC keypairs (ML-KEM, ML-DSA, SLH-DSA): CKA_PARAMETER_SET
- DSA / DH / X9.42 DH / KEA / GOSTR: need domain parameters — skipped
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import destroy_quietly, gen_keypair, pack_attrs, read_attributes
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_LOCAL,
    CKA_MODULUS_BITS,
    CKA_PARAMETER_SET,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_DH,
    CKK_DSA,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_GOSTR3410,
    CKK_KEA,
    CKK_ML_DSA,
    CKK_ML_KEM,
    CKK_RSA,
    CKK_SEED,
    CKK_SLH_DSA,
    CKK_X9_42_DH,
    CKM,
    CKP_ML_DSA_65,
    CKP_ML_KEM_768,
    CKP_SLH_DSA_SHA2_128S,
    CKR_OK,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.keygen]

# Fixed-length key types: CKA_VALUE_LEN must NOT be included in the template.
# The module derives the key size from the mechanism itself (e.g. CKM_DES_KEY_GEN).
_FIXED_LENGTH_KEY_TYPES: set[int] = {
    int(CKK_DES),
    int(CKK_DES2),
    int(CKK_DES3),
    int(CKK_SEED),
}

# Key types that need CKA_EC_PARAMS (DER-encoded curve OID) in the public template.
_EC_KEY_TYPES: set[int] = {
    int(CKK_EC),
    int(CKK_EC_EDWARDS),
    int(CKK_EC_MONTGOMERY),
}

# Key types that require pre-existing domain parameters (p, q, g) — skipped here.
_DOMAIN_PARAM_KEY_TYPES: set[int] = {
    int(CKK_DSA),
    int(CKK_DH),
    int(CKK_X9_42_DH),
    int(CKK_KEA),
    int(CKK_GOSTR3410),
}

# Default curve OIDs used for keypair generation tests
_P256_OID: bytes = encode_named_curve_parameters("secp256r1")
_ED25519_OID: bytes = encode_named_curve_parameters("ed25519")
_X25519_OID: bytes = encode_named_curve_parameters("x25519")


def _needs_domain_params(config: MechConfig) -> bool:
    """Return True if this keygen mechanism requires external domain parameters."""
    return config.key_type is not None and int(config.key_type) in _DOMAIN_PARAM_KEY_TYPES


def _pick_key_size(entry: MechEntry, config: MechConfig) -> int | None:
    """Pick a key size (bits) within the module's reported range for variable-length keys.

    Returns None for:
    - Fixed-length key types (DES/SEED) — no CKA_VALUE_LEN needed
    - Curve-based or parameter-set types with no bit sizes defined (key_sizes == ())
    - When no registry size fits the module's reported min/max range
    """
    if config.key_type is not None and int(config.key_type) in _FIXED_LENGTH_KEY_TYPES:
        return None
    if not config.key_sizes:
        return None
    max_size = entry.max_key_size if entry.max_key_size != 0 else 0xFFFFFFFF
    for size in sorted(config.key_sizes):
        if entry.min_key_size <= size <= max_size:
            return size
    return config.key_sizes[0]


def _gen_symmetric_key(rs: RawSession, entry: MechEntry, config: MechConfig) -> int:
    """Generate a symmetric (secret) key using the named mechanism.

    Handles both fixed-length (DES) and variable-length (AES, Camellia, etc.)
    symmetric keys.  Returns the key handle.  Asserts CKR_OK.
    """
    key_type = config.key_type
    is_fixed = key_type is not None and int(key_type) in _FIXED_LENGTH_KEY_TYPES

    attrs: dict[int, Any] = {CKA_TOKEN: False}
    if key_type is not None:
        attrs[CKA_KEY_TYPE] = key_type

    packed: list[Any] = []
    if not is_fixed:
        key_size = _pick_key_size(entry, config)
        if key_size is None:
            pytest.skip(f"{entry.mech_name}: no usable key size in registry")
        packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))

    tmpl = template(*packed)
    mech = mech_simple(CKM(entry.mech_id))
    handle = CK_OBJECT_HANDLE(0)

    rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
        rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
    )
    assert rv == CKR_OK, f"C_GenerateKey failed with {rv} for {entry.mech_name}"
    return handle.value


def _gen_keypair(rs: RawSession, entry: MechEntry, config: MechConfig) -> tuple[int, int]:
    """Generate an asymmetric key pair for the given mechanism.

    Returns (pub_handle, priv_handle).  Calls pytest.skip for unsupported key types.
    """
    key_type = config.key_type
    if key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    if _needs_domain_params(config):
        pytest.skip(
            f"{entry.mech_name}: requires external domain parameters "
            "(DSA/DH/GOSTR/KEA — not covered by this test)"
        )

    kt = int(key_type)

    if kt == int(CKK_RSA):
        key_size = _pick_key_size(entry, config) or 2048
        return gen_keypair(
            rs.raw,
            rs.sh,
            entry.mech_id,
            pub_base=[
                attr_ulong(CKA_MODULUS_BITS, key_size),
                attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
            ],
            priv_base=[],
            public_attrs={CKA_VERIFY: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )

    if kt in _EC_KEY_TYPES:
        if kt == int(CKK_EC_EDWARDS):
            curve_oid = _ED25519_OID
        elif kt == int(CKK_EC_MONTGOMERY):
            curve_oid = _X25519_OID
        else:
            curve_oid = _P256_OID
        return gen_keypair(
            rs.raw,
            rs.sh,
            entry.mech_id,
            pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
            priv_base=[],
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            pub_skip={CKA_EC_PARAMS},
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

    pytest.skip(
        f"{entry.mech_name}: keypair generation for key type {key_type!r} "
        "not yet covered by this test"
    )


class TestMechKeygen:
    """Key generation for every advertised keygen mechanism with a registry config."""

    def test_generate_key(
        self, p11_raw_session: RawSession, mech_keygen_entry: MechEntry
    ) -> None:
        """Generate a key/keypair and verify the returned handle is non-zero."""
        rs = p11_raw_session
        entry = mech_keygen_entry
        config = entry.config
        if config is None:
            pytest.skip("No registry config")
        if config.is_param_gen:
            pytest.skip("Domain parameter generation not covered by this test")

        if config.is_keypair:
            pub, priv = _gen_keypair(rs, entry, config)
            try:
                assert pub != 0, f"{entry.mech_name}: public key handle is 0"
                assert priv != 0, f"{entry.mech_name}: private key handle is 0"
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        else:
            key = _gen_symmetric_key(rs, entry, config)
            try:
                assert key != 0, f"{entry.mech_name}: secret key handle is 0"
            finally:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_local_flag(
        self, p11_raw_session: RawSession, mech_keygen_entry: MechEntry
    ) -> None:
        """Keys generated by C_GenerateKey/C_GenerateKeyPair must have CKA_LOCAL=True."""
        rs = p11_raw_session
        entry = mech_keygen_entry
        config = entry.config
        if config is None:
            pytest.skip("No registry config")
        if config.is_param_gen:
            pytest.skip("Domain parameter generation not covered by this test")

        if config.is_keypair:
            pub, priv = _gen_keypair(rs, entry, config)
            try:
                for label, handle in (("public", pub), ("private", priv)):
                    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_LOCAL])
                    if CKA_LOCAL in attrs:
                        assert attrs[CKA_LOCAL] is True, (
                            f"{entry.mech_name}: CKA_LOCAL should be True on generated "
                            f"{label} key (got {attrs[CKA_LOCAL]!r})"
                        )
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        else:
            key = _gen_symmetric_key(rs, entry, config)
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LOCAL])
                if CKA_LOCAL in attrs:
                    assert attrs[CKA_LOCAL] is True, (
                        f"{entry.mech_name}: CKA_LOCAL should be True on generated key "
                        f"(got {attrs[CKA_LOCAL]!r})"
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
