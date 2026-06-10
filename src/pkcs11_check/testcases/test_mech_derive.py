"""Mechanism-driven key derivation tests.

Parametrized by mech_derive_entry -- tests every derive mechanism advertised
by the module that also has a registry config.

Derivation categories handled:
- SHA key derivation (no params): base generic secret key -> derived key
- HKDF (CK_HKDF_PARAMS): HKDF base key -> AES-128 derived key
- ECDH1 (CK_ECDH1_DERIVE_PARAMS): EC keypair -> shared secret
- AES-ECB encrypt-data derivation: AES base key -> derived key
- DES-ECB / DES3-ECB encrypt-data derivation: DES/DES3 base key -> derived key
- CONCATENATE / XOR / EXTRACT: generic secret base key -> derived key

Mechanisms skipped here (too complex for generic parametrized tests):
- HKDF_DATA (raw bytes output, not a key object handle)
- SP800-108 / TLS / SSL / WTLS / IKE: need large protocol-specific params
- Signal protocol (X3DH, X2Ratchet): need protocol state machines
- ECDH cofactor, ECMQV: variants of ECDH handled separately
- AES-CBC-ENCRYPT-DATA: needs custom struct (CK_AES_CBC_ENCRYPT_DATA_PARAMS)
- DES-CBC-ENCRYPT-DATA / DES3-CBC-ENCRYPT-DATA: need CK_DES_CBC_ENCRYPT_DATA_PARAMS
- PUB_KEY_FROM_PRIV_KEY: derives public key from existing private key (EC)
"""

from __future__ import annotations

import ctypes
import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.api import ckm_name
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_ulong, mech_bytes, mech_simple, template
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_hkdf, mech_string_data
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKK_AES,
    CKK_DES,
    CKK_DES3,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKM,
    CKM_DES3_KEY_GEN,
    CKM_DES_KEY_GEN,
    CKM_SHA256,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._capability_claims import claim_refusal_passes
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import gen_generic_secret

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.derive]


# SHA key derivation mechanisms have no params and use a generic secret base key
_SHA_KEY_DERIV_MECHS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import (
        CKM_SHA1_KEY_DERIVATION,
        CKM_SHA3_224_KEY_DERIVATION,
        CKM_SHA3_256_KEY_DERIVATION,
        CKM_SHA3_384_KEY_DERIVATION,
        CKM_SHA3_512_KEY_DERIVATION,
        CKM_SHA224_KEY_DERIVATION,
        CKM_SHA256_KEY_DERIVATION,
        CKM_SHA384_KEY_DERIVATION,
        CKM_SHA512_224_KEY_DERIVATION,
        CKM_SHA512_256_KEY_DERIVATION,
        CKM_SHA512_KEY_DERIVATION,
        CKM_SHA512_T_KEY_DERIVATION,
        CKM_SHAKE_128_KEY_DERIVATION,
        CKM_SHAKE_256_KEY_DERIVATION,
    )

    _SHA_KEY_DERIV_MECHS = {
        int(CKM_SHA1_KEY_DERIVATION),
        int(CKM_SHA224_KEY_DERIVATION),
        int(CKM_SHA256_KEY_DERIVATION),
        int(CKM_SHA384_KEY_DERIVATION),
        int(CKM_SHA512_KEY_DERIVATION),
        int(CKM_SHA512_224_KEY_DERIVATION),
        int(CKM_SHA512_256_KEY_DERIVATION),
        int(CKM_SHA512_T_KEY_DERIVATION),
        int(CKM_SHA3_224_KEY_DERIVATION),
        int(CKM_SHA3_256_KEY_DERIVATION),
        int(CKM_SHA3_384_KEY_DERIVATION),
        int(CKM_SHA3_512_KEY_DERIVATION),
        int(CKM_SHAKE_128_KEY_DERIVATION),
        int(CKM_SHAKE_256_KEY_DERIVATION),
    }
except ImportError:
    pass

# HKDF mechanisms
_HKDF_DERIVE_ID: int = 0
_HKDF_DATA_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_HKDF_DATA, CKM_HKDF_DERIVE

    _HKDF_DERIVE_ID = int(CKM_HKDF_DERIVE)
    _HKDF_DATA_ID = int(CKM_HKDF_DATA)
except ImportError:
    pass

# ECDH1 derive mechanisms
_ECDH1_MECH_IDS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import CKM_ECDH1_COFACTOR_DERIVE, CKM_ECDH1_DERIVE

    _ECDH1_MECH_IDS = {int(CKM_ECDH1_DERIVE), int(CKM_ECDH1_COFACTOR_DERIVE)}
except ImportError:
    pass

# Concatenation / XOR / Extract derivation mechanisms (generic secret base key, data param)
_CONCAT_DATA_MECH_IDS: set[int] = set()
_XOR_MECH_ID: int = 0
_EXTRACT_MECH_ID: int = 0
try:
    from pkcs11_check.raw.types_std import (
        CKM_CONCATENATE_BASE_AND_DATA,
        CKM_CONCATENATE_DATA_AND_BASE,
        CKM_EXTRACT_KEY_FROM_KEY,
        CKM_XOR_BASE_AND_DATA,
    )

    _CONCAT_DATA_MECH_IDS = {
        int(CKM_CONCATENATE_BASE_AND_DATA),
        int(CKM_CONCATENATE_DATA_AND_BASE),
    }
    _XOR_MECH_ID = int(CKM_XOR_BASE_AND_DATA)
    _EXTRACT_MECH_ID = int(CKM_EXTRACT_KEY_FROM_KEY)
except ImportError:
    pass

# CONCATENATE_BASE_AND_KEY needs a second key object handle in the param
_CONCAT_KEY_MECH_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_CONCATENATE_BASE_AND_KEY

    _CONCAT_KEY_MECH_ID = int(CKM_CONCATENATE_BASE_AND_KEY)
except ImportError:
    pass

# AES ECB encrypt-data derive mechanism
_AES_ECB_ENCRYPT_DATA_ID: int = 0
_AES_CBC_ENCRYPT_DATA_ID: int = 0
try:
    from pkcs11_check.raw.types_std import (
        CKM_AES_CBC_ENCRYPT_DATA,
        CKM_AES_ECB_ENCRYPT_DATA,
    )

    _AES_ECB_ENCRYPT_DATA_ID = int(CKM_AES_ECB_ENCRYPT_DATA)
    _AES_CBC_ENCRYPT_DATA_ID = int(CKM_AES_CBC_ENCRYPT_DATA)
except ImportError:
    pass

# DES / DES3 ECB and CBC encrypt-data derive mechanisms
_DES_ECB_ENCRYPT_DATA_ID: int = 0
_DES_CBC_ENCRYPT_DATA_ID: int = 0
_DES3_ECB_ENCRYPT_DATA_ID: int = 0
_DES3_CBC_ENCRYPT_DATA_ID: int = 0
try:
    from pkcs11_check.raw.types_std import (
        CKM_DES3_CBC_ENCRYPT_DATA,
        CKM_DES3_ECB_ENCRYPT_DATA,
        CKM_DES_CBC_ENCRYPT_DATA,
        CKM_DES_ECB_ENCRYPT_DATA,
    )

    _DES_ECB_ENCRYPT_DATA_ID = int(CKM_DES_ECB_ENCRYPT_DATA)
    _DES_CBC_ENCRYPT_DATA_ID = int(CKM_DES_CBC_ENCRYPT_DATA)
    _DES3_ECB_ENCRYPT_DATA_ID = int(CKM_DES3_ECB_ENCRYPT_DATA)
    _DES3_CBC_ENCRYPT_DATA_ID = int(CKM_DES3_CBC_ENCRYPT_DATA)
except ImportError:
    pass

# Mechanisms that produce key material output, not key object handles (skip)
_SKIPPED_PROTOCOL_MECHS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import (
        CKM_IKE1_EXTENDED_DERIVE,
        CKM_IKE1_PRF_DERIVE,
        CKM_IKE2_PRF_PLUS_DERIVE,
        CKM_IKE_PRF_DERIVE,
        CKM_PKCS5_PBKD2,
        CKM_SP800_108_COUNTER_KDF,
        CKM_SP800_108_DOUBLE_PIPELINE_KDF,
        CKM_SP800_108_FEEDBACK_KDF,
        CKM_SSL3_KEY_AND_MAC_DERIVE,
        CKM_SSL3_MASTER_KEY_DERIVE,
        CKM_SSL3_MASTER_KEY_DERIVE_DH,
        CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
        CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
        CKM_TLS12_KDF,
        CKM_TLS12_KEY_AND_MAC_DERIVE,
        CKM_TLS12_KEY_SAFE_DERIVE,
        CKM_TLS12_MASTER_KEY_DERIVE,
        CKM_TLS12_MASTER_KEY_DERIVE_DH,
        CKM_TLS_KDF,
        CKM_TLS_PRE_MASTER_KEY_GEN,
        CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
        CKM_WTLS_MASTER_KEY_DERIVE,
        CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
        CKM_WTLS_PRF,
        CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        CKM_X2RATCHET_INITIALIZE,
        CKM_X2RATCHET_RESPOND,
        CKM_X3DH_INITIALIZE,
        CKM_X3DH_RESPOND,
    )

    _SKIPPED_PROTOCOL_MECHS = {
        int(CKM_SP800_108_COUNTER_KDF),
        int(CKM_SP800_108_FEEDBACK_KDF),
        int(CKM_SP800_108_DOUBLE_PIPELINE_KDF),
        int(CKM_TLS_PRE_MASTER_KEY_GEN),
        int(CKM_TLS12_MASTER_KEY_DERIVE),
        int(CKM_TLS12_MASTER_KEY_DERIVE_DH),
        int(CKM_TLS12_KEY_AND_MAC_DERIVE),
        int(CKM_TLS12_KEY_SAFE_DERIVE),
        int(CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE),
        int(CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH),
        int(CKM_TLS_KDF),
        int(CKM_TLS12_KDF),
        int(CKM_SSL3_MASTER_KEY_DERIVE),
        int(CKM_SSL3_MASTER_KEY_DERIVE_DH),
        int(CKM_SSL3_KEY_AND_MAC_DERIVE),
        int(CKM_WTLS_MASTER_KEY_DERIVE),
        int(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
        int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
        int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
        int(CKM_WTLS_PRF),
        int(CKM_IKE_PRF_DERIVE),
        int(CKM_IKE1_PRF_DERIVE),
        int(CKM_IKE1_EXTENDED_DERIVE),
        int(CKM_IKE2_PRF_PLUS_DERIVE),
        int(CKM_PKCS5_PBKD2),
        int(CKM_X3DH_INITIALIZE),
        int(CKM_X3DH_RESPOND),
        int(CKM_X2RATCHET_INITIALIZE),
        int(CKM_X2RATCHET_RESPOND),
    }
except ImportError:
    pass

# PUB_KEY_FROM_PRIV_KEY -- derive public key from private, not a typical derive test
_PUB_KEY_FROM_PRIV_KEY_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_PUB_KEY_FROM_PRIV_KEY

    _PUB_KEY_FROM_PRIV_KEY_ID = int(CKM_PUB_KEY_FROM_PRIV_KEY)
except ImportError:
    pass

# CKF_NULL_DERIVE -- no derivation semantics
_CKM_NULL_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_NULL

    _CKM_NULL_ID = int(CKM_NULL)
except ImportError:
    pass

_P256_OID: bytes = encode_named_curve_parameters("secp256r1")


def _gen_hkdf_base_key(rs: RawSession) -> int:
    """Generate a CKK_HKDF key for use as HKDF base key.

    Must use CKM_HKDF_KEY_GEN (not CKM_GENERIC_SECRET_KEY_GEN) with CKK_HKDF.
    Kryoptic returns CKR_TEMPLATE_INCONSISTENT for any other combination.
    """
    try:
        from pkcs11_check.raw.types_std import CKM_HKDF_KEY_GEN
    except ImportError:
        import pytest

        pytest.skip("CKM_HKDF_KEY_GEN not in types_std -- cannot generate HKDF base key")
    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: CKK_HKDF,
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_EXTRACTABLE: True,
        CKA_SENSITIVE: False,
    }
    packed = [attr_ulong(CKA_VALUE_LEN, 32)]
    packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    tmpl = template(*packed)
    mech = mech_simple(CKM_HKDF_KEY_GEN)
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    assert rv == CKR_OK, f"HKDF base key gen failed: {rv}"
    return handle.value


# Template for derived AES-128 key.
# CKA_CLASS is required by PKCS#11 spec for C_DeriveKey -- some modules (Kryoptic)
# return CKR_TEMPLATE_INCONSISTENT when it is absent.
_DERIVED_AES_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_AES,
    CKA_VALUE_LEN: 16,
    CKA_ENCRYPT: True,
    CKA_DECRYPT: True,
    CKA_TOKEN: False,
    CKA_EXTRACTABLE: True,
    CKA_SENSITIVE: False,
}

# Template for derived generic secret key.
# CKA_CLASS is required by PKCS#11 spec for C_DeriveKey -- some modules (Kryoptic)
# return CKR_TEMPLATE_INCONSISTENT when it is absent.
_DERIVED_GENERIC_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
    CKA_VALUE_LEN: 16,
    CKA_DERIVE: True,
    CKA_TOKEN: False,
    CKA_EXTRACTABLE: True,
    CKA_SENSITIVE: False,
}


def _derive_hkdf(rs: RawSession, entry: MechEntry) -> None:
    """HKDF_DERIVE: generate HKDF base key, derive AES-128 key via CK_HKDF_PARAMS."""
    mech_id = entry.mech_id
    if not rs.has_mechanism("HKDF_KEY_GEN"):
        pytest.skip("HKDF_KEY_GEN not available -- cannot generate HKDF base key")
    base_key = _gen_hkdf_base_key(rs)
    derived_key: int = 0
    try:
        salt = os.urandom(16)
        hkdf_param = mech_hkdf(
            CKM(mech_id),
            hash_mech=CKM_SHA256,
            extract=True,
            expand=True,
            salt=salt,
            info=b"pkcs11-check derive test",
        )
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_AES_ATTRS,
            mech_param=hkdf_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_ecdh(rs: RawSession, entry: MechEntry) -> None:
    """ECDH1 (and cofactor): generate two P-256 keypairs, derive shared secret.

    The private key must have CKA_DERIVE=True.  The derived key uses
    CKA_CLASS=CKO_SECRET_KEY (required by the PKCS#11 spec for C_DeriveKey)
    and no CKA_VALUE_LEN -- ECDH with CKD_NULL derives the full curve-output
    length (32 bytes for P-256) without truncation.
    """
    mech_id = entry.mech_id
    from pkcs11_check.raw.types_std import CKA_EC_POINT

    priv_a, pub_a = 0, 0
    priv_b, pub_b = 0, 0
    derived_key: int = 0
    try:
        pub_a, priv_a = gen_ec_keypair(
            rs.raw, rs.sh, _P256_OID, private_attrs={CKA_DERIVE: True, CKA_TOKEN: False}
        )
        pub_b, priv_b = gen_ec_keypair(rs.raw, rs.sh, _P256_OID)
        # Read peer (B's) public point
        peer_attrs = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])
        peer_point = peer_attrs.get(CKA_EC_POINT)
        if not peer_point or not isinstance(peer_point, bytes):
            pytest.skip(f"{entry.mech_name}: cannot read CKA_EC_POINT from peer key")
        ecdh_param = mech_ecdh(
            CKM(mech_id),
            kdf=CKD_NULL,
            public_data=peer_point,
        )
        # CKA_CLASS required; no CKA_VALUE_LEN -- ECDH output length is curve-fixed
        ecdh_derived_attrs: dict[int, Any] = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_EXTRACTABLE: True,
            CKA_SENSITIVE: False,
        }
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            priv_a,
            CKM(mech_id),
            attrs=ecdh_derived_attrs,
            mech_param=ecdh_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: ECDH derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_a)
        destroy_quietly(rs.raw, rs.sh, priv_a)
        destroy_quietly(rs.raw, rs.sh, pub_b)
        destroy_quietly(rs.raw, rs.sh, priv_b)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_aes_ecb(rs: RawSession, entry: MechEntry) -> None:
    """AES-ECB-ENCRYPT-DATA: derive by encrypting a 16-byte block with AES base key."""
    mech_id = entry.mech_id
    base_key = gen_aes_key(
        rs.raw,
        rs.sh,
        256,
        attrs={CKA_DERIVE: True, CKA_TOKEN: False},
    )
    derived_key: int = 0
    try:
        # CK_KEY_DERIVATION_STRING_DATA: 16 bytes (one AES block)
        data_param = mech_string_data(
            CKM(mech_id),
            b"derive__test__01",  # 16 bytes
        )
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
            mech_param=data_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _gen_des_base_key(rs: RawSession, des3: bool) -> int:
    """Generate a DES or DES3 base key with CKA_DERIVE=True.

    DES and DES3 keys have fixed lengths (no CKA_VALUE_LEN).
    """
    from ctypes import byref

    key_type = CKK_DES3 if des3 else CKK_DES
    keygen_ckm = CKM_DES3_KEY_GEN if des3 else CKM_DES_KEY_GEN
    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: key_type,
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_EXTRACTABLE: True,
        CKA_SENSITIVE: False,
    }
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    mech = mech_simple(keygen_ckm)
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    assert rv == CKR_OK, f"DES{'3' if des3 else ''} base key gen failed: {rv}"
    return handle.value


def _derive_des_ecb(rs: RawSession, entry: MechEntry, des3: bool) -> None:
    """DES[3]_ECB_ENCRYPT_DATA: derive by encrypting an 8-byte block with a DES[3] base key."""
    mech_id = entry.mech_id
    keygen_name = "DES3_KEY_GEN" if des3 else "DES_KEY_GEN"
    if not rs.has_mechanism(keygen_name):
        pytest.skip(f"{entry.mech_name}: {keygen_name} not available")
    base_key = _gen_des_base_key(rs, des3=des3)
    derived_key: int = 0
    try:
        # CK_KEY_DERIVATION_STRING_DATA: 8 bytes (one DES block)
        data_param = mech_string_data(
            CKM(mech_id),
            b"derive08",  # 8 bytes
        )
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
            mech_param=data_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_concat_data(rs: RawSession, entry: MechEntry) -> None:
    """CONCATENATE_BASE_AND_DATA / CONCATENATE_DATA_AND_BASE / XOR_BASE_AND_DATA.

    Uses a CK_KEY_DERIVATION_STRING_DATA param with a random 16-byte value.
    """
    mech_id = entry.mech_id
    base_key = gen_generic_secret(rs, bits=256, extra_attrs={CKA_DERIVE: True})
    derived_key: int = 0
    try:
        data_param = mech_string_data(CKM(mech_id), os.urandom(16))
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
            mech_param=data_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_extract(rs: RawSession, entry: MechEntry) -> None:
    """EXTRACT_KEY_FROM_KEY: extract a sub-key starting at bit position 0."""
    mech_id = entry.mech_id
    base_key = gen_generic_secret(rs, bits=256, extra_attrs={CKA_DERIVE: True})
    derived_key: int = 0
    try:
        # CK_EXTRACT_PARAMS is a CK_ULONG bit position (extract from bit 0).
        # Serialise as native byte order CK_ULONG and pass via mech_bytes.
        bit_index = ctypes.c_ulong(0)
        param_bytes = bytes(ctypes.string_at(ctypes.addressof(bit_index), ctypes.sizeof(bit_index)))
        extract_param = mech_bytes(CKM(mech_id), param_bytes)
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
            mech_param=extract_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_concat_key(rs: RawSession, entry: MechEntry) -> None:
    """CONCATENATE_BASE_AND_KEY: concatenate base key with a second key object."""
    mech_id = entry.mech_id
    base_key = gen_generic_secret(rs, bits=128, extra_attrs={CKA_DERIVE: True})
    addon_key = gen_generic_secret(rs, bits=128, extra_attrs={CKA_DERIVE: True})
    derived_key: int = 0
    try:
        # CKM_CONCATENATE_BASE_AND_KEY param is a CK_OBJECT_HANDLE
        # (native CK_ULONG). Serialise and pass via mech_bytes.
        handle_ctype = CK_OBJECT_HANDLE(addon_key)
        param_bytes = bytes(
            ctypes.string_at(ctypes.addressof(handle_ctype), ctypes.sizeof(handle_ctype))
        )
        concat_param = mech_bytes(CKM(mech_id), param_bytes)
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
            mech_param=concat_param,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        destroy_quietly(rs.raw, rs.sh, addon_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_sha(rs: RawSession, entry: MechEntry) -> None:
    """SHA key derivation (no params): generic secret base key -> derived key."""
    mech_id = entry.mech_id
    base_key = gen_generic_secret(rs, bits=256, extra_attrs={CKA_DERIVE: True})
    derived_key: int = 0
    try:
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
        )
        assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
    finally:
        destroy_quietly(rs.raw, rs.sh, base_key)
        if derived_key != 0:
            destroy_quietly(rs.raw, rs.sh, derived_key)


def _derive_pub_from_priv(rs: RawSession, entry: MechEntry) -> None:
    """CKM_PUB_KEY_FROM_PRIV_KEY: derive a public key from an EC private key.

    Generates a P-256 EC key pair, then uses C_DeriveKey with the private key
    to produce a new public key object. Verifies the derived handle is non-zero
    and has CKA_CLASS == CKO_PUBLIC_KEY.
    """
    mech_id = entry.mech_id
    if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
        pytest.skip(f"{entry.mech_name}: EC_KEY_PAIR_GEN not available")
    pub_a, priv_a = 0, 0
    derived_pub: int = 0
    try:
        pub_a, priv_a = gen_ec_keypair(
            rs.raw,
            rs.sh,
            _P256_OID,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
        # CKM_PUB_KEY_FROM_PRIV_KEY takes no mechanism params (NULL)
        derive_mech = mech_simple(CKM(mech_id))
        # Template for the derived public key
        derive_attrs: dict[int, Any] = {
            CKA_CLASS: CKO_PUBLIC_KEY,
            CKA_KEY_TYPE: CKK_EC,
            CKA_TOKEN: False,
        }
        derived_pub = derive_key(
            rs.raw,
            rs.sh,
            priv_a,
            CKM(mech_id),
            attrs=derive_attrs,
            mech_param=derive_mech,
        )
        assert derived_pub != 0, f"{entry.mech_name}: derive returned handle 0"
        # Verify the derived object is a public key
        result = read_attributes(rs.raw, rs.sh, derived_pub, [CKA_CLASS])
        obj_class_raw = result.get(CKA_CLASS)
        if obj_class_raw is not None and isinstance(obj_class_raw, int):
            assert obj_class_raw == int(CKO_PUBLIC_KEY), (
                f"{entry.mech_name}: derived object class {obj_class_raw:#x} != CKO_PUBLIC_KEY"
            )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_a)
        destroy_quietly(rs.raw, rs.sh, priv_a)
        if derived_pub != 0:
            destroy_quietly(rs.raw, rs.sh, derived_pub)


class TestMechDerive:
    """Key derivation for every advertised derive mechanism with a registry config."""

    def test_derive_produces_key(
        self, p11_module_session: RawSession, mech_derive_entry: MechEntry
    ) -> None:
        """Derive a key and verify the returned handle is valid (non-zero).

        Routing logic by mechanism family:
        - SHA key derivation: no params, generic secret base key
        - HKDF_DERIVE: CK_HKDF_PARAMS, HKDF base key
        - ECDH1/cofactor: CK_ECDH1_DERIVE_PARAMS from peer public key
        - AES_ECB_ENCRYPT_DATA: 16-byte block data string param, AES base key
        - DES_ECB_ENCRYPT_DATA / DES3_ECB_ENCRYPT_DATA: 8-byte block string param, DES/DES3 base key
        - CONCATENATE_BASE_AND_DATA / CONCATENATE_DATA_AND_BASE / XOR_BASE_AND_DATA:
          CK_KEY_DERIVATION_STRING_DATA param
        - EXTRACT_KEY_FROM_KEY: CK_ULONG bit position param
        - CONCATENATE_BASE_AND_KEY: CK_OBJECT_HANDLE param
        - Everything else: skipped with an explanatory message
        """
        rs = p11_module_session
        entry = mech_derive_entry
        config = entry.config
        mech_id = entry.mech_id

        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        # Check availability
        mech_short = ckm_name(mech_id).removeprefix("CKM_")
        if not rs.has_mechanism(mech_short):
            pytest.skip(f"{entry.mech_name}: mechanism not available")

        # Skip protocol KDFs that need complex params
        if mech_id in _SKIPPED_PROTOCOL_MECHS:
            pytest.skip(
                f"{entry.mech_name}: protocol KDF (TLS/SSL/IKE/SP800/Signal) "
                "-- complex params, skipped here"
            )

        # Skip HKDF_DATA (produces raw data output, not a key handle)
        if _HKDF_DATA_ID and mech_id == _HKDF_DATA_ID:
            pytest.skip(f"{entry.mech_name}: produces raw data output, not a key handle")

        # CKM_PUB_KEY_FROM_PRIV_KEY: derive public key from private key
        if _PUB_KEY_FROM_PRIV_KEY_ID and mech_id == _PUB_KEY_FROM_PRIV_KEY_ID:
            _derive_pub_from_priv(rs, entry)
            return

        # Skip CKM_NULL (no derivation semantics)
        if _CKM_NULL_ID and mech_id == _CKM_NULL_ID:
            pytest.skip(f"{entry.mech_name}: null mechanism -- no derivation semantics")

        # Skip AES-CBC-ENCRYPT-DATA (needs custom struct with IV)
        if _AES_CBC_ENCRYPT_DATA_ID and mech_id == _AES_CBC_ENCRYPT_DATA_ID:
            pytest.skip(
                f"{entry.mech_name}: needs CK_AES_CBC_ENCRYPT_DATA_PARAMS struct -- "
                "covered in test_aes_kdf.py"
            )

        # Skip DES-CBC-ENCRYPT-DATA (needs CK_DES_CBC_ENCRYPT_DATA_PARAMS struct with IV)
        if _DES_CBC_ENCRYPT_DATA_ID and mech_id == _DES_CBC_ENCRYPT_DATA_ID:
            pytest.skip(f"{entry.mech_name}: needs CK_DES_CBC_ENCRYPT_DATA_PARAMS struct with IV")
        if _DES3_CBC_ENCRYPT_DATA_ID and mech_id == _DES3_CBC_ENCRYPT_DATA_ID:
            pytest.skip(f"{entry.mech_name}: needs CK_DES_CBC_ENCRYPT_DATA_PARAMS struct with IV")

        try:
            # Dispatch to per-family helpers
            if _HKDF_DERIVE_ID and mech_id == _HKDF_DERIVE_ID:
                _derive_hkdf(rs, entry)
            elif mech_id in _ECDH1_MECH_IDS:
                _derive_ecdh(rs, entry)
            elif _AES_ECB_ENCRYPT_DATA_ID and mech_id == _AES_ECB_ENCRYPT_DATA_ID:
                _derive_aes_ecb(rs, entry)
            elif _DES_ECB_ENCRYPT_DATA_ID and mech_id == _DES_ECB_ENCRYPT_DATA_ID:
                _derive_des_ecb(rs, entry, des3=False)
            elif _DES3_ECB_ENCRYPT_DATA_ID and mech_id == _DES3_ECB_ENCRYPT_DATA_ID:
                _derive_des_ecb(rs, entry, des3=True)
            elif mech_id in _CONCAT_DATA_MECH_IDS or mech_id == _XOR_MECH_ID:
                _derive_concat_data(rs, entry)
            elif _EXTRACT_MECH_ID and mech_id == _EXTRACT_MECH_ID:
                _derive_extract(rs, entry)
            elif _CONCAT_KEY_MECH_ID and mech_id == _CONCAT_KEY_MECH_ID:
                _derive_concat_key(rs, entry)
            elif mech_id in _SHA_KEY_DERIV_MECHS:
                _derive_sha(rs, entry)
            else:
                pytest.skip(
                    f"{entry.mech_name}: derive param construction not yet implemented "
                    "in this generic test"
                )
        except AssertionError as exc:
            if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:derive"):
                return
