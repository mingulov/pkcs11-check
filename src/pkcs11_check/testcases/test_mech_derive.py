"""Mechanism-driven key derivation tests.

Parametrized by mech_derive_entry -- tests every derive mechanism advertised
by the module that also has a registry config.

Derivation categories handled:
- SHA key derivation (no params): base generic secret key -> derived key
- HKDF (CK_HKDF_PARAMS): HKDF base key -> derived key or data object
- ECDH1 (CK_ECDH1_DERIVE_PARAMS): EC keypair -> shared secret
- AES-ECB encrypt-data derivation: AES base key -> derived key
- DES-ECB / DES3-ECB encrypt-data derivation: DES/DES3 base key -> derived key
- DES-CBC / DES3-CBC encrypt-data derivation: DES/DES3 base key -> derived key
- CONCATENATE / XOR / EXTRACT: generic secret base key -> derived key

Mechanisms skipped here (too complex for generic parametrized tests):
- SP800-108 / TLS / SSL / WTLS / IKE: need large protocol-specific params
- Signal protocol (X3DH, X2Ratchet): need protocol state machines
- ECDH cofactor, ECMQV: variants of ECDH handled separately
- AES-CBC-ENCRYPT-DATA: needs custom struct (CK_AES_CBC_ENCRYPT_DATA_PARAMS)
- PUB_KEY_FROM_PRIV_KEY: derives public key from existing private key (EC)
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Sized
from ctypes import byref
from typing import Any, NamedTuple, NoReturn

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.api import ckm_name
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    LengthArg,
    PackedMechanism,
    PointerArg,
    attr_ulong,
    mech_bytes,
    mech_simple,
    template,
)
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_hkdf, mech_string_data
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
    CK_BYTE,
    CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
    CK_DES_CBC_ENCRYPT_DATA_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKK_AES,
    CKK_ARIA,
    CKK_CAMELLIA,
    CKK_DES,
    CKK_DES3,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKK_SEED,
    CKM,
    CKM_ARIA_CBC_ENCRYPT_DATA,
    CKM_ARIA_ECB_ENCRYPT_DATA,
    CKM_ARIA_KEY_GEN,
    CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    CKM_CAMELLIA_KEY_GEN,
    CKM_DES3_CBC_ENCRYPT_DATA,
    CKM_DES3_KEY_GEN,
    CKM_DES_CBC_ENCRYPT_DATA,
    CKM_DES_KEY_GEN,
    CKM_SEED_CBC_ENCRYPT_DATA,
    CKM_SEED_ECB_ENCRYPT_DATA,
    CKM_SEED_KEY_GEN,
    CKM_SHA256,
    CKO_DATA,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._capability_claims import claim_refusal_passes
from pkcs11_check.testcases._ec_export import (
    read_conventional_ec_point_or_xfail,
    select_ecdh_point_form,
)
from pkcs11_check.testcases.conftest import (
    IMPORT_STORAGE_SHAPE_REJECTS,
    import_secret_key_negotiated,
)
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
_DES3_ECB_ENCRYPT_DATA_ID: int = 0
try:
    from pkcs11_check.raw.types_std import (
        CKM_DES3_ECB_ENCRYPT_DATA,
        CKM_DES_ECB_ENCRYPT_DATA,
    )

    _DES_ECB_ENCRYPT_DATA_ID = int(CKM_DES_ECB_ENCRYPT_DATA)
    _DES3_ECB_ENCRYPT_DATA_ID = int(CKM_DES3_ECB_ENCRYPT_DATA)
except ImportError:
    pass


# Cipher ECB/CBC encrypt-data derive mechanisms.
class _CipherEncryptDataDeriveCase(NamedTuple):
    keygen_name: str
    keygen_mech: CKM
    key_type: int
    mode: str
    block_size: int
    cbc_params_cls: type[Any] | None = None
    key_size_bits: int | None = 128


_CIPHER_ENCRYPT_DATA_DERIVE_CASES: dict[int, _CipherEncryptDataDeriveCase] = {
    int(CKM_DES_CBC_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="DES_KEY_GEN",
        keygen_mech=CKM_DES_KEY_GEN,
        key_type=CKK_DES,
        mode="cbc",
        block_size=8,
        cbc_params_cls=CK_DES_CBC_ENCRYPT_DATA_PARAMS,
        key_size_bits=None,
    ),
    int(CKM_DES3_CBC_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="DES3_KEY_GEN",
        keygen_mech=CKM_DES3_KEY_GEN,
        key_type=CKK_DES3,
        mode="cbc",
        block_size=8,
        # PKCS#11 aliases the DES3 CBC-encrypt-data parameter type to the
        # same eight-byte CK_DES_CBC_ENCRYPT_DATA_PARAMS layout.
        cbc_params_cls=CK_DES_CBC_ENCRYPT_DATA_PARAMS,
        key_size_bits=None,
    ),
    int(CKM_CAMELLIA_ECB_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="CAMELLIA_KEY_GEN",
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_type=CKK_CAMELLIA,
        mode="ecb",
        block_size=16,
    ),
    int(CKM_CAMELLIA_CBC_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="CAMELLIA_KEY_GEN",
        keygen_mech=CKM_CAMELLIA_KEY_GEN,
        key_type=CKK_CAMELLIA,
        mode="cbc",
        block_size=16,
        cbc_params_cls=CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
    ),
    int(CKM_ARIA_ECB_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="ARIA_KEY_GEN",
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_type=CKK_ARIA,
        mode="ecb",
        block_size=16,
    ),
    int(CKM_ARIA_CBC_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="ARIA_KEY_GEN",
        keygen_mech=CKM_ARIA_KEY_GEN,
        key_type=CKK_ARIA,
        mode="cbc",
        block_size=16,
        cbc_params_cls=CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
    ),
    int(CKM_SEED_ECB_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="SEED_KEY_GEN",
        keygen_mech=CKM_SEED_KEY_GEN,
        key_type=CKK_SEED,
        mode="ecb",
        block_size=16,
        key_size_bits=None,
    ),
    int(CKM_SEED_CBC_ENCRYPT_DATA): _CipherEncryptDataDeriveCase(
        keygen_name="SEED_KEY_GEN",
        keygen_mech=CKM_SEED_KEY_GEN,
        key_type=CKK_SEED,
        mode="cbc",
        block_size=16,
        cbc_params_cls=CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
        key_size_bits=None,
    ),
}

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
    Some modules return CKR_TEMPLATE_INCONSISTENT for any other combination.
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
    expect_rv(rv, CKR_OK, context="HKDF base key gen")
    return handle.value


# Template for derived AES-128 key.
# CKA_CLASS is required by PKCS#11 spec for C_DeriveKey -- some modules
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
# CKA_CLASS is required by PKCS#11 spec for C_DeriveKey -- some modules
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

# CKM_HKDF_DATA produces a data object, not a secret-key object.  The output
# length is the SHA-256 digest length used by the generic HKDF probe.
_DERIVED_HKDF_DATA_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_DATA,
    CKA_VALUE_LEN: 32,
    CKA_TOKEN: False,
}

_HKDF_CREATE_REF = "PKCS#11 v3.2 · C_CreateObject"
_HKDF_READ_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


def _hkdf_provenance(
    *,
    producer_operation: str,
    producer_mechanism: str | None,
    consumer_operation: str,
    consumer_mechanism: str | None,
) -> dict[str, str | None]:
    """Describe the operation that produced a handle and its consumer."""
    return {
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
        "consumer_operation": consumer_operation,
        "consumer_mechanism": consumer_mechanism,
    }


def _claim_hkdf_refusal(
    exc: CkrAssertionError,
    rs: RawSession,
    *,
    probe_key: str,
    operation: str,
    mechanism: str | None,
    spec_ref: str,
    detail: dict[str, str | None],
) -> bool:
    """Apply the advertised-capability claim to one HKDF operation boundary.

    ``claim_refusal_passes`` owns the verdict (including the sanctioned
    ``CKR_OPERATION_NOT_VALIDATED`` pass).  Its generic record intentionally
    has no operation context, so attach the exact boundary metadata after it
    emits the record.  This also keeps a stale active mechanism from leaking
    into mechanism-free setup/readback records.
    """
    records_before = len(C.get_records())
    try:
        return claim_refusal_passes(exc, rs, probe_key=probe_key)
    finally:
        records = C.get_records()
        if len(records) > records_before:
            record = records[-1]
            record.operation = operation
            record.mechanism = mechanism
            record.spec_ref = spec_ref
            record.detail = detail


def _create_hkdf_data_base_key(rs: RawSession) -> int:
    """Create the CKK_GENERIC_SECRET input required by CKM_HKDF_DATA."""
    try:
        handle = import_secret_key_negotiated(
            rs,
            CKK_GENERIC_SECRET,
            bytes(range(32)),
            attrs={CKA_DERIVE: True, CKA_TOKEN: False, CKA_SENSITIVE: False},
            purpose="CKM_HKDF_DATA base-key provisioning",
        )
    except CkrAssertionError as exc:
        if exc.rv not in IMPORT_STORAGE_SHAPE_REJECTS:
            raise
        C.xfail_as(
            "not_operational",
            label="CKM_HKDF_DATA base-key provisioning",
            operation="C_CreateObject",
            mechanism=None,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            spec_ref=_HKDF_CREATE_REF,
            summary=(
                "CKM_HKDF_DATA base-key provisioning advertised but not operational "
                f"({ckr_name(exc.rv)})"
            ),
            detail=_hkdf_provenance(
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            ),
        )
    if handle == 0:
        C.fail_as(
            "self_contradiction",
            kind="lifecycle",
            label="CKM_HKDF_DATA base-key provisioning handle",
            operation="C_CreateObject",
            mechanism=None,
            inherit_mechanism=False,
            spec_ref=_HKDF_CREATE_REF,
            expected="non-zero object handle",
            actual=handle,
            summary="CKM_HKDF_DATA base-key provisioning returned a zero handle",
            detail=_hkdf_provenance(
                producer_operation="C_CreateObject",
                producer_mechanism=None,
                consumer_operation="C_DeriveKey",
                consumer_mechanism="CKM_HKDF_DATA",
            ),
        )
    return handle


def _record_hkdf_data_shape_failure(
    entry: MechEntry,
    *,
    attr: int,
    expected: object,
    actual: object,
    expected_shape: dict[str, Any],
) -> Any:
    """Record a malformed HKDF_DATA output attribute with producer detail."""
    attr_name = "CKA_CLASS" if attr == int(CKA_CLASS) else "CKA_VALUE"
    actual_length: int | None = len(actual) if isinstance(actual, Sized) else None
    record = C.record_as(
        "wrong_result",
        kind="metadata",
        label=f"{entry.mech_name}: derived {attr_name} readback",
        operation="C_GetAttributeValue",
        mechanism=None,
        spec_ref=_HKDF_READ_REF,
        inherit_mechanism=False,
        summary=(
            f"{entry.mech_name}: derived output {attr_name} does not match the HKDF_DATA contract"
        ),
        detail={
            "attribute": {"name": attr_name, "id": int(attr)},
            "expected": expected if attr == int(CKA_CLASS) else expected_shape,
            "actual": actual
            if attr == int(CKA_CLASS)
            else {
                "type": type(actual).__name__,
                "length": actual_length,
            },
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": entry.mech_name,
            "consumer_operation": "C_GetAttributeValue",
            "consumer_mechanism": None,
        },
    )
    return record


def _read_hkdf_data_attribute(
    attrs: dict[int, Any],
    attr: int,
    *,
    label: str,
) -> Any:
    """Read HKDF_DATA metadata and attach producer/consumer detail if absent."""
    value = attr_or_record(
        attrs,
        attr,
        label=label,
        reason="not_operational",
        kind="metadata",
        mechanism=None,
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        records = C.get_records()
        if records:
            detail = records[-1].detail
            if detail is None:
                detail = {}
                records[-1].detail = detail
            detail.update(
                _hkdf_provenance(
                    producer_operation="C_DeriveKey",
                    producer_mechanism="CKM_HKDF_DATA",
                    consumer_operation="C_GetAttributeValue",
                    consumer_mechanism=None,
                )
            )
    return value


def _derive_hkdf(rs: RawSession, entry: MechEntry) -> None:
    """Run the generic HKDF derive probe for secret-key and data outputs."""
    mech_id = entry.mech_id
    is_data = mech_id == _HKDF_DATA_ID
    base_key = 0
    if is_data:
        # The negotiated importer owns the narrow shape-refusal XFAIL/skip
        # policy.  Other C_CreateObject CKRs are setup failures, not a clean
        # refusal of the advertised derive operation, and must propagate.
        base_key = _create_hkdf_data_base_key(rs)
    else:
        if not rs.has_mechanism("HKDF_KEY_GEN"):
            pytest.skip("HKDF_KEY_GEN not available -- cannot generate HKDF base key")
        try:
            base_key = _gen_hkdf_base_key(rs)
        except CkrAssertionError as exc:
            if _claim_hkdf_refusal(
                exc,
                rs,
                probe_key=f"{entry.mech_name}:base-key",
                operation="C_GenerateKey",
                mechanism="CKM_HKDF_KEY_GEN",
                spec_ref="PKCS#11 v3.2 · C_GenerateKey · CKM_HKDF_KEY_GEN",
                detail=_hkdf_provenance(
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_HKDF_KEY_GEN",
                    consumer_operation="C_DeriveKey",
                    consumer_mechanism=entry.mech_name,
                ),
            ):
                return
    if base_key == 0:
        C.fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=f"{entry.mech_name}: base-key provisioning handle",
            operation="C_CreateObject" if is_data else "C_GenerateKey",
            mechanism=None if is_data else "CKM_HKDF_KEY_GEN",
            inherit_mechanism=False,
            spec_ref=(
                _HKDF_CREATE_REF if is_data else "PKCS#11 v3.2 · C_GenerateKey · CKM_HKDF_KEY_GEN"
            ),
            expected="non-zero object handle",
            actual=base_key,
            summary=f"{entry.mech_name}: base-key provisioning returned a zero handle",
            detail=_hkdf_provenance(
                producer_operation="C_CreateObject" if is_data else "C_GenerateKey",
                producer_mechanism=None if is_data else "CKM_HKDF_KEY_GEN",
                consumer_operation="C_DeriveKey",
                consumer_mechanism=entry.mech_name,
            ),
        )
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
        try:
            derived_key = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM(mech_id),
                attrs=_DERIVED_HKDF_DATA_ATTRS if is_data else _DERIVED_AES_ATTRS,
                mech_param=hkdf_param,
            )
        except CkrAssertionError as exc:
            if _claim_hkdf_refusal(
                exc,
                rs,
                probe_key=f"{entry.mech_name}:derive",
                operation="C_DeriveKey",
                mechanism=entry.mech_name,
                spec_ref=f"PKCS#11 v3.2 · C_DeriveKey · {entry.mech_name}",
                detail=_hkdf_provenance(
                    producer_operation="C_CreateObject" if is_data else "C_GenerateKey",
                    producer_mechanism=None if is_data else "CKM_HKDF_KEY_GEN",
                    consumer_operation="C_DeriveKey",
                    consumer_mechanism=entry.mech_name,
                ),
            ):
                return
        if derived_key == 0:
            if is_data:
                C.fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label=f"{entry.mech_name}: derive returned handle",
                    operation="C_DeriveKey",
                    mechanism=entry.mech_name,
                    spec_ref=f"PKCS#11 v3.2 · C_DeriveKey · {entry.mech_name}",
                    expected="non-zero object handle",
                    actual=derived_key,
                    summary=f"{entry.mech_name}: CKR_OK returned a zero derived-object handle",
                    detail=_hkdf_provenance(
                        producer_operation="C_DeriveKey",
                        producer_mechanism=entry.mech_name,
                        consumer_operation="C_GetAttributeValue",
                        consumer_mechanism=None,
                    ),
                )
            assert derived_key != 0, f"{entry.mech_name}: derive returned handle 0"
        if not is_data:
            return

        # ``read_attributes`` already preserves per-attribute refusal evidence
        # for C_GetAttributeValue.  This metadata read is not another advertised
        # mechanism claim: a call-level CKR (including
        # CKR_OPERATION_NOT_VALIDATED) must propagate as a hard readback error.
        attrs = read_attributes(rs.raw, rs.sh, derived_key, [CKA_CLASS, CKA_VALUE])

        object_class = _read_hkdf_data_attribute(
            attrs,
            CKA_CLASS,
            label=f"{entry.mech_name}: derived CKA_CLASS readback",
        )
        value = _read_hkdf_data_attribute(
            attrs,
            CKA_VALUE,
            label=f"{entry.mech_name}: derived CKA_VALUE readback",
        )
        malformed: list[Any] = []
        if object_class is not MISSING_ATTRIBUTE and (
            not isinstance(object_class, int)
            or isinstance(object_class, bool)
            or int(object_class) != int(CKO_DATA)
        ):
            malformed.append(
                _record_hkdf_data_shape_failure(
                    entry,
                    attr=int(CKA_CLASS),
                    expected=int(CKO_DATA),
                    actual=object_class,
                    expected_shape={"type": "int", "value": int(CKO_DATA)},
                )
            )
        if value is not MISSING_ATTRIBUTE and type(value) is not bytes:
            malformed.append(
                _record_hkdf_data_shape_failure(
                    entry,
                    attr=int(CKA_VALUE),
                    expected=bytes,
                    actual=value,
                    expected_shape={
                        "type": "bytes",
                        "length": _DERIVED_HKDF_DATA_ATTRS[CKA_VALUE_LEN],
                    },
                )
            )
        if value is not MISSING_ATTRIBUTE and type(value) is bytes:
            if len(value) != _DERIVED_HKDF_DATA_ATTRS[CKA_VALUE_LEN]:
                malformed.append(
                    _record_hkdf_data_shape_failure(
                        entry,
                        attr=int(CKA_VALUE),
                        expected=bytes,
                        actual=value,
                        expected_shape={
                            "type": "bytes",
                            "length": _DERIVED_HKDF_DATA_ATTRS[CKA_VALUE_LEN],
                        },
                    )
                )
        if malformed:
            C.raise_for_record(malformed[-1])
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

    priv_a, pub_a = 0, 0
    priv_b, pub_b = 0, 0
    derived_key: int = 0
    try:
        pub_a, priv_a = gen_ec_keypair(
            rs.raw, rs.sh, _P256_OID, private_attrs={CKA_DERIVE: True, CKA_TOKEN: False}
        )
        pub_b, priv_b = gen_ec_keypair(rs.raw, rs.sh, _P256_OID)
        peer = read_conventional_ec_point_or_xfail(
            rs,
            pub_b,
            ec.SECP256R1(),
            label=f"{entry.mech_name}: peer public key",
        )
        peer_point = select_ecdh_point_form(
            peer,
            supports_compressed=rs.has_mechanism_flag(mech_id, int(CKF_EC_COMPRESS)),
            supports_uncompressed=rs.has_mechanism_flag(mech_id, int(CKF_EC_UNCOMPRESS)),
        )
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


def _classify_base_keygen_refusal(exc: CkrAssertionError, keygen_mech: CKM) -> NoReturn:
    """Attribute a clean derive-base setup refusal to its actual keygen call."""
    mechanism_name = ckm_name(int(keygen_mech))
    C.xfail_as(
        "not_operational",
        label=f"{mechanism_name}: derive base-key setup",
        operation="C_GenerateKey",
        mechanism=mechanism_name,
        expected=CKR_OK,
        actual=exc.rv,
        summary=(
            f"{mechanism_name}: advertised base-key generation is not operational "
            f"({ckr_name(exc.rv)})"
        ),
    )


def _require_nonzero_base_handle(handle: int, keygen_mech: CKM) -> None:
    """Reject CKR_OK plus a zero base-key handle as a lifecycle contradiction."""
    if handle != 0:
        return
    mechanism_name = ckm_name(int(keygen_mech))
    C.fail_as(
        "self_contradiction",
        kind="lifecycle",
        label=f"{mechanism_name}: derive base-key handle",
        operation="C_GenerateKey",
        mechanism=mechanism_name,
        expected="non-zero object handle",
        actual=handle,
        summary=f"{mechanism_name}: CKR_OK returned a zero derive base-key handle",
    )


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
    try:
        expect_rv(rv, CKR_OK, context=f"DES{'3' if des3 else ''} base key gen")
    except CkrAssertionError as exc:
        _classify_base_keygen_refusal(exc, keygen_ckm)
    _require_nonzero_base_handle(handle.value, keygen_ckm)
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


def _gen_cipher_encrypt_data_base_key(
    rs: RawSession,
    case: _CipherEncryptDataDeriveCase,
) -> int:
    """Generate a regional cipher base key with CKA_DERIVE=True."""
    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: case.key_type,
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_EXTRACTABLE: True,
        CKA_SENSITIVE: False,
    }
    packed = []
    if case.key_size_bits is not None:
        packed.append(attr_ulong(CKA_VALUE_LEN, case.key_size_bits // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))
    tmpl = template(*packed)
    mech = mech_simple(case.keygen_mech)
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    try:
        expect_rv(rv, CKR_OK, context=f"{case.keygen_name} base key gen")
    except CkrAssertionError as exc:
        _classify_base_keygen_refusal(exc, case.keygen_mech)
    _require_nonzero_base_handle(handle.value, case.keygen_mech)
    return handle.value


def _mech_block_cbc_encrypt_data(
    mechanism_type: CKM | int,
    params_cls: type[Any],
    *,
    iv: bytes,
    data: bytes,
) -> PackedMechanism:
    """Pack a CK_*_CBC_ENCRYPT_DATA_PARAMS value for the cipher's block size."""
    params = params_cls()
    block_size = len(params.iv)
    if len(iv) != block_size:
        raise ValueError(f"CBC encrypt-data IV must be exactly {block_size} bytes")
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError(f"CBC encrypt-data input must be a non-empty {block_size}-byte multiple")
    for index, value in enumerate(iv):
        params.iv[index] = CK_BYTE(value)
    data_buf = (ctypes.c_ubyte * len(data))(*data)
    params.pData = ctypes.cast(data_buf, ctypes.c_void_p)
    params.length = len(data)

    pointer_arg = PointerArg.to_storage(params, origin="mech_block_cbc_encrypt_data")
    length_arg = LengthArg.native(ctypes.sizeof(params))
    result = PackedMechanism(
        CK_MECHANISM(mechanism_type, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    result._keepalive.append(data_buf)
    return result


def _check_cipher_derived_value_shape(
    rs: RawSession,
    handle: int,
    *,
    entry: MechEntry,
    expected_length: int,
) -> None:
    """Verify a successful encrypt-data derive exposes a correctly shaped value."""
    label = f"{entry.mech_name}: derived CKA_VALUE"
    value = attr_or_record(
        read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE]),
        CKA_VALUE,
        label=label,
        reason="not_operational",
        kind="metadata",
        mechanism=entry.mech_name,
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        return
    if type(value) is bytes and len(value) == expected_length:
        return
    try:
        actual_length: int | None = len(value)
    except TypeError:
        actual_length = None
    record = C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=entry.mech_name,
        summary=(f"{label}: provider returned malformed value; expected {expected_length} bytes"),
        detail={
            "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
            "expected": {"type": "bytes", "length": expected_length},
            "actual": {"type": type(value).__name__, "length": actual_length},
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": entry.mech_name,
        },
    )
    C.raise_for_record(record)


def _derive_cipher_encrypt_data(
    rs: RawSession,
    entry: MechEntry,
    case: _CipherEncryptDataDeriveCase,
) -> None:
    """Cipher ECB/CBC encrypt-data derive path with output-shape validation."""
    if not rs.has_mechanism(case.keygen_name):
        pytest.skip(f"{entry.mech_name}: {case.keygen_name} not available")

    mech_id = entry.mech_id
    base_key = _gen_cipher_encrypt_data_base_key(rs, case)
    derived_key: int = 0
    try:
        data = b"derive__test__01"
        if case.mode == "ecb":
            data_param = mech_string_data(CKM(mech_id), data)
        else:
            if case.cbc_params_cls is None:
                raise AssertionError(f"{entry.mech_name}: missing CBC parameter struct")
            data_param = _mech_block_cbc_encrypt_data(
                CKM(mech_id),
                case.cbc_params_cls,
                iv=bytes(range(case.block_size)),
                data=data,
            )
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            CKM(mech_id),
            attrs=_DERIVED_GENERIC_ATTRS,
            mech_param=data_param,
        )
        if derived_key == 0:
            C.classify(
                "self_contradiction",
                kind="lifecycle",
                label=f"{entry.mech_name}: derive returned handle",
                operation="C_DeriveKey",
                mechanism=entry.mech_name,
                expected="non-zero object handle",
                actual=derived_key,
                summary=f"{entry.mech_name}: CKR_OK returned a zero derived-key handle",
            )
        _check_cipher_derived_value_shape(
            rs,
            derived_key,
            entry=entry,
            expected_length=len(data),
        )
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
        before = len(C.get_records())
        obj_class_raw = attr_or_record(
            result,
            CKA_CLASS,
            # label already names the derive mechanism; this is a plain
            # C_GetAttributeValue readback, not the C_DeriveKey outcome (F6).
            label=f"{entry.mech_name}: derived object class",
            reason="not_operational",
            kind="metadata",
            inherit_mechanism=False,
        )
        if obj_class_raw is MISSING_ATTRIBUTE:
            records = C.get_records()
            if len(records) > before:
                C.raise_for_record(records[-1])
            C.fail_as(
                "harness_error",
                kind="metadata",
                label=f"{entry.mech_name}: derived object class",
                operation="C_GetAttributeValue",
                mechanism=entry.mech_name,
                summary=(
                    f"{entry.mech_name}: missing derived object class produced no classification"
                ),
            )
        if type(obj_class_raw) is not int or obj_class_raw != int(CKO_PUBLIC_KEY):
            record = C.record_as(
                "wrong_result",
                kind="metadata",
                label=f"{entry.mech_name}: derived object class",
                operation="C_GetAttributeValue",
                mechanism=entry.mech_name,
                detail={
                    "attribute": int(CKA_CLASS),
                    "expected": "strict int equal to CKO_PUBLIC_KEY",
                    "expected_value": int(CKO_PUBLIC_KEY),
                    "actual_type": type(obj_class_raw).__name__,
                    "actual": repr(obj_class_raw),
                    "producer_operation": "C_DeriveKey",
                    "producer_mechanism": entry.mech_name,
                },
                summary=(
                    f"{entry.mech_name}: derived object CKA_CLASS is malformed or wrong; "
                    f"expected strict int CKO_PUBLIC_KEY, got {obj_class_raw!r}"
                ),
            )
            C.raise_for_record(record)
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
        - HKDF_DATA: CK_HKDF_PARAMS, generic-secret base key and CKO_DATA output
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

        try:
            # Dispatch to per-family helpers
            if (_HKDF_DERIVE_ID and mech_id == _HKDF_DERIVE_ID) or (
                _HKDF_DATA_ID and mech_id == _HKDF_DATA_ID
            ):
                _derive_hkdf(rs, entry)
            elif mech_id in _ECDH1_MECH_IDS:
                _derive_ecdh(rs, entry)
            elif _AES_ECB_ENCRYPT_DATA_ID and mech_id == _AES_ECB_ENCRYPT_DATA_ID:
                _derive_aes_ecb(rs, entry)
            elif _DES_ECB_ENCRYPT_DATA_ID and mech_id == _DES_ECB_ENCRYPT_DATA_ID:
                _derive_des_ecb(rs, entry, des3=False)
            elif _DES3_ECB_ENCRYPT_DATA_ID and mech_id == _DES3_ECB_ENCRYPT_DATA_ID:
                _derive_des_ecb(rs, entry, des3=True)
            elif mech_id in _CIPHER_ENCRYPT_DATA_DERIVE_CASES:
                _derive_cipher_encrypt_data(
                    rs,
                    entry,
                    _CIPHER_ENCRYPT_DATA_DERIVE_CASES[mech_id],
                )
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
            # HKDF has separate setup, derive, and readback claim boundaries above.
            # Leave those exceptions untouched here so a setup/readback refusal
            # cannot be mislabeled as the C_DeriveKey claim.  Other dispatch
            # helpers retain the historical single-operation claim layer.
            if mech_id in {_HKDF_DERIVE_ID, _HKDF_DATA_ID}:
                raise
            if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:derive"):
                return
