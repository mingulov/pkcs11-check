"""ffi_length arm group: NULL / empty inner-mechanism-parameter probes.

Moved verbatim from ffi_length.py (god-module split, 2026-07-17); dispatched via
ffi_length._DISPATCH.  Output protocol unchanged (TARGET_RV/SETUP_XFAIL lines).
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, attr_ulong
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    gen_keypair,
    gen_rsa_keypair,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS,
    CK_AES_GCM_PARAMS,
    CK_ATTRIBUTE,
    CK_ECDH1_DERIVE_PARAMS,
    CK_EDDSA_PARAMS,
    CK_HKDF_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_SIGN_ADDITIONAL_CONTEXT,
    CK_SP800_108_KDF_PARAMS,
    CK_SSL3_RANDOM_DATA,
    CK_TLS_KDF_PARAMS,
    CK_ULONG,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_PARAMETER_SET,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKD_NULL,
    CKF_HKDF_SALT_DATA,
    CKF_HKDF_SALT_NULL,
    CKG_MGF1_SHA256,
    CKH_HEDGE_PREFERRED,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKM_AES_KEY_GEN,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_ECDH1_DERIVE,
    CKM_EDDSA,
    CKM_HKDF_DERIVE,
    CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SP800_108_COUNTER_KDF,
    CKM_TLS_KDF,
    CKP_ML_DSA_65,
    CKR_OK,
    CKZ_DATA_SPECIFIED,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _derived_secret_key_template,
    _import_generic_secret_derive_key,
    _setup_reject_or_raise,
)
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
)


def _run_generate_key_oom(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKey (AES) with a large-but-valid CKA_VALUE_LEN (checked-alloc guard)."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    value_len = int(extra["value_len"])

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_KEY_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    val_len = CK_ULONG(value_len)
    token_false = ctypes.c_ubyte(0)
    enc_true = ctypes.c_ubyte(1)

    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_VALUE_LEN
    attrs[0].pValue = ctypes.cast(ctypes.pointer(val_len), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(val_len)
    attrs[1].type = CKA_TOKEN
    attrs[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[1].ulValueLen = 1
    attrs[2].type = CKA_ENCRYPT
    attrs[2].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
    attrs[2].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(
        sh,
        ctypes.byref(mech),
        ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        3,
        ctypes.byref(key),
    )
    print(f"TARGET_RV:0x{rv:08x}")


def _run_gcm_null_iv(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit (AES-GCM) with pIv=NULL but ulIvLen=12, ulIvBits=96."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        params = CK_AES_GCM_PARAMS()
        params.pIv = None
        params.ulIvLen = 12
        params.ulIvBits = 96
        params.pAAD = None
        params.ulAADLen = 0
        params.ulTagBits = 128
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_ecdh_null_public_data(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey (ECDH1) with pPublicData=NULL but ulPublicDataLen=65."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    curve_oid = encode_named_curve_parameters("secp256r1")
    try:
        pub, priv = gen_ec_keypair(
            raw, sh, curve_oid, private_attrs={CKA_DERIVE: True, CKA_TOKEN: False}
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "EC keypair generation rejected")

    try:
        params = CK_ECDH1_DERIVE_PARAMS()
        params.kdf = CKD_NULL
        params.ulSharedDataLen = 0
        params.pSharedData = None
        params.ulPublicDataLen = 65
        params.pPublicData = None
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDH1_DERIVE
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_secret_key_template()
        derived = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            priv,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_oaep_null_source_data(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit (RSA-OAEP) with pSourceData=NULL but ulSourceDataLen=16."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_TOKEN: False},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected")

    try:
        params = CK_RSA_PKCS_OAEP_PARAMS()
        params.hashAlg = CKM_SHA256
        params.mgf = CKG_MGF1_SHA256
        params.source = CKZ_DATA_SPECIFIED
        params.pSourceData = None
        params.ulSourceDataLen = 16
        mech = CK_MECHANISM()
        mech.mechanism = CKM_RSA_PKCS_OAEP
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), pub)
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_hkdf_null_salt(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey (HKDF) with pSalt=NULL but ulSaltLen=16, ulSaltType=CKF_HKDF_SALT_DATA."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    base_key = _import_generic_secret_derive_key(ctx, value_len=32, reject_label="HKDF")
    try:
        info_data = (ctypes.c_ubyte * 4)(*b"test")
        params = CK_HKDF_PARAMS()
        params.bExtract = 1
        params.bExpand = 1
        params.prfHashMechanism = CKM_SHA256
        params.ulSaltType = CKF_HKDF_SALT_DATA
        params.pSalt = None
        params.ulSaltLen = 16
        params.hSaltKey = 0
        params.pInfo = ctypes.cast(info_data, ctypes.c_void_p)
        params.ulInfoLen = 4
        mech = CK_MECHANISM()
        mech.mechanism = CKM_HKDF_DERIVE
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_secret_key_template()
        derived = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_hkdf_null_info(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey (HKDF) with pInfo=NULL but ulInfoLen=16 (ulSaltType=CKF_HKDF_SALT_NULL)."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    base_key = _import_generic_secret_derive_key(ctx, value_len=32, reject_label="HKDF")
    try:
        params = CK_HKDF_PARAMS()
        params.bExtract = 1
        params.bExpand = 1
        params.prfHashMechanism = CKM_SHA256
        params.ulSaltType = CKF_HKDF_SALT_NULL
        params.pSalt = None
        params.ulSaltLen = 0
        params.hSaltKey = 0
        params.pInfo = None
        params.ulInfoLen = 16
        mech = CK_MECHANISM()
        mech.mechanism = CKM_HKDF_DERIVE
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_secret_key_template()
        derived = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_eddsa_null_context_data(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SignInit (EdDSA) with pContextData=NULL but ulContextDataLen=16."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    curve_oid = encode_named_curve_parameters("ed25519")
    try:
        pub, priv = gen_keypair(
            raw,
            sh,
            CKM_EC_EDWARDS_KEY_PAIR_GEN,
            pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
            priv_base=[],
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            pub_skip={CKA_EC_PARAMS},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(
            exc, KEYPAIR_RUNTIME_REJECT_RVS, "EC_EDWARDS keypair generation rejected"
        )

    try:
        params = CK_EDDSA_PARAMS()
        params.phFlag = 0
        params.ulContextDataLen = 16
        params.pContextData = None
        mech = CK_MECHANISM()
        mech.mechanism = CKM_EDDSA
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_mldsa_empty_context(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_VerifyInit/C_Verify (ML-DSA) with a non-NULL empty CK_SIGN_ADDITIONAL_CONTEXT.pContext."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    message = b"ML-DSA empty context pointer crash probe"
    try:
        pub, priv = gen_keypair(
            raw,
            sh,
            CKM_ML_DSA_KEY_PAIR_GEN,
            pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65)],
            priv_base=[],
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            pub_skip={CKA_PARAMETER_SET},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(
            exc, KEYPAIR_RUNTIME_REJECT_RVS, "ML-DSA keypair generation rejected"
        )

    try:
        sig = sign_single(raw, sh, priv, CKM_ML_DSA, message)

        context = (ctypes.c_ubyte * 0)()
        params = CK_SIGN_ADDITIONAL_CONTEXT()
        params.hedgeVariant = CKH_HEDGE_PREFERRED
        params.pContext = ctypes.cast(context, ctypes.c_void_p)
        params.ulContextLen = 0

        mech = CK_MECHANISM()
        mech.mechanism = CKM_ML_DSA
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
        print(f"init_rv={rv}")
        if rv == CKR_OK:
            data_buf = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
            sig_buf = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
            rv = raw.C_Verify(sh, data_buf, len(message), sig_buf, len(sig))
            print(f"verify_rv={rv}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_ccm_null_nonce(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit (AES-CCM) with pNonce=NULL but ulNonceLen=7."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        params = CK_AES_CCM_PARAMS()
        params.ulDataLen = 32
        params.pNonce = None
        params.ulNonceLen = 7
        params.pAAD = None
        params.ulAADLen = 0
        params.ulMACLen = 16
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_concat_base_data_null(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey (CONCATENATE_BASE_AND_DATA) with pData=NULL but ulLen=16."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    base_key = _import_generic_secret_derive_key(ctx, value_len=32, reject_label="CONCATENATE")
    try:
        params = CK_KEY_DERIVATION_STRING_DATA()
        params.pData = None
        params.ulLen = 16
        mech = CK_MECHANISM()
        mech.mechanism = CKM_CONCATENATE_BASE_AND_DATA
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_secret_key_template()
        derived = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_tls_kdf_null_label(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey (TLS_KDF) with pLabel=NULL but ulLabelLength=16."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    base_key = _import_generic_secret_derive_key(ctx, value_len=48, reject_label="TLS_KDF")
    try:
        client_random = (ctypes.c_ubyte * 32)(*range(32))
        server_random = (ctypes.c_ubyte * 32)(*range(32))
        random_info = CK_SSL3_RANDOM_DATA()
        random_info.pClientRandom = ctypes.cast(client_random, ctypes.c_void_p)
        random_info.ulClientRandomLen = 32
        random_info.pServerRandom = ctypes.cast(server_random, ctypes.c_void_p)
        random_info.ulServerRandomLen = 32

        params = CK_TLS_KDF_PARAMS()
        params.prfMechanism = CKM_SHA256
        params.pLabel = None
        params.ulLabelLength = 16
        params.RandomInfo = random_info
        params.pContextData = None
        params.ulContextDataLength = 0
        mech = CK_MECHANISM()
        mech.mechanism = CKM_TLS_KDF
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_secret_key_template()
        derived = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_sp800_108_null_data_params(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey (SP800-108 counter KDF) with pDataParams=NULL but ulNumberOfDataParams=1."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    base_key = _import_generic_secret_derive_key(ctx, value_len=32, reject_label="SP800-108")
    try:
        params = CK_SP800_108_KDF_PARAMS()
        params.prfType = CKM_SHA256_HMAC
        params.ulNumberOfDataParams = 1
        params.pDataParams = None
        params.ulAdditionalDerivedKeys = 0
        params.pAdditionalDerivedKeys = None
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SP800_108_COUNTER_KDF
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_secret_key_template()
        derived = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}")
    finally:
        destroy_quietly(raw, sh, base_key)


# ---------------------------------------------------------------------------
# Nested / mechanism-parameter length-boundary probes (Batch 4)
#
# These overflow a SCALAR or NESTED length/count field inside a mechanism-param
# struct (sLen, ulAADLen, PBKDF2 / PBE nested salt+password lengths, TLS-KDF
# random lengths, SP800-108 data-param / additional-derived-key counts).  Per
# docs/probe-soundness.md a scalar overflow is always sound; the AES-CBC and
# RSA-PSS probes pass tiny real buffers, while the AAD / KDF probes pair the
# oversized *claimed* length with a demand-zero honeypot exactly as the legacy
# children did (only where the legacy used ``_HONEYPOT_MMAP_CODE``).
#
# Additional dispatch keys (in addition to ``"probe"`` / ``"module_path"`` /
# ``"slot_id"``):
#   ``"aes_cbc_encrypt_data_malformed"`` -- ``case_label`` (str, echoed),
#       ``null_data`` (bool -- pData NULL vs tiny), ``data_len`` (int -- length).
#   ``"rsa_pss_salt_length"``            -- ``salt_len`` (int -- sLen).
#   ``"gcm_aad_length"`` / ``"ccm_aad_length"`` -- ``aad_len`` (int).
#   ``"pbkdf2_nested_length"``           -- ``field`` (password/salt/prf_data),
#       ``data_len`` (int).
#   ``"pbe_nested_length"``              -- ``mechanism`` (int CKM), ``key_type``
#       (int CKK), ``iv_len`` (int), ``sign_verify`` (bool), ``field``
#       (password/salt), ``data_len`` (int).
#   ``"tls_kdf_random_length"``          -- ``field`` (client/server),
#       ``data_len`` (int).
#   ``"sp800_108_data_param_count"`` / ``"sp800_108_additional_derived_key_count"``
#       -- ``data_len`` (int -- the overflowed count).
# ---------------------------------------------------------------------------
