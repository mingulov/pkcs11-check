"""ffi_length arm group: length-field boundary probes inside mechanism params.

Moved verbatim from ffi_length.py (god-module split, 2026-07-17); dispatched via
ffi_length._DISPATCH.  Output protocol unchanged (TARGET_RV/SETUP_XFAIL lines).
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_keypair,
    gen_rsa_keypair,
    import_secret_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    CK_AES_CCM_PARAMS,
    CK_AES_GCM_PARAMS,
    CK_ATTRIBUTE,
    CK_EDDSA_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PBE_PARAMS,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_PRF_DATA_PARAM,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_SP800_108_BYTE_ARRAY,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_DKM_LENGTH,
    CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_KDF_PARAMS,
    CK_SSL3_RANDOM_DATA,
    CK_TLS_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_CBC_ENCRYPT_DATA,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EDDSA,
    CKM_PKCS5_PBKD2,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SP800_108_COUNTER_KDF,
    CKM_TLS_KDF,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKR_OK,
    CKZ_DATA_SPECIFIED,
    CKZ_SALT_SPECIFIED,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _derived_aes_key_template,
    _derived_secret_key_template,
    _import_derive_base_key,
    _setup_reject_or_raise,
    _SetupRejected,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
)


def _run_aes_cbc_encrypt_data_malformed(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey(AES_CBC_ENCRYPT_DATA) with a malformed nested pData/length pair."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    case_label = extra["case_label"]
    null_data = bool(extra["null_data"])
    data_len = int(extra["data_len"])

    data_buf = (ctypes.c_ubyte * 16)(*range(16))
    try:
        base_key = import_secret_key(
            raw,
            sh,
            CKK_AES,
            bytes(range(32)),
            attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        print(f"{SETUP_XFAIL_PREFIX}AES derive base-key import rejected: {exc}")
        raise _SetupRejected from exc

    try:
        params = CK_AES_CBC_ENCRYPT_DATA_PARAMS()
        for idx in range(16):
            params.iv[idx] = idx
        params.pData = None if null_data else ctypes.cast(data_buf, ctypes.c_void_p)
        params.length = data_len

        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CBC_ENCRYPT_DATA
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        derived_template = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        derived = CK_OBJECT_HANDLE(0)
        print(f"TARGET_CALL:C_DeriveKey(AES_CBC_ENCRYPT_DATA,{case_label})", flush=True)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            derived_template.ptr,
            derived_template.count,
            ctypes.byref(derived),
        )
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
        if rv == CKR_OK:
            destroy_quietly(raw, sh, derived.value)
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_rsa_pss_salt_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Sign(SHA256_RSA_PKCS_PSS) with an isize-boundary sLen (salt length)."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    salt_len = int(extra["salt_len"])

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        _setup_reject_or_raise(exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected")

    try:
        params = CK_RSA_PKCS_PSS_PARAMS()
        params.hashAlg = CKM_SHA256
        params.mgf = CKG_MGF1_SHA256
        params.sLen = salt_len

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS_PSS
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            data = (ctypes.c_ubyte * 16)(*range(16))
            sig_len = CK_ULONG(512)
            sig_buf = (ctypes.c_ubyte * 512)()
            print(f"TARGET_CALL:C_Sign(SHA256_RSA_PKCS_PSS,sLen={salt_len:#x})", flush=True)
            rv = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_gcm_aad_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(AES_GCM) with a tiny (honeypot) pAAD + huge ulAADLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    aad_len = int(extra["aad_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        iv = (ctypes.c_ubyte * 12)(*range(12))
        params = CK_AES_GCM_PARAMS()
        params.pIv = ctypes.cast(iv, ctypes.c_void_p)
        params.ulIvLen = 12
        params.ulIvBits = 96
        params.pAAD = ctypes.cast(buf, ctypes.c_void_p)
        params.ulAADLen = aad_len
        params.ulTagBits = 128
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(64)
            out = (ctypes.c_ubyte * 64)()
            print(f"TARGET_CALL:C_Encrypt(AES_GCM,ulAADLen={aad_len:#x})", flush=True)
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_ccm_aad_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(AES_CCM) with a tiny (honeypot) pAAD + huge ulAADLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    aad_len = int(extra["aad_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        nonce = (ctypes.c_ubyte * 13)(*range(13))
        params = CK_AES_CCM_PARAMS()
        params.ulDataLen = 16
        params.pNonce = ctypes.cast(nonce, ctypes.c_void_p)
        params.ulNonceLen = 13
        params.pAAD = ctypes.cast(buf, ctypes.c_void_p)
        params.ulAADLen = aad_len
        params.ulMACLen = 16
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(64)
            out = (ctypes.c_ubyte * 64)()
            print(f"TARGET_CALL:C_Encrypt(AES_CCM,ulAADLen={aad_len:#x})", flush=True)
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_pbkdf2_nested_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKey(PBKDF2) with an oversized nested password/salt/prf-data length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    field = extra["field"]
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    password_real = (ctypes.c_ubyte * 8)(*b"password")
    salt_real = (ctypes.c_ubyte * 8)(*b"salt1234")

    params = CK_PKCS5_PBKD2_PARAMS2()
    params.saltSource = CKZ_SALT_SPECIFIED
    salt_buf = buf if field == "salt" else salt_real
    params.pSaltSourceData = ctypes.cast(salt_buf, ctypes.c_void_p)
    params.ulSaltSourceDataLen = data_len if field == "salt" else len(salt_real)
    params.iterations = 1024
    params.prf = CKP_PKCS5_PBKD2_HMAC_SHA256
    if field == "prf_data":
        params.pPrfData = ctypes.cast(buf, ctypes.c_void_p)
        params.ulPrfDataLen = data_len
    else:
        params.pPrfData = None
        params.ulPrfDataLen = 0
    pw_buf = buf if field == "password" else password_real
    params.pPassword = ctypes.cast(pw_buf, ctypes.c_void_p)
    params.ulPasswordLen = data_len if field == "password" else len(password_real)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_PKCS5_PBKD2
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    tmpl = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
    )
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, ctypes.byref(mech), tmpl.ptr, tmpl.count, ctypes.byref(key))
    print(f"TARGET_RV:0x{rv:08x}")
    print(f"TARGET_RV_NAME:{ckr_name(rv)}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, key.value)


def _run_pbe_nested_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKey(PBE) with an oversized nested password/salt length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    mechanism = int(extra["mechanism"])
    key_type = int(extra["key_type"])
    iv_len = int(extra["iv_len"])
    sign_verify = bool(extra["sign_verify"])
    field = extra["field"]
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    init_vector = (ctypes.c_ubyte * iv_len)()
    password_real = (ctypes.c_ubyte * 8)(*b"password")
    salt_real = (ctypes.c_ubyte * 8)(*b"salt1234")

    params = CK_PBE_PARAMS()
    params.pInitVector = ctypes.cast(init_vector, ctypes.c_void_p)
    pw_buf = buf if field == "password" else password_real
    params.pPassword = ctypes.cast(pw_buf, ctypes.c_void_p)
    params.ulPasswordLen = data_len if field == "password" else len(password_real)
    salt_buf = buf if field == "salt" else salt_real
    params.pSalt = ctypes.cast(salt_buf, ctypes.c_void_p)
    params.ulSaltLen = data_len if field == "salt" else len(salt_real)
    params.ulIteration = 1024

    mech = CK_MECHANISM()
    mech.mechanism = mechanism
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    tmpl = template(
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_SIGN if sign_verify else CKA_ENCRYPT, True),
        attr_bool(CKA_VERIFY if sign_verify else CKA_DECRYPT, True),
    )
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, ctypes.byref(mech), tmpl.ptr, tmpl.count, ctypes.byref(key))
    print(f"TARGET_RV:0x{rv:08x}")
    print(f"TARGET_RV_NAME:{ckr_name(rv)}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, key.value)


def _run_tls_kdf_random_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey(TLS_KDF) with an oversized nested client/server random length."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    field = extra["field"]
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    base_key = _import_derive_base_key(ctx, value_len=48, label="TLS KDF")
    try:
        label = (ctypes.c_ubyte * 12)(*b"test label!!")
        client_random_real = (ctypes.c_ubyte * 32)(*range(32))
        server_random_real = (ctypes.c_ubyte * 32)(*range(32))

        random_info = CK_SSL3_RANDOM_DATA()
        random_info.pClientRandom = ctypes.cast(
            buf if field == "client" else client_random_real, ctypes.c_void_p
        )
        random_info.ulClientRandomLen = data_len if field == "client" else 32
        random_info.pServerRandom = ctypes.cast(
            buf if field == "server" else server_random_real, ctypes.c_void_p
        )
        random_info.ulServerRandomLen = data_len if field == "server" else 32

        params = CK_TLS_KDF_PARAMS()
        params.prfMechanism = CKM_SHA256
        params.pLabel = ctypes.cast(label, ctypes.c_void_p)
        params.ulLabelLength = len(label)
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
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        if rv == CKR_OK:
            destroy_quietly(raw, sh, derived.value)
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_sp800_108_data_param_count(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey(SP800_108_COUNTER_KDF) with an oversized ulNumberOfDataParams."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    base_key = _import_derive_base_key(ctx, value_len=32, label="SP800-108")
    try:
        params = CK_SP800_108_KDF_PARAMS()
        params.prfType = CKM_SHA256_HMAC
        params.ulNumberOfDataParams = data_len
        params.pDataParams = ctypes.cast(buf, ctypes.c_void_p)
        params.ulAdditionalDerivedKeys = 0
        params.pAdditionalDerivedKeys = None

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SP800_108_COUNTER_KDF
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_aes_key_template()
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
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        if rv == CKR_OK:
            destroy_quietly(raw, sh, derived.value)
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_sp800_108_additional_derived_key_count(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey(SP800_108_COUNTER_KDF) with an oversized ulAdditionalDerivedKeys."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    base_key = _import_derive_base_key(ctx, value_len=32, label="SP800-108")
    try:
        counter = CK_SP800_108_COUNTER_FORMAT()
        counter.bLittleEndian = 0
        counter.ulWidthInBits = 32
        label = (ctypes.c_ubyte * 12)(*b"hardening-1")
        context = (ctypes.c_ubyte * 12)(*b"hardening-2")
        dkm = CK_SP800_108_DKM_LENGTH_FORMAT()
        dkm.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
        dkm.bLittleEndian = 0
        dkm.ulWidthInBits = 32

        data_params = (CK_PRF_DATA_PARAM * 4)()
        data_params[0].type = CK_SP800_108_ITERATION_VARIABLE
        data_params[0].pValue = ctypes.cast(ctypes.pointer(counter), ctypes.c_void_p)
        data_params[0].ulValueLen = ctypes.sizeof(counter)
        data_params[1].type = CK_SP800_108_BYTE_ARRAY
        data_params[1].pValue = ctypes.cast(label, ctypes.c_void_p)
        data_params[1].ulValueLen = len(label)
        data_params[2].type = CK_SP800_108_BYTE_ARRAY
        data_params[2].pValue = ctypes.cast(context, ctypes.c_void_p)
        data_params[2].ulValueLen = len(context)
        data_params[3].type = CK_SP800_108_DKM_LENGTH
        data_params[3].pValue = ctypes.cast(ctypes.pointer(dkm), ctypes.c_void_p)
        data_params[3].ulValueLen = ctypes.sizeof(dkm)

        params = CK_SP800_108_KDF_PARAMS()
        params.prfType = CKM_SHA256_HMAC
        params.ulNumberOfDataParams = 4
        params.pDataParams = ctypes.cast(data_params, ctypes.c_void_p)
        params.ulAdditionalDerivedKeys = data_len
        params.pAdditionalDerivedKeys = ctypes.cast(buf, ctypes.c_void_p)

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SP800_108_COUNTER_KDF
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)

        d_tmpl, _keepalive = _derived_aes_key_template()
        primary = CK_OBJECT_HANDLE(0)
        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            4,
            ctypes.byref(primary),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        if rv == CKR_OK:
            destroy_quietly(raw, sh, primary.value)
    finally:
        destroy_quietly(raw, sh, base_key)


# ---------------------------------------------------------------------------
# Mechanism-parameter length-boundary probes (Batch 5, gated @requires_64bit_ck_ulong)
#
# These overflow a buffer-length or a scalar-length field inside a mechanism-param
# struct (RSA-OAEP source-data len, AES-GCM IV len / tag bits, AES-CCM nonce len /
# MAC len, EdDSA context len).  Per docs/probe-soundness.md the buffer-length probes
# back the oversized *claimed* length with a demand-zero honeypot exactly as the
# legacy children did; the scalar overflows (ulTagBits, ulMACLen) pass a tiny real
# buffer and need no honeypot.  Output protocol is preserved verbatim for the parent
# classifier _classify_unhonorable_length_outcome.
#
# Additional dispatch keys (in addition to "probe" / "module_path" / "slot_id"):
#   "rsa_oaep_source_data_length" -- "data_len"  (int; honeypot pSourceData).
#   "gcm_iv_length"               -- "iv_len"    (int; honeypot pIv).
#   "gcm_tag_bits_length"         -- "tag_bits"  (int; scalar ulTagBits).
#   "ccm_nonce_length"            -- "nonce_len" (int; honeypot pNonce).
#   "ccm_mac_length"              -- "mac_len"   (int; scalar ulMACLen).
#   "eddsa_context_length"        -- "ctx_len"   (int; honeypot pContextData).
#
# Output-guard / continuation probes (Batch 5, NOT gated).  These give a
# deliberately-small (1-byte) output buffer or exercise the NULL-output size query
# and verify the module honours the buffer-size query without overrunning a guard
# region or terminating the operation.  They take no "extra" values and preserve
# their own printed protocol (INIT_RV / QUERY_RV / NEEDED / FINAL_RV / LEN /
# OVERWRITTEN / GUARD_OVERWRITE / UPDATE_RV / CONTINUATION_RV / TARGET_RV):
#   "encrypt_update_guard" / "decrypt_update_guard"
#   "encrypt_update_continuation" / "decrypt_update_continuation"
#   "encrypt_final_continuation" / "decrypt_final_continuation"
#   "encrypt_single_shot_guard" / "decrypt_single_shot_guard"
# ---------------------------------------------------------------------------


def _run_rsa_oaep_source_data_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(RSA_PKCS_OAEP) with honeypot pSourceData + huge ulSourceDataLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    data_len = int(extra["data_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

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
        params.pSourceData = ctypes.cast(buf, ctypes.c_void_p)
        params.ulSourceDataLen = data_len
        mech = CK_MECHANISM()
        mech.mechanism = CKM_RSA_PKCS_OAEP
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), pub)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(512)
            out = (ctypes.c_ubyte * 512)()
            print(
                f"TARGET_CALL:C_Encrypt(RSA_PKCS_OAEP,ulSourceDataLen={data_len:#x})",
                flush=True,
            )
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_gcm_iv_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(AES_GCM) with honeypot pIv + huge ulIvLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    iv_len = int(extra["iv_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        params = CK_AES_GCM_PARAMS()
        params.pIv = ctypes.cast(buf, ctypes.c_void_p)
        params.ulIvLen = iv_len
        params.ulIvBits = 96
        params.pAAD = None
        params.ulAADLen = 0
        params.ulTagBits = 128
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(64)
            out = (ctypes.c_ubyte * 64)()
            print(f"TARGET_CALL:C_Encrypt(AES_GCM,ulIvLen={iv_len:#x})", flush=True)
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_gcm_tag_bits_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(AES_GCM) with an impossible scalar ulTagBits."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    tag_bits = int(extra["tag_bits"])

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        iv = (ctypes.c_ubyte * 12)(*range(12))
        params = CK_AES_GCM_PARAMS()
        params.pIv = ctypes.cast(iv, ctypes.c_void_p)
        params.ulIvLen = 12
        params.ulIvBits = 96
        params.pAAD = None
        params.ulAADLen = 0
        params.ulTagBits = tag_bits
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(64)
            out = (ctypes.c_ubyte * 64)()
            print(f"TARGET_CALL:C_Encrypt(AES_GCM,ulTagBits={tag_bits:#x})", flush=True)
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_ccm_nonce_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(AES_CCM) with honeypot pNonce + huge ulNonceLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    nonce_len = int(extra["nonce_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        params = CK_AES_CCM_PARAMS()
        params.ulDataLen = 16
        params.pNonce = ctypes.cast(buf, ctypes.c_void_p)
        params.ulNonceLen = nonce_len
        params.pAAD = None
        params.ulAADLen = 0
        params.ulMACLen = 16
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(64)
            out = (ctypes.c_ubyte * 64)()
            print(f"TARGET_CALL:C_Encrypt(AES_CCM,ulNonceLen={nonce_len:#x})", flush=True)
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_ccm_mac_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit/C_Encrypt(AES_CCM) with an impossible scalar ulMACLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    mac_len = int(extra["mac_len"])

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        nonce = (ctypes.c_ubyte * 13)(*range(13))
        params = CK_AES_CCM_PARAMS()
        params.ulDataLen = 16
        params.pNonce = ctypes.cast(nonce, ctypes.c_void_p)
        params.ulNonceLen = 13
        params.pAAD = None
        params.ulAADLen = 0
        params.ulMACLen = mac_len
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_CCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            pt = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(64)
            out = (ctypes.c_ubyte * 64)()
            print(f"TARGET_CALL:C_Encrypt(AES_CCM,ulMACLen={mac_len:#x})", flush=True)
            rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_eddsa_context_length(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SignInit/C_Sign(EDDSA) with honeypot pContextData + huge ulContextDataLen."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw
    ctx_len = int(extra["ctx_len"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

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
        params.pContextData = ctypes.cast(buf, ctypes.c_void_p)
        params.ulContextDataLen = ctx_len
        mech = CK_MECHANISM()
        mech.mechanism = CKM_EDDSA
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            msg = (ctypes.c_ubyte * 16)(*range(16))
            sig_len = CK_ULONG(128)
            sig = (ctypes.c_ubyte * 128)()
            print(f"TARGET_CALL:C_Sign(EDDSA,ulContextDataLen={ctx_len:#x})", flush=True)
            rv = raw.C_Sign(sh, msg, 16, sig, ctypes.byref(sig_len))
        print(f"TARGET_RV:0x{rv:08x}", flush=True)
        print(f"TARGET_RV_NAME:{ckr_name(rv)}", flush=True)
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


# ---------------------------------------------------------------------------
# Output-guard + continuation probes (Batch 5; small 1-byte output buffer or
# NULL-output size-query continuation).  AES-ECB throughout; no honeypot.
# ---------------------------------------------------------------------------
