"""Probe: arithmetic overflow probes for user-controlled size fields.

Ports the f-string child-script bodies from security/test_arithmetic_overflow.py
into dispatchable probe functions.  Output protocol lines are byte-identical to the
originals so the parent classifiers require no changes.

All probes run at Level.LOGIN.

Dispatch on params.extra["which"]:
  "data_length_overflow"               -- func, init_func, data_len
  "gcm_decrypt_update_accumulation"    -- (no extra params)
  "mechanism_param_length_overflow"    -- mech_name, real_size
  "gcm_tag_bits_overflow"              -- tag_bits
  "pss_salt_length_overflow"           -- salt_len
  "template_count_overflow"            -- op, count
  "template_count_overflow_valid_handles" -- op, count
  "derive_key_template_count_overflow" -- count
  "kem_template_count_overflow"        -- op, count
  "key_value_len_overflow"             -- mech_name
  "attribute_value_len_overflow"       -- op
  "generate_key_pair_count_overflow"   -- pub_count, priv_count

Output protocol (preserved verbatim for parent classifier):
  rv={integer}             -- C_* return value (most probes)
  CKR_UPDATE1:0x%08x       -- first C_DecryptUpdate rv (gcm_decrypt_update_accumulation)
  CKR_UPDATE2:0x%08x       -- second C_DecryptUpdate rv (if first was CKR_OK)
  SETUP_XFAIL:<reason>     -- setup rejected; parent xfails as not_operational
"""

from __future__ import annotations

import ctypes
from typing import Any

import pkcs11_check.raw.types_std as _types_std
from pkcs11_check.raw.recipes import destroy_quietly, encapsulate_key, gen_aes_key, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS,
    CK_ATTRIBUTE,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_ULONG,
    CKA_APPLICATION,
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_DERIVE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKP_ML_KEM_768,
    CKR_OK,
)
from pkcs11_check.testcases._probes.honeypot import HoneypotUnavailable, demand_zero_buffer
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
)
from pkcs11_check.testcases.security.conftest import child_setup_reject_known

# CK_ULONG-width max: 2^64-1 on LP64, 2^32-1 on Win64 LLP64.
_CK_ULONG_MAX: int = ctypes.c_ulong(-1).value

# 32-bit boundary constant used in the GCM accumulation probe.
_ULONG_32BIT_MAX = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _create_data_object(ctx: ProbeContext) -> int | None:
    """Create a session CKO_DATA object for template-count overflow probes.

    Returns the object handle on success.  On setup failure prints SETUP_XFAIL
    and returns None so the caller can return immediately.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh

    value = (ctypes.c_ubyte * 16)(*range(16))
    label = (ctypes.c_ubyte * 9)(*b"count-key")
    application = (ctypes.c_ubyte * 12)(*b"pkcs11-check")
    cls_val = CK_ULONG(CKO_DATA)
    token_false = ctypes.c_ubyte(0)

    base_tmpl = (CK_ATTRIBUTE * 5)()
    base_tmpl[0].type = CKA_CLASS
    base_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    base_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    base_tmpl[1].type = CKA_TOKEN
    base_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    base_tmpl[1].ulValueLen = 1
    base_tmpl[2].type = CKA_LABEL
    base_tmpl[2].pValue = ctypes.cast(label, ctypes.c_void_p)
    base_tmpl[2].ulValueLen = len(label)
    base_tmpl[3].type = CKA_APPLICATION
    base_tmpl[3].pValue = ctypes.cast(application, ctypes.c_void_p)
    base_tmpl[3].ulValueLen = len(application)
    base_tmpl[4].type = CKA_VALUE
    base_tmpl[4].pValue = ctypes.cast(value, ctypes.c_void_p)
    base_tmpl[4].ulValueLen = len(value)

    base_object = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(base_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(base_object),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:data-object import rejected: {ckr_name(rv)}", flush=True)
        return None
    return base_object.value


def _create_ml_kem_keypair(ctx: ProbeContext) -> tuple[int, int] | None:
    """Generate an ML-KEM-768 session keypair for KEM template-count overflow probes.

    Returns (pub_handle, priv_handle) on success.  On setup failure prints
    SETUP_XFAIL and returns None so the caller can return immediately.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh

    param_set = CK_ULONG(CKP_ML_KEM_768)
    pub_encapsulate = ctypes.c_ubyte(1)
    pub_token = ctypes.c_ubyte(0)
    priv_decapsulate = ctypes.c_ubyte(1)
    priv_token = ctypes.c_ubyte(0)
    priv_sensitive = ctypes.c_ubyte(0)
    priv_extractable = ctypes.c_ubyte(0)

    def _set_bool_attr(attr: CK_ATTRIBUTE, attr_type: int, value_ref: ctypes.c_ubyte) -> None:
        attr.type = attr_type
        attr.pValue = ctypes.cast(ctypes.pointer(value_ref), ctypes.c_void_p)
        attr.ulValueLen = 1

    def _set_ulong_attr(attr: CK_ATTRIBUTE, attr_type: int, value_ref: CK_ULONG) -> None:
        attr.type = attr_type
        attr.pValue = ctypes.cast(ctypes.pointer(value_ref), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(value_ref)

    pub_tmpl = (CK_ATTRIBUTE * 3)()
    _set_bool_attr(pub_tmpl[0], CKA_ENCAPSULATE, pub_encapsulate)
    _set_ulong_attr(pub_tmpl[1], CKA_PARAMETER_SET, param_set)
    _set_bool_attr(pub_tmpl[2], CKA_TOKEN, pub_token)

    priv_tmpl = (CK_ATTRIBUTE * 5)()
    _set_bool_attr(priv_tmpl[0], CKA_DECAPSULATE, priv_decapsulate)
    _set_ulong_attr(priv_tmpl[1], CKA_PARAMETER_SET, param_set)
    _set_bool_attr(priv_tmpl[2], CKA_TOKEN, priv_token)
    _set_bool_attr(priv_tmpl[3], CKA_SENSITIVE, priv_sensitive)
    _set_bool_attr(priv_tmpl[4], CKA_EXTRACTABLE, priv_extractable)

    keygen = CK_MECHANISM()
    keygen.mechanism = CKM_ML_KEM_KEY_PAIR_GEN
    keygen.pParameter = None
    keygen.ulParameterLen = 0
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        ctypes.byref(keygen),
        ctypes.cast(pub_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        3,
        ctypes.cast(priv_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(pub),
        ctypes.byref(priv),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:ML-KEM keypair generation rejected: {ckr_name(rv)}", flush=True)
        return None
    return pub.value, priv.value


# ---------------------------------------------------------------------------
# Probe functions
# ---------------------------------------------------------------------------


def _run_data_length_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Encrypt/C_Decrypt with a near-SIZE_MAX ulDataLen after AES-ECB Init.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    func: str = extra["func"]
    init_func: str = extra["init_func"]
    data_len: int = int(extra["data_len"])

    key = 0
    try:
        try:
            key = gen_aes_key(raw, sh, 256)
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
            ):
                return
            raise
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = getattr(raw, init_func)(sh, ctypes.byref(mech), key)
        if rv == CKR_OK:
            # Small real buffer, but claim huge length
            buf = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv2 = getattr(raw, func)(sh, buf, data_len, out_buf, ctypes.byref(out_len))
            print(f"rv={rv2}")
        else:
            print(f"rv={rv}")
    finally:
        if key:
            destroy_quietly(raw, sh, key)


def _run_gcm_decrypt_update_accumulation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-GCM C_DecryptUpdate two-call accumulation wrap probe.

    Prints ``CKR_UPDATE1:0x{rv:08x}`` and optionally ``CKR_UPDATE2:0x{rv:08x}``.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh

    key = 0
    try:
        try:
            key = gen_aes_key(raw, sh, 256)
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
            ):
                return
            raise

        try:
            honeypot_buf = demand_zero_buffer()
        except HoneypotUnavailable as exc:
            print(f"SETUP_XFAIL:{exc}", flush=True)
            return

        iv = (ctypes.c_ubyte * 12)(*range(12))
        params = CK_AES_GCM_PARAMS()
        params.pIv = ctypes.cast(iv, ctypes.c_void_p)
        params.ulIvLen = 12
        params.ulIvBits = 96
        params.pAAD = None
        params.ulAADLen = 0
        params.ulTagBits = 128
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        rv_init = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        if rv_init != CKR_OK:
            print(f"SETUP_XFAIL:C_DecryptInit rejected: {rv_init}")
            return

        # Honest buffer (docs/probe-soundness.md): the claimed 0xFFFFFFFF bytes are
        # backed by a demand-zero mmap, so a module that honors the length reads real
        # zeroed pages -- any crash that remains (e.g. the word32 encSz accumulator
        # wrapping on the second update -> under-alloc + over-write) is the module's
        # own bug, a real finding, not an over-read of our short buffer.
        out1 = (ctypes.c_ubyte * 32)()
        out1_len = CK_ULONG(32)
        rv1 = raw.C_DecryptUpdate(sh, honeypot_buf, _ULONG_32BIT_MAX, out1, ctypes.byref(out1_len))
        print(f"CKR_UPDATE1:0x{rv1:08x}")
        if rv1 == CKR_OK:
            # If the first update was accepted, attempt the wrap-triggering second
            # call only if the module allowed the first; a crash here IS the finding.
            buf2 = (ctypes.c_ubyte * 2)(*[0, 1])
            out2 = (ctypes.c_ubyte * 32)()
            out2_len = CK_ULONG(32)
            rv2 = raw.C_DecryptUpdate(sh, buf2, 2, out2, ctypes.byref(out2_len))
            print(f"CKR_UPDATE2:0x{rv2:08x}")
    finally:
        if key:
            destroy_quietly(raw, sh, key)


def _run_mechanism_param_length_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncryptInit with pParameter pointing to a small buffer but ulParameterLen=ULONG_MAX.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    mech_name: str = extra["mech_name"]  # e.g. "CKM_AES_CBC" or "CKM_AES_GCM"
    real_size: int = int(extra["real_size"])

    mech_id = getattr(_types_std, mech_name)

    key = 0
    try:
        try:
            key = gen_aes_key(raw, sh, 256)
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
            ):
                return
            raise
        param_buf = (ctypes.c_ubyte * real_size)(*range(real_size))
        mech = CK_MECHANISM()
        mech.mechanism = mech_id
        mech.pParameter = ctypes.cast(param_buf, ctypes.c_void_p)
        mech.ulParameterLen = _CK_ULONG_MAX  # Real buffer is only real_size bytes!
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"rv={rv}")
    finally:
        if key:
            destroy_quietly(raw, sh, key)


def _run_gcm_tag_bits_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """AES-GCM C_EncryptInit with extreme ulTagBits values.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    tag_bits: int = int(extra["tag_bits"])

    key = 0
    try:
        try:
            key = gen_aes_key(raw, sh, 256)
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
            ):
                return
            raise
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
        print(f"rv={rv}")
    finally:
        if key:
            destroy_quietly(raw, sh, key)


def _run_pss_salt_length_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """RSA-PSS C_SignInit with extreme sLen values.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    salt_len: int = int(extra["salt_len"])

    pub = 0
    priv = 0
    try:
        try:
            pub, priv = gen_rsa_keypair(
                raw,
                sh,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
        except AssertionError as exc:
            if child_setup_reject_known(
                exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected"
            ):
                return
            raise
        pss_params = CK_RSA_PKCS_PSS_PARAMS()
        pss_params.hashAlg = CKM_SHA256
        pss_params.mgf = CKG_MGF1_SHA256
        pss_params.sLen = salt_len
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS_PSS
        mech.pParameter = ctypes.cast(ctypes.pointer(pss_params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(pss_params)
        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        print(f"rv={rv}")
    finally:
        if pub:
            destroy_quietly(raw, sh, pub)
        if priv:
            destroy_quietly(raw, sh, priv)


def _run_template_count_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Template-accepting functions with a huge template count and 1 real CK_ATTRIBUTE.

    Dispatches on extra["op"]:
      C_CreateObject / C_GenerateKey / C_FindObjectsInit / C_SetAttributeValue -- no keygen
      C_UnwrapKey -- requires AES keygen setup inside the child

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    op: str = extra["op"]
    count: int = int(extra["count"])

    if op == "C_CreateObject":
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        cls_val = CK_ULONG(CKO_DATA)
        attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(cls_val)
        handle = CK_OBJECT_HANDLE(0)
        rv = raw.C_CreateObject(sh, ctypes.byref(attr), count, ctypes.byref(handle))
        print(f"rv={rv}")

    elif op == "C_GenerateKey":
        mech_gen = CK_MECHANISM()
        mech_gen.mechanism = getattr(_types_std, "CKM_AES_KEY_GEN")
        mech_gen.pParameter = None
        mech_gen.ulParameterLen = 0
        attr = CK_ATTRIBUTE()
        attr.type = CKA_VALUE_LEN
        vlen = CK_ULONG(32)
        attr.pValue = ctypes.cast(ctypes.pointer(vlen), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(vlen)
        key = CK_OBJECT_HANDLE(0)
        rv = raw.C_GenerateKey(
            sh, ctypes.byref(mech_gen), ctypes.byref(attr), count, ctypes.byref(key)
        )
        print(f"rv={rv}")

    elif op == "C_FindObjectsInit":
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        cls_val = CK_ULONG(CKO_DATA)
        attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(cls_val)
        rv = raw.C_FindObjectsInit(sh, ctypes.byref(attr), count)
        print(f"rv={rv}")

    elif op == "C_SetAttributeValue":
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        cls_val = CK_ULONG(CKO_DATA)
        attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(cls_val)
        # Use object handle 0 -- the huge count should be rejected first
        rv = raw.C_SetAttributeValue(sh, 0, ctypes.byref(attr), count)
        print(f"rv={rv}")

    elif op == "C_UnwrapKey":
        wrap_key = 0
        try:
            try:
                wrap_key = gen_aes_key(raw, sh, 256)
            except AssertionError as exc:
                if child_setup_reject_known(
                    exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
                ):
                    return
                raise
            attr = CK_ATTRIBUTE()
            attr.type = CKA_CLASS
            cls_val = CK_ULONG(CKO_SECRET_KEY)
            attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
            attr.ulValueLen = ctypes.sizeof(cls_val)
            mech_unwrap = CK_MECHANISM()
            mech_unwrap.mechanism = CKM_AES_ECB
            mech_unwrap.pParameter = None
            mech_unwrap.ulParameterLen = 0
            fake_wrapped = (ctypes.c_ubyte * 32)(*range(32))
            out_key = CK_OBJECT_HANDLE(0)
            rv = raw.C_UnwrapKey(
                sh,
                ctypes.byref(mech_unwrap),
                wrap_key,
                fake_wrapped,
                32,
                ctypes.byref(attr),
                count,
                ctypes.byref(out_key),
            )
            print(f"rv={rv}")
        finally:
            if wrap_key:
                destroy_quietly(raw, sh, wrap_key)

    else:
        raise ValueError(f"arithmetic_overflow template_count_overflow: unknown op {op!r}")


def _run_template_count_overflow_valid_handles(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Template-count overflow probes that reach a valid object-handle path.

    Creates a CKO_DATA object first, then probes with a huge template count.
    Prints ``rv={int}`` unconditionally (or SETUP_XFAIL if object creation fails).
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    op: str = extra["op"]
    count: int = int(extra["count"])

    base_object = _create_data_object(ctx)
    if base_object is None:
        return

    if op == "C_GetAttributeValue":
        try:
            out_class = CK_ULONG(0)
            attr = CK_ATTRIBUTE()
            attr.type = CKA_CLASS
            attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
            attr.ulValueLen = ctypes.sizeof(out_class)
            rv = raw.C_GetAttributeValue(sh, base_object, ctypes.byref(attr), count)
            print(f"rv={rv}")
        finally:
            destroy_quietly(raw, sh, base_object)

    elif op == "C_SetAttributeValue":
        try:
            label = (ctypes.c_ubyte * 8)(*b"countchk")
            attr = CK_ATTRIBUTE()
            attr.type = CKA_LABEL
            attr.pValue = ctypes.cast(label, ctypes.c_void_p)
            attr.ulValueLen = 8
            rv = raw.C_SetAttributeValue(sh, base_object, ctypes.byref(attr), count)
            print(f"rv={rv}")
        finally:
            destroy_quietly(raw, sh, base_object)

    elif op == "C_CopyObject":
        copy_object = CK_OBJECT_HANDLE(0)
        token_false = ctypes.c_ubyte(0)
        try:
            attr = CK_ATTRIBUTE()
            attr.type = CKA_TOKEN
            attr.pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
            attr.ulValueLen = 1
            rv = raw.C_CopyObject(
                sh,
                base_object,
                ctypes.byref(attr),
                count,
                ctypes.byref(copy_object),
            )
            print(f"rv={rv}")
        finally:
            if copy_object.value:
                destroy_quietly(raw, sh, copy_object.value)
            destroy_quietly(raw, sh, base_object)

    else:
        destroy_quietly(raw, sh, base_object)
        raise ValueError(
            f"arithmetic_overflow template_count_overflow_valid_handles: unknown op {op!r}"
        )


def _run_derive_key_template_count_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_DeriveKey with a huge derived-key template count and a valid base key.

    Prints ``rv={int}`` unconditionally (or SETUP_XFAIL if base-key import fails).
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    count: int = int(extra["count"])

    base_value = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    kt_val = CK_ULONG(CKK_GENERIC_SECRET)
    derive_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)

    base_tmpl = (CK_ATTRIBUTE * 5)()
    base_tmpl[0].type = CKA_CLASS
    base_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    base_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    base_tmpl[1].type = CKA_KEY_TYPE
    base_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    base_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
    base_tmpl[2].type = CKA_VALUE
    base_tmpl[2].pValue = ctypes.cast(base_value, ctypes.c_void_p)
    base_tmpl[2].ulValueLen = len(base_value)
    base_tmpl[3].type = CKA_DERIVE
    base_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
    base_tmpl[3].ulValueLen = 1
    base_tmpl[4].type = CKA_TOKEN
    base_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    base_tmpl[4].ulValueLen = 1

    base_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(base_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(base_key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:derive base-key import rejected: {ckr_name(rv)}")
        return

    derived = CK_OBJECT_HANDLE(0)
    try:
        data = (ctypes.c_ubyte * 16)(*range(16))
        str_params = CK_KEY_DERIVATION_STRING_DATA()
        str_params.pData = ctypes.cast(data, ctypes.c_void_p)
        str_params.ulLen = len(data)
        mech = CK_MECHANISM()
        mech.mechanism = CKM_CONCATENATE_BASE_AND_DATA
        mech.pParameter = ctypes.cast(ctypes.pointer(str_params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(str_params)

        out_class = CK_ULONG(CKO_SECRET_KEY)
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(out_class)

        rv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base_key.value,
            ctypes.byref(attr),
            count,
            ctypes.byref(derived),
        )
        print(f"rv={rv}")
    finally:
        if derived.value:
            destroy_quietly(raw, sh, derived.value)
        destroy_quietly(raw, sh, base_key.value)


def _run_kem_template_count_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_EncapsulateKey / C_DecapsulateKey with a huge output-template count.

    Prints ``rv={int}`` unconditionally (or SETUP_XFAIL if keypair gen fails).
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    op: str = extra["op"]
    count: int = int(extra["count"])

    keypair = _create_ml_kem_keypair(ctx)
    if keypair is None:
        return
    pub_h, priv_h = keypair

    if op == "C_EncapsulateKey":
        out_class = CK_ULONG(CKO_SECRET_KEY)
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
        attr.ulValueLen = ctypes.sizeof(out_class)

        mech = CK_MECHANISM()
        mech.mechanism = CKM_ML_KEM
        mech.pParameter = None
        mech.ulParameterLen = 0
        ct_len = CK_ULONG(0)
        secret = CK_OBJECT_HANDLE(0)
        try:
            rv = raw.C_EncapsulateKey(
                sh,
                ctypes.byref(mech),
                pub_h,
                ctypes.byref(attr),
                count,
                None,
                ctypes.byref(ct_len),
                ctypes.byref(secret),
            )
            print(f"rv={rv}")
        finally:
            if secret.value:
                destroy_quietly(raw, sh, secret.value)
            destroy_quietly(raw, sh, pub_h)
            destroy_quietly(raw, sh, priv_h)

    elif op == "C_DecapsulateKey":
        setup_secret = 0
        secret = CK_OBJECT_HANDLE(0)
        try:
            try:
                setup_secret, ciphertext = encapsulate_key(
                    raw,
                    sh,
                    pub_h,
                    CKM_ML_KEM,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_VALUE_LEN: 32,
                        CKA_TOKEN: False,
                    },
                )
            except AssertionError as exc:
                print(f"SETUP_XFAIL:ML-KEM encapsulate rejected: {exc}", flush=True)
                return

            out_class = CK_ULONG(CKO_SECRET_KEY)
            attr = CK_ATTRIBUTE()
            attr.type = CKA_CLASS
            attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
            attr.ulValueLen = ctypes.sizeof(out_class)

            mech = CK_MECHANISM()
            mech.mechanism = CKM_ML_KEM
            mech.pParameter = None
            mech.ulParameterLen = 0
            ct_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
            rv = raw.C_DecapsulateKey(
                sh,
                ctypes.byref(mech),
                priv_h,
                ctypes.byref(attr),
                count,
                ct_buf,
                len(ciphertext),
                ctypes.byref(secret),
            )
            print(f"rv={rv}")
        finally:
            if secret.value:
                destroy_quietly(raw, sh, secret.value)
            if setup_secret:
                destroy_quietly(raw, sh, setup_secret)
            destroy_quietly(raw, sh, pub_h)
            destroy_quietly(raw, sh, priv_h)

    else:
        destroy_quietly(raw, sh, pub_h)
        destroy_quietly(raw, sh, priv_h)
        raise ValueError(f"arithmetic_overflow kem_template_count_overflow: unknown op {op!r}")


def _run_key_value_len_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKey with CKA_VALUE_LEN = ULONG_MAX.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    mech_name: str = extra["mech_name"]  # e.g. "CKM_AES_KEY_GEN" or "CKM_DES3_KEY_GEN"

    mech_id = getattr(_types_std, mech_name)

    mech = CK_MECHANISM()
    mech.mechanism = mech_id
    mech.pParameter = None
    mech.ulParameterLen = 0

    val_len = CK_ULONG(_CK_ULONG_MAX)
    token_false = ctypes.c_ubyte(0)
    enc_true = ctypes.c_ubyte(1)

    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_VALUE_LEN
    attrs[0].pValue = ctypes.cast(ctypes.pointer(val_len), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(val_len)
    attrs[1].type = CKA_TOKEN
    attrs[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[1].ulValueLen = 1
    attrs[2].type = getattr(_types_std, "CKA_ENCRYPT")
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
    print(f"rv={rv}")


def _run_attribute_value_len_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Attribute functions with CK_ATTRIBUTE.ulValueLen = ULONG_MAX.

    Passes a CK_ATTRIBUTE whose pValue points to a small buffer but whose
    ulValueLen claims ULONG_MAX bytes.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    op: str = extra["op"]

    if op == "C_GetAttributeValue":
        buf = (ctypes.c_ubyte * 8)()
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
        attr.ulValueLen = _CK_ULONG_MAX
        # Object handle 0 -- module may reject handle before reading attr
        rv = raw.C_GetAttributeValue(sh, 0, ctypes.pointer(attr), 1)
        print(f"rv={rv}")

    elif op == "C_SetAttributeValue":
        buf = (ctypes.c_ubyte * 8)()
        attr = CK_ATTRIBUTE()
        attr.type = CKA_TOKEN
        attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
        attr.ulValueLen = _CK_ULONG_MAX
        rv = raw.C_SetAttributeValue(sh, 0, ctypes.pointer(attr), 1)
        print(f"rv={rv}")

    elif op == "C_CreateObject":
        buf = (ctypes.c_ubyte * 8)()
        attr = CK_ATTRIBUTE()
        attr.type = CKA_CLASS
        attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
        attr.ulValueLen = _CK_ULONG_MAX
        handle = CK_OBJECT_HANDLE(0)
        rv = raw.C_CreateObject(sh, ctypes.pointer(attr), 1, ctypes.byref(handle))
        print(f"rv={rv}")

    else:
        raise ValueError(f"arithmetic_overflow attribute_value_len_overflow: unknown op {op!r}")


def _run_generate_key_pair_count_overflow(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKeyPair with ULONG_MAX template count for the pub or priv template.

    Prints ``rv={int}`` unconditionally.
    """
    raw = ctx.raw
    assert ctx.sh is not None
    sh: int = ctx.sh
    pub_count: int = int(extra["pub_count"])
    priv_count: int = int(extra["priv_count"])

    mech = CK_MECHANISM()
    mech.mechanism = getattr(_types_std, "CKM_RSA_PKCS_KEY_PAIR_GEN")
    mech.pParameter = None
    mech.ulParameterLen = 0

    # 1 real attribute in each template
    token_false = ctypes.c_ubyte(0)

    pub_attr = CK_ATTRIBUTE()
    pub_attr.type = CKA_TOKEN
    pub_attr.pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    pub_attr.ulValueLen = 1

    priv_token = ctypes.c_ubyte(0)
    priv_attr = CK_ATTRIBUTE()
    priv_attr.type = CKA_TOKEN
    priv_attr.pValue = ctypes.cast(ctypes.pointer(priv_token), ctypes.c_void_p)
    priv_attr.ulValueLen = 1

    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        ctypes.byref(mech),
        ctypes.byref(pub_attr),
        pub_count,
        ctypes.byref(priv_attr),
        priv_count,
        ctypes.byref(pub_h),
        ctypes.byref(priv_h),
    )
    print(f"rv={rv}")


# ---------------------------------------------------------------------------
# Dispatch table and entry point
# ---------------------------------------------------------------------------

_DISPATCH = {
    "data_length_overflow": _run_data_length_overflow,
    "gcm_decrypt_update_accumulation": _run_gcm_decrypt_update_accumulation,
    "mechanism_param_length_overflow": _run_mechanism_param_length_overflow,
    "gcm_tag_bits_overflow": _run_gcm_tag_bits_overflow,
    "pss_salt_length_overflow": _run_pss_salt_length_overflow,
    "template_count_overflow": _run_template_count_overflow,
    "template_count_overflow_valid_handles": _run_template_count_overflow_valid_handles,
    "derive_key_template_count_overflow": _run_derive_key_template_count_overflow,
    "kem_template_count_overflow": _run_kem_template_count_overflow,
    "key_value_len_overflow": _run_key_value_len_overflow,
    "attribute_value_len_overflow": _run_attribute_value_len_overflow,
    "generate_key_pair_count_overflow": _run_generate_key_pair_count_overflow,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which: str = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"arithmetic_overflow probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
