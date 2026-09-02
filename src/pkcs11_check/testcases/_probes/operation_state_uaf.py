"""Probe: operation-state use-after-free (C_DestroyObject mid-operation, crash safety).

Ports the f-string child-script bodies from security/test_operation_state_uaf.py
(Batch A: Sign / AES-Encrypt / AES-Decrypt / Digest / Verify) into dispatchable
probe functions.  Each probe creates a key, starts an operation, destroys the key
while the operation is active, then completes the operation on possibly-freed
state.  A conformant module either refuses the destroy, returns a clean error, or
(snapshot-based) completes normally -- the one hard requirement is no crash.

Output protocol lines (``DESTROY_RV:0x...``, ``SIGN_RV:0x...``, ``ENCRYPT_RV:0x...``,
``EXPECTED:<hex>``, ``ENCRYPT_CT:<hex>``, ``SETUP_XFAIL:...`` etc.) are byte-identical
to the original generated scripts so the parent (assert_subprocess_no_crash +
classify_negative_rv + the ciphertext oracle) requires no changes.

All probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"sign"``        -- CKM_SHA256_HMAC key destroyed between C_SignInit and C_Sign.
  ``"aes_encrypt"`` -- AES key destroyed between C_EncryptInit and C_Encrypt, with a
                       live-key ciphertext oracle.  Extra key: ``ckm`` (one of
                       ``"CKM_AES_ECB"`` / ``"CKM_AES_CBC"`` / ``"CKM_AES_CTR"`` /
                       ``"CKM_AES_GCM"``).
  ``"aes_decrypt"`` -- AES key destroyed between C_DecryptInit and C_Decrypt.  Extra
                       key: ``ckm`` (as above).
  ``"digest"``      -- C_DigestInit(CKM_SHA256) then C_DigestKey on a destroyed handle.
  ``"verify"``      -- CKM_SHA256_HMAC key destroyed between C_VerifyInit and C_Verify.
  ``"derive"``      -- EC base private key destroyed before C_DeriveKey(CKM_ECDH1_DERIVE).
  ``"cross_session"`` -- token HMAC key sign-inited in session A, destroyed from session B,
                       then C_Sign completed in session A (CWE-416 across sessions).
  ``"ecdsa_sign"``  -- EC private key destroyed between C_SignInit(CKM_ECDSA) and C_Sign.
  ``"rsa_decrypt"`` -- RSA private key destroyed between C_DecryptInit(CKM_RSA_PKCS) and
                       C_Decrypt (invalid 256-zero-byte ciphertext; clean error acceptable).
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack_mechanisms import mech_ecdh
from pkcs11_check.raw.recipes import (
    RSAUsage,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CTR_PARAMS,
    CK_AES_GCM_PARAMS,
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_NOTIFY,
    CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKD_NULL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_GENERIC_SECRET,
    CKM_AES_CBC,
    CKM_AES_CTR,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_ECDH1_DERIVE,
    CKM_ECDSA,
    CKM_RSA_PKCS,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
)
from pkcs11_check.testcases.security.conftest import child_setup_reject_known

# Mechanism-name -> CKM value.  The name (not the numeric value) is what the
# original ``SETUP_XFAIL:C_<op>Init(<name>) failed`` line printed, so the parent
# carries the name and the probe maps it back to the mechanism constant.
_AES_CKM_BY_NAME: dict[str, int] = {
    "CKM_AES_ECB": CKM_AES_ECB,
    "CKM_AES_CBC": CKM_AES_CBC,
    "CKM_AES_CTR": CKM_AES_CTR,
    "CKM_AES_GCM": CKM_AES_GCM,
}


def _setup_aes_mech(mech: CK_MECHANISM, ckm_val: int, keepalive: list[Any]) -> None:
    """Populate *mech* for the given AES mechanism.

    Parameter buffers are appended to *keepalive* so the caller keeps them alive
    for the duration of the C_*Init call (a cast to ``c_void_p`` drops ctypes'
    own reference to the backing object).
    """
    if ckm_val == CKM_AES_ECB:
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
    elif ckm_val == CKM_AES_CBC:
        iv = (ctypes.c_ubyte * 16)(*range(16))
        mech.mechanism = CKM_AES_CBC
        mech.pParameter = ctypes.cast(iv, ctypes.c_void_p)
        mech.ulParameterLen = 16
        keepalive.append(iv)
    elif ckm_val == CKM_AES_CTR:
        ctr_params = CK_AES_CTR_PARAMS()
        ctr_params.ulCounterBits = 32
        for i in range(16):
            ctr_params.cb[i] = i
        mech.mechanism = CKM_AES_CTR
        mech.pParameter = ctypes.cast(ctypes.byref(ctr_params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(ctr_params)
        keepalive.append(ctr_params)
    else:  # CKM_AES_GCM
        gcm_iv = (ctypes.c_ubyte * 12)(*range(12))
        gcm_params = CK_AES_GCM_PARAMS()
        gcm_params.pIv = ctypes.cast(gcm_iv, ctypes.c_void_p)
        gcm_params.ulIvLen = 12
        gcm_params.ulIvBits = 96
        gcm_params.pAAD = None
        gcm_params.ulAADLen = 0
        gcm_params.ulTagBits = 128
        mech.mechanism = CKM_AES_GCM
        mech.pParameter = ctypes.cast(ctypes.byref(gcm_params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(gcm_params)
        keepalive.append(gcm_iv)
        keepalive.append(gcm_params)


def _run_sign(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """CKM_SHA256_HMAC key destroyed between C_SignInit and C_Sign."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    # --- create a 32-byte generic-secret key with CKA_SIGN ---
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_false = ctypes.c_ubyte(0)
    sign_true = ctypes.c_ubyte(1)

    tmpl = (CK_ATTRIBUTE * 5)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    tmpl[2].type = CKA_TOKEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1
    tmpl[3].type = CKA_VALUE
    tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    tmpl[3].ulValueLen = 32
    tmpl[4].type = CKA_SIGN
    tmpl[4].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
    tmpl[4].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HMAC key import rejected: {ckr_name(rv)}")
        cleanup()
        raise SystemExit(0)

    # --- C_SignInit ---
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_SignInit(CKM_SHA256_HMAC) failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, key.value)
        cleanup()
        raise SystemExit(0)

    # --- C_DestroyObject while sign operation is active ---
    destroy_rv = raw.C_DestroyObject(sh, key.value)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")

    # --- C_Sign on possibly-freed state ---
    data = (ctypes.c_ubyte * 16)(*range(16))
    sig_len = CK_ULONG(0)
    sign_rv = raw.C_Sign(sh, data, 16, None, ctypes.byref(sig_len))
    print(f"SIGN_RV:0x{sign_rv:08x}")
    if sign_rv == CKR_OK:
        sig_buf = (ctypes.c_ubyte * sig_len.value)()
        sign_rv2 = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
        print(f"SIGN_RV2:0x{sign_rv2:08x}")

    cleanup()


def _aes_uaf(ctx: ProbeContext, extra: dict[str, Any], op: str, *, with_oracle: bool) -> None:
    """AES key destroyed mid-operation; ``op`` is ``"Encrypt"`` or ``"Decrypt"``.

    When ``with_oracle`` is True (Encrypt only) the expected ciphertext is captured
    with the live key first and printed as ``EXPECTED:<hex>``; the post-destroy
    ciphertext is printed as ``ENCRYPT_CT:<hex>`` so the parent can compare them.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    op_upper = op.upper()
    ckm_name = extra["ckm"]
    ckm_val = _AES_CKM_BY_NAME[ckm_name]

    try:
        aes_key = gen_aes_key(
            raw,
            sh,
            128,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
        ):
            cleanup()
            raise SystemExit(0) from None
        raise

    keepalive: list[Any] = []

    if with_oracle and op == "Encrypt":
        # --- oracle: encrypt with live key to capture EXPECTED ciphertext ---
        mech_ref = CK_MECHANISM()
        _setup_aes_mech(mech_ref, ckm_val, keepalive)
        rv_ref = raw.C_EncryptInit(sh, ctypes.byref(mech_ref), aes_key)
        if rv_ref == CKR_OK:
            plain_ref = (ctypes.c_ubyte * 16)(*range(16))
            exp_len = CK_ULONG(0)
            rv_ref2 = raw.C_Encrypt(sh, plain_ref, 16, None, ctypes.byref(exp_len))
            if rv_ref2 == CKR_OK and exp_len.value > 0:
                exp_buf = (ctypes.c_ubyte * exp_len.value)()
                rv_ref3 = raw.C_Encrypt(sh, plain_ref, 16, exp_buf, ctypes.byref(exp_len))
                if rv_ref3 == CKR_OK:
                    print("EXPECTED:" + bytes(exp_buf[: exp_len.value]).hex())

    c_op_init = getattr(raw, f"C_{op}Init")
    c_op = getattr(raw, f"C_{op}")

    mech = CK_MECHANISM()
    _setup_aes_mech(mech, ckm_val, keepalive)
    rv = c_op_init(sh, ctypes.byref(mech), aes_key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_{op}Init({ckm_name}) failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, aes_key)
        cleanup()
        raise SystemExit(0)
    destroy_rv = raw.C_DestroyObject(sh, aes_key)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")
    data = (ctypes.c_ubyte * 16)(*range(16))
    out_len = CK_ULONG(0)
    op_rv = c_op(sh, data, 16, None, ctypes.byref(out_len))
    print(f"{op_upper}_RV:0x{op_rv:08x}")
    if op_rv == CKR_OK and out_len.value > 0:
        out_buf = (ctypes.c_ubyte * out_len.value)()
        op_rv2 = c_op(sh, data, 16, out_buf, ctypes.byref(out_len))
        print(f"{op_upper}_RV2:0x{op_rv2:08x}")
        if with_oracle and op == "Encrypt" and op_rv2 == CKR_OK:
            print("ENCRYPT_CT:" + bytes(out_buf[: out_len.value]).hex())

    cleanup()


def _run_aes_encrypt(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """AES key destroyed between C_EncryptInit and C_Encrypt (with ciphertext oracle)."""
    _aes_uaf(ctx, extra, "Encrypt", with_oracle=True)


def _run_aes_decrypt(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """AES key destroyed between C_DecryptInit and C_Decrypt."""
    _aes_uaf(ctx, extra, "Decrypt", with_oracle=False)


def _run_digest(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DigestInit(CKM_SHA256) then C_DigestKey on a destroyed key handle."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    # --- create a 32-byte generic-secret key ---
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_false = ctypes.c_ubyte(0)

    tmpl = (CK_ATTRIBUTE * 4)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    tmpl[2].type = CKA_TOKEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1
    tmpl[3].type = CKA_VALUE
    tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    tmpl[3].ulValueLen = 32

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:key import rejected: {ckr_name(rv)}")
        cleanup()
        raise SystemExit(0)

    if "C_DigestKey" not in raw.available_function_names():
        print("SETUP_XFAIL:C_DigestKey is not exposed by this interface")
        raw.C_DestroyObject(sh, key.value)
        cleanup()
        raise SystemExit(0)

    # --- C_DigestInit ---
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_DigestInit(CKM_SHA256) failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, key.value)
        cleanup()
        raise SystemExit(0)

    # --- C_DestroyObject before C_DigestKey ---
    destroy_rv = raw.C_DestroyObject(sh, key.value)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")

    # --- C_DigestKey on possibly-freed handle ---
    digest_key_rv = raw.C_DigestKey(sh, key.value)
    print(f"DIGEST_KEY_RV:0x{digest_key_rv:08x}")

    cleanup()


def _run_verify(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """CKM_SHA256_HMAC key destroyed between C_VerifyInit and C_Verify."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    # --- import a 32-byte generic-secret key with CKA_VERIFY ---
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_false = ctypes.c_ubyte(0)
    verify_true = ctypes.c_ubyte(1)

    tmpl = (CK_ATTRIBUTE * 5)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    tmpl[2].type = CKA_TOKEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1
    tmpl[3].type = CKA_VALUE
    tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    tmpl[3].ulValueLen = 32
    tmpl[4].type = CKA_VERIFY
    tmpl[4].pValue = ctypes.cast(ctypes.pointer(verify_true), ctypes.c_void_p)
    tmpl[4].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HMAC verify key import rejected: {ckr_name(rv)}")
        cleanup()
        raise SystemExit(0)

    # --- C_VerifyInit ---
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key.value)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_VerifyInit(CKM_SHA256_HMAC) failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, key.value)
        cleanup()
        raise SystemExit(0)

    # --- C_DestroyObject while verify operation is active ---
    destroy_rv = raw.C_DestroyObject(sh, key.value)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")

    # --- C_Verify on possibly-freed state (dummy 32-byte signature) ---
    data = (ctypes.c_ubyte * 16)(*range(16))
    dummy_sig = (ctypes.c_ubyte * 32)(0)
    verify_rv = raw.C_Verify(sh, data, 16, dummy_sig, 32)
    print(f"VERIFY_RV:0x{verify_rv:08x}")

    cleanup()


def _run_derive(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """EC base private key destroyed before C_DeriveKey (use-after-destroy of base key)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    # --- generate two EC keypairs on P-256 ---
    curve_oid = encode_named_curve_parameters("secp256r1")

    try:
        pub_a_h, priv_a_h = gen_ec_keypair(
            raw,
            sh,
            curve_oid,
            public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        print(f"SETUP_XFAIL:EC keypair generation rejected: {exc}")
        cleanup()
        raise SystemExit(0) from None

    try:
        pub_b_h, priv_b_h = gen_ec_keypair(
            raw,
            sh,
            curve_oid,
            public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        print(f"SETUP_XFAIL:EC keypair (peer) generation rejected: {exc}")
        raw.C_DestroyObject(sh, pub_a_h)
        raw.C_DestroyObject(sh, priv_a_h)
        cleanup()
        raise SystemExit(0) from None

    # --- read the peer public-key EC point ---
    try:
        attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])
        ec_point_b = bytes(attrs_b[CKA_EC_POINT])
    except AssertionError as exc:
        print(f"SETUP_XFAIL:Could not read peer EC point: {exc}")
        for h in (pub_a_h, priv_a_h, pub_b_h, priv_b_h):
            raw.C_DestroyObject(sh, h)
        cleanup()
        raise SystemExit(0) from None

    # Destroy peer keypair -- only the peer's public point is needed hereafter.
    raw.C_DestroyObject(sh, pub_b_h)
    raw.C_DestroyObject(sh, priv_b_h)

    # --- destroy the *base* private key before C_DeriveKey ---
    destroy_rv = raw.C_DestroyObject(sh, priv_a_h)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")
    raw.C_DestroyObject(sh, pub_a_h)

    # --- derive template: a 32-byte generic-secret ---
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_false = ctypes.c_ubyte(0)
    sensitive_false = ctypes.c_ubyte(0)
    extractable_true = ctypes.c_ubyte(1)

    derive_tmpl = (CK_ATTRIBUTE * 5)()
    derive_tmpl[0].type = CKA_CLASS
    derive_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    derive_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    derive_tmpl[1].type = CKA_KEY_TYPE
    derive_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    derive_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    derive_tmpl[2].type = CKA_TOKEN
    derive_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    derive_tmpl[2].ulValueLen = 1
    derive_tmpl[3].type = CKA_SENSITIVE
    derive_tmpl[3].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
    derive_tmpl[3].ulValueLen = 1
    derive_tmpl[4].type = CKA_EXTRACTABLE
    derive_tmpl[4].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
    derive_tmpl[4].ulValueLen = 1

    packed_mech = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=ec_point_b)
    derived_key = CK_OBJECT_HANDLE(0)

    # --- C_DeriveKey with the already-destroyed private key handle ---
    derive_rv = raw.C_DeriveKey(
        sh,
        packed_mech.byref(),
        priv_a_h,
        ctypes.cast(derive_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(derived_key),
    )
    print(f"DERIVE_RV:0x{derive_rv:08x}")

    if derive_rv == CKR_OK and derived_key.value != 0:
        raw.C_DestroyObject(sh, derived_key.value)

    cleanup()


def _run_cross_session(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Token HMAC key sign-inited in session A, destroyed from session B, then C_Sign in A."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    assert ctx.slot_id is not None, "probe requires a slot (Level.LOGIN)"
    sh = ctx.sh
    slot_id = ctx.slot_id
    cleanup = ctx.cleanup

    # --- create a TOKEN sign key on session A (sh) ---
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    token_true = ctypes.c_ubyte(1)
    sign_true = ctypes.c_ubyte(1)

    tmpl = (CK_ATTRIBUTE * 5)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    tmpl[2].type = CKA_TOKEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_true), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1
    tmpl[3].type = CKA_VALUE
    tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    tmpl[3].ulValueLen = 32
    tmpl[4].type = CKA_SIGN
    tmpl[4].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
    tmpl[4].ulValueLen = 1

    token_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        5,
        ctypes.byref(token_key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:TOKEN HMAC key creation not operational: {ckr_name(rv)}")
        cleanup()
        raise SystemExit(0)

    # --- open session B on the same slot ---
    sh_b = CK_SESSION_HANDLE(0)
    rv_b = raw.C_OpenSession(
        slot_id,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        None,
        CK_NOTIFY(),
        ctypes.byref(sh_b),
    )
    if rv_b != CKR_OK:
        print(f"SETUP_XFAIL:C_OpenSession(session B) failed: {ckr_name(rv_b)}")
        raw.C_DestroyObject(sh, token_key.value)
        cleanup()
        raise SystemExit(0)

    # --- C_SignInit in session A with the token key ---
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), token_key.value)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_SignInit(CKM_SHA256_HMAC) in session A failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, token_key.value)
        raw.C_CloseSession(sh_b.value)
        cleanup()
        raise SystemExit(0)

    # --- C_DestroyObject from session B ---
    destroy_rv = raw.C_DestroyObject(sh_b.value, token_key.value)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")

    # --- C_Sign in session A (operation may reference freed/invalid key) ---
    data = (ctypes.c_ubyte * 16)(*range(16))
    sig_len = CK_ULONG(0)
    xsession_rv = raw.C_Sign(sh, data, 16, None, ctypes.byref(sig_len))
    print(f"XSESSION_SIGN_RV:0x{xsession_rv:08x}")
    if xsession_rv == CKR_OK:
        sig_buf = (ctypes.c_ubyte * sig_len.value)()
        xsession_rv2 = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
        print(f"XSESSION_SIGN_RV2:0x{xsession_rv2:08x}")

    # --- clean up session B and token object (best-effort; may already be gone) ---
    raw.C_DestroyObject(sh_b.value, token_key.value)
    raw.C_CloseSession(sh_b.value)

    cleanup()


def _run_ecdsa_sign(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """EC private key destroyed between C_SignInit(CKM_ECDSA) and C_Sign."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    # --- generate a session P-256 EC keypair (CKA_SIGN on private) ---
    curve_oid = encode_named_curve_parameters("secp256r1")
    try:
        pub_h, priv_h = gen_ec_keypair(
            raw,
            sh,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, KEYPAIR_RUNTIME_REJECT_RVS, "EC keypair generation rejected"
        ):
            cleanup()
            raise SystemExit(0) from None
        raise

    raw.C_DestroyObject(sh, pub_h)

    # --- C_SignInit with CKM_ECDSA ---
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv_h)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_SignInit(CKM_ECDSA) failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, priv_h)
        cleanup()
        raise SystemExit(0)

    # --- C_DestroyObject on the private key while sign operation is active ---
    destroy_rv = raw.C_DestroyObject(sh, priv_h)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")

    # --- C_Sign on possibly-freed key reference (two-pass) ---
    data = (ctypes.c_ubyte * 32)(*range(32))
    sig_len = CK_ULONG(0)
    sign_rv = raw.C_Sign(sh, data, 32, None, ctypes.byref(sig_len))
    print(f"SIGN_RV:0x{sign_rv:08x}")
    if sign_rv == CKR_OK and sig_len.value > 0:
        sig_buf = (ctypes.c_ubyte * sig_len.value)()
        sign_rv2 = raw.C_Sign(sh, data, 32, sig_buf, ctypes.byref(sig_len))
        print(f"SIGN_RV2:0x{sign_rv2:08x}")

    cleanup()


def _run_rsa_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """RSA private key destroyed between C_DecryptInit(CKM_RSA_PKCS) and C_Decrypt."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup

    # --- generate a session RSA-2048 keypair (CKA_DECRYPT on private) ---
    try:
        pub_h, priv_h = gen_rsa_keypair(raw, sh, 2048, usage=RSAUsage.DECRYPT)
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected"
        ):
            cleanup()
            raise SystemExit(0) from None
        raise

    raw.C_DestroyObject(sh, pub_h)

    # --- C_DecryptInit with CKM_RSA_PKCS ---
    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv_h)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_DecryptInit(CKM_RSA_PKCS) failed: {ckr_name(rv)}")
        raw.C_DestroyObject(sh, priv_h)
        cleanup()
        raise SystemExit(0)

    # --- C_DestroyObject on the private key while decrypt operation is active ---
    destroy_rv = raw.C_DestroyObject(sh, priv_h)
    print(f"DESTROY_RV:0x{destroy_rv:08x}")

    # --- C_Decrypt on possibly-freed key reference (two-pass, modulus-sized zero input) ---
    # 256 zero bytes is an invalid RSA-PKCS#1 v1.5 ciphertext; a clean decrypt error
    # (e.g. CKR_FUNCTION_FAILED, CKR_ENCRYPTED_DATA_INVALID) is acceptable.  No crash is the
    # only hard requirement.
    ciphertext = (ctypes.c_ubyte * 256)(0)
    dec_len = CK_ULONG(0)
    dec_rv = raw.C_Decrypt(sh, ciphertext, 256, None, ctypes.byref(dec_len))
    print(f"DECRYPT_RV:0x{dec_rv:08x}")
    if dec_rv == CKR_OK and dec_len.value > 0:
        dec_buf = (ctypes.c_ubyte * dec_len.value)()
        dec_rv2 = raw.C_Decrypt(sh, ciphertext, 256, dec_buf, ctypes.byref(dec_len))
        print(f"DECRYPT_RV2:0x{dec_rv2:08x}")

    cleanup()


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "sign": _run_sign,
    "aes_encrypt": _run_aes_encrypt,
    "aes_decrypt": _run_aes_decrypt,
    "digest": _run_digest,
    "verify": _run_verify,
    "derive": _run_derive,
    "cross_session": _run_cross_session,
    "ecdsa_sign": _run_ecdsa_sign,
    "rsa_decrypt": _run_rsa_decrypt,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"operation_state_uaf probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
