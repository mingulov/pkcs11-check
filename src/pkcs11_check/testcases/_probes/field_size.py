"""Probe: field-size oversize/truncation for key-size, find-count, and KDF-param fields.

Ports the five child-script bodies from security/test_field_size_boundary.py into a
single dispatchable probe module.  Output protocol lines are byte-identical to the
originals so the parent classifiers require no changes.

Output protocol (preserved verbatim for the parent classifier):
  SETUP_XFAIL:<reason>   -- setup rejected; parent xfails as not_operational
  TARGET_RV:0x%08x       -- return value from the probed call (rsa/dh/dsa/aes/find)
  COUNT_OUT:<int>        -- C_FindObjects ulObjectCount out (find_objects_count only)
  GUARD_OVERWRITE:<int>  -- handle-buffer guard words changed (find_objects_count only)
  PROBE_RV:0x%08x        -- oversized-length HKDF derive rv (hkdf_* only)
  TRUNCATED:<int>        -- 1 if probe key == 8-byte reference key (hkdf_* only)
  PROBE_HEX:<hex>        -- derived probe key bytes (hkdf_* only; diagnostic)
  REF_HEX:<hex>          -- derived reference key bytes (hkdf_* only; diagnostic)

Dispatch on ``params.extra["which"]``:
  ``"rsa_modulus_bits"``   -- C_GenerateKeyPair(RSA) with oversized CKA_MODULUS_BITS value
  ``"dh_prime_bits"``      -- C_GenerateKeyPair(DH) with oversized CKA_PRIME_BITS value
  ``"dsa_prime_bits"``     -- C_GenerateKeyPair(DSA) with oversized CKA_PRIME_BITS value
  ``"aes_value_len"``      -- C_GenerateKey(AES) with oversized CKA_VALUE_LEN value
  ``"find_objects_count"`` -- C_FindObjects with oversized ulMaxObjectCount (crash survival)
  ``"hkdf_salt_len"``      -- C_DeriveKey(HKDF) ulSaltLen 64->32 truncation comparison
  ``"hkdf_info_len"``      -- C_DeriveKey(HKDF) ulInfoLen 64->32 truncation comparison

Required extra keys per dispatch value:
  ``"rsa_modulus_bits"``:  ``modulus_bits`` (int)
  ``"dh_prime_bits"`` / ``"dsa_prime_bits"``: ``prime_bits`` (int)
  ``"aes_value_len"``:     ``value_len`` (int)
  ``"find_objects_count"``: ``max_count`` (int)
  ``"hkdf_salt_len"`` / ``"hkdf_info_len"``: ``oversize_len`` (int)

Safety: the oversized HKDF salt/info field is backed by the shared demand-zero honeypot
(``demand_zero_buffer``), so a module that honors the full 64-bit length reads real zeroed
pages instead of faulting (docs/probe-soundness.md).  Truncation is detected behaviorally:
the 8-byte reference derive uses the low-32 portion of that buffer (8 zero bytes), so a
module that truncates ulSaltLen/ulInfoLen to its low 32 bits produces a key identical to
the reference -> TRUNCATED:1.
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_HKDF_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PRIME_BITS,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKF_HKDF_SALT_DATA,
    CKF_HKDF_SALT_NULL,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_GEN,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_HKDF_DERIVE,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

_ATTR_PTR = ctypes.POINTER(CK_ATTRIBUTE)


# ---------------------------------------------------------------------------
# 1. CKA_MODULUS_BITS oversized value in C_GenerateKeyPair(RSA)
# ---------------------------------------------------------------------------


def _run_rsa_modulus_bits(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKeyPair(RSA) with an oversized CKA_MODULUS_BITS value."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    # Impossible 64-bit modulus bits value; low32 = 2048 (valid RSA size).
    modulus_bits = CK_ULONG(int(extra["modulus_bits"]))
    token_false = ctypes.c_ubyte(0)
    priv_true = ctypes.c_ubyte(1)

    pub_tmpl = (CK_ATTRIBUTE * 2)()
    pub_tmpl[0].type = CKA_MODULUS_BITS
    pub_tmpl[0].pValue = ctypes.cast(ctypes.pointer(modulus_bits), ctypes.c_void_p)
    pub_tmpl[0].ulValueLen = ctypes.sizeof(modulus_bits)
    pub_tmpl[1].type = CKA_TOKEN
    pub_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    pub_tmpl[1].ulValueLen = 1

    priv_tmpl = (CK_ATTRIBUTE * 2)()
    priv_tmpl[0].type = CKA_TOKEN
    priv_tmpl[0].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    priv_tmpl[0].ulValueLen = 1
    priv_tmpl[1].type = CKA_PRIVATE
    priv_tmpl[1].pValue = ctypes.cast(ctypes.pointer(priv_true), ctypes.c_void_p)
    priv_tmpl[1].ulValueLen = 1

    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        ctypes.byref(mech),
        ctypes.cast(pub_tmpl, _ATTR_PTR),
        2,
        ctypes.cast(priv_tmpl, _ATTR_PTR),
        2,
        ctypes.byref(pub),
        ctypes.byref(priv),
    )
    if rv == CKR_OK:
        destroy_quietly(raw, sh, pub.value)
        destroy_quietly(raw, sh, priv.value)
    print(f"TARGET_RV:0x{rv:08x}")


# ---------------------------------------------------------------------------
# 2. CKA_PRIME_BITS oversized value in C_GenerateKeyPair(DH or DSA)
# ---------------------------------------------------------------------------


def _prime_bits_keygen(raw: Any, sh: int, prime_bits_value: int, mechanism: int) -> None:
    """C_GenerateKeyPair(DH/DSA) with an oversized CKA_PRIME_BITS value."""
    prime_bits = CK_ULONG(prime_bits_value)
    token_false = ctypes.c_ubyte(0)

    pub_tmpl = (CK_ATTRIBUTE * 2)()
    pub_tmpl[0].type = CKA_PRIME_BITS
    pub_tmpl[0].pValue = ctypes.cast(ctypes.pointer(prime_bits), ctypes.c_void_p)
    pub_tmpl[0].ulValueLen = ctypes.sizeof(prime_bits)
    pub_tmpl[1].type = CKA_TOKEN
    pub_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    pub_tmpl[1].ulValueLen = 1

    priv_tmpl = (CK_ATTRIBUTE * 1)()
    priv_tmpl[0].type = CKA_TOKEN
    priv_tmpl[0].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    priv_tmpl[0].ulValueLen = 1

    mech = CK_MECHANISM()
    mech.mechanism = mechanism
    mech.pParameter = None
    mech.ulParameterLen = 0

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        ctypes.byref(mech),
        ctypes.cast(pub_tmpl, _ATTR_PTR),
        2,
        ctypes.cast(priv_tmpl, _ATTR_PTR),
        1,
        ctypes.byref(pub),
        ctypes.byref(priv),
    )
    if rv == CKR_OK:
        destroy_quietly(raw, sh, pub.value)
        destroy_quietly(raw, sh, priv.value)
    print(f"TARGET_RV:0x{rv:08x}")


def _run_dh_prime_bits(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKeyPair(DH) with an oversized CKA_PRIME_BITS value."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    _prime_bits_keygen(ctx.raw, ctx.sh, int(extra["prime_bits"]), CKM_DH_PKCS_KEY_PAIR_GEN)


def _run_dsa_prime_bits(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKeyPair(DSA) with an oversized CKA_PRIME_BITS value."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    _prime_bits_keygen(ctx.raw, ctx.sh, int(extra["prime_bits"]), CKM_DSA_KEY_PAIR_GEN)


# ---------------------------------------------------------------------------
# 3. CKA_VALUE_LEN truncation-revealing value in C_GenerateKey (AES)
# ---------------------------------------------------------------------------


def _run_aes_value_len(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_GenerateKey(AES) with an oversized CKA_VALUE_LEN value."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    # Impossible 64-bit value_len; low32 = 8 bytes (truncating provider succeeds).
    value_len = CK_ULONG(int(extra["value_len"]))
    token_false = ctypes.c_ubyte(0)
    enc_true = ctypes.c_ubyte(1)

    tmpl = (CK_ATTRIBUTE * 3)()
    tmpl[0].type = CKA_VALUE_LEN
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(value_len), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(value_len)
    tmpl[1].type = CKA_TOKEN
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    tmpl[1].ulValueLen = 1
    tmpl[2].type = CKA_ENCRYPT
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_KEY_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(
        sh,
        ctypes.byref(mech),
        ctypes.cast(tmpl, _ATTR_PTR),
        3,
        ctypes.byref(key),
    )
    if rv == CKR_OK:
        destroy_quietly(raw, sh, key.value)
    print(f"TARGET_RV:0x{rv:08x}")


# ---------------------------------------------------------------------------
# 4. C_FindObjects ulMaxObjectCount truncation-revealing value
# ---------------------------------------------------------------------------


def _run_find_objects_count(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_FindObjects with a truncation-revealing ulMaxObjectCount must not crash."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    max_count = int(extra["max_count"])

    # Empty template = match all objects; we are not looking for specific ones.
    rv_init = raw.C_FindObjectsInit(sh, None, 0)
    if rv_init != CKR_OK:
        print(f"SETUP_XFAIL:C_FindObjectsInit rejected: {ckr_name(rv_init)}")
        return

    # 8-slot handle buffer with guard bytes immediately after.
    guard_sentinel = 0xA5
    handle_slots = 8
    guard_slots = 8

    class FindProbe(ctypes.Structure):
        _fields_ = [
            ("handles", CK_OBJECT_HANDLE * handle_slots),
            ("guard", ctypes.c_ulong * guard_slots),
        ]

    probe = FindProbe()
    for idx in range(guard_slots):
        probe.guard[idx] = guard_sentinel

    count_out = ctypes.c_ulong(0)
    rv = raw.C_FindObjects(
        sh,
        ctypes.cast(probe.handles, ctypes.POINTER(CK_OBJECT_HANDLE)),
        max_count,  # ulMaxObjectCount -- cap field, CKR_OK is spec-legal
        ctypes.byref(count_out),
    )
    print(f"TARGET_RV:0x{rv:08x}")
    print(f"COUNT_OUT:{count_out.value}")

    overwritten = sum(1 for g in probe.guard if g != guard_sentinel)
    print(f"GUARD_OVERWRITE:{overwritten}")

    raw.C_FindObjectsFinal(sh)


# ---------------------------------------------------------------------------
# 5. HKDF ulSaltLen / ulInfoLen 64-bit length truncation (honeypot-backed, behavioral)
# ---------------------------------------------------------------------------


def _import_hkdf_base_key(raw: Any, sh: int) -> int | None:
    """Import a 32-byte extractable generic-secret base key; return handle or None.

    CKA_SENSITIVE=False + CKA_EXTRACTABLE=True so derived keys can be read back for
    behavioral comparison.  Prints SETUP_XFAIL and returns None on import failure.
    """
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    derive_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)
    sensitive_false = ctypes.c_ubyte(0)
    extractable_true = ctypes.c_ubyte(1)

    key_tmpl = (CK_ATTRIBUTE * 7)()
    key_tmpl[0].type = CKA_CLASS
    key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    key_tmpl[1].type = CKA_KEY_TYPE
    key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
    key_tmpl[2].type = CKA_VALUE
    key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    key_tmpl[2].ulValueLen = 32
    key_tmpl[3].type = CKA_DERIVE
    key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
    key_tmpl[3].ulValueLen = 1
    key_tmpl[4].type = CKA_TOKEN
    key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    key_tmpl[4].ulValueLen = 1
    key_tmpl[5].type = CKA_SENSITIVE
    key_tmpl[5].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
    key_tmpl[5].ulValueLen = 1
    key_tmpl[6].type = CKA_EXTRACTABLE
    key_tmpl[6].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
    key_tmpl[6].ulValueLen = 1

    base_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(key_tmpl, _ATTR_PTR),
        7,
        ctypes.byref(base_key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HKDF base key import not operational 0x{rv:08x}")
        return None
    return base_key.value


def _hkdf_derive_template() -> tuple[Any, list[Any]]:
    """Build the extractable-session-key HKDF derive template.

    Returns ``(tmpl, keepalive)`` where ``keepalive`` holds the ctypes value objects
    the template's pointers reference; the caller must keep it alive for the derive.
    """
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_sens = ctypes.c_ubyte(0)
    d_extr = ctypes.c_ubyte(1)
    d_tmpl = (CK_ATTRIBUTE * 6)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1
    d_tmpl[4].type = CKA_SENSITIVE
    d_tmpl[4].pValue = ctypes.cast(ctypes.pointer(d_sens), ctypes.c_void_p)
    d_tmpl[4].ulValueLen = 1
    d_tmpl[5].type = CKA_EXTRACTABLE
    d_tmpl[5].pValue = ctypes.cast(ctypes.pointer(d_extr), ctypes.c_void_p)
    d_tmpl[5].ulValueLen = 1
    return d_tmpl, [d_cls, d_kt, d_vl, d_tok, d_sens, d_extr]


def _extract_key_value(raw: Any, sh: int, handle: int) -> bytes | None:
    """Return 32 bytes of CKA_VALUE from a derived key, or None on failure."""
    val_buf = (ctypes.c_ubyte * 32)()
    attr = (CK_ATTRIBUTE * 1)()
    attr[0].type = CKA_VALUE
    attr[0].pValue = ctypes.cast(val_buf, ctypes.c_void_p)
    attr[0].ulValueLen = 32
    rv_get = raw.C_GetAttributeValue(sh, handle, ctypes.cast(attr, _ATTR_PTR), 1)
    if rv_get != CKR_OK:
        return None
    return bytes(val_buf)


def _hkdf_truncation_probe(
    ctx: ProbeContext,
    oversize_len: int,
    *,
    on_salt: bool,
) -> None:
    """Detect 64->32-bit truncation of HKDF ulSaltLen (on_salt) or ulInfoLen.

    Two derives are performed against a demand-zero honeypot buffer: a probe derive with
    the full ``oversize_len`` and a reference derive with only the low-32 portion
    (8 zero bytes -- the first 8 bytes of the same demand-zero region).  If both succeed
    and produce the SAME key material the module truncated the 64-bit length to its low
    32 bits (TRUNCATED:1); different material means it honored the full length.
    """
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    base_key = _import_hkdf_base_key(raw, sh)
    if base_key is None:
        return

    try:
        try:
            buf = demand_zero_buffer()
        except HoneypotUnavailable as exc:
            print(f"{SETUP_XFAIL_PREFIX}{exc}")
            return

        d_tmpl, _keepalive = _hkdf_derive_template()

        # --- Probe derive: full oversize_len salt/info (honeypot-backed) ---
        params_probe = CK_HKDF_PARAMS()
        params_probe.bExtract = 1
        params_probe.bExpand = 1
        params_probe.prfHashMechanism = CKM_SHA256
        if on_salt:
            params_probe.ulSaltType = CKF_HKDF_SALT_DATA
            params_probe.pSalt = ctypes.cast(buf, ctypes.c_void_p)
            params_probe.ulSaltLen = oversize_len
            params_probe.hSaltKey = 0
            params_probe.pInfo = None
            params_probe.ulInfoLen = 0
        else:
            params_probe.ulSaltType = CKF_HKDF_SALT_NULL
            params_probe.pSalt = None
            params_probe.ulSaltLen = 0
            params_probe.hSaltKey = 0
            params_probe.pInfo = ctypes.cast(buf, ctypes.c_void_p)
            params_probe.ulInfoLen = oversize_len

        mech_probe = CK_MECHANISM()
        mech_probe.mechanism = CKM_HKDF_DERIVE
        mech_probe.pParameter = ctypes.cast(ctypes.pointer(params_probe), ctypes.c_void_p)
        mech_probe.ulParameterLen = ctypes.sizeof(params_probe)

        derived_probe = CK_OBJECT_HANDLE(0)
        rv_probe = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech_probe),
            base_key,
            ctypes.cast(d_tmpl, _ATTR_PTR),
            6,
            ctypes.byref(derived_probe),
        )
        print(f"PROBE_RV:0x{rv_probe:08x}")

        if rv_probe == CKR_OK:
            probe_bytes = _extract_key_value(raw, sh, derived_probe.value)
            destroy_quietly(raw, sh, derived_probe.value)
        else:
            probe_bytes = None

        # --- Reference derive: only the first 8 bytes (the low-32 portion) ---
        if rv_probe == CKR_OK:
            ref_field = (ctypes.c_ubyte * 8)()  # 8 zero bytes = low-32 of the demand-zero buffer
            params_ref = CK_HKDF_PARAMS()
            params_ref.bExtract = 1
            params_ref.bExpand = 1
            params_ref.prfHashMechanism = CKM_SHA256
            if on_salt:
                params_ref.ulSaltType = CKF_HKDF_SALT_DATA
                params_ref.pSalt = ctypes.cast(ref_field, ctypes.c_void_p)
                params_ref.ulSaltLen = 8
                params_ref.hSaltKey = 0
                params_ref.pInfo = None
                params_ref.ulInfoLen = 0
            else:
                params_ref.ulSaltType = CKF_HKDF_SALT_NULL
                params_ref.pSalt = None
                params_ref.ulSaltLen = 0
                params_ref.hSaltKey = 0
                params_ref.pInfo = ctypes.cast(ref_field, ctypes.c_void_p)
                params_ref.ulInfoLen = 8

            mech_ref = CK_MECHANISM()
            mech_ref.mechanism = CKM_HKDF_DERIVE
            mech_ref.pParameter = ctypes.cast(ctypes.pointer(params_ref), ctypes.c_void_p)
            mech_ref.ulParameterLen = ctypes.sizeof(params_ref)

            derived_ref = CK_OBJECT_HANDLE(0)
            rv_ref = raw.C_DeriveKey(
                sh,
                ctypes.byref(mech_ref),
                base_key,
                ctypes.cast(d_tmpl, _ATTR_PTR),
                6,
                ctypes.byref(derived_ref),
            )
            if rv_ref == CKR_OK:
                ref_bytes = _extract_key_value(raw, sh, derived_ref.value)
                destroy_quietly(raw, sh, derived_ref.value)
                if ref_bytes is not None and probe_bytes is not None:
                    truncated = 1 if probe_bytes == ref_bytes else 0
                    print(f"TRUNCATED:{truncated}")
                    print(f"PROBE_HEX:{probe_bytes.hex()}")
                    print(f"REF_HEX:{ref_bytes.hex()}")
    finally:
        destroy_quietly(raw, sh, base_key)


def _run_hkdf_salt_len(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """HKDF ulSaltLen 64->32-bit truncation detection."""
    _hkdf_truncation_probe(ctx, int(extra["oversize_len"]), on_salt=True)


def _run_hkdf_info_len(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """HKDF ulInfoLen 64->32-bit truncation detection."""
    _hkdf_truncation_probe(ctx, int(extra["oversize_len"]), on_salt=False)


# ---------------------------------------------------------------------------
# Dispatch table and entry point
# ---------------------------------------------------------------------------

_DISPATCH = {
    "rsa_modulus_bits": _run_rsa_modulus_bits,
    "dh_prime_bits": _run_dh_prime_bits,
    "dsa_prime_bits": _run_dsa_prime_bits,
    "aes_value_len": _run_aes_value_len,
    "find_objects_count": _run_find_objects_count,
    "hkdf_salt_len": _run_hkdf_salt_len,
    "hkdf_info_len": _run_hkdf_info_len,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Dispatch to the sub-probe identified by ``extra["which"]``."""
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"field_size probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
