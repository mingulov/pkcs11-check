"""Probe: C_GetOperationState / C_SetOperationState save-restore round-trips.

Ports the f-string child-script bodies from testcases/test_operation_state.py into
dispatchable probe functions.  Each probe drives the digest / encrypt init-update-final
C-level steps directly (the python-pkcs11 high-level API does not expose those steps as
individually callable Python calls) to save operation state mid-operation and restore it.

Output protocol lines (``REFERENCE:...``, ``SINGLESHOT_OK:...``, ``STATE_SAVED:...``,
``STATE_RESTORED``, ``RESTORED:...``, ``KEY_GENERATED:...``, ``CROSS_SESSION_ACCEPTED:1``,
``CROSS_SESSION_REJECTED:0x...``, ``SKIP:...``, ``FATAL:...``) are byte-identical to the
original generated scripts so the parent (parse_output + fail_as/xfail_as + the digest /
ciphertext oracle) requires no changes.

All probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).  The PIN is
never embedded in the probe source or params.

Dispatch on ``params.extra["probe"]``:
  ``"digest_same_session"``  -- SHA-256 multi-part digest state save/restore on one session.
  ``"digest_cross_session"`` -- SHA-256 digest state saved on session A, restored on B.
  ``"encrypt_same_session"`` -- AES-CBC multi-part encrypt state save/restore on one session.
"""

from __future__ import annotations

import binascii
import ctypes
import hashlib
import sys
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw import CK_ATTRIBUTE_PTR, CK_MECHANISM, CK_OBJECT_HANDLE
from pkcs11_check.raw.bootstrap import close_session_quietly, open_session
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_KEY_GEN,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_STATE_UNSAVEABLE,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: Any) -> Any:
    return ctypes.cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data: bytes) -> Any:
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _run_digest_same_session(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """SHA-256 multi-part digest state save/restore on the same session."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ulong = ctypes.c_ulong
    c_ubyte = ctypes.c_ubyte

    part1 = b"Hello, "
    part2 = b"PKCS#11 state!"

    # Reference via hashlib
    ref = hashlib.sha256(part1 + part2).hexdigest()
    print(f"REFERENCE:{ref}")

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256

    # --- Single-shot cross-check ---
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv != CKR_OK:
        print(f"FATAL:DigestInit_1shot:0x{rv:08x}")
        sys.exit(1)
    full = part1 + part2
    full_buf = _byte_array(full)
    rv = raw.C_DigestUpdate(sh, full_buf, c_ulong(len(full)))
    if rv != CKR_OK:
        print(f"FATAL:DigestUpdate_1shot:0x{rv:08x}")
        sys.exit(1)
    dlen = c_ulong(32)
    dbuf = (c_ubyte * 32)()
    rv = raw.C_DigestFinal(sh, dbuf, byref(dlen))
    if rv != CKR_OK:
        print(f"FATAL:DigestFinal_1shot:0x{rv:08x}")
        sys.exit(1)
    singleshot = binascii.hexlify(bytes(dbuf[: dlen.value])).decode()
    if singleshot != ref:
        print(f"FATAL:SingleshotMismatch:got={singleshot} ref={ref}")
        sys.exit(1)
    print(f"SINGLESHOT_OK:{singleshot}")

    # --- Multi-part with state save/restore ---
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv != CKR_OK:
        print(f"FATAL:DigestInit_mp:0x{rv:08x}")
        sys.exit(1)
    part1_buf = _byte_array(part1)
    rv = raw.C_DigestUpdate(sh, part1_buf, c_ulong(len(part1)))
    if rv != CKR_OK:
        print(f"FATAL:DigestUpdate_mp:0x{rv:08x}")
        sys.exit(1)

    # Save state (length query)
    state_len = c_ulong(0)
    rv = raw.C_GetOperationState(sh, None, byref(state_len))
    if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
        print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GetState_len:0x{rv:08x}")
        sys.exit(1)

    # Save state (data)
    state_buf = (c_ubyte * state_len.value)()
    rv = raw.C_GetOperationState(sh, state_buf, byref(state_len))
    if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
        print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GetState_data:0x{rv:08x}")
        sys.exit(1)
    state_bytes = bytes(state_buf[: state_len.value])
    state_bytes_buf = _byte_array(state_bytes)
    print(f"STATE_SAVED:{len(state_bytes)}")

    # Restore state on the same session
    rv = raw.C_SetOperationState(
        sh,
        state_bytes_buf,
        c_ulong(len(state_bytes)),
        c_ulong(0),
        c_ulong(0),
    )
    if rv != CKR_OK:
        print(f"FATAL:SetOperationState:0x{rv:08x}")
        sys.exit(1)
    print("STATE_RESTORED")

    # Continue with part2 and finalise
    part2_buf = _byte_array(part2)
    rv = raw.C_DigestUpdate(sh, part2_buf, c_ulong(len(part2)))
    if rv != CKR_OK:
        print(f"FATAL:DigestUpdate_part2:0x{rv:08x}")
        sys.exit(1)
    dlen2 = c_ulong(32)
    dbuf2 = (c_ubyte * 32)()
    rv = raw.C_DigestFinal(sh, dbuf2, byref(dlen2))
    if rv != CKR_OK:
        print(f"FATAL:DigestFinal_mp:0x{rv:08x}")
        sys.exit(1)
    restored = binascii.hexlify(bytes(dbuf2[: dlen2.value])).decode()
    print(f"RESTORED:{restored}")


def _run_digest_cross_session(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """SHA-256 digest state saved on session A, restore attempted on session B."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    assert ctx.slot_id is not None, "probe requires a slot (Level.LOGIN)"
    sh = ctx.sh
    slot_id = ctx.slot_id

    byref = ctypes.byref
    c_ulong = ctypes.c_ulong
    c_ubyte = ctypes.c_ubyte

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256

    part1 = b"cross-session data"
    part1_buf = _byte_array(part1)

    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv != CKR_OK:
        print(f"SKIP:DigestInitFailed:0x{rv:08x}")
        sys.exit(0)

    rv = raw.C_DigestUpdate(sh, part1_buf, c_ulong(len(part1)))
    if rv != CKR_OK:
        print(f"SKIP:DigestUpdateFailed:0x{rv:08x}")
        sys.exit(0)

    # Save state
    state_len = c_ulong(0)
    rv = raw.C_GetOperationState(sh, None, byref(state_len))
    if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
        print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"SKIP:GetStateFailed:0x{rv:08x}")
        sys.exit(0)

    state_buf = (c_ubyte * state_len.value)()
    rv = raw.C_GetOperationState(sh, state_buf, byref(state_len))
    if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
        print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"SKIP:GetStateDataFailed:0x{rv:08x}")
        sys.exit(0)
    state_bytes = bytes(state_buf[: state_len.value])
    state_bytes_buf = _byte_array(state_bytes)
    print(f"STATE_SAVED:{len(state_bytes)}")

    # Open a second session
    try:
        sh2 = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    except AssertionError as exc:
        if "CKR_" in str(exc):
            print(f"SKIP:OpenSession2Failed:{exc}")
            sys.exit(0)
        raise

    # Try to restore state on the second session
    rv2 = raw.C_SetOperationState(
        sh2,
        state_bytes_buf,
        c_ulong(len(state_bytes)),
        c_ulong(0),
        c_ulong(0),
    )
    if rv2 == CKR_OK:
        print("CROSS_SESSION_ACCEPTED:1")
    else:
        print(f"CROSS_SESSION_REJECTED:0x{rv2:08x}")

    close_session_quietly(raw, sh2)


def _run_encrypt_same_session(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CBC multi-part encrypt state save/restore on the same session."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ulong = ctypes.c_ulong
    c_ubyte = ctypes.c_ubyte
    c_void_p = ctypes.c_void_p

    # 16-byte IV and two 16-byte plaintext blocks (AES-CBC block-aligned)
    iv = b"\x00" * 16
    part1 = b"Block-one-data!!"  # 16 bytes
    part2 = b"Block-two-data!!"  # 16 bytes
    part1_buf = _byte_array(part1)
    part2_buf = _byte_array(part2)

    # Build AES key-gen template
    attrs = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_AES),
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )

    kg_mech = mech_simple(CKM_AES_KEY_GEN)

    h_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, kg_mech.byref(), _template_ptr(attrs), attrs.count, byref(h_key))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED,):
        print(f"SKIP:GenerateKeyUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKey:0x{rv:08x}")
        sys.exit(1)
    print(f"KEY_GENERATED:{h_key.value}")

    # Build AES-CBC mechanism with IV as parameter
    iv_buf = (c_ubyte * 16)(*iv)
    enc_mech = CK_MECHANISM()
    enc_mech.mechanism = CKM_AES_CBC
    enc_mech.pParameter = ctypes.cast(iv_buf, c_void_p)
    enc_mech.ulParameterLen = 16

    # --- Reference encryption (no state save) ---
    rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), h_key)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED,):
        print(f"SKIP:EncryptInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit_ref:0x{rv:08x}")
        sys.exit(1)

    ref_out = bytearray()
    out_len = c_ulong(32)
    out_buf = (c_ubyte * 32)()

    rv = raw.C_EncryptUpdate(sh, part1_buf, c_ulong(len(part1)), out_buf, byref(out_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate_ref1:0x{rv:08x}")
        sys.exit(1)
    ref_out += bytes(out_buf[: out_len.value])

    out_len2 = c_ulong(32)
    out_buf2 = (c_ubyte * 32)()
    rv = raw.C_EncryptUpdate(sh, part2_buf, c_ulong(len(part2)), out_buf2, byref(out_len2))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate_ref2:0x{rv:08x}")
        sys.exit(1)
    ref_out += bytes(out_buf2[: out_len2.value])

    final_len = c_ulong(32)
    final_buf = (c_ubyte * 32)()
    rv = raw.C_EncryptFinal(sh, final_buf, byref(final_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal_ref:0x{rv:08x}")
        sys.exit(1)
    ref_out += bytes(final_buf[: final_len.value])
    ref_hex = binascii.hexlify(bytes(ref_out)).decode()
    print(f"REFERENCE:{ref_hex}")

    # --- Multi-part encryption with state save/restore ---
    rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), h_key)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit_mp:0x{rv:08x}")
        sys.exit(1)

    mp_out = bytearray()
    mp_len1 = c_ulong(32)
    mp_buf1 = (c_ubyte * 32)()
    rv = raw.C_EncryptUpdate(sh, part1_buf, c_ulong(len(part1)), mp_buf1, byref(mp_len1))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate_mp1:0x{rv:08x}")
        sys.exit(1)
    mp_out += bytes(mp_buf1[: mp_len1.value])

    # Save encrypt state (length query)
    state_len = c_ulong(0)
    rv = raw.C_GetOperationState(sh, None, byref(state_len))
    if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
        print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GetState_len:0x{rv:08x}")
        sys.exit(1)

    # Save encrypt state (data)
    state_buf = (c_ubyte * state_len.value)()
    rv = raw.C_GetOperationState(sh, state_buf, byref(state_len))
    if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
        print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GetState_data:0x{rv:08x}")
        sys.exit(1)
    state_bytes = bytes(state_buf[: state_len.value])
    state_bytes_buf = _byte_array(state_bytes)
    print(f"STATE_SAVED:{len(state_bytes)}")

    # Restore state on the same session, supplying the encryption key handle
    rv = raw.C_SetOperationState(
        sh,
        state_bytes_buf,
        c_ulong(len(state_bytes)),
        h_key,  # hEncryptionKey
        c_ulong(0),  # hAuthenticationKey (not used)
    )
    if rv != CKR_OK:
        print(f"FATAL:SetOperationState:0x{rv:08x}")
        sys.exit(1)
    print("STATE_RESTORED")

    # Continue encryption from restored state
    mp_len2 = c_ulong(32)
    mp_buf2 = (c_ubyte * 32)()
    rv = raw.C_EncryptUpdate(sh, part2_buf, c_ulong(len(part2)), mp_buf2, byref(mp_len2))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate_mp2:0x{rv:08x}")
        sys.exit(1)
    mp_out += bytes(mp_buf2[: mp_len2.value])

    mp_final_len = c_ulong(32)
    mp_final_buf = (c_ubyte * 32)()
    rv = raw.C_EncryptFinal(sh, mp_final_buf, byref(mp_final_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal_mp:0x{rv:08x}")
        sys.exit(1)
    mp_out += bytes(mp_final_buf[: mp_final_len.value])

    restored_hex = binascii.hexlify(bytes(mp_out)).decode()
    print(f"RESTORED:{restored_hex}")


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "digest_same_session": _run_digest_same_session,
    "digest_cross_session": _run_digest_cross_session,
    "encrypt_same_session": _run_encrypt_same_session,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"operation_state probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
