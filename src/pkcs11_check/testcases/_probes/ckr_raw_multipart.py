"""Probe: CKR multipart-operation error conditions via a raw session.

Twelve child bodies ported verbatim from the legacy ``ckr/test_ckr_raw_multipart.py``
scripts, dispatched on ``extra["probe"]``.  Each drives a multipart crypto call
(``C_EncryptUpdate`` / ``C_EncryptFinal`` / ``C_DecryptUpdate`` / ``C_DecryptFinal`` /
``C_SignUpdate`` / ``C_SignFinal`` / ``C_DigestUpdate`` / ``C_DigestFinal`` /
``C_VerifyUpdate`` / ``C_VerifyFinal``) through a ``RawPKCS11`` session and prints the
resulting ``CKR:0x...`` line for the parent-side ``_classify_multipart_ckr`` classifier.

Two groups:
  - ``*_update`` / ``*_final`` (no prior ``C_*Init``): a C_*Update/Final without the matching
    C_*Init must reject with CKR_OPERATION_NOT_INITIALIZED.
  - ``digest_update_after_final`` / ``encrypt_update_after_final``: run a full multipart op to
    completion, then a C_*Update on the terminated operation (PKCS#11 v3.2 §5.2) -- must reject
    with CKR_OPERATION_NOT_INITIALIZED.  Setup failures print ``SETUP_XFAIL:...`` (advertised
    capability not operational -> parent xfail).

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot discovery +
``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before handing the probe
``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a session and logged in
*only* when a PIN was configured.  The PIN travels ONLY via the ``_P11CHECK_PIN`` env var; it is
never read, printed, or embedded here or in the probe params.  This CLOSES the legacy leak that
formatted the PIN literal into the generated child-script source (Invariant I3).  Session
teardown + rv-trace are handled by ``probe_main`` atexit, matching the legacy
``_p11check_cleanup_session`` / rv-trace setup.

Output protocol (byte-identical to the legacy child, for ``_classify_multipart_ckr`` over the
first ``CKR:0x...`` line):
  ``CKR:0x{rv:08x}``   -- return value of the tested multipart call
  ``SETUP_XFAIL:...``  -- a setup step (Init/Update/Final/keygen) cleanly failed before the probe
  ``OK``               -- probe reached its expected point

A wrong CK_RV is classified in the parent (not via an in-child ``assert``); a crash
(returncode < 0) is a provider crash finding.

Required ``extra`` keys:
  ``"probe"`` -- one of the dispatch keys below.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CKM_AES_ECB,
    CKM_SHA256,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _encrypt_update(ctx: ProbeContext) -> None:
    """C_EncryptUpdate without C_EncryptInit."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    out = (ctypes.c_ubyte * 32)()
    out_len = ctypes.c_ulong(32)
    rv = ctx.raw.C_EncryptUpdate(ctx.sh, data, 16, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _encrypt_final(ctx: ProbeContext) -> None:
    """C_EncryptFinal without C_EncryptInit."""
    out = (ctypes.c_ubyte * 32)()
    out_len = ctypes.c_ulong(32)
    rv = ctx.raw.C_EncryptFinal(ctx.sh, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _decrypt_update(ctx: ProbeContext) -> None:
    """C_DecryptUpdate without C_DecryptInit."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    out = (ctypes.c_ubyte * 32)()
    out_len = ctypes.c_ulong(32)
    rv = ctx.raw.C_DecryptUpdate(ctx.sh, data, 16, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _decrypt_final(ctx: ProbeContext) -> None:
    """C_DecryptFinal without C_DecryptInit."""
    out = (ctypes.c_ubyte * 32)()
    out_len = ctypes.c_ulong(32)
    rv = ctx.raw.C_DecryptFinal(ctx.sh, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _sign_update(ctx: ProbeContext) -> None:
    """C_SignUpdate without C_SignInit."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    rv = ctx.raw.C_SignUpdate(ctx.sh, data, 16)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _sign_final(ctx: ProbeContext) -> None:
    """C_SignFinal without C_SignInit."""
    out = (ctypes.c_ubyte * 256)()
    out_len = ctypes.c_ulong(256)
    rv = ctx.raw.C_SignFinal(ctx.sh, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _digest_update(ctx: ProbeContext) -> None:
    """C_DigestUpdate without C_DigestInit."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    rv = ctx.raw.C_DigestUpdate(ctx.sh, data, 16)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _digest_final(ctx: ProbeContext) -> None:
    """C_DigestFinal without C_DigestInit."""
    out = (ctypes.c_ubyte * 64)()
    out_len = ctypes.c_ulong(64)
    rv = ctx.raw.C_DigestFinal(ctx.sh, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _verify_update(ctx: ProbeContext) -> None:
    """C_VerifyUpdate without C_VerifyInit."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    rv = ctx.raw.C_VerifyUpdate(ctx.sh, data, 16)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _verify_final(ctx: ProbeContext) -> None:
    """C_VerifyFinal without C_VerifyInit."""
    sig = (ctypes.c_ubyte * 32)(*([0] * 32))
    rv = ctx.raw.C_VerifyFinal(ctx.sh, sig, 32)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _digest_update_after_final(ctx: ProbeContext) -> None:
    """C_DigestUpdate after C_DigestFinal must return CKR_OPERATION_NOT_INITIALIZED."""
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256)
    mech.pParameter = None
    mech.ulParameterLen = 0

    # Init
    rv_init = ctx.raw.C_DigestInit(ctx.sh, ctypes.byref(mech))
    if rv_init != CKR_OK:
        print(f"SETUP_XFAIL: C_DigestInit(SHA256) not operational: 0x{rv_init:08x}")
        print("OK")
    else:
        # Feed some data
        data = (ctypes.c_ubyte * 4)(*[0x61, 0x62, 0x63, 0x64])
        rv_upd = ctx.raw.C_DigestUpdate(ctx.sh, data, 4)
        if rv_upd != CKR_OK:
            print(f"SETUP_XFAIL: C_DigestUpdate failed: 0x{rv_upd:08x}")
            print("OK")
        else:
            # Finalize
            digest_buf = (ctypes.c_ubyte * 64)()
            digest_len = ctypes.c_ulong(64)
            rv_final = ctx.raw.C_DigestFinal(ctx.sh, digest_buf, ctypes.byref(digest_len))
            if rv_final != CKR_OK:
                print(f"SETUP_XFAIL: C_DigestFinal failed: 0x{rv_final:08x}")
                print("OK")
            else:
                # Probe: C_DigestUpdate after Final -- must return OPERATION_NOT_INITIALIZED
                data2 = (ctypes.c_ubyte * 4)(*[0x65, 0x66, 0x67, 0x68])
                rv = ctx.raw.C_DigestUpdate(ctx.sh, data2, 4)
                print(f"CKR:0x{rv:08x}")
                print("OK")


def _encrypt_update_after_final(ctx: ProbeContext) -> None:
    """C_EncryptUpdate after C_EncryptFinal must return CKR_OPERATION_NOT_INITIALIZED."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    # Generate a 128-bit AES key for encrypt
    key_handle = 0
    try:
        key_handle = gen_aes_key(ctx.raw, sh, 128)
    except AssertionError as exc:
        print(f"SETUP_XFAIL: AES_KEY_GEN not operational: {exc}")
        print("OK")
    if key_handle:
        mech_enc = CK_MECHANISM()
        mech_enc.mechanism = int(CKM_AES_ECB)
        mech_enc.pParameter = None
        mech_enc.ulParameterLen = 0

        rv_init = ctx.raw.C_EncryptInit(sh, ctypes.byref(mech_enc), key_handle)
        if rv_init != CKR_OK:
            destroy_quietly(ctx.raw, sh, key_handle)
            print(f"SETUP_XFAIL: C_EncryptInit(AES_ECB) not operational: 0x{rv_init:08x}")
            print("OK")
        else:
            # Feed one block
            plain = (ctypes.c_ubyte * 16)(*([0] * 16))
            enc_buf = (ctypes.c_ubyte * 32)()
            enc_len = ctypes.c_ulong(32)
            rv_upd = ctx.raw.C_EncryptUpdate(sh, plain, 16, enc_buf, ctypes.byref(enc_len))
            if rv_upd != CKR_OK:
                destroy_quietly(ctx.raw, sh, key_handle)
                print(f"SETUP_XFAIL: C_EncryptUpdate failed: 0x{rv_upd:08x}")
                print("OK")
            else:
                # Finalize
                fin_buf = (ctypes.c_ubyte * 32)()
                fin_len = ctypes.c_ulong(32)
                rv_final = ctx.raw.C_EncryptFinal(sh, fin_buf, ctypes.byref(fin_len))
                destroy_quietly(ctx.raw, sh, key_handle)
                if rv_final != CKR_OK:
                    print(f"SETUP_XFAIL: C_EncryptFinal failed: 0x{rv_final:08x}")
                    print("OK")
                else:
                    # Probe: C_EncryptUpdate after Final -- must be OPERATION_NOT_INITIALIZED
                    plain2 = (ctypes.c_ubyte * 16)(*([0xFF] * 16))
                    enc_buf2 = (ctypes.c_ubyte * 32)()
                    enc_len2 = ctypes.c_ulong(32)
                    rv = ctx.raw.C_EncryptUpdate(sh, plain2, 16, enc_buf2, ctypes.byref(enc_len2))
                    print(f"CKR:0x{rv:08x}")
                    print("OK")


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "encrypt_update": _encrypt_update,
    "encrypt_final": _encrypt_final,
    "decrypt_update": _decrypt_update,
    "decrypt_final": _decrypt_final,
    "sign_update": _sign_update,
    "sign_final": _sign_final,
    "digest_update": _digest_update,
    "digest_final": _digest_final,
    "verify_update": _verify_update,
    "verify_final": _verify_final,
    "digest_update_after_final": _digest_update_after_final,
    "encrypt_update_after_final": _encrypt_update_after_final,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
