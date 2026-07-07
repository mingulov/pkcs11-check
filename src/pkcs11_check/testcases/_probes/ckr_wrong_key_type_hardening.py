"""Probe: wrong asymmetric key-type operation-continuation crash safety.

Ports the f-string child-script bodies from
``ckr/test_ckr_wrong_key_type_hardening.py`` into dispatchable probe functions.
Each probe generates a fresh RSA 2048-bit keypair, then drives a *terminal*
operation (C_Sign / C_Verify) under CKM_ECDSA with the wrong (RSA) key to check
that a module lenient at ``*Init`` does not leave a usable wrong-key operation
behind.

The contract is "a wrong key type must not leave a USABLE operation behind".
Classify by effect, not by the ``*Init`` return code:
  - ``*Init`` rejects (any clean CK_RV)              -> no usable op    (OK)
  - ``*Init`` lenient (CKR_OK), terminal op refuses  -> safe deviation  (xfail)
  - ``*Init`` lenient (CKR_OK), terminal op succeeds  -> usable wrong-key op (fail)
  - either call crashes                              -> signal death    (fail)

Output protocol lines (``OK:``, ``BREAK:``, ``DEVIATION_XFAIL:``) are
byte-identical to the originals so the parent (assert_ckr_subprocess_ok)
requires no changes.

Both probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"sign"``   -- RSA private key under CKM_ECDSA: C_SignInit then C_Sign.
  ``"verify"`` -- RSA public key under CKM_ECDSA: C_VerifyInit then C_Verify.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_ECDSA,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _gen_rsa_sign_verify_keypair(raw: Any, sh: int) -> tuple[int, int]:
    """Generate the RSA sign/verify keypair shared by both probes."""
    return gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={int(CKA_VERIFY): True, int(CKA_TOKEN): False},
        private_attrs={int(CKA_SIGN): True, int(CKA_TOKEN): False},
    )


def _run_sign(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """RSA private key under CKM_ECDSA: C_SignInit then C_Sign if accepted."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    pub, priv = _gen_rsa_sign_verify_keypair(raw, sh)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDSA
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
        if rv != CKR_OK:
            print(f"OK:C_SignInit rejected wrong RSA key for ECDSA: {ckr_name(rv)}", flush=True)
        else:
            data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
            sig = (ctypes.c_ubyte * 512)()
            sig_len = CK_ULONG(512)
            sign_rv = raw.C_Sign(sh, data, 32, sig, ctypes.byref(sig_len))
            if int(sign_rv) == int(CKR_OK):
                print(
                    "BREAK:C_SignInit(CKM_ECDSA, RSA private key) returned CKR_OK and "
                    "C_Sign PRODUCED a signature -- usable wrong-key operation",
                    flush=True,
                )
            else:
                print(
                    "DEVIATION_XFAIL:C_SignInit(CKM_ECDSA, RSA private key) accepted "
                    f"(CKR_OK) but C_Sign safely refused with {ckr_name(sign_rv)} -- "
                    "lenient init, no usable operation (PKCS#11 5.2 prefers "
                    "CKR_KEY_TYPE_INCONSISTENT at init)",
                    flush=True,
                )
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_verify(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """RSA public key under CKM_ECDSA: C_VerifyInit then C_Verify if accepted."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    pub, priv = _gen_rsa_sign_verify_keypair(raw, sh)
    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDSA
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
        if rv != CKR_OK:
            print(f"OK:C_VerifyInit rejected wrong RSA key for ECDSA: {ckr_name(rv)}", flush=True)
        else:
            data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
            sig = (ctypes.c_ubyte * 64)(*([0xA5] * 64))
            verify_rv = raw.C_Verify(sh, data, 32, sig, 64)
            if int(verify_rv) == int(CKR_OK):
                print(
                    "BREAK:C_VerifyInit(CKM_ECDSA, RSA public key) returned CKR_OK and "
                    "C_Verify ACCEPTED a signature -- usable wrong-key operation",
                    flush=True,
                )
            else:
                print(
                    "DEVIATION_XFAIL:C_VerifyInit(CKM_ECDSA, RSA public key) accepted "
                    f"(CKR_OK) but C_Verify safely refused with {ckr_name(verify_rv)} -- "
                    "lenient init, no usable operation (PKCS#11 5.2 prefers "
                    "CKR_KEY_TYPE_INCONSISTENT at init)",
                    flush=True,
                )
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "sign": _run_sign,
    "verify": _run_verify,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"ckr_wrong_key_type_hardening probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
