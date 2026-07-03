"""Probe: RSA PKCS#1 v1.5 / OAEP decrypt + verify error paths (crash safety).

Ports the f-string child-script bodies from security/test_error_path_rsa.py into
dispatchable probe functions.  Each probe generates a fresh RSA 2048-bit keypair,
crafts a malformed ciphertext or a bit-flipped signature sized relative to the
actual modulus, and calls C_Decrypt / C_Verify.  A conformant module must return
a CKR error cleanly -- never crash.

Output protocol lines (``decrypt_init_rv=<CKR>``, ``decrypt_rv=<CKR>``,
``verify_init_rv=<CKR>``, ``verify_rv=<CKR>``) are byte-identical to the original
so the parent (assert_subprocess_no_crash) requires no changes.

Both probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"decrypt"`` -- RSA decrypt of a malformed ciphertext.  Extra keys:
                   ``mech`` (``"pkcs"`` | ``"oaep"``), ``variant``
                   (``"random"`` | ``"truncated"`` | ``"extended"`` |
                   ``"all_zeros"`` | ``"all_ff"``).
  ``"verify"``  -- RSA SHA256_RSA_PKCS verify of a bit-flipped signature.  No
                   extra keys beyond ``probe``.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_MODULUS,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKG_MGF1_SHA256,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _make_bad_ct(variant: str, mod_len: int) -> bytes:
    """Build a malformed ciphertext of the requested corruption variant."""
    if variant == "random":
        return os.urandom(mod_len)
    if variant == "truncated":
        return os.urandom(mod_len // 2)
    if variant == "extended":
        return os.urandom(mod_len + 16)
    if variant == "all_zeros":
        return bytes(mod_len)
    if variant == "all_ff":
        return b"\xff" * mod_len
    raise ValueError(f"error_path_rsa probe: unknown decrypt 'variant' value {variant!r}")


def _pkcs_decrypt(raw: Any, sh: int, priv: int, bad_ct: bytes, mod_len: int) -> None:
    """C_DecryptInit(CKM_RSA_PKCS) + C_Decrypt on the malformed ciphertext."""
    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv)
    if rv != 0:
        print(f"decrypt_init_rv={rv}")
    else:
        ct_buf = (ctypes.c_ubyte * len(bad_ct))(*bad_ct)
        out_buf = (ctypes.c_ubyte * (mod_len + 16))()
        out_len = CK_ULONG(mod_len + 16)
        rv = raw.C_Decrypt(sh, ct_buf, len(bad_ct), out_buf, ctypes.byref(out_len))
        print(f"decrypt_rv={rv}")


def _oaep_decrypt(raw: Any, sh: int, priv: int, bad_ct: bytes, mod_len: int) -> None:
    """C_DecryptInit(CKM_RSA_PKCS_OAEP) + C_Decrypt on the malformed ciphertext."""
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = CKM_SHA256
    params.mgf = CKG_MGF1_SHA256
    params.source = 0
    params.pSourceData = None
    params.ulSourceDataLen = 0

    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_OAEP
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv)
    if rv != 0:
        print(f"decrypt_init_rv={rv}")
    else:
        ct_buf = (ctypes.c_ubyte * len(bad_ct))(*bad_ct)
        out_buf = (ctypes.c_ubyte * (mod_len + 16))()
        out_len = CK_ULONG(mod_len + 16)
        rv = raw.C_Decrypt(sh, ct_buf, len(bad_ct), out_buf, ctypes.byref(out_len))
        print(f"decrypt_rv={rv}")


def _run_decrypt(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Generate an RSA keypair, craft a malformed ciphertext, and C_Decrypt it."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        private_attrs={int(CKA_DECRYPT): True, int(CKA_TOKEN): False},
        public_attrs={int(CKA_ENCRYPT): True, int(CKA_TOKEN): False},
    )
    try:
        attrs = read_attributes(raw, sh, pub, [int(CKA_MODULUS)])
        mod_bytes = attrs[int(CKA_MODULUS)]
        mod_len = len(mod_bytes)

        bad_ct = _make_bad_ct(extra["variant"], mod_len)
        if extra["mech"] == "pkcs":
            _pkcs_decrypt(raw, sh, priv, bad_ct, mod_len)
        else:
            _oaep_decrypt(raw, sh, priv, bad_ct, mod_len)
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


def _run_verify(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Sign valid data, flip a bit in the signature, and C_Verify it."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        private_attrs={int(CKA_SIGN): True, int(CKA_TOKEN): False},
        public_attrs={int(CKA_VERIFY): True, int(CKA_TOKEN): False},
    )
    try:
        # Sign valid data to get a well-formed signature
        sig = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, b"test data for verification")

        # Flip first bit in signature to corrupt it
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0x01
        bad_sig_bytes = bytes(bad_sig)

        # Attempt verify with corrupted signature
        data = b"test data for verification"
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
        if rv != 0:
            print(f"verify_init_rv={rv}")
        else:
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * len(bad_sig_bytes))(*bad_sig_bytes)
            rv = raw.C_Verify(sh, data_buf, len(data), sig_buf, len(bad_sig_bytes))
            print(f"verify_rv={rv}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "decrypt": _run_decrypt,
    "verify": _run_verify,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"error_path_rsa probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
