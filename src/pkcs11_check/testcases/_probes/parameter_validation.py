"""Probe: AEAD NULL-pointer / non-zero-length mismatch parameter validation.

Ports the two subprocess child bodies from
``security/test_parameter_validation.py`` (CCM NULL nonce and GCM NULL AAD) into
dispatchable probe functions.  Each builds a ``CK_*_PARAMS`` struct with a NULL
pointer field but a non-zero *matching* length and calls ``C_EncryptInit``.  A
conformant module must return a clean CKR (or initialise) without dereferencing
the NULL pointer -- a crash is the finding.

The single protocol line ``rv=<int>`` is byte-identical to the original f-string
child so the parent (``assert_subprocess_no_crash``) needs no changes.

Both probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"ccm_null_nonce"`` -- CK_CCM_PARAMS with ``pNonce=NULL`` and ``ulNonceLen=13``.
  ``"gcm_null_aad"``   -- CK_AES_GCM_PARAMS with ``pAAD=NULL`` and ``ulAADLen=16``.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS,
    CK_CCM_PARAMS,
    CK_MECHANISM,
    CKM_AES_CCM,
    CKM_AES_GCM,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def build_ccm_null_nonce_params() -> CK_CCM_PARAMS:
    """Build CK_CCM_PARAMS with a NULL nonce pointer but non-zero ulNonceLen.

    The deliberate NULL-pointer + non-zero-length mismatch this probe exercises.
    """
    params = CK_CCM_PARAMS()
    params.ulDataLen = 0
    params.pNonce = None  # NULL pointer
    params.ulNonceLen = 13  # Non-zero length -- mismatch!
    params.pAAD = None
    params.ulAADLen = 0
    params.ulMACLen = 16
    return params


def build_gcm_null_aad_params() -> tuple[CK_AES_GCM_PARAMS, Any]:
    """Build CK_AES_GCM_PARAMS with a NULL AAD pointer but non-zero ulAADLen.

    Returns ``(params, iv_keepalive)``: the IV buffer is cast into the ``pIv``
    pointer field, so the caller MUST keep ``iv_keepalive`` alive for as long as
    ``params.pIv`` is dereferenced (PC-1: the original probe assigned a raw ctypes
    array straight to ``pIv``, which raised before ``C_EncryptInit`` was reached).
    """
    params = CK_AES_GCM_PARAMS()
    iv_buf = (ctypes.c_ubyte * 12)(*range(12))
    params.pIv = ctypes.cast(iv_buf, ctypes.c_void_p)
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = None  # NULL pointer
    params.ulAADLen = 16  # Non-zero length -- mismatch!
    params.ulTagBits = 128
    return params, iv_buf


def _run_ccm_null_nonce(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit(CKM_AES_CCM) with a NULL nonce pointer + non-zero ulNonceLen."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    key = gen_aes_key(raw, sh, 256)
    params = build_ccm_null_nonce_params()
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    try:
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_gcm_null_aad(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit(CKM_AES_GCM) with a NULL AAD pointer + non-zero ulAADLen."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    key = gen_aes_key(raw, sh, 256)
    # Hold the IV buffer alive until after C_EncryptInit (params.pIv points into it).
    params, _iv_keepalive = build_gcm_null_aad_params()
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    try:
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"rv={rv}")
    finally:
        destroy_quietly(raw, sh, key)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "ccm_null_nonce": _run_ccm_null_nonce,
    "gcm_null_aad": _run_gcm_null_aad,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"parameter_validation probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
