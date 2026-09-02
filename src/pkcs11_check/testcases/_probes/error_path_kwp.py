"""Probe: AES-KWP / AES-KW unwrap/decrypt error paths on corrupted wrapped blobs.

Ports the f-string child-script bodies from security/test_error_path_kwp.py into
dispatchable probe functions.  Each probe generates a 256-bit AES wrapping key,
wraps a 128-bit AES target key with AES-KWP or AES-KW, corrupts the wrapped blob,
then attempts to unwrap (C_UnwrapKey) or decrypt (C_Decrypt) the corrupted data.
A crash (negative returncode = signal), child-script failure, or output-buffer
guard overwrite confirms the vulnerability.

Targets heap overflows found in:
- heap overflow in AES-KWP unwrap (module error path)
- OpenSSL PR #30663: heap overflow in AES-KW unwrap with corrupted data

Output protocol lines (``unwrap_rv=<CKR>``, ``decrypt_init_rv=<CKR>``,
``decrypt_rv=<CKR>``, and the ``SETUP_XFAIL:`` marker) are byte-identical to the
original so the parent (assert_subprocess_no_crash + _parse_op_rv +
classify_negative_rv) requires no changes.

Both probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"corrupted_unwrap"`` -- 8 corruption types x {unwrap, decrypt}.  Extra keys:
                            ``ckm_name`` (CKM symbol name), ``corruption`` (type),
                            ``api`` ("unwrap" | "decrypt").
  ``"bit_flip_unwrap"``  -- single-bit flip at a byte offset, always via unwrap.
                            Extra keys: ``ckm_name``, ``offset`` (int).
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw import types_std
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.recipes import wrap_key as wrap_key_recipe
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_WRAP,
    CKK_AES,
    CKO_SECRET_KEY,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# Clean rejections of the wrap *setup* (advertised but not operational for this
# key/mechanism). Classified as SETUP_XFAIL so the probe's real target -- unwrap
# integrity on a corrupted blob -- is not scored as a provider failure. An
# unexpected error or a crash is NOT in this set and still surfaces.
_WRAP_SETUP_REJECT_RVS = (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)


def _apply_corruption(wrapped_blob: bytes, corruption_type: str) -> bytes:
    """Apply a named corruption to the wrapped blob (mirrors _CORRUPTION_CODE)."""
    blob = bytearray(wrapped_blob)

    if corruption_type == "aiv":
        for i in range(min(4, len(blob))):
            blob[i] ^= 0xFF
    elif corruption_type == "padding":
        for i in range(max(0, len(blob) - 8), len(blob)):
            blob[i] ^= 0xFF
    elif corruption_type == "length":
        for i in range(4, min(8, len(blob))):
            blob[i] ^= 0xFF
    elif corruption_type == "truncate":
        blob = blob[:-8]
    elif corruption_type == "extend":
        blob = blob + bytearray(os.urandom(8))
    elif corruption_type == "random":
        blob = bytearray(os.urandom(len(blob)))
    elif corruption_type == "all_zeros":
        blob = bytearray(len(blob))
    elif corruption_type == "all_ff":
        blob = bytearray(b"\xff" * len(blob))

    return bytes(blob)


def _apply_bit_flip(wrapped_blob: bytes, offset: int) -> bytes:
    """Flip bit 0 at *offset* in the wrapped blob (mirrors _BIT_FLIP_CODE)."""
    blob = bytearray(wrapped_blob)
    if offset < len(blob):
        blob[offset] ^= 0x01
    return bytes(blob)


def _do_unwrap(raw: Any, sh: int, wrap_key: int, corrupted: bytes, ckm: int) -> None:
    """Attempt C_UnwrapKey on the corrupted blob (mirrors _UNWRAP_CODE)."""
    tmpl_attrs = [
        (int(CKA_CLASS), int(CKO_SECRET_KEY)),
        (int(CKA_KEY_TYPE), int(CKK_AES)),
        (int(CKA_ENCRYPT), 1),
        (int(CKA_DECRYPT), 1),
        (int(CKA_TOKEN), 0),
    ]
    attrs = (CK_ATTRIBUTE * len(tmpl_attrs))()
    vals = []
    for i, (atype, aval) in enumerate(tmpl_attrs):
        attrs[i].type = atype
        v = CK_ULONG(aval)
        vals.append(v)
        attrs[i].pValue = ctypes.cast(ctypes.pointer(v), ctypes.c_void_p)
        attrs[i].ulValueLen = ctypes.sizeof(v)

    mech = CK_MECHANISM()
    mech.mechanism = ckm
    mech.pParameter = None
    mech.ulParameterLen = 0

    data_buf = (ctypes.c_ubyte * len(corrupted))(*corrupted)
    new_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        sh,
        ctypes.byref(mech),
        wrap_key,
        data_buf,
        len(corrupted),
        attrs,
        len(tmpl_attrs),
        ctypes.byref(new_key),
    )
    print(f"unwrap_rv={rv}")
    if rv == 0:
        raw.C_DestroyObject(sh, new_key)


def _do_decrypt(
    raw: Any, sh: int, wrap_key: int, corrupted: bytes, ckm: int, ckm_name: str
) -> None:
    """Attempt C_DecryptInit + C_Decrypt on the corrupted blob (mirrors _DECRYPT_CODE)."""
    mech = CK_MECHANISM()
    mech.mechanism = ckm
    mech.pParameter = None
    mech.ulParameterLen = 0

    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), wrap_key)
    if rv != 0:
        print(f"decrypt_init_rv={rv}")
    else:
        data_buf = (ctypes.c_ubyte * len(corrupted))(*corrupted)
        minimal_len = max(0, len(corrupted) - 8)
        guard_sentinel = b"PKCS11CHK"
        out_buf = (ctypes.c_ubyte * (minimal_len + len(guard_sentinel)))()
        for i, byte in enumerate(guard_sentinel):
            out_buf[minimal_len + i] = byte
        out_len = CK_ULONG(minimal_len)
        rv = raw.C_Decrypt(sh, data_buf, len(corrupted), out_buf, ctypes.byref(out_len))
        print(f"decrypt_rv={rv}")
        guard = bytes(out_buf[minimal_len : minimal_len + len(guard_sentinel)])
        if guard != guard_sentinel:
            raise AssertionError(
                "C_Decrypt wrote past the minimal output buffer on a corrupted "
                f"{ckm_name} error path: guard={guard.hex()}"
            )


def _run_body(
    ctx: ProbeContext,
    *,
    ckm_name: str,
    api: str,
    corrupt_fn: Callable[[bytes], bytes],
) -> None:
    """Shared keygen + wrap + corrupt + unwrap/decrypt body for both probes."""
    from pkcs11_check.testcases.security.conftest import child_setup_reject_known

    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    ckm: int = getattr(types_std, ckm_name)

    wrap_key = gen_aes_key(
        raw,
        sh,
        256,
        attrs={
            CKA_WRAP: True,
            CKA_UNWRAP: True,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )
    target_key = gen_aes_key(
        raw,
        sh,
        128,
        attrs={
            CKA_EXTRACTABLE: True,
            CKA_SENSITIVE: False,
            CKA_TOKEN: False,
        },
    )

    try:
        try:
            # output_size_hint: some modules do not set the wrapped-key length on
            # the NULL-buffer size-query pass for AES-KEY-WRAP-KWP, so the two-call
            # protocol would fail with CKR_BUFFER_TOO_SMALL. 64 covers the 8-byte ICV
            # + up to 15 bytes padding for AES-128/192/256 targets (same hint as
            # test_extended_mechanisms.py). Modules that report the size ignore it.
            wrapped_blob = wrap_key_recipe(raw, sh, wrap_key, target_key, ckm, output_size_hint=64)
        except AssertionError as _wrap_exc:
            if child_setup_reject_known(
                _wrap_exc, _WRAP_SETUP_REJECT_RVS, "AES key wrap setup rejected"
            ):
                raise SystemExit(0) from None
            raise
        destroy_quietly(raw, sh, target_key)

        corrupted = corrupt_fn(wrapped_blob)
        if api == "unwrap":
            _do_unwrap(raw, sh, wrap_key, corrupted, ckm)
        else:
            _do_decrypt(raw, sh, wrap_key, corrupted, ckm, ckm_name)
    finally:
        destroy_quietly(raw, sh, wrap_key)


def _run_corrupted_unwrap(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """8-corruption-type unwrap/decrypt probe."""
    corruption: str = extra["corruption"]
    _run_body(
        ctx,
        ckm_name=extra["ckm_name"],
        api=extra["api"],
        corrupt_fn=lambda blob: _apply_corruption(blob, corruption),
    )


def _run_bit_flip_unwrap(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Single-bit-flip unwrap probe (api is always unwrap)."""
    offset: int = extra["offset"]
    _run_body(
        ctx,
        ckm_name=extra["ckm_name"],
        api="unwrap",
        corrupt_fn=lambda blob: _apply_bit_flip(blob, offset),
    )


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "corrupted_unwrap": _run_corrupted_unwrap,
    "bit_flip_unwrap": _run_bit_flip_unwrap,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"error_path_kwp probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
