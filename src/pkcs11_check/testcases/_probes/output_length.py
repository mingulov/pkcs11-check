"""Probe: demand-zero mmap oracle for C_Encrypt/C_Decrypt 64-bit->32-bit output-length truncation.

Ports the stream-cipher child-script bodies from
``security/test_output_length_truncation.py`` into one dispatchable probe module.
Output protocol lines are byte-identical to the originals so the parent
classifiers require no changes.

Output protocol (preserved verbatim for parent classifier):
  SETUP_XFAIL:<reason>        — setup rejected; parent xfails as not_operational
  TARGET_RV:0x%08x            — return value from the probed C_Encrypt / C_Decrypt call
  TARGET_RV_NAME:<name>       — human-readable name of the return value
  UNDERFILL:%d                — 1 if output past probe offset is all-zero (truncation), else 0
  OUT_LEN:0x%016x             — *pulEncryptedDataLen / *pulDataLen after the call

Dispatch on ``params["which"]``:
  ``"aes_ctr_encrypt"``    — AES-CTR C_Encrypt oversize-length probe
  ``"aes_ctr_decrypt"``    — AES-CTR C_Decrypt oversize-length probe
  ``"aes_ofb_encrypt"``    — AES-OFB C_Encrypt oversize-length probe
  ``"aes_ofb_decrypt"``    — AES-OFB C_Decrypt oversize-length probe
  ``"aes_cfb128_encrypt"`` — AES-CFB128 C_Encrypt oversize-length probe
  ``"aes_cfb128_decrypt"`` — AES-CFB128 C_Decrypt oversize-length probe
  ``"aes_cfb8_encrypt"``   — AES-CFB8 C_Encrypt oversize-length probe
  ``"aes_cfb8_decrypt"``   — AES-CFB8 C_Decrypt oversize-length probe
  ``"chacha20_encrypt"``   — ChaCha20 C_Encrypt oversize-length probe
  ``"chacha20_decrypt"``   — ChaCha20 C_Decrypt oversize-length probe

Required extra key:
  ``"which"`` — dispatch key (see above)
"""

from __future__ import annotations

import ctypes
import mmap
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CTR_PARAMS,
    CK_CHACHA20_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CFB8,
    CKM_AES_CFB128,
    CKM_AES_CTR,
    CKM_AES_OFB,
    CKM_CHACHA20,
    CKM_CHACHA20_KEY_GEN,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security._boundary_values import OVERSIZE_WRITE_LEN, PROBE_OFFSET
from pkcs11_check.testcases.security.conftest import child_setup_reject_known


class _SetupXfailError(Exception):
    """Internal signal: a clean setup rejection was encountered; SETUP_XFAIL already printed."""


# ---------------------------------------------------------------------------
# Key-generation helpers
# ---------------------------------------------------------------------------


def _setup_aes_key(raw: Any, sh: int) -> int:
    """Generate AES-256 session key; raises _SetupXfailError on known-clean keygen rejection."""
    try:
        return gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
        ):
            raise _SetupXfailError() from exc
        raise


def _setup_chacha20_key(raw: Any, sh: int) -> int:
    """Generate ChaCha20 session key; raises _SetupXfailError on known-clean keygen rejection."""
    try:
        return gen_aes_key(raw, sh, 256, mechanism=CKM_CHACHA20_KEY_GEN)
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "ChaCha20 key generation rejected"
        ):
            raise _SetupXfailError() from exc
        raise


# ---------------------------------------------------------------------------
# Mechanism-construction helpers
# ---------------------------------------------------------------------------


def _make_aes_ctr_mech() -> tuple[CK_MECHANISM, tuple[Any, ...]]:
    """Build a CK_MECHANISM for AES-CTR with a deterministic counter block."""
    ctr_params = CK_AES_CTR_PARAMS()
    ctr_params.ulCounterBits = 32
    # Counter block: deterministic, non-zero so a correct cipher produces non-zero
    # keystream regardless of the (zero) demand-zero plaintext.
    for _i in range(16):
        ctr_params.cb[_i] = (_i + 1) & 0xFF
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CTR
    mech.pParameter = ctypes.cast(ctypes.pointer(ctr_params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(ctr_params)
    return mech, (ctr_params,)


def _make_aes_iv16_mech(mech_const: int) -> tuple[CK_MECHANISM, tuple[Any, ...]]:
    """Build a CK_MECHANISM using a raw 16-byte IV (AES-OFB / AES-CFB128 / AES-CFB8)."""
    iv = (ctypes.c_ubyte * 16)(*range(1, 17))
    mech = CK_MECHANISM()
    mech.mechanism = mech_const
    mech.pParameter = ctypes.cast(iv, ctypes.c_void_p)
    mech.ulParameterLen = 16
    return mech, (iv,)


def _make_chacha20_mech() -> tuple[CK_MECHANISM, tuple[Any, ...]]:
    """Build a CK_MECHANISM for ChaCha20 (CK_CHACHA20_PARAMS: 128-bit counter + 96-bit nonce)."""
    counter = (ctypes.c_ubyte * 16)()  # all-zero counter at position 0
    nonce = (ctypes.c_ubyte * 12)(*range(12))
    chacha_params = CK_CHACHA20_PARAMS()
    chacha_params.pBlockCounter = ctypes.cast(counter, ctypes.c_void_p)
    chacha_params.blockCounterBits = 128
    chacha_params.pNonce = ctypes.cast(nonce, ctypes.c_void_p)
    chacha_params.ulNonceBits = 96
    mech = CK_MECHANISM()
    mech.mechanism = CKM_CHACHA20
    mech.pParameter = ctypes.cast(ctypes.pointer(chacha_params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(chacha_params)
    return mech, (counter, nonce, chacha_params)


# ---------------------------------------------------------------------------
# Demand-zero buffer allocation
# ---------------------------------------------------------------------------


def _demand_zero_pair() -> tuple[mmap.mmap, mmap.mmap]:
    """Allocate two demand-zero MAP_ANONYMOUS mmaps of OVERSIZE_WRITE_LEN bytes.

    Raises _SetupXfailError (after printing SETUP_XFAIL:) on non-POSIX or alloc failure.
    If the second alloc fails, the first is closed before raising.
    """
    if not hasattr(mmap, "MAP_ANONYMOUS"):
        print("SETUP_XFAIL:demand-zero honeypot needs POSIX mmap (unavailable on this platform)")
        raise _SetupXfailError()
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    flags |= getattr(mmap, "MAP_NORESERVE", 0)
    try:
        in_mm = mmap.mmap(-1, OVERSIZE_WRITE_LEN, flags=flags)
    except (OSError, ValueError) as exc:
        print(f"SETUP_XFAIL:demand-zero input mmap failed: {exc}")
        raise _SetupXfailError() from exc
    try:
        out_mm = mmap.mmap(-1, OVERSIZE_WRITE_LEN, flags=flags)
    except (OSError, ValueError) as exc:
        in_mm.close()
        print(f"SETUP_XFAIL:demand-zero output mmap failed: {exc}")
        raise _SetupXfailError() from exc
    return in_mm, out_mm


# ---------------------------------------------------------------------------
# Shared oracle body
# ---------------------------------------------------------------------------


def _run_oracle(
    raw: Any, sh: int, *, init_fn: str, op_fn: str, mech: CK_MECHANISM, key: int
) -> None:
    """Demand-zero mmap oracle: init cipher, run op over oversize buffers, sample probe offset.

    Prints SETUP_XFAIL: and raises _SetupXfailError if Init rejects.
    Prints TARGET_RV / TARGET_RV_NAME unconditionally; prints UNDERFILL + OUT_LEN on CKR_OK.
    """
    init_rv = getattr(raw, init_fn)(sh, ctypes.byref(mech), key)
    if init_rv != CKR_OK:
        print(f"SETUP_XFAIL:{init_fn} not operational: {ckr_name(init_rv)}")
        raise _SetupXfailError()

    # Oversize demand-zero input + output buffers.  For 1:1 stream ciphers the
    # output length equals the input length: an oversize input drives an oversize
    # write.  A truncating provider casts OVERSIZE_WRITE_LEN to 32 bits (=8),
    # processes 8 input bytes, writes ~8 output bytes -> output[PROBE_OFFSET] stays zero.
    in_mm: mmap.mmap | None = None
    out_mm: mmap.mmap | None = None
    in_view = None
    out_view = None
    try:
        in_mm, out_mm = _demand_zero_pair()
        in_view = (ctypes.c_ubyte * OVERSIZE_WRITE_LEN).from_buffer(in_mm)
        out_view = (ctypes.c_ubyte * OVERSIZE_WRITE_LEN).from_buffer(out_mm)
        out_len = CK_ULONG(OVERSIZE_WRITE_LEN)

        rv = getattr(raw, op_fn)(
            sh,
            ctypes.cast(in_view, ctypes.POINTER(ctypes.c_ubyte)),
            OVERSIZE_WRITE_LEN,
            ctypes.cast(out_view, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(out_len),
        )
        print(f"TARGET_RV:0x{rv:08x}")
        print(f"TARGET_RV_NAME:{ckr_name(rv)}")
        if rv == CKR_OK:
            sample = bytes(out_mm[PROBE_OFFSET : PROBE_OFFSET + 64])
            underfill = 1 if sample == b"\x00" * 64 else 0
            print(f"UNDERFILL:{underfill}")
            print(f"OUT_LEN:0x{out_len.value:016x}")
    finally:
        # Release ctypes views before their mmaps.
        if in_view is not None:
            del in_view
        if out_view is not None:
            del out_view
        if in_mm is not None:
            in_mm.close()
        if out_mm is not None:
            out_mm.close()


# ---------------------------------------------------------------------------
# Cipher-family helpers (shared between encrypt and decrypt)
# ---------------------------------------------------------------------------


def _run_aes_ctr_cipher(ctx: ProbeContext, *, init_fn: str, op_fn: str) -> None:
    """AES-CTR demand-zero oracle (shared body for encrypt and decrypt)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    key = 0
    try:
        key = _setup_aes_key(raw, sh)
        mech, _refs = _make_aes_ctr_mech()
        _run_oracle(raw, sh, init_fn=init_fn, op_fn=op_fn, mech=mech, key=key)
    except _SetupXfailError:
        pass
    finally:
        if key:
            destroy_quietly(raw, sh, key)


def _run_aes_iv16_cipher(ctx: ProbeContext, *, mech_const: int, init_fn: str, op_fn: str) -> None:
    """AES-OFB / AES-CFB128 / AES-CFB8 demand-zero oracle (shared body for encrypt and decrypt)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    key = 0
    try:
        key = _setup_aes_key(raw, sh)
        mech, _refs = _make_aes_iv16_mech(mech_const)
        _run_oracle(raw, sh, init_fn=init_fn, op_fn=op_fn, mech=mech, key=key)
    except _SetupXfailError:
        pass
    finally:
        if key:
            destroy_quietly(raw, sh, key)


def _run_chacha20_cipher(ctx: ProbeContext, *, init_fn: str, op_fn: str) -> None:
    """ChaCha20 demand-zero oracle (shared body for encrypt and decrypt)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    key = 0
    try:
        key = _setup_chacha20_key(raw, sh)
        mech, _refs = _make_chacha20_mech()
        _run_oracle(raw, sh, init_fn=init_fn, op_fn=op_fn, mech=mech, key=key)
    except _SetupXfailError:
        pass
    finally:
        if key:
            destroy_quietly(raw, sh, key)


# ---------------------------------------------------------------------------
# Dispatch functions (one per which value)
# ---------------------------------------------------------------------------


def _run_aes_ctr_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CTR C_Encrypt oversize-length probe."""
    _run_aes_ctr_cipher(ctx, init_fn="C_EncryptInit", op_fn="C_Encrypt")


def _run_aes_ctr_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CTR C_Decrypt oversize-length probe."""
    _run_aes_ctr_cipher(ctx, init_fn="C_DecryptInit", op_fn="C_Decrypt")


def _run_aes_ofb_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-OFB C_Encrypt oversize-length probe."""
    _run_aes_iv16_cipher(ctx, mech_const=CKM_AES_OFB, init_fn="C_EncryptInit", op_fn="C_Encrypt")


def _run_aes_ofb_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-OFB C_Decrypt oversize-length probe."""
    _run_aes_iv16_cipher(ctx, mech_const=CKM_AES_OFB, init_fn="C_DecryptInit", op_fn="C_Decrypt")


def _run_aes_cfb128_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CFB128 C_Encrypt oversize-length probe."""
    _run_aes_iv16_cipher(ctx, mech_const=CKM_AES_CFB128, init_fn="C_EncryptInit", op_fn="C_Encrypt")


def _run_aes_cfb128_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CFB128 C_Decrypt oversize-length probe."""
    _run_aes_iv16_cipher(ctx, mech_const=CKM_AES_CFB128, init_fn="C_DecryptInit", op_fn="C_Decrypt")


def _run_aes_cfb8_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CFB8 C_Encrypt oversize-length probe."""
    _run_aes_iv16_cipher(ctx, mech_const=CKM_AES_CFB8, init_fn="C_EncryptInit", op_fn="C_Encrypt")


def _run_aes_cfb8_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """AES-CFB8 C_Decrypt oversize-length probe."""
    _run_aes_iv16_cipher(ctx, mech_const=CKM_AES_CFB8, init_fn="C_DecryptInit", op_fn="C_Decrypt")


def _run_chacha20_encrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """ChaCha20 C_Encrypt oversize-length probe."""
    _run_chacha20_cipher(ctx, init_fn="C_EncryptInit", op_fn="C_Encrypt")


def _run_chacha20_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """ChaCha20 C_Decrypt oversize-length probe."""
    _run_chacha20_cipher(ctx, init_fn="C_DecryptInit", op_fn="C_Decrypt")


_DISPATCH = {
    "aes_ctr_encrypt": _run_aes_ctr_encrypt,
    "aes_ctr_decrypt": _run_aes_ctr_decrypt,
    "aes_ofb_encrypt": _run_aes_ofb_encrypt,
    "aes_ofb_decrypt": _run_aes_ofb_decrypt,
    "aes_cfb128_encrypt": _run_aes_cfb128_encrypt,
    "aes_cfb128_decrypt": _run_aes_cfb128_decrypt,
    "aes_cfb8_encrypt": _run_aes_cfb8_encrypt,
    "aes_cfb8_decrypt": _run_aes_cfb8_decrypt,
    "chacha20_encrypt": _run_chacha20_encrypt,
    "chacha20_decrypt": _run_chacha20_decrypt,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"output_length probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
