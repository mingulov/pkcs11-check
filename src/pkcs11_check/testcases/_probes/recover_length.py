"""Probe: crash-safe length-boundary probes for sign/verify-recover APIs.

Ports the five child-script bodies from security/test_recover_length_boundary.py
into a single dispatchable probe module.  Output protocol lines are byte-identical
to the originals so the parent classifiers require no changes.

Output protocol (preserved verbatim for parent classifier):
  SETUP_XFAIL:<reason>       — setup rejected; parent xfails as not_operational
  TARGET:<fn>                — which C_ function was probed
  LEN:<hex>                  — probed length value (sign_huge_data_len / verify_huge_sig_len)
  CKR:0x%08x                 — return value from the probed call
  OUT_LEN:<int>              — output-length CK_ULONG value after the call
  INFLATED_LEN:<hex>         — initial inflated *pulDataLen (verify_inflated_out_len only)
  NEEDED:<int>               — size-query result (one-byte-guard probes only)
  OVERWRITTEN:<int>          — guard bytes changed (one-byte-guard probes only)

Dispatch on ``params.extra["which"]``:
  ``"sign_huge_data_len"``      — C_SignRecover with huge ulDataLen
  ``"verify_huge_sig_len"``     — C_VerifyRecover with huge ulSignatureLen
  ``"verify_inflated_out_len"`` — C_VerifyRecover with inflated *pulDataLen
  ``"verify_one_byte_guard"``   — C_VerifyRecover one-byte output buffer guard
  ``"sign_one_byte_guard"``     — C_SignRecover one-byte output buffer guard

Required extra keys:
  ``"which"``    — dispatch key (see above)
  ``"data_len"`` — int, for ``"sign_huge_data_len"`` only
  ``"sig_len"``  — int, for ``"verify_huge_sig_len"`` only
"""

from __future__ import annotations

import ctypes
from typing import Any, NoReturn

from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN_RECOVER,
    CKA_TOKEN,
    CKA_VERIFY_RECOVER,
    CKK_RSA,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_X_509,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import KEYPAIR_RUNTIME_REJECT_RVS

# Oversized output-length: low 32 bits = 256 (matches a 256-byte output buffer),
# high 32 bits set.  A module that writes only the low 32 bits of *pulDataLen
# leaves the high half intact, producing a huge value that drives an OOB copy.
_R6_INFLATED_PULDATALEN = (1 << 32) + 256

# Clean, advertised-but-not-operational rejections acceptable during setup.
# Matches the _RECOVER_SETUP_RVS definition in the original child script.
_RECOVER_SETUP_RVS: frozenset[int] = frozenset(int(rv) for rv in KEYPAIR_RUNTIME_REJECT_RVS) | {
    int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    int(CKR_OPERATION_NOT_INITIALIZED),
}


class _SetupXfailError(Exception):
    """Internal signal: a clean setup rejection was encountered; SETUP_XFAIL already printed."""


def _setup_xfail_rv(rv: int, purpose: str) -> NoReturn:
    print(f"SETUP_XFAIL:{purpose}: {ckr_name(rv)}")
    raise _SetupXfailError()


def _setup_xfail_if_known(rv: int, purpose: str) -> None:
    if int(rv) in _RECOVER_SETUP_RVS:
        _setup_xfail_rv(rv, purpose)


def _template_ptr(attrs: Any) -> Any:
    return ctypes.cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data: bytes) -> Any:
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _gen_recover_keypair(raw: Any, sh: int) -> tuple[Any, Any]:
    """Generate a 2048-bit RSA keypair with SIGN_RECOVER / VERIFY_RECOVER attributes."""
    pub_template = template(
        attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_RSA),
        attr_ulong(CKA_MODULUS_BITS, 2048),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_VERIFY_RECOVER, True),
        attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
    )
    prv_template = template(
        attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_RSA),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SIGN_RECOVER, True),
    )
    kg_mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        kg_mech.byref(),
        _template_ptr(pub_template),
        pub_template.count,
        _template_ptr(prv_template),
        prv_template.count,
        ctypes.byref(pub),
        ctypes.byref(priv),
    )
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "RSA recover keypair generation rejected")
        raise AssertionError(f"C_GenerateKeyPair returned {ckr_name(rv)}")
    return pub, priv


def _padded_recover_block(label: bytes) -> bytes:
    """Build a PKCS#1 raw RSA-X_509 block padded for a 2048-bit key."""
    pad_len = 256 - 3 - len(label)
    return b"\x00\x01" + b"\xff" * pad_len + b"\x00" + label


def _sign_recover(raw: Any, sh: int, priv: Any, payload: bytes) -> bytes:
    """Sign *payload* via C_SignRecover (CKM_RSA_X_509) and return the signature bytes."""
    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_SignRecoverInit(sh, mech.byref(), priv.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecoverInit rejected")
        raise AssertionError(f"C_SignRecoverInit returned {ckr_name(rv)}")
    payload_buf = _byte_array(payload)
    sig_len = CK_ULONG(0)
    rv = raw.C_SignRecover(sh, payload_buf, len(payload), None, ctypes.byref(sig_len))
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecover size query rejected")
        raise AssertionError(f"C_SignRecover size query returned {ckr_name(rv)}")
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = raw.C_SignRecover(sh, payload_buf, len(payload), sig_buf, ctypes.byref(sig_len))
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecover setup signing rejected")
        raise AssertionError(f"C_SignRecover returned {ckr_name(rv)}")
    return bytes(sig_buf[: sig_len.value])


# ---------------------------------------------------------------------------
# Dispatch functions
# ---------------------------------------------------------------------------


def _run_sign_huge_data_len(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_SignRecover with a tiny real buffer and huge ulDataLen."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    data_len = int(extra["data_len"])

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    try:
        pub, priv = _gen_recover_keypair(raw, sh)
        mech = mech_simple(CKM_RSA_X_509)
        rv = raw.C_SignRecoverInit(sh, mech.byref(), priv.value)
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_SignRecoverInit rejected")
            raise AssertionError(f"C_SignRecoverInit returned {ckr_name(rv)}")
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_buf = (ctypes.c_ubyte * 256)()
        sig_len = CK_ULONG(256)
        print("TARGET:C_SignRecover")
        print(f"LEN:{data_len:#x}")
        rv = raw.C_SignRecover(sh, data, data_len, sig_buf, ctypes.byref(sig_len))
        print(f"CKR:0x{rv:08x}")
        print(f"OUT_LEN:{sig_len.value}")
    except _SetupXfailError:
        pass
    finally:
        if priv.value:
            destroy_quietly(raw, sh, priv.value)
        if pub.value:
            destroy_quietly(raw, sh, pub.value)


def _run_verify_huge_sig_len(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_VerifyRecover with a tiny real signature and huge ulSignatureLen."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    sig_len = int(extra["sig_len"])

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    try:
        pub, priv = _gen_recover_keypair(raw, sh)
        mech = mech_simple(CKM_RSA_X_509)
        rv = raw.C_VerifyRecoverInit(sh, mech.byref(), pub.value)
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_VerifyRecoverInit rejected")
            raise AssertionError(f"C_VerifyRecoverInit returned {ckr_name(rv)}")
        signature = (ctypes.c_ubyte * 16)(*range(16))
        recovered = (ctypes.c_ubyte * 256)()
        recovered_len = CK_ULONG(256)
        print("TARGET:C_VerifyRecover")
        print(f"LEN:{sig_len:#x}")
        rv = raw.C_VerifyRecover(
            sh,
            signature,
            sig_len,
            recovered,
            ctypes.byref(recovered_len),
        )
        print(f"CKR:0x{rv:08x}")
        print(f"OUT_LEN:{recovered_len.value}")
    except _SetupXfailError:
        pass
    finally:
        if priv.value:
            destroy_quietly(raw, sh, priv.value)
        if pub.value:
            destroy_quietly(raw, sh, pub.value)


def _run_verify_inflated_out_len(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_VerifyRecover with *pulDataLen high 32 bits set must not crash."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    try:
        pub, priv = _gen_recover_keypair(raw, sh)
        payload = _padded_recover_block(b"output-len-pun-probe")
        signature = _sign_recover(raw, sh, priv, payload)
        signature_buf = _byte_array(signature)

        mech = mech_simple(CKM_RSA_X_509)
        rv = raw.C_VerifyRecoverInit(sh, mech.byref(), pub.value)
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_VerifyRecoverInit rejected")
            raise AssertionError(f"C_VerifyRecoverInit returned {ckr_name(rv)}")

        out_buf = (ctypes.c_ubyte * 256)()
        out_len = CK_ULONG(_R6_INFLATED_PULDATALEN)
        print("TARGET:C_VerifyRecover")
        print(f"INFLATED_LEN:{out_len.value:#x}")
        rv = raw.C_VerifyRecover(
            sh,
            signature_buf,
            len(signature),
            out_buf,
            ctypes.byref(out_len),
        )
        print(f"CKR:0x{rv:08x}")
        print(f"OUT_LEN:{out_len.value}")
    except _SetupXfailError:
        pass
    finally:
        if priv.value:
            destroy_quietly(raw, sh, priv.value)
        if pub.value:
            destroy_quietly(raw, sh, pub.value)


def _run_verify_one_byte_guard(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_VerifyRecover with one declared output byte must not overwrite guard bytes."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    try:
        pub, priv = _gen_recover_keypair(raw, sh)
        payload = _padded_recover_block(b"verify-recover guard")
        signature = _sign_recover(raw, sh, priv, payload)
        signature_buf = _byte_array(signature)

        mech = mech_simple(CKM_RSA_X_509)
        rv = raw.C_VerifyRecoverInit(sh, mech.byref(), pub.value)
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_VerifyRecoverInit rejected")
            raise AssertionError(f"C_VerifyRecoverInit returned {ckr_name(rv)}")

        needed = CK_ULONG(0)
        rv = raw.C_VerifyRecover(
            sh,
            signature_buf,
            len(signature),
            None,
            ctypes.byref(needed),
        )
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_VerifyRecover size query rejected")
            raise AssertionError(f"C_VerifyRecover size query returned {ckr_name(rv)}")
        if needed.value <= 1:
            _setup_xfail_rv(CKR_OK, f"C_VerifyRecover reported only {needed.value} output byte(s)")

        guard_byte = 0xB6
        guard_size = 32

        class RecoverProbe(ctypes.Structure):
            _fields_ = [
                ("data", ctypes.c_ubyte * 1),
                ("guard", ctypes.c_ubyte * guard_size),
            ]

        probe = RecoverProbe()
        for idx in range(guard_size):
            probe.guard[idx] = guard_byte

        # No re-Init here: per PKCS#11, the NULL-output size query above did NOT
        # terminate the operation. Calling C_VerifyRecover again with a real output
        # buffer is the correct continuation. (Re-Init would return
        # CKR_OPERATION_ACTIVE on a conformant module -- the previous test bug.)
        out_len = CK_ULONG(1)
        print(f"NEEDED:{needed.value}")
        rv = raw.C_VerifyRecover(
            sh,
            signature_buf,
            len(signature),
            ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(out_len),
        )
        print(f"CKR:0x{rv:08x}")
        print(f"LEN:{out_len.value}")
        overwritten = sum(1 for byte in probe.guard if byte != guard_byte)
        print(f"OVERWRITTEN:{overwritten}")
        assert overwritten == 0, (
            "C_VerifyRecover wrote past the declared one-byte output buffer: "
            f"{overwritten} guard byte(s) changed"
        )
    except _SetupXfailError:
        pass
    finally:
        if priv.value:
            destroy_quietly(raw, sh, priv.value)
        if pub.value:
            destroy_quietly(raw, sh, pub.value)


def _run_sign_one_byte_guard(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignRecover with one declared output byte must not overwrite guard bytes."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    try:
        pub, priv = _gen_recover_keypair(raw, sh)
        payload = _padded_recover_block(b"sign-recover guard")
        payload_buf = _byte_array(payload)

        mech = mech_simple(CKM_RSA_X_509)
        rv = raw.C_SignRecoverInit(sh, mech.byref(), priv.value)
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_SignRecoverInit rejected")
            raise AssertionError(f"C_SignRecoverInit returned {ckr_name(rv)}")

        needed = CK_ULONG(0)
        rv = raw.C_SignRecover(sh, payload_buf, len(payload), None, ctypes.byref(needed))
        if rv != CKR_OK:
            _setup_xfail_if_known(rv, "C_SignRecover size query rejected")
            raise AssertionError(f"C_SignRecover size query returned {ckr_name(rv)}")
        if needed.value <= 1:
            _setup_xfail_rv(CKR_OK, f"C_SignRecover reported only {needed.value} output byte(s)")

        guard_byte = 0xB7
        guard_size = 32

        class RecoverProbe(ctypes.Structure):
            _fields_ = [
                ("data", ctypes.c_ubyte * 1),
                ("guard", ctypes.c_ubyte * guard_size),
            ]

        probe = RecoverProbe()
        for idx in range(guard_size):
            probe.guard[idx] = guard_byte

        # Continuation real call (NO re-Init): the NULL-output size query above did
        # not terminate the operation, so we call C_SignRecover again with a real
        # 1-byte output buffer + guard bytes to detect overflow.
        out_len = CK_ULONG(1)
        print(f"NEEDED:{needed.value}")
        rv = raw.C_SignRecover(
            sh,
            payload_buf,
            len(payload),
            ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(out_len),
        )
        print(f"CKR:0x{rv:08x}")
        print(f"LEN:{out_len.value}")
        overwritten = sum(1 for byte in probe.guard if byte != guard_byte)
        print(f"OVERWRITTEN:{overwritten}")
        assert overwritten == 0, (
            "C_SignRecover wrote past the declared one-byte output buffer: "
            f"{overwritten} guard byte(s) changed"
        )
    except _SetupXfailError:
        pass
    finally:
        if priv.value:
            destroy_quietly(raw, sh, priv.value)
        if pub.value:
            destroy_quietly(raw, sh, pub.value)


_DISPATCH = {
    "sign_huge_data_len": _run_sign_huge_data_len,
    "verify_huge_sig_len": _run_verify_huge_sig_len,
    "verify_inflated_out_len": _run_verify_inflated_out_len,
    "verify_one_byte_guard": _run_verify_one_byte_guard,
    "sign_one_byte_guard": _run_sign_one_byte_guard,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"recover_length probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
