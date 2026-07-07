"""Probe: C_SignRecover / C_VerifyRecover happy-path operations (CKM_RSA_X_509).

Ports the f-string child-script bodies from testcases/test_sign_recover.py into
dispatchable probe functions.  C_SignRecover / C_VerifyRecover are not exposed by the
python-pkcs11 high-level API, so each probe drives the raw C-level calls directly:
generate an RSA-2048 recovery keypair, then run sign-recover / verify-recover.

Output protocol lines (``KEYGEN_OK:...``, ``SIG_LEN:...``, ``SIG:...``, ``ORIGINAL:...``,
``RECOVERED:...``, ``RESULT:...``, ``NOTE:...``, ``SKIP:...``, ``FATAL:...``) are
byte-identical to the original generated scripts so the parent (parse_output +
_handle_subprocess_failure + assert_correct / classify) requires no changes.

All probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).  The PIN is
never embedded in the probe source or params.

Dispatch on ``params.extra["probe"]``:
  ``"sign_recover_produces_output"``   -- C_SignRecover produces a 256-byte signature.
  ``"verify_recover_round_trip"``      -- C_SignRecover then C_VerifyRecover recovers data.
  ``"sign_recover_wrong_data_length"`` -- C_SignRecover with short data must be rejected.
"""

from __future__ import annotations

import binascii
import ctypes
import sys
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw import CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
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
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: Any) -> Any:
    return ctypes.cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data: bytes) -> Any:
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _generate_keypair(raw: Any, sh: int) -> tuple[Any, Any]:
    """Generate an RSA-2048 recovery keypair; SKIP/FATAL + exit on the legacy child paths."""
    byref = ctypes.byref

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
    h_pub = CK_OBJECT_HANDLE(0)
    h_prv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        kg_mech.byref(),
        _template_ptr(pub_template),
        pub_template.count,
        _template_ptr(prv_template),
        prv_template.count,
        byref(h_pub),
        byref(h_prv),
    )
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:GenerateKeyPairUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKeyPair:0x{rv:08x}")
        sys.exit(1)
    print(f"KEYGEN_OK:{h_pub.value}:{h_prv.value}")
    return h_pub, h_prv


def _run_sign_recover_produces_output(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignRecover with RSA X.509 produces a 256-byte signature block."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ubyte = ctypes.c_ubyte

    _h_pub, h_prv = _generate_keypair(raw, sh)

    sr_mech = mech_simple(CKM_RSA_X_509)

    # Input must be exactly 256 bytes (RSA-2048 modulus size)
    # Use PKCS#1 v1.5-style padding: 0x00 0x01 0xFF...FF 0x00 <data>
    data = b"Hello sign-recover"
    pad_len = 256 - 3 - len(data)
    padded = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + data
    padded_buf = _byte_array(padded)

    rv = raw.C_SignRecoverInit(sh, sr_mech.byref(), h_prv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    sig_len = ctypes.c_ulong(0)
    rv = raw.C_SignRecover(sh, padded_buf, len(padded), None, byref(sig_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:SignRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverLen:0x{rv:08x}")
        sys.exit(1)

    sig_buf = (c_ubyte * sig_len.value)()
    rv = raw.C_SignRecover(sh, padded_buf, len(padded), sig_buf, byref(sig_len))
    if rv != CKR_OK:
        print(f"FATAL:SignRecover:0x{rv:08x}")
        sys.exit(1)

    sig_hex = binascii.hexlify(bytes(sig_buf[: sig_len.value])).decode()
    print(f"SIG_LEN:{sig_len.value}")
    print(f"SIG:{sig_hex}")


def _run_verify_recover_round_trip(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignRecover then C_VerifyRecover recovers the original padded data."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ubyte = ctypes.c_ubyte

    h_pub, h_prv = _generate_keypair(raw, sh)

    sr_mech = mech_simple(CKM_RSA_X_509)

    # Input: exactly 256 bytes with PKCS#1 type-1 padding
    data = b"Round-trip test data"
    pad_len = 256 - 3 - len(data)
    padded = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + data
    padded_buf = _byte_array(padded)
    padded_hex = binascii.hexlify(padded).decode()
    print(f"ORIGINAL:{padded_hex}")

    # --- Sign-recover ---
    rv = raw.C_SignRecoverInit(sh, sr_mech.byref(), h_prv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    sig_len = ctypes.c_ulong(0)
    rv = raw.C_SignRecover(sh, padded_buf, len(padded), None, byref(sig_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:SignRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverLen:0x{rv:08x}")
        sys.exit(1)

    sig_buf = (c_ubyte * sig_len.value)()
    rv = raw.C_SignRecover(sh, padded_buf, len(padded), sig_buf, byref(sig_len))
    if rv != CKR_OK:
        print(f"FATAL:SignRecover:0x{rv:08x}")
        sys.exit(1)
    sig_bytes = bytes(sig_buf[: sig_len.value])
    sig_in = _byte_array(sig_bytes)
    print(f"SIG_LEN:{sig_len.value}")

    # --- Verify-recover ---
    rv = raw.C_VerifyRecoverInit(sh, sr_mech.byref(), h_pub)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:VerifyRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    rec_len = ctypes.c_ulong(0)
    rv = raw.C_VerifyRecover(sh, sig_in, len(sig_bytes), None, byref(rec_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:VerifyRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecoverLen:0x{rv:08x}")
        sys.exit(1)

    rec_buf = (c_ubyte * rec_len.value)()
    rv = raw.C_VerifyRecover(sh, sig_in, len(sig_bytes), rec_buf, byref(rec_len))
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecover:0x{rv:08x}")
        sys.exit(1)

    recovered_hex = binascii.hexlify(bytes(rec_buf[: rec_len.value])).decode()
    print(f"RECOVERED:{recovered_hex}")


def _run_sign_recover_wrong_data_length(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_SignRecover with wrong-length data returns a PKCS#11 error (not crash)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ubyte = ctypes.c_ubyte

    _h_pub, h_prv = _generate_keypair(raw, sh)

    sr_mech = mech_simple(CKM_RSA_X_509)

    rv = raw.C_SignRecoverInit(sh, sr_mech.byref(), h_prv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Data shorter than modulus - must be rejected
    short_data = b"too short"
    short_data_buf = _byte_array(short_data)
    sig_len = ctypes.c_ulong(256)
    sig_buf = (c_ubyte * 256)()
    rv = raw.C_SignRecover(sh, short_data_buf, len(short_data), sig_buf, byref(sig_len))

    if rv == CKR_OK:
        print("RESULT:ACCEPTED_SHORT_DATA")
    else:
        print(f"RESULT:REJECTED:0x{rv:08x}")
        # Any non-OK return is acceptable - the module correctly rejected it
        acceptable = {
            CKR_DATA_LEN_RANGE,
            CKR_ARGUMENTS_BAD,
            CKR_BUFFER_TOO_SMALL,
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_MECHANISM_INVALID,
        }
        if rv not in acceptable:
            # Non-standard CKR - still a valid rejection; note it
            print(f"NOTE:NonStandardRejection:0x{rv:08x}")


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "sign_recover_produces_output": _run_sign_recover_produces_output,
    "verify_recover_round_trip": _run_verify_recover_round_trip,
    "sign_recover_wrong_data_length": _run_sign_recover_wrong_data_length,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"sign_recover probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
