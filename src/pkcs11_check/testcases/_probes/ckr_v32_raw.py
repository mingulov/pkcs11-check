"""Probe: PKCS#11 v3.2 function error conditions via a raw session.

Eight child bodies ported verbatim from the legacy ``ckr/test_ckr_v32_raw.py`` scripts,
dispatched on ``extra["probe"]``.  Each drives a v3.2 function
(``C_VerifySignatureInit`` / ``C_VerifySignature`` / ``C_EncapsulateKey`` /
``C_DecapsulateKey`` / ``C_AsyncGetID`` / ``C_WrapKeyAuthenticated``) through a
logged-in ``RawPKCS11`` session and prints the resulting ``CKR:0x...`` line for the
parent-side ``_check`` classifier.

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot
discovery + ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before
handing the probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a
session and logged in *only* when a PIN was configured.  The PIN travels ONLY via the
``_P11CHECK_PIN`` env var; it is never read, printed, or embedded here or in the probe
params.  This CLOSES the legacy leak that formatted the PIN literal into the generated
child-script source (Invariant I3).  Session teardown + rv-trace are handled by
``probe_main`` atexit, matching the legacy ``_p11check_cleanup_session`` / rv-trace setup.

The shared v3.2-availability gate (``SKIP:no_v32`` / ``SKIP:no_v32_funcs``) runs at the
top of ``_run`` before dispatching, exactly as the legacy template did before the test body
(the legacy checked these *before* opening a session; the ordering difference is invisible in
the output, and the parent gates every method with ``@pytest.mark.needs_function`` so a
non-v3.2 module never reaches the probe).

Output protocol (byte-identical to the legacy child, for ``_check``):
  ``SKIP:no_v32``                            -- module does not advertise the v3.2 interface
  ``SKIP:no_v32_funcs``                      -- module lacks ``C_VerifySignatureInit``
  ``CKR:0x{rv:08x}``                         -- return value of the tested v3.2 call
  ``NULL pMechanism -> CKR:0x{rv:08x}``      -- NULL-pointer sub-probes (Encapsulate/Decapsulate)
  ``NULL pulCiphertextLen -> CKR:0x{rv:08x}``
  ``NULL phKey -> CKR:0x{rv:08x}``
  ``NULL pCiphertext with length>0 -> CKR:0x{rv:08x}``
  ``OK``                                     -- probe reached its expected point

A wrong CK_RV trips the child ``assert`` (non-zero exit) -> the parent reports a child
failure; a crash (returncode < 0) is a provider crash finding.

Required ``extra`` keys:
  ``"probe"`` -- one of the dispatch keys below.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _verify_signature_mech_invalid(ctx: ProbeContext) -> None:
    """C_VerifySignatureInit with an encrypt mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB - not a verify mechanism
    sig = (ctypes.c_ubyte * 32)(*([0] * 32))
    rv = ctx.raw.C_VerifySignatureInit(ctx.sh, mech.byref(), 0, sig, 32)
    print(f"CKR:0x{rv:08x}")
    assert rv != CKR_OK, "Should have rejected AES_ECB for VerifySignature"
    print("OK")


def _verify_signature_no_init(ctx: ProbeContext) -> None:
    """C_VerifySignature without Init -> CKR_OPERATION_NOT_INITIALIZED."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    rv = ctx.raw.C_VerifySignature(ctx.sh, data, 16)
    print(f"CKR:0x{rv:08x}")
    assert rv in (CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED), f"Got 0x{rv:08x}"
    print("OK")


def _encapsulate_wrong_mechanism(ctx: ProbeContext) -> None:
    """C_EncapsulateKey with an AES mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB - not a KEM mechanism
    ct = (ctypes.c_ubyte * 2048)()
    ct_len = ctypes.c_ulong(2048)
    enc_key = ctypes.c_ulong(0)
    rv = ctx.raw.C_EncapsulateKey(
        ctx.sh, mech.byref(), 0, None, 0, ct, ctypes.byref(ct_len), ctypes.byref(enc_key)
    )
    print(f"CKR:0x{rv:08x}")
    assert rv != CKR_OK, "Should have rejected AES_ECB for Encapsulate"
    print("OK")


def _encapsulate_null_pointers(ctx: ProbeContext) -> None:
    """C_EncapsulateKey with NULL pointers must return CKR_ARGUMENTS_BAD without crashing."""
    mech = mech_simple(CKM_AES_ECB)
    ct = (ctypes.c_ubyte * 2048)()
    ct_len = ctypes.c_ulong(2048)
    enc_key = ctypes.c_ulong(0)

    # Pass NULL for pMechanism
    rv = ctx.raw.C_EncapsulateKey(
        ctx.sh, None, 0, None, 0, ct, ctypes.byref(ct_len), ctypes.byref(enc_key)
    )
    print(f"NULL pMechanism -> CKR:0x{rv:08x}")
    assert rv == CKR_ARGUMENTS_BAD, "NULL pMechanism should yield CKR_ARGUMENTS_BAD"

    # Pass NULL for pulCiphertextLen
    rv = ctx.raw.C_EncapsulateKey(ctx.sh, mech.byref(), 0, None, 0, ct, None, ctypes.byref(enc_key))
    print(f"NULL pulCiphertextLen -> CKR:0x{rv:08x}")
    assert rv == CKR_ARGUMENTS_BAD, "NULL pulCiphertextLen should yield CKR_ARGUMENTS_BAD"

    print("OK")


def _decapsulate_wrong_mechanism(ctx: ProbeContext) -> None:
    """C_DecapsulateKey with an AES mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB
    ct = (ctypes.c_ubyte * 1088)(*([0xFF] * 1088))
    key = ctypes.c_ulong(0)
    rv = ctx.raw.C_DecapsulateKey(ctx.sh, mech.byref(), 0, None, 0, ct, 1088, ctypes.byref(key))
    print(f"CKR:0x{rv:08x}")
    assert rv != CKR_OK, "Should have rejected AES_ECB for Decapsulate"
    print("OK")


def _decapsulate_null_pointers(ctx: ProbeContext) -> None:
    """C_DecapsulateKey with NULL pointers must return CKR_ARGUMENTS_BAD without crashing."""
    mech = mech_simple(CKM_AES_ECB)
    ct = (ctypes.c_ubyte * 1088)(*([0xFF] * 1088))
    key = ctypes.c_ulong(0)

    # Pass NULL for pMechanism
    rv = ctx.raw.C_DecapsulateKey(ctx.sh, None, 0, None, 0, ct, 1088, ctypes.byref(key))
    print(f"NULL pMechanism -> CKR:0x{rv:08x}")
    assert rv == CKR_ARGUMENTS_BAD, "NULL pMechanism should yield CKR_ARGUMENTS_BAD"

    # Pass NULL for phKey
    rv = ctx.raw.C_DecapsulateKey(ctx.sh, mech.byref(), 0, None, 0, ct, 1088, None)
    print(f"NULL phKey -> CKR:0x{rv:08x}")
    assert rv in (
        CKR_ARGUMENTS_BAD,
        CKR_MECHANISM_INVALID,
        CKR_KEY_HANDLE_INVALID,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_TEMPLATE_INCONSISTENT,
    ), f"NULL phKey rejected with unexpected CKR 0x{rv:08x}"

    # Note: OASIS may allow pCiphertext=None if ulCiphertextLen=0, but otherwise ARGUMENTS_BAD
    rv = ctx.raw.C_DecapsulateKey(ctx.sh, mech.byref(), 0, None, 0, None, 1088, ctypes.byref(key))
    print(f"NULL pCiphertext with length>0 -> CKR:0x{rv:08x}")
    assert rv == CKR_ARGUMENTS_BAD, "NULL pCiphertext should yield CKR_ARGUMENTS_BAD"

    print("OK")


def _async_get_id_no_operation(ctx: ProbeContext) -> None:
    """C_AsyncGetID with no pending async operation."""
    id_buf = (ctypes.c_ubyte * 256)()
    id_len = ctypes.c_ulong(256)
    rv = ctx.raw.C_AsyncGetID(ctx.sh, id_buf, ctypes.byref(id_len))
    print(f"CKR:0x{rv:08x}")
    # OPERATION_NOT_INITIALIZED or FUNCTION_NOT_SUPPORTED - both acceptable
    assert rv != CKR_OK, "Should have failed with no async operation"
    print("OK")


def _wrap_auth_wrong_mechanism(ctx: ProbeContext) -> None:
    """C_WrapKeyAuthenticated with a digest mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_SHA256)  # SHA256 - not a wrap mechanism
    ct = (ctypes.c_ubyte * 256)()
    ct_len = ctypes.c_ulong(256)
    out = (ctypes.c_ubyte * 256)()
    out_len = ctypes.c_ulong(256)
    rv = ctx.raw.C_WrapKeyAuthenticated(
        ctx.sh, mech.byref(), 0, 0, ct, ct_len, out, ctypes.byref(out_len)
    )
    print(f"CKR:0x{rv:08x}")
    assert rv != CKR_OK, "Should have rejected SHA256 for WrapAuth"
    print("OK")


_PROBES = {
    "verify_signature_mech_invalid": _verify_signature_mech_invalid,
    "verify_signature_no_init": _verify_signature_no_init,
    "encapsulate_wrong_mechanism": _encapsulate_wrong_mechanism,
    "encapsulate_null_pointers": _encapsulate_null_pointers,
    "decapsulate_wrong_mechanism": _decapsulate_wrong_mechanism,
    "decapsulate_null_pointers": _decapsulate_null_pointers,
    "async_get_id_no_operation": _async_get_id_no_operation,
    "wrap_auth_wrong_mechanism": _wrap_auth_wrong_mechanism,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    # Shared v3.2-availability gate (mirrors the legacy template's pre-body checks).
    if ctx.raw.interface_version != "3.2":
        print("SKIP:no_v32")
        return
    if "C_VerifySignatureInit" not in ctx.raw._funcs:
        print("SKIP:no_v32_funcs")
        return
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
