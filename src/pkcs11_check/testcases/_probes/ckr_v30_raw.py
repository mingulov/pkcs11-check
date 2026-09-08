"""Probe: PKCS#11 v3.0 message-op / session-cancel error conditions via a raw session.

Six child bodies ported from the legacy ``ckr/test_ckr_v30_raw.py`` scripts,
dispatched on ``extra["probe"]``.  Each drives a v3.0 function
(``C_MessageEncryptInit`` / ``C_MessageDecryptInit`` / ``C_MessageSignInit`` /
``C_MessageVerifyInit`` / ``C_EncryptMessage`` / ``C_SessionCancel``) through a
logged-in ``RawPKCS11`` session and emits a phase-labelled result for the parent-side
``_check`` classifier.

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot
discovery + ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before
handing the probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a
session and logged in *only* when a PIN was configured.  The PIN travels ONLY via the
``_P11CHECK_PIN`` env var; it is never read, printed, or embedded here or in the probe
params.  This CLOSES the legacy leak that formatted the PIN literal into the generated
child-script source (Invariant I3).  Session teardown + rv-trace are handled by
``probe_main`` atexit, matching the legacy ``_p11check_cleanup_session`` / rv-trace setup.

The shared v3.0-availability gate (``SKIP:v2.40_only`` / ``SKIP:no_v3_funcs``) runs at the
top of ``_run`` before dispatching, exactly as the legacy template did before the test body
(the legacy checked these *before* opening a session; the ordering difference is invisible in
the output, and the parent gates every method with ``@pytest.mark.needs_function`` so a v2.40
module never reaches the probe).

Output protocol:
  ``SKIP:v2.40_only``          -- module advertises only the v2.40 interface
  ``SKIP:no_v3_funcs``         -- module lacks ``C_MessageEncryptInit``
  ``SKIP:no_EncryptMessage``   -- module lacks ``C_EncryptMessage``
  ``SKIP:no_SessionCancel``    -- module lacks ``C_SessionCancel``
  ``RESULT:<phase>:CKR:0x{rv:08x}`` -- return value of the tested v3.0 call
  ``OK:<phase>``                    -- probe reached its expected point

Provider CKRs, including unexpected clean codes, are emitted and returned normally so
the parent can distinguish provider deviations from harness failures. A crash
(returncode < 0) remains a provider crash finding.

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
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _emit_result(phase: str, rv: int) -> None:
    """Emit one provider measurement without making a child assertion."""
    print(f"RESULT:{phase}:CKR:0x{rv:08x}", flush=True)


def _emit_complete(probe: str) -> None:
    print(f"OK:{probe}", flush=True)


def _message_encrypt_mech_invalid(ctx: ProbeContext) -> None:
    """C_MessageEncryptInit with a digest mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_SHA256)  # CKM_SHA256 - not an encrypt mechanism
    rv = ctx.raw.C_MessageEncryptInit(ctx.sh, mech.byref(), 0)
    _emit_result("C_MessageEncryptInit", rv)
    _emit_complete("C_MessageEncryptInit")


def _encrypt_message_no_init(ctx: ProbeContext) -> None:
    """C_EncryptMessage without MessageEncryptInit -> CKR_OPERATION_NOT_INITIALIZED."""
    data = (ctypes.c_ubyte * 16)(*([0] * 16))
    out = (ctypes.c_ubyte * 32)()
    out_len = ctypes.c_ulong(32)
    if "C_EncryptMessage" in ctx.raw._funcs:
        rv = ctx.raw.C_EncryptMessage(
            ctx.sh, None, 0, data, 16, None, 0, out, ctypes.byref(out_len)
        )
        _emit_result("C_EncryptMessage", rv)
        _emit_complete("C_EncryptMessage")
    else:
        print("SKIP:no_EncryptMessage")


def _message_decrypt_mech_invalid(ctx: ProbeContext) -> None:
    """C_MessageDecryptInit with a digest mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_SHA256)  # SHA256
    rv = ctx.raw.C_MessageDecryptInit(ctx.sh, mech.byref(), 0)
    _emit_result("C_MessageDecryptInit", rv)
    _emit_complete("C_MessageDecryptInit")


def _message_sign_mech_invalid(ctx: ProbeContext) -> None:
    """C_MessageSignInit with an encrypt mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB - not a sign mechanism
    rv = ctx.raw.C_MessageSignInit(ctx.sh, mech.byref(), 0)
    _emit_result("C_MessageSignInit", rv)
    _emit_complete("C_MessageSignInit")


def _message_verify_mech_invalid(ctx: ProbeContext) -> None:
    """C_MessageVerifyInit with an encrypt mechanism -> must reject (not CKR_OK)."""
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB
    rv = ctx.raw.C_MessageVerifyInit(ctx.sh, mech.byref(), 0)
    _emit_result("C_MessageVerifyInit", rv)
    _emit_complete("C_MessageVerifyInit")


def _session_cancel_no_operation(ctx: ProbeContext) -> None:
    """C_SessionCancel with no active operation -> OK or OPERATION_ACTIVE (both accepted)."""
    if "C_SessionCancel" in ctx.raw._funcs:
        rv = ctx.raw.C_SessionCancel(ctx.sh, 0)
        _emit_result("C_SessionCancel", rv)
        _emit_complete("C_SessionCancel")
    else:
        print("SKIP:no_SessionCancel")


_PROBES = {
    "message_encrypt_mech_invalid": _message_encrypt_mech_invalid,
    "encrypt_message_no_init": _encrypt_message_no_init,
    "message_decrypt_mech_invalid": _message_decrypt_mech_invalid,
    "message_sign_mech_invalid": _message_sign_mech_invalid,
    "message_verify_mech_invalid": _message_verify_mech_invalid,
    "session_cancel_no_operation": _session_cancel_no_operation,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    # Shared v3.0-availability gate (mirrors the legacy template's pre-body checks).
    if ctx.raw.interface_version == "2.40":
        print("SKIP:v2.40_only")
        return
    if "C_MessageEncryptInit" not in ctx.raw._funcs:
        print("SKIP:no_v3_funcs")
        return
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
