"""Probe: ``C_OpenSession`` NULL-``phSession`` check (needs a slot, no login).

Most modules do not export ``C_OpenSession`` as a *direct* symbol -- only via
CK_FUNCTION_LIST.  The legacy child discovered a slot through RawPKCS11, then resolved
the direct exported ``C_OpenSession`` symbol and called it with a NULL output-handle
pointer.  Here ``probe_main`` at ``Level.SESSION`` performs C_Initialize + slot discovery
(and opens a session, harmlessly) so the probe receives ``ctx.slot_id``; the probe then
loads a direct-symbol CDLL handle and does the raw NULL call.

No login: ``C_OpenSession`` must reject a NULL handle without a PIN, so this stays off the
LOGIN path entirely (Invariant I3 -- no PIN is read or embedded here).

Output protocol (byte-identical to the legacy child, for ``_check_null_result``):
  ``CKR:0x{rv:08x}``                    -- the return value of ``C_OpenSession(NULL)``
  ``CKR:0x00000000:not_exported``       -- module does not export the direct symbol

Required ``extra`` keys:
  ``"module_path"`` -- path to the ``.so`` / ``.dll`` (for the direct-symbol handle;
                       the reserved top-level ``module_path`` is not forwarded to run_fn,
                       so the parent also passes it inside ``extra``).

Launch with ``coverage="session"``.
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

_CKF_SERIAL_SESSION_RW = 0x06  # CKF_SERIAL_SESSION (0x04) | CKF_RW_SESSION (0x02)


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    # Direct-symbol handle onto the same module (mirrors legacy `so = ctypes.CDLL(module)`).
    so = ctypes.CDLL(extra["module_path"])
    try:
        c_open_session = so.C_OpenSession
    except AttributeError:
        print("CKR:0x00000000:not_exported")
        return

    c_open_session.restype = ctypes.c_ulong
    c_open_session.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    rv = c_open_session(ctx.slot_id, _CKF_SERIAL_SESSION_RW, None, None, None)
    print(f"CKR:0x{rv:08x}")


if __name__ == "__main__":
    probe_main(_run, level=Level.SESSION)
