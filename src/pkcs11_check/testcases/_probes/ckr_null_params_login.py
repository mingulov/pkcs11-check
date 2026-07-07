"""Probe: ``C_GenerateRandom`` NULL-buffer check (needs a logged-in session).

``C_GenerateRandom`` requires an open, logged-in session, so this runs through
``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot discovery +
``C_OpenSession`` + ``C_Login`` before handing the probe ``ctx.sh``.  The PIN travels
ONLY via the ``_P11CHECK_PIN`` env var, which the LOGIN path reads (Invariant I3) -- it
is never read, printed, or embedded here, and never rides in the probe params.  (This
closes the legacy leak that formatted the PIN literal into the generated child script.)

The probe then loads a direct-symbol CDLL handle and calls the exported
``C_GenerateRandom`` with a NULL output buffer.

Output protocol (byte-identical to the legacy child, for ``_check_null_result``):
  ``CKR:0x{rv:08x}``                    -- the return value of ``C_GenerateRandom(NULL)``
  ``CKR:0x00000000:not_exported``       -- module does not export the direct symbol

Required ``extra`` keys:
  ``"module_path"`` -- path to the ``.so`` / ``.dll`` (for the direct-symbol handle;
                       the reserved top-level ``module_path`` is not forwarded to run_fn,
                       so the parent also passes it inside ``extra``).

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    # Direct-symbol handle onto the same module (mirrors legacy `so = ctypes.CDLL(module)`).
    so = ctypes.CDLL(extra["module_path"])
    try:
        c_generate_random = so.C_GenerateRandom
    except AttributeError:
        print("CKR:0x00000000:not_exported")
        return

    c_generate_random.restype = ctypes.c_ulong
    c_generate_random.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    rv = c_generate_random(ctx.sh, None, 32)
    print(f"CKR:0x{rv:08x}")


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
