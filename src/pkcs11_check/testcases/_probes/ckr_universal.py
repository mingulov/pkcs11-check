"""Probe: universal CKR-code triggers driven through a RawPKCS11 session.

Two child bodies ported verbatim from the legacy ``ckr/test_ckr_universal.py`` scripts,
dispatched on ``extra["probe"]``:

  ``"not_initialized"`` -- after C_Initialize + C_Finalize, call ``C_GetSlotList``; the
      module should answer CKR_CRYPTOKI_NOT_INITIALIZED (some auto-reinitialize -> CKR_OK).
      Emits ``CKR:0x{rv:08x}`` then ``OK``.  Runs at ``Level.INIT``: the infra performs the
      C_Initialize, the probe performs the C_Finalize + the post-finalize call (mirroring the
      legacy child, which did Init -> Finalize -> C_GetSlotList itself).

  ``"device_removed"`` -- load the fault-proxy (``module_path``) with the real module +
      injection config threaded through ``extra`` and set into the environment *before* the
      proxy loads, then ``C_GenerateRandom`` must surface the injected CKR_DEVICE_REMOVED.
      Emits ``OK:DEVICE_REMOVED`` / ``FAIL`` / ``OTHER:0x{rv:08x}``.  Runs at ``Level.SESSION``
      (open session, no login -- the legacy child imported but never called ``login_user``).

No PIN is ever read here: neither probe logs in (Invariant I3).  Session teardown, rv-trace,
and coverage are handled by ``probe_main`` atexit, matching the legacy
``_p11check_cleanup_session`` / rv-trace setup.

The fault-proxy reads its injection config from the environment as it loads, which happens
inside ``probe_main``'s ``from_lib`` -- *before* ``_run``.  So the three ``PKCS11_*`` env vars
are set from ``params.extra`` in ``_main`` before ``probe_main`` runs (plain data threaded
through params, never a PIN), reproducing the legacy child's pre-load ``os.environ`` writes.

Output protocol (byte-identical to the legacy child, for ``assert_ckr_subprocess_ok`` and the
parent-side ``in stdout`` checks):
  ``CKR:0x{rv:08x}``     -- C_GetSlotList return value after C_Finalize (not_initialized)
  ``OK``                 -- not_initialized probe reached its expected point
  ``OK:DEVICE_REMOVED``  -- device_removed probe saw the injected CKR_DEVICE_REMOVED
  ``FAIL``               -- device_removed probe saw CKR_OK (injection did not fire)
  ``OTHER:0x{rv:08x}``   -- device_removed probe saw some other CK_RV

Required ``extra`` keys:
  ``"probe"`` -- ``"not_initialized"`` or ``"device_removed"``.
For ``"device_removed"`` additionally (plain data, never a PIN):
  ``"real_module"``     -- path the fault-proxy delegates to (``PKCS11_REAL_MODULE``)
  ``"inject_function"`` -- function to inject on (``PKCS11_INJECT_FUNCTION``)
  ``"inject_error"``    -- CK_RV hex string to inject (``PKCS11_INJECT_ERROR``)

Launch with ``coverage="session"`` and no PIN (neither probe logs in).
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Any

from pkcs11_check.raw.types_std import CKR_DEVICE_REMOVED, CKR_OK
from pkcs11_check.testcases._probes.params import ProbeParams
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _not_initialized(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GetSlotList after C_Finalize -> CKR_CRYPTOKI_NOT_INITIALIZED (or CKR_OK)."""
    ctx.raw.C_Finalize(None)
    # Now call something - should get NOT_INITIALIZED
    sc = ctypes.c_ulong(0)
    rv = ctx.raw.C_GetSlotList(1, None, ctypes.byref(sc))
    print(f"CKR:0x{rv:08x}")
    # Report result without asserting -- outer test checks compliance
    print("OK")


def _device_removed(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateRandom must surface the fault-proxy's injected CKR_DEVICE_REMOVED."""
    buf = (ctypes.c_ubyte * 32)()
    rv = ctx.raw.C_GenerateRandom(ctx.sh, buf, 32)
    if rv == CKR_DEVICE_REMOVED:
        print("OK:DEVICE_REMOVED")
    elif rv == CKR_OK:
        print("FAIL")
    else:
        print(f"OTHER:0x{rv:08x}")


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    if probe == "not_initialized":
        _not_initialized(ctx, extra)
    elif probe == "device_removed":
        _device_removed(ctx, extra)
    else:
        raise ValueError(f"unknown probe {probe!r}")


def _main() -> None:
    params = ProbeParams.load(sys.argv[1])
    if params.extra.get("probe") == "device_removed":
        # The fault-proxy reads these from the environment as it loads, which happens
        # inside probe_main's from_lib() before _run -- so set them here, ahead of
        # probe_main, from the params (plain data; never a PIN).
        os.environ["PKCS11_REAL_MODULE"] = params.extra["real_module"]
        os.environ["PKCS11_INJECT_FUNCTION"] = params.extra["inject_function"]
        os.environ["PKCS11_INJECT_ERROR"] = params.extra["inject_error"]
        probe_main(_run, level=Level.SESSION)
    else:
        probe_main(_run, level=Level.INIT)


if __name__ == "__main__":
    _main()
