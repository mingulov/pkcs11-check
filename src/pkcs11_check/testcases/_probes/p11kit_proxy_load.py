"""Probe: load a PKCS#11 module and C_Initialize it under crash isolation.

Used by test_interop_openssl.py::test_load_module_via_p11kit to load the p11-kit proxy
module (passed as ``module_path``) and initialize it in its own process, so a crash in the
proxy load/init path kills only this child.  Runs at Level.LOAD so the probe drives
C_Initialize itself inside the try/except (the entry point does the from_lib).

The broad ``except Exception`` is intentional: this is a crash-safety probe whose contract
is to report ANY load/init failure as an ``ERROR:`` line rather than propagate it (the
parent asserts the child printed either ``OK:`` or ``ERROR:`` and did not crash).

Output protocol (preserved verbatim for the parent):
  OK: p11-kit proxy loaded and initialized
  ERROR: <ExcType>: <message>
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _load_and_init(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Initialize the already-loaded module; report OK or ERROR (never propagate)."""
    raw = ctx.raw
    try:
        raw.C_Initialize()
        print("OK: p11-kit proxy loaded and initialized")
        raw.C_Finalize()
    except Exception as e:  # noqa: BLE001 - crash-safety probe reports ANY failure as ERROR:
        print(f"ERROR: {type(e).__name__}: {e}")


if __name__ == "__main__":
    probe_main(_load_and_init, level=Level.LOAD)
