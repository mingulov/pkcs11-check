"""Probe: C_Initialize called twice must return OK or ALREADY_INITIALIZED.

Runs at Level.LOAD (the module is loaded but NOT initialized by the entry point) so the
probe itself drives both C_Initialize calls, reproducing the legacy double-initialize
subprocess script.  Output protocol preserved verbatim for the parent classifier in
test_protocol_edge_cases.py::TestProtocolEdgeCases.test_double_initialize.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.types_std import CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _double_initialize(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Call C_Initialize twice; the second must return OK or ALREADY_INITIALIZED."""
    raw = ctx.raw
    raw.C_Initialize(None)
    rv = raw.C_Initialize(None)
    if rv == CKR_OK:
        print("OK: second init succeeded")
    elif rv == CKR_CRYPTOKI_ALREADY_INITIALIZED:
        print("OK: CKR_CRYPTOKI_ALREADY_INITIALIZED")
    else:
        print(f"OK: 0x{rv:08x}")
    raw.C_Finalize(None)


if __name__ == "__main__":
    probe_main(_double_initialize, level=Level.LOAD)
