"""Arity guards for the p11-kit proxy load probe (fw#49).

``C_Initialize`` and ``C_Finalize`` each declare one parameter, so calling
them with zero arguments dies with ``TypeError`` before the module is
reached -- the same pre-call rejection family as the ``C_AsyncGetID``
selector. The probe reports any exception as ``ERROR:``, which the parent
accepts, so an arity slip would pass the test without ever initializing.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.types_std import CKR_OK, CK_C_Finalize, CK_C_Initialize
from pkcs11_check.testcases._probes import p11kit_proxy_load
from pkcs11_check.testcases._probes.session import ProbeContext


class _FakeRaw:
    """Record init/finalize calls through the real prototypes (fw#49)."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.C_Initialize = CK_C_Initialize(self._initialize)
        self.C_Finalize = CK_C_Finalize(self._finalize)

    def _initialize(self, reserved: Any) -> int:
        del reserved
        self.calls.append("C_Initialize")
        return int(CKR_OK)

    def _finalize(self, reserved: Any) -> int:
        del reserved
        self.calls.append("C_Finalize")
        return int(CKR_OK)


def test_load_and_init_calls_both_entry_points(capsys: Any) -> None:
    """The probe must call C_Initialize(None) and C_Finalize(None) (fw#49)."""
    raw = _FakeRaw()
    ctx = ProbeContext(raw=raw, sh=0, slot_id=0, cleanup=lambda: None, module_path="fake")
    p11kit_proxy_load._load_and_init(ctx, {})
    assert raw.calls == ["C_Initialize", "C_Finalize"]
    assert "OK:" in capsys.readouterr().out
