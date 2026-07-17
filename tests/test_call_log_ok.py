"""raw._call must count CKR_OK invocations per C_* function (call_log_ok) so the
hollow-pass oracle can distinguish 'called' from 'productively succeeded'."""

from __future__ import annotations

from collections import defaultdict

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OK


def _bare_raw() -> RawPKCS11:
    """A RawPKCS11 with only the attributes _call touches (no real module load)."""
    raw = object.__new__(RawPKCS11)
    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._rv_trace = None
    raw._journal = None
    raw._funcs = {}
    return raw


def test_call_log_ok_counts_only_ok_results() -> None:
    raw = _bare_raw()
    raw._funcs = {
        "C_GetInfo": lambda *a: int(CKR_OK),
        "C_GetSlotInfo": lambda *a: int(CKR_DEVICE_ERROR),
    }
    raw._call("C_GetInfo")
    raw._call("C_GetInfo")
    raw._call("C_GetSlotInfo")

    assert raw.call_log["C_GetInfo"] == 2
    assert raw.call_log["C_GetSlotInfo"] == 1  # called
    assert raw.call_log_ok["C_GetInfo"] == 2  # both OK
    assert raw.call_log_ok.get("C_GetSlotInfo", 0) == 0  # errored -> not productive (no key)


def test_reset_clears_ok_log() -> None:
    raw = _bare_raw()
    raw._funcs = {"C_GetInfo": lambda *a: int(CKR_OK)}
    raw._call("C_GetInfo")
    raw.reset_call_log()
    assert raw.call_log_ok == {}
