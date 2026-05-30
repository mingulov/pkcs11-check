"""Meta-tests for the per-test CK_RV trace (PKCS11_CHECK_RV_TRACE / --p11-rv-trace).

These drive the *real* ``RawPKCS11._call`` choke point with stub ``_funcs`` so
they assert the exact trace the harness would attach to ``report.jsonl``'s
``user_properties``. See docs/rv-trace-design.md.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from ctypes import byref
from typing import Any

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CBC,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
)


# The exact attribute set ``_call`` touches.  Building via ``object.__new__``
# bypasses ``__init__`` (which requires a real loaded module) so the test can
# exercise the genuine choke point with lambda stubs.
def _stub_raw(funcs: dict[str, Any]) -> RawPKCS11:
    raw = object.__new__(RawPKCS11)
    raw._funcs = dict(funcs)
    raw._lib = None
    raw._call_log = defaultdict(int)
    raw._used_mechanisms = set()
    raw._mechanism_counts = Counter()
    raw._rv_trace = None
    raw._rv_trace_total = 0
    return raw


def _mech(mech_id: int) -> Any:
    m = CK_MECHANISM()
    m.mechanism = mech_id
    return byref(m)


def _len_ptr() -> Any:
    return byref(CK_ULONG(0))


def test_rv_trace_captures_exact_sequence() -> None:
    raw = _stub_raw(
        {
            "C_EncryptInit": lambda *a: 0,
            "C_Sign": lambda *a: 0,
            "C_GetSessionInfo": lambda *a: 0x12345678,
        }
    )
    raw.enable_rv_trace()

    raw.C_EncryptInit(7, _mech(int(CKM_AES_CBC)), 3)
    raw.C_Sign(7, b"x", 1, None, _len_ptr())
    raw.C_GetSessionInfo(7, None)

    assert raw.rv_trace == [
        {"i": 0, "fn": "C_EncryptInit", "mech": int(CKM_AES_CBC), "rv": 0, "rv_name": "CKR_OK"},
        {"i": 1, "fn": "C_Sign", "mech": None, "rv": 0, "rv_name": "CKR_OK"},
        {
            "i": 2,
            "fn": "C_GetSessionInfo",
            "mech": None,
            "rv": 0x12345678,
            "rv_name": "0x12345678",
        },
    ]
    assert raw.rv_trace_dropped == 0


def test_rv_trace_disabled_records_nothing() -> None:
    raw = _stub_raw({"C_Sign": lambda *a: 0})
    # tracing never enabled -> no buffer, nothing recorded
    raw.C_Sign(7, b"x", 1, None, _len_ptr())
    assert raw.rv_trace == []
    assert raw.rv_trace_dropped == 0


def test_rv_trace_never_leaks_secret_material() -> None:
    raw = _stub_raw(
        {
            "C_Login": lambda *a: 0,
            "C_GenerateKey": lambda *a: 0,
            "C_EncryptInit": lambda *a: 0,
            "C_Encrypt": lambda *a: 0,
        }
    )
    raw.enable_rv_trace()

    pin = b"S3CR3T-PIN-9999"
    key_material = b"K3Y-BYTES-AAAA"
    plaintext = b"PLAINTEXT-BBBB"

    raw.C_Login(7, 1, pin, len(pin))
    raw.C_GenerateKey(7, _mech(int(CKM_AES_CBC)), key_material, len(key_material), _len_ptr())
    raw.C_EncryptInit(7, _mech(int(CKM_AES_CBC)), 5)
    raw.C_Encrypt(7, plaintext, len(plaintext), None, _len_ptr())

    blob = json.dumps(raw.rv_trace)
    for secret in (pin, key_material, plaintext):
        assert secret.decode() not in blob

    whitelist = {"i", "fn", "mech", "rv", "rv_name"}
    for entry in raw.rv_trace:
        assert set(entry) <= whitelist, entry
    # C_Login is recorded by name+rv only, never its PIN argument.
    assert any(e["fn"] == "C_Login" for e in raw.rv_trace)


def test_single_rv_change_is_localized() -> None:
    def build(sign_rv: int) -> list[dict[str, Any]]:
        raw = _stub_raw({"C_EncryptInit": lambda *a: 0, "C_Sign": lambda *a: sign_rv})
        raw.enable_rv_trace()
        raw.C_EncryptInit(7, _mech(int(CKM_AES_CBC)), 3)
        raw.C_Sign(7, b"x", 1, None, _len_ptr())
        return raw.rv_trace

    baseline = build(int(CKR_OK))
    changed = build(int(CKR_SIGNATURE_INVALID))

    diffs = [(a, b) for a, b in zip(baseline, changed, strict=True) if a != b]
    assert len(diffs) == 1
    before, after = diffs[0]
    # The change is pinpointed to exactly (i, fn, mech) == (1, C_Sign, None).
    assert (before["i"], before["fn"], before["mech"]) == (1, "C_Sign", None)
    assert (after["i"], after["fn"], after["mech"]) == (1, "C_Sign", None)
    assert before["rv"] != after["rv"]
