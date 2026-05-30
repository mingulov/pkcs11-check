"""Meta-tests for the per-test CK_RV trace (PKCS11_CHECK_RV_TRACE / --p11-rv-trace).

These drive the *real* ``RawPKCS11._call`` choke point with stub ``_funcs`` so
they assert the exact trace the harness would attach to ``report.jsonl``'s
``user_properties``. See docs/rv-trace-design.md.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from ctypes import byref
from types import SimpleNamespace
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


# --- integration wiring: teardown drain + config resolution ---------------


def _fake_item(raw: RawPKCS11, fixture: str = "p11_raw_session") -> Any:
    return SimpleNamespace(funcargs={fixture: SimpleNamespace(raw=raw)}, user_properties=[])


def test_drain_appends_trace_once_to_user_properties() -> None:
    from pkcs11_check.plugin import _drain_rv_trace

    raw = _stub_raw({"C_Sign": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_Sign(7, b"x", 1, None, _len_ptr())

    item = _fake_item(raw)
    _drain_rv_trace(item)

    assert item.user_properties == [
        ("pkcs11_rv_trace", [{"i": 0, "fn": "C_Sign", "mech": None, "rv": 0, "rv_name": "CKR_OK"}])
    ]


def test_drain_is_noop_when_tracing_off() -> None:
    from pkcs11_check.plugin import _drain_rv_trace

    raw = _stub_raw({"C_Sign": lambda *a: 0})  # never enabled
    raw.C_Sign(7, b"x", 1, None, _len_ptr())

    item = _fake_item(raw)
    _drain_rv_trace(item)

    assert item.user_properties == []


def test_drain_records_dropped_in_compact_mode() -> None:
    from pkcs11_check.plugin import _drain_rv_trace

    raw = _stub_raw({"C_Sign": lambda *a: 0})
    raw.enable_rv_trace(maxlen=2)
    for _ in range(5):
        raw.C_Sign(7, b"x", 1, None, _len_ptr())

    item = _fake_item(raw)
    _drain_rv_trace(item)

    props = dict(item.user_properties)
    assert [e["i"] for e in props["pkcs11_rv_trace"]] == [3, 4]  # absolute tail indices
    assert props["pkcs11_rv_trace_dropped"] == 3


def test_resolve_compact_implies_enabled() -> None:
    from pkcs11_check.fixtures import _resolve_rv_trace

    assert _resolve_rv_trace(
        opt_trace=False, opt_compact=256, env_trace=None, env_compact=None
    ) == (
        True,
        256,
    )


def test_resolve_option_enables_full_capture() -> None:
    from pkcs11_check.fixtures import _resolve_rv_trace

    assert _resolve_rv_trace(
        opt_trace=True, opt_compact=None, env_trace=None, env_compact=None
    ) == (
        True,
        None,
    )


def test_resolve_env_bridge() -> None:
    from pkcs11_check.fixtures import _resolve_rv_trace

    assert _resolve_rv_trace(
        opt_trace=False, opt_compact=None, env_trace="1", env_compact="512"
    ) == (True, 512)


def test_resolve_off_by_default() -> None:
    from pkcs11_check.fixtures import _resolve_rv_trace

    assert _resolve_rv_trace(
        opt_trace=False, opt_compact=None, env_trace=None, env_compact=None
    ) == (False, None)


def test_real_teardown_hook_drains_trace_for_testcase_item() -> None:
    """The actual pytest_runtest_teardown hook attaches the trace (gate + drain).

    Exercises the real hook: the _is_testcase_item gate, the independent drain,
    and coexistence with the coverage early-return (session=None). Proves the
    plumbing that lands the trace on the teardown report's user_properties.
    """
    from pathlib import Path

    from pkcs11_check import plugin

    raw = _stub_raw({"C_Sign": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_Sign(7, b"x", 1, None, _len_ptr())

    item = SimpleNamespace(
        funcargs={"p11_raw_session": SimpleNamespace(raw=raw)},
        user_properties=[],
        path=Path("/repo/src/pkcs11_check/testcases/test_foo.py"),
        session=None,  # coverage drain returns early; rv-trace drain already ran
    )

    plugin.pytest_runtest_teardown(item, None)

    props = dict(item.user_properties)
    assert props["pkcs11_rv_trace"] == [
        {"i": 0, "fn": "C_Sign", "mech": None, "rv": 0, "rv_name": "CKR_OK"}
    ]


def test_real_teardown_hook_records_nothing_when_off() -> None:
    """Off ⇒ the hook leaves user_properties empty (byte-identical report.jsonl)."""
    from pathlib import Path

    from pkcs11_check import plugin

    raw = _stub_raw({"C_Sign": lambda *a: 0})  # never enabled
    raw.C_Sign(7, b"x", 1, None, _len_ptr())

    item = SimpleNamespace(
        funcargs={"p11_raw_session": SimpleNamespace(raw=raw)},
        user_properties=[],
        path=Path("/repo/src/pkcs11_check/testcases/test_foo.py"),
        session=None,
    )

    plugin.pytest_runtest_teardown(item, None)

    assert item.user_properties == []
