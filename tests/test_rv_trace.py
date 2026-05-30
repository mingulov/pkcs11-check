"""Meta-tests for the per-test CK_RV trace (PKCS11_CHECK_RV_TRACE / --p11-rv-trace).

These drive the *real* ``RawPKCS11._call`` choke point with stub ``_funcs`` so
they assert the exact trace the harness would attach to ``report.jsonl``'s
``user_properties``. See docs/rv-trace-design.md.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from ctypes import byref
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CBC,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_FAILED,
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
    # Non-output, mixed-mechanism functions so the entries are the pure core
    # schema (no in_len/out_len enrichment — those have dedicated tests below).
    raw = _stub_raw(
        {
            "C_EncryptInit": lambda *a: 0,
            "C_Logout": lambda *a: 0,
            "C_GetSessionInfo": lambda *a: 0x12345678,
        }
    )
    raw.enable_rv_trace()

    raw.C_EncryptInit(7, _mech(int(CKM_AES_CBC)), 3)
    raw.C_Logout(7)
    raw.C_GetSessionInfo(7, None)

    assert raw.rv_trace == [
        {"i": 0, "fn": "C_EncryptInit", "mech": int(CKM_AES_CBC), "rv": 0, "rv_name": "CKR_OK"},
        {"i": 1, "fn": "C_Logout", "mech": None, "rv": 0, "rv_name": "CKR_OK"},
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

    whitelist = {"i", "fn", "mech", "rv", "rv_name", "in_len", "out_len"}
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

    raw = _stub_raw({"C_GetSessionInfo": lambda *a: 0})  # non-output -> pure core schema
    raw.enable_rv_trace()
    raw.C_GetSessionInfo(7, _len_ptr())

    item = _fake_item(raw)
    _drain_rv_trace(item)

    assert item.user_properties == [
        (
            "pkcs11_rv_trace",
            [{"i": 0, "fn": "C_GetSessionInfo", "mech": None, "rv": 0, "rv_name": "CKR_OK"}],
        )
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


def test_resolve_nonsensical_compact_falls_back_to_full() -> None:
    from pkcs11_check.fixtures import _resolve_rv_trace

    # A negative/zero window is a user error -> enabled (they asked for tracing)
    # + full capture (None), never a deque(maxlen) ValueError in fixture setup.
    assert _resolve_rv_trace(
        opt_trace=False, opt_compact=-5, env_trace=None, env_compact=None
    ) == (True, None)
    assert _resolve_rv_trace(
        opt_trace=False, opt_compact=None, env_trace=None, env_compact="0"
    ) == (True, None)


def test_real_teardown_hook_drains_trace_for_testcase_item() -> None:
    """The actual pytest_runtest_teardown hook attaches the trace (gate + drain).

    Exercises the real hook: the _is_testcase_item gate, the independent drain,
    and coexistence with the coverage early-return (session=None). Proves the
    plumbing that lands the trace on the teardown report's user_properties.
    """
    from pathlib import Path

    from pkcs11_check import plugin

    raw = _stub_raw({"C_GetSessionInfo": lambda *a: 0})  # non-output -> pure core schema
    raw.enable_rv_trace()
    raw.C_GetSessionInfo(7, _len_ptr())

    item = SimpleNamespace(
        funcargs={"p11_raw_session": SimpleNamespace(raw=raw)},
        user_properties=[],
        path=Path("/repo/src/pkcs11_check/testcases/test_foo.py"),
        session=None,  # coverage drain returns early; rv-trace drain already ran
    )

    plugin.pytest_runtest_teardown(item, None)

    props = dict(item.user_properties)
    assert props["pkcs11_rv_trace"] == [
        {"i": 0, "fn": "C_GetSessionInfo", "mech": None, "rv": 0, "rv_name": "CKR_OK"}
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


# --- Phase 3: out_len / in_len (best-effort, length-only) ------------------


def test_out_len_and_in_len_recorded_for_output_call() -> None:
    raw = _stub_raw({"C_Sign": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_Sign(7, b"data", 4, None, byref(CK_ULONG(48)))  # in_len=args[2]=4, out_len=48
    e = raw.rv_trace[0]
    assert e["in_len"] == 4
    assert e["out_len"] == 48


def test_out_len_absent_for_non_output_function() -> None:
    raw = _stub_raw({"C_GetSessionInfo": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_GetSessionInfo(7, byref(CK_ULONG(99)))  # readable ulong last arg, but not output
    e = raw.rv_trace[0]
    assert "out_len" not in e
    assert "in_len" not in e


def test_out_len_absent_for_derive_key_handle() -> None:
    """C_DeriveKey's last arg is a key HANDLE, not a length — never read as out_len."""
    raw = _stub_raw({"C_DeriveKey": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_DeriveKey(7, _mech(int(CKM_AES_CBC)), 1, 0, byref(CK_ULONG(4242)))
    e = raw.rv_trace[0]
    assert e["mech"] == int(CKM_AES_CBC)  # mechanism still captured
    assert "out_len" not in e  # the 4242 handle must NOT be mislabeled


def test_out_len_only_on_ok_or_buffer_too_small() -> None:
    # hard error -> out_len absent (stale), but in_len (an input) still present
    raw = _stub_raw({"C_Sign": lambda *a: int(CKR_FUNCTION_FAILED)})
    raw.enable_rv_trace()
    raw.C_Sign(7, b"x", 1, None, byref(CK_ULONG(48)))
    e = raw.rv_trace[0]
    assert "out_len" not in e
    assert e["in_len"] == 1

    # CKR_BUFFER_TOO_SMALL sets the required length -> out_len present
    raw2 = _stub_raw({"C_Sign": lambda *a: int(CKR_BUFFER_TOO_SMALL)})
    raw2.enable_rv_trace()
    raw2.C_Sign(7, b"x", 1, None, byref(CK_ULONG(256)))
    assert raw2.rv_trace[0]["out_len"] == 256


def test_output_len_funcs_covers_two_call_output_callers() -> None:
    """Drift guard: every _two_call_output caller must be in _OUTPUT_LEN_FUNCS."""
    import pathlib
    import re

    import pkcs11_check.raw.recipes as recipes_mod
    from pkcs11_check.raw.api import _OUTPUT_LEN_FUNCS

    src = pathlib.Path(recipes_mod.__file__).read_text()
    direct_callers = set(re.findall(r'_two_call_output\(\s*raw,\s*"(C_\w+)"', src))
    assert direct_callers, "regex found no _two_call_output callers (pattern drift?)"
    # _multipart_output(raw, session, init_fn, update_fn, final_fn, ...): the
    # final_fn (3rd string) is also an output-producing call (C_EncryptFinal, ...).
    multipart_finals = set(
        re.findall(
            r'_multipart_output\(\s*raw,\s*session,\s*"C_\w+",\s*"C_\w+",\s*"(C_\w+)"',
            src,
        )
    )
    assert multipart_finals, "regex found no _multipart_output final_fn (pattern drift?)"
    missing = (direct_callers | multipart_finals) - _OUTPUT_LEN_FUNCS
    assert not missing, f"output-producing recipes missing from _OUTPUT_LEN_FUNCS: {missing}"


# --- Sub-mechanism params (stacked mechanism config, deterministic) ---------


def test_mech_params_recorded_for_stacked_mechanism() -> None:
    from pkcs11_check.raw.pack import PackedMechanism

    raw = _stub_raw({"C_EncryptInit": lambda *a: 0})
    raw.enable_rv_trace()
    ck = CK_MECHANISM()
    ck.mechanism = int(CKM_RSA_PKCS_OAEP)
    pm = PackedMechanism(ck, sub_mechanisms={"hashAlg": int(CKM_SHA256)})

    raw.C_EncryptInit(7, pm.byref(), 5)

    e = raw.rv_trace[0]
    assert e["mech"] == int(CKM_RSA_PKCS_OAEP)
    assert e["mech_params"] == {"hashAlg": int(CKM_SHA256)}


def test_mech_params_absent_for_simple_mechanism() -> None:
    raw = _stub_raw({"C_EncryptInit": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_EncryptInit(7, _mech(int(CKM_AES_CBC)), 5)  # plain CK_MECHANISM, no sub-params
    assert "mech_params" not in raw.rv_trace[0]


# --- Phase 4: crash-survivable write-ahead journal -------------------------


def test_crash_journal_records_completed_calls(tmp_path: Path) -> None:
    from pkcs11_check.raw import api as rawapi

    jpath = tmp_path / "j.jsonl"
    raw = _stub_raw({"C_EncryptInit": lambda *a: 0, "C_GetSessionInfo": lambda *a: 0})
    raw._journal = rawapi._RvTraceJournal(str(jpath))

    raw.C_EncryptInit(7, _mech(int(CKM_AES_CBC)), 5)
    raw.C_GetSessionInfo(7, None)

    done, incomplete = rawapi.read_crash_journal(jpath)
    assert [d["fn"] for d in done] == ["C_EncryptInit", "C_GetSessionInfo"]
    assert incomplete is None
    assert done[0]["mech"] == int(CKM_AES_CBC)
    assert done[0]["rv"] == 0 and done[0]["rv_name"] == "CKR_OK"


def test_crash_journal_recovers_last_call_before_crash(tmp_path: Path) -> None:
    from pkcs11_check.raw import api as rawapi

    def boom(*_a: Any) -> int:
        raise RuntimeError("segfault stand-in")  # the C_* call never returns

    jpath = tmp_path / "j.jsonl"
    raw = _stub_raw({"C_GetSessionInfo": lambda *a: 0, "C_Sign": boom})
    raw._journal = rawapi._RvTraceJournal(str(jpath))

    raw.C_GetSessionInfo(7, None)
    with pytest.raises(RuntimeError):
        raw.C_Sign(7, b"x", 1, None, _len_ptr())

    done, incomplete = rawapi.read_crash_journal(jpath)
    assert [d["fn"] for d in done] == ["C_GetSessionInfo"]  # only the call that returned
    assert incomplete is not None
    assert incomplete["fn"] == "C_Sign"  # the crashing call, recovered from the WAL


def test_crash_journal_tolerates_torn_final_line(tmp_path: Path) -> None:
    from pkcs11_check.raw import api as rawapi

    jpath = tmp_path / "j.jsonl"
    jpath.write_text(
        '{"ev": "call", "i": 0, "fn": "C_Sign", "mech": null}\n'
        '{"ev": "ret", "i": 0, "rv": 0, "rv_name": "CKR_OK"}\n'
        '{"ev": "call", "i": 1, "fn": "C_Dec'  # torn mid-write by the crash
    )
    done, incomplete = rawapi.read_crash_journal(jpath)
    assert [d["fn"] for d in done] == ["C_Sign"]
    assert incomplete is None  # torn line is skipped, not crashed on


# --- Hardening: serialization round-trip + capture edge cases --------------


def test_trace_survives_reportlog_serialization_unchanged() -> None:
    """The rich nested trace is natively JSON-serializable, so reportlog's
    cleanup_unserializable is a no-op (it never str()-mangles our value)."""
    from pytest_reportlog.plugin import cleanup_unserializable

    from pkcs11_check.raw.pack import PackedMechanism

    raw = _stub_raw({"C_EncryptInit": lambda *a: 0, "C_Sign": lambda *a: 0})
    raw.enable_rv_trace()
    ck = CK_MECHANISM()
    ck.mechanism = int(CKM_RSA_PKCS_OAEP)
    pm = PackedMechanism(ck, sub_mechanisms={"hashAlg": int(CKM_SHA256)})
    raw.C_EncryptInit(7, pm.byref(), 5)
    raw.C_Sign(7, b"data", 4, None, byref(CK_ULONG(48)))

    trace = raw.rv_trace
    assert any("mech_params" in e for e in trace)  # exercises every rich field
    assert any("in_len" in e and "out_len" in e for e in trace)

    payload = {"nodeid": "x", "user_properties": [["pkcs11_rv_trace", trace]]}
    assert cleanup_unserializable(payload) == payload  # nothing was str()-coerced
    assert json.loads(json.dumps(payload)) == payload  # round-trips faithfully


def test_mech_null_when_mechanism_arg_malformed() -> None:
    raw = _stub_raw({"C_EncryptInit": lambda *a: 0})
    raw.enable_rv_trace()
    raw.C_EncryptInit(7, 12345, 5)  # args[1] is a plain int -> no ._obj -> mech None
    e = raw.rv_trace[0]
    assert e["fn"] == "C_EncryptInit"
    assert e["mech"] is None


def test_reset_rv_trace_preserves_maxlen() -> None:
    raw = _stub_raw({"C_GetSessionInfo": lambda *a: 0})
    raw.enable_rv_trace(maxlen=2)
    for _ in range(5):
        raw.C_GetSessionInfo(7, None)
    assert len(raw.rv_trace) == 2
    assert raw.rv_trace_dropped == 3

    raw.reset_rv_trace()
    assert raw.rv_trace == []
    assert raw.rv_trace_dropped == 0

    for _ in range(5):
        raw.C_GetSessionInfo(7, None)
    assert len(raw.rv_trace) == 2  # ring-buffer window preserved across reset
    assert raw.rv_trace_dropped == 3


def test_compact_keeps_absolute_indices() -> None:
    raw = _stub_raw({"C_GetSessionInfo": lambda *a: 0})
    raw.enable_rv_trace(maxlen=3)
    for _ in range(10):
        raw.C_GetSessionInfo(7, None)
    assert [e["i"] for e in raw.rv_trace] == [7, 8, 9]  # absolute, not 0,1,2
    assert raw.rv_trace_dropped == 7


def test_journal_path_expands_pid_placeholder() -> None:
    import os

    from pkcs11_check.raw.api import _journal_path

    assert _journal_path("/tmp/rvj-{pid}.jsonl") == f"/tmp/rvj-{os.getpid()}.jsonl"
    assert _journal_path("/tmp/rvj.jsonl") == "/tmp/rvj.jsonl"  # no placeholder, unchanged


def test_crash_journal_survives_real_process_death(tmp_path: Path) -> None:
    """End-to-end: a real SIGABRT mid-call leaves the crashing call on disk."""
    import subprocess
    import sys

    jpath = tmp_path / "j.jsonl"
    script = (
        "import os\n"
        "from collections import Counter, defaultdict\n"
        "from pkcs11_check.raw.api import RawPKCS11, _RvTraceJournal\n"
        "raw = object.__new__(RawPKCS11)\n"
        "raw._funcs = {'C_GetInfo': lambda *a: 0, 'C_Sign': lambda *a: os.abort()}\n"
        "raw._lib = None\n"
        "raw._call_log = defaultdict(int)\n"
        "raw._used_mechanisms = set()\n"
        "raw._mechanism_counts = Counter()\n"
        "raw._rv_trace = None\n"
        "raw._rv_trace_total = 0\n"
        f"raw._journal = _RvTraceJournal({str(jpath)!r})\n"
        "raw.C_GetInfo(0)\n"
        "raw.C_Sign(7, b'x', 1, None, None)\n"  # os.abort() -> SIGABRT, never returns
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True)
    assert result.returncode != 0  # the child died by signal

    from pkcs11_check.raw.api import read_crash_journal

    done, incomplete = read_crash_journal(jpath)
    assert [d["fn"] for d in done] == ["C_GetInfo"]  # the call that returned
    assert incomplete is not None
    assert incomplete["fn"] == "C_Sign"  # the crashing call, recovered after real death
