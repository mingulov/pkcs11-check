"""Child-channel call counters: coverage-file fold-in + raw-CDLL counting (fw#73, Task 4).

The probe child flattens its process-global counters into the coverage file
(``call_counters`` key, flat wire format); the parent folds them into its own
globals under the active bucket when it ingests that file. A child whose
counters never arrive (crash, corrupt file, pre-channel payload) is accounted
via ``note_lost_probe`` by the launcher.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
import warnings
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.core import call_counters
from pkcs11_check.core.process_observation import drain_process_observations
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import CK_SESSION_HANDLE, CK_ULONG, CKR_CANT_LOCK, CKR_OK
from pkcs11_check.testcases import _raw_subprocess, _subprocess_preamble, test_threading
from pkcs11_check.testcases._probes import (
    _ckr_ctypes,
    _emit,
    ckr_null_params_login,
    ckr_null_params_session,
    raw_session,
    session,
)
from pkcs11_check.testcases._probes import subprocess_safety as subprocess_safety_probe
from pkcs11_check.testcases._probes.runner import run_probe


@pytest.fixture(autouse=True)
def _clean_counters() -> Iterator[None]:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


def _unknown_buckets(snap: dict[str, Any]) -> dict[str, Any]:
    """Inner buckets of the single unknown-module block (no handle involved)."""
    assert set(snap["by_module"]) == {""}
    return snap["by_module"][""]["buckets"]


_IngestFn = Callable[[str], bool]

_INGEST_FNS: tuple[_IngestFn, ...] = (
    _subprocess_preamble.ingest_subprocess_coverage,
    _raw_subprocess.ingest_raw_subprocess_coverage,
)


def _write_coverage_file(path: Path, payload: dict[str, Any]) -> str:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _child_payload() -> dict[str, Any]:
    return {
        "call_log": {},
        "mechanism_counts": {},
        "call_log_ok": {},
        "mechanism_rv_counts": {},
        "call_counters": [["C_Login", 0, 2], ["C_Login", 49, 1]],
    }


def test_ingest_merges_child_counts_under_active_bucket(tmp_path: Path) -> None:
    cov = _write_coverage_file(tmp_path / "cov.json", _child_payload())
    with call_counters.counted_bucket("test"):
        assert _subprocess_preamble.ingest_subprocess_coverage(cov) is True
    entry = _unknown_buckets(call_counters.serialize_current())["test"]["by_fn"]["C_Login"]
    assert entry["calls"] == 3
    assert entry["by_rv"]["0"]["count"] == 2
    assert entry["by_rv"]["49"]["count"] == 1


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_merges_child_counts_both_paths(ingest: _IngestFn, tmp_path: Path) -> None:
    cov = _write_coverage_file(tmp_path / "cov.json", _child_payload())
    with call_counters.counted_bucket("test"):
        assert ingest(cov) is True
    entry = _unknown_buckets(call_counters.serialize_current())["test"]["by_fn"]["C_Login"]
    assert entry["calls"] == 3
    assert entry["by_rv"]["0"]["count"] == 2
    assert entry["by_rv"]["49"]["count"] == 1


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_missing_file_returns_false(ingest: _IngestFn, tmp_path: Path) -> None:
    assert ingest(str(tmp_path / "no-such-file.json")) is False
    assert ingest("") is False
    assert call_counters.serialize_current()["total_calls"] == 0
    assert call_counters.probes_lost() == 0  # ingest never accounts loss itself


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_corrupt_file_returns_false(ingest: _IngestFn, tmp_path: Path) -> None:
    cov = tmp_path / "cov.json"
    cov.write_text("not json{{{", encoding="utf-8")
    assert ingest(str(cov)) is False  # swallowed, never raises
    assert call_counters.serialize_current()["total_calls"] == 0


def test_ingest_non_dict_payload_returns_false_session(tmp_path: Path) -> None:
    cov = tmp_path / "cov.json"
    cov.write_text("[]", encoding="utf-8")
    assert _subprocess_preamble.ingest_subprocess_coverage(str(cov)) is False
    assert call_counters.serialize_current()["total_calls"] == 0


def test_ingest_non_dict_payload_returns_false_raw(tmp_path: Path) -> None:
    cov = tmp_path / "cov.json"
    cov.write_text("[]", encoding="utf-8")
    assert _raw_subprocess.ingest_raw_subprocess_coverage(str(cov)) is False
    assert call_counters.serialize_current()["total_calls"] == 0


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_finalized_only_file_returns_false(ingest: _IngestFn, tmp_path: Path) -> None:
    cov = _write_coverage_file(tmp_path / "cov.json", {"python_finalized": True})
    assert ingest(cov) is False
    assert call_counters.serialize_current()["total_calls"] == 0


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
@pytest.mark.parametrize(
    "counters",
    ["garbage", {"C_Login": 1}, 42, None],
    ids=["str", "dict", "int", "none"],
)
def test_ingest_unusable_counters_returns_false(
    ingest: _IngestFn, counters: Any, tmp_path: Path
) -> None:
    payload = _child_payload()
    payload["call_counters"] = counters
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is False
    assert call_counters.serialize_current()["total_calls"] == 0


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_empty_counters_list_reports_true(ingest: _IngestFn, tmp_path: Path) -> None:
    # A child that made no calls reports zero rows; the channel worked, nothing was lost.
    payload = _child_payload()
    payload["call_counters"] = []
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is True
    assert call_counters.serialize_current()["total_calls"] == 0


def test_write_coverage_embeds_call_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    _emit.write_coverage(
        {"C_Login": 3},
        {},
        {"C_Login": 2},
        {},
        call_counters=[["C_Login", 0, 2], ["C_Login", None, 1]],
    )
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["call_counters"] == [["C_Login", 0, 2], ["C_Login", None, 1]]
    assert data["call_log"] == {"C_Login": 3}
    assert data["call_log_ok"] == {"C_Login": 2}


def test_write_coverage_omits_call_counters_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pre-channel callers (e.g. the _echo stub probe) write no key; ingest reads
    # the absence as "no counters reported".
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    _emit.write_coverage({"C_Echo": 1}, {})
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert "call_counters" not in data
    assert data["call_log"] == {"C_Echo": 1}


def _fake_raw() -> Any:
    """Minimal RawPKCS11 double exposing only what _write_coverage reads."""
    return SimpleNamespace(
        call_log={"C_Initialize": 1},
        mechanism_counts={},
        call_log_ok={"C_Initialize": 1},
        mechanism_rv_counts={},
    )


def test_session_write_coverage_embeds_flattened_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_counters.record_direct_call("C_Initialize", 0)
    call_counters.record_call("C_Login")  # unreturned entry -> None row
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    session._write_coverage(_fake_raw())
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["call_counters"] == [["", "C_Initialize", 0, 1], ["", "C_Login", None, 1]]
    assert data["call_log"] == {"C_Initialize": 1}


def test_session_write_coverage_round_trip_merges_into_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_counters.record_direct_call("C_Initialize", 0)
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    session._write_coverage(_fake_raw())
    call_counters.reset_for_tests()  # parent starts clean, as a fresh process would
    with call_counters.counted_bucket("test"):
        assert _subprocess_preamble.ingest_subprocess_coverage(str(cov)) is True
    entry = _unknown_buckets(call_counters.serialize_current())["test"]["by_fn"]["C_Initialize"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1


def test_raw_write_coverage_embeds_flattened_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_counters.record_direct_call("C_GetFunctionList", 0)
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    raw_session._write_raw_coverage()
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["call_counters"] == [["", "C_GetFunctionList", 0, 1]]
    assert data["call_log"] == {}


class _StubGetFunctionList:
    """CDLL double whose C_GetFunctionList answers a fixed RV."""

    def __init__(self, rv: int) -> None:
        self._rv = rv
        self.calls = 0
        self.C_GetFunctionList = self._func()

    def _func(self) -> Any:
        parent = self

        class _Func:
            def __call__(self, *args: Any) -> int:
                parent.calls += 1
                return parent._rv

        return _Func()


def test_get_function_list_records_direct_call() -> None:
    lib = _StubGetFunctionList(0)
    funclist_ptr, rv = raw_session._get_function_list(cast("ctypes.CDLL", lib))
    assert rv == 0
    assert funclist_ptr is not None
    assert lib.calls == 1
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GetFunctionList"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1


def test_get_function_list_records_rejection() -> None:
    lib = _StubGetFunctionList(7)  # CKR_ARGUMENTS_BAD
    funclist_ptr, rv = raw_session._get_function_list(cast("ctypes.CDLL", lib))
    assert rv == 7
    assert funclist_ptr is None
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GetFunctionList"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"]["7"]["count"] == 1


def _drain_probe_side_effects() -> None:
    """Clear globals a real run_probe touches so later tests see a clean slate."""
    _subprocess_preamble.get_preamble_subprocess_coverage()
    _raw_subprocess.get_raw_subprocess_coverage()
    drain_process_observations()


def test_run_probe_notes_lost_probe_when_counters_absent() -> None:
    # _echo writes coverage WITHOUT call_counters: the session-path ingest
    # reports False and the launcher accounts exactly one lost child.
    try:
        result = run_probe("_echo", {"module_path": "/nonexistent.so"}, timeout=30)
    finally:
        _drain_probe_side_effects()
    assert result.returncode == 0, result.stderr
    assert "ECHO_MARKER" not in result.stdout  # protocol output unchanged
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0


def test_run_probe_notes_lost_probe_raw_path() -> None:
    try:
        result = run_probe("_echo", {"module_path": "/nonexistent.so"}, timeout=30, coverage="raw")
    finally:
        _drain_probe_side_effects()
    assert result.returncode == 0, result.stderr
    assert call_counters.probes_lost() == 1


def test_run_probe_notes_lost_probe_on_abrupt_exit() -> None:
    # A child that dies before writing coverage leaves an empty file: ingest
    # reports False and the launcher accounts exactly one lost child.
    try:
        result = run_probe("_abrupt_exit", {"module_path": "/nonexistent.so"}, timeout=30)
    finally:
        _drain_probe_side_effects()
    assert result.returncode == 17
    assert result.stdout == "ABRUPT_MARKER\n"
    assert call_counters.probes_lost() == 1


class _StubCFunc:
    """_FuncPtr-shaped double: callable with settable restype/argtypes/errcheck."""

    def __init__(self, result: Any = 0) -> None:
        self._result = result
        self.calls: list[tuple[Any, ...]] = []
        self.restype: Any = None
        self.argtypes: Any = None
        self.errcheck: Any = None

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self._result, BaseException):
            raise self._result
        return self._result


class _StubCDLL:
    """CDLL-shaped double: one C_* symbol plus one plain attribute."""

    def __init__(self, result: Any = 0) -> None:
        self.C_Login = _StubCFunc(result)
        self.plain = object()


def _proxy_for(stub: _StubCDLL) -> Any:
    return raw_session._CountingCDLL(cast("ctypes.CDLL", stub))


def test_proxy_counts_one_entry_and_exit_per_call() -> None:
    stub = _StubCDLL()
    proxy = _proxy_for(stub)
    assert proxy.C_Login("a") == 0
    stub.C_Login._result = 49
    assert proxy.C_Login("b") == 49
    assert stub.C_Login.calls == [("a",), ("b",)]
    by_fn = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"]
    entry = by_fn["C_Login"]
    assert entry["calls"] == 2
    assert entry["by_rv"]["0"]["count"] == 1
    assert entry["by_rv"]["49"]["count"] == 1


def test_proxy_forwards_restype_argtypes_errcheck() -> None:
    stub = _StubCDLL()
    proxy = _proxy_for(stub)
    func = proxy.C_Login

    def _errcheck(_result: Any, _func: Any, _args: Any) -> Any:
        return _result

    func.restype = ctypes.c_ulong
    func.argtypes = [ctypes.c_void_p]
    func.errcheck = _errcheck
    assert stub.C_Login.restype is ctypes.c_ulong
    assert stub.C_Login.argtypes == [ctypes.c_void_p]
    assert stub.C_Login.errcheck is func.errcheck
    assert func.restype is ctypes.c_ulong  # reads come back from the real func


def test_proxy_forwards_to_real_funcptr() -> None:
    # A ctypes callback IS a real _FuncPtr: attribute sets must land on it and
    # the call must pass through with its return value intact.
    def _seven(_ptr: Any) -> int:
        return 7

    real = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(_seven)
    wrapped = raw_session._CountingFuncPtr("C_Seven", real)
    wrapped.restype = ctypes.c_ulong
    wrapped.argtypes = [ctypes.c_void_p]
    assert real.restype is ctypes.c_ulong
    assert real.argtypes == [ctypes.c_void_p]
    assert wrapped(ctypes.c_void_p(None)) == 7
    by_fn = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"]
    entry = by_fn["C_Seven"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["7"]["count"] == 1


def test_proxy_missing_symbol_raises_attributeerror() -> None:
    # ckr_general relies on AttributeError for absent exports (CKR:NO_METHOD).
    proxy = _proxy_for(_StubCDLL())
    with pytest.raises(AttributeError):
        proxy.C_Missing


def test_proxy_passes_non_c_attrs_through_untouched() -> None:
    stub = _StubCDLL()
    proxy = _proxy_for(stub)
    assert proxy.plain is stub.plain
    assert call_counters.serialize_current()["total_calls"] == 0


def test_proxy_caches_wrapper_per_symbol() -> None:
    # Mirrors CDLL's own attribute caching: repeated access returns the same
    # object, so restype set through one access is visible through another.
    proxy = _proxy_for(_StubCDLL())
    assert proxy.C_Login is proxy.C_Login
    proxy.C_Login.restype = ctypes.c_ulong
    assert proxy.C_Login.restype is ctypes.c_ulong


def test_proxy_call_exception_counts_entry_only() -> None:
    stub = _StubCDLL(RuntimeError("boom"))
    proxy = _proxy_for(stub)
    with pytest.raises(RuntimeError, match="boom"):
        proxy.C_Login()
    assert stub.C_Login.calls == [()]
    by_fn = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"]
    entry = by_fn["C_Login"]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def test_proxy_non_integer_result_passes_through_without_exit() -> None:
    # An exotic restype (e.g. c_void_p answering None) must not break the call:
    # the value passes through and only the entry is counted.
    stub = _StubCDLL(None)
    proxy = _proxy_for(stub)
    assert proxy.C_Login() is None
    by_fn = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"]
    entry = by_fn["C_Login"]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def test_call_func_counts_stubbed_address_call() -> None:
    # A fake CK_FUNCTION_LIST in real memory: one slot holds a ctypes callback
    # address, laid out exactly as make_caller's pointer arithmetic expects
    # (base + header + index * stride). No provider needed.
    seen: list[tuple[Any, ...]] = []

    def _ok(*args: Any) -> int:
        seen.append(args)
        return 0

    callback = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(_ok)
    addr = ctypes.cast(callback, ctypes.c_void_p).value
    assert addr is not None
    idx = _ckr_ctypes.FUNC_INDICES["C_Initialize"]
    table = (ctypes.c_void_p * (idx + 1))()
    table[idx] = ctypes.c_void_p(addr)
    base = ctypes.addressof(table) - _ckr_ctypes._HEADER_SIZE

    call_func, get_func = _ckr_ctypes.make_caller(SimpleNamespace(value=base))
    assert get_func(idx) == addr
    assert call_func("C_Initialize", ctypes.c_void_p(None)) == 0
    assert len(seen) == 1
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_Initialize"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1


# --- Final fix wave (fw#73 review): loss propagation wire extension ---


def test_add_lost_probes_accumulates() -> None:
    call_counters.note_lost_probe()
    call_counters.add_lost_probes(2)
    call_counters.add_lost_probes(3)
    assert call_counters.probes_lost() == 6


@pytest.mark.parametrize("garbage", [0, -1, True, False, "2", 2.0, None, [1]])
def test_add_lost_probes_ignores_garbage(garbage: Any) -> None:
    # The ingest path must never raise on a hostile payload value.
    call_counters.add_lost_probes(garbage)
    assert call_counters.probes_lost() == 0


def test_write_coverage_embeds_probes_lost(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    _emit.write_coverage({"C_Login": 1}, {}, call_counters=[["C_Login", 0, 1]], probes_lost=2)
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["probes_lost"] == 2


def test_write_coverage_defaults_probes_lost_to_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pre-existing callers (e.g. the _echo stub) are unchanged: the key is
    # always present so readers never have to distinguish "zero" from "absent".
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    _emit.write_coverage({"C_Echo": 1}, {})
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["probes_lost"] == 0
    assert "call_counters" not in data


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_accumulates_child_probes_lost(ingest: _IngestFn, tmp_path: Path) -> None:
    payload = _child_payload()
    payload["probes_lost"] = 2
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is True
    assert call_counters.probes_lost() == 2


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_old_payload_without_lost_key(ingest: _IngestFn, tmp_path: Path) -> None:
    # Backward compat: payloads written before the wire extension carry no
    # key and read as zero losses.
    cov = _write_coverage_file(tmp_path / "cov.json", _child_payload())
    assert ingest(cov) is True
    assert call_counters.probes_lost() == 0


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
@pytest.mark.parametrize("garbage", ["x", -1, True, 1.5, None, [2]])
def test_ingest_ignores_garbage_probes_lost(
    ingest: _IngestFn, garbage: Any, tmp_path: Path
) -> None:
    payload = _child_payload()
    payload["probes_lost"] = garbage
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is True
    assert call_counters.probes_lost() == 0


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_drops_inner_loss_when_counters_unusable(ingest: _IngestFn, tmp_path: Path) -> None:
    # A payload the channel cannot use is one lost child, owned by the
    # launcher; inner loss claims are untrusted and dropped (no double count).
    payload = _child_payload()
    payload["call_counters"] = "garbage"
    payload["probes_lost"] = 3
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is False
    assert call_counters.probes_lost() == 0


def test_session_write_coverage_embeds_child_side_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_counters.note_lost_probe()
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    session._write_coverage(_fake_raw())
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["probes_lost"] == 1


def test_raw_write_coverage_embeds_child_side_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_counters.note_lost_probe()
    call_counters.note_lost_probe()
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    raw_session._write_raw_coverage()
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["probes_lost"] == 2


# --- Final fix wave: bare-CDLL direct-symbol probes (I1.1, I1.2) ---


def test_counting_cdll_wraps_direct_symbol_handle() -> None:
    stub = SimpleNamespace(C_GenerateRandom=_StubCFunc(7))
    wrapped = raw_session.counting_cdll(cast("ctypes.CDLL", stub))
    wrapped.C_GenerateRandom.restype = ctypes.c_ulong
    assert wrapped.C_GenerateRandom(11, None, 32) == 7
    assert stub.C_GenerateRandom.calls == [(11, None, 32)]
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GenerateRandom"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"]["7"]["count"] == 1


def test_ckr_null_login_direct_call_lands_in_child_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = SimpleNamespace(C_GenerateRandom=_StubCFunc(0))
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: stub)
    ckr_null_params_login._run(SimpleNamespace(sh=11), {"module_path": "fake-module.so"})
    assert stub.C_GenerateRandom.calls == [(11, None, 32)]
    # The child payload written at teardown carries the direct call.
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    session._write_coverage(_fake_raw())
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert ["fake-module.so", "C_GenerateRandom", 0, 1] in data["call_counters"]


def test_ckr_null_session_direct_call_lands_in_child_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = SimpleNamespace(C_OpenSession=_StubCFunc(0))
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: stub)
    ckr_null_params_session._run(SimpleNamespace(slot_id=3), {"module_path": "fake-module.so"})
    assert stub.C_OpenSession.calls == [(3, 0x06, None, None, None)]
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    session._write_coverage(_fake_raw())
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert ["fake-module.so", "C_OpenSession", 0, 1] in data["call_counters"]


def test_ckr_null_login_not_exported_still_reports_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A module without the direct symbol keeps its output protocol and counts
    # nothing (the module was never invoked).
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: SimpleNamespace())
    ckr_null_params_login._run(SimpleNamespace(sh=11), {"module_path": "fake-module.so"})
    assert capsys.readouterr().out == "CKR:0x00000000:not_exported\n"
    assert call_counters.serialize_current()["total_calls"] == 0


# --- Final fix wave: threading workload child channel (I1.3) ---
# The workload tests are skip-disabled, so these pin the MECHANISM with stubs:
# marker present -> folded in, absent/unusable -> one lost probe.


def _workload_stdout(payload: str) -> str:
    return f"{test_threading._CALL_COUNTERS_MARKER}{payload}\nOK\n"


def test_workload_counters_marker_merged_into_parent() -> None:
    flat = [["C_Login", 0, 2], ["C_Login", 49, 1]]
    with call_counters.counted_bucket("test"):
        test_threading._ingest_workload_counters(_workload_stdout(json.dumps(flat)))
    entry = _unknown_buckets(call_counters.serialize_current())["test"]["by_fn"]["C_Login"]
    assert entry["calls"] == 3
    assert entry["by_rv"]["0"]["count"] == 2
    assert entry["by_rv"]["49"]["count"] == 1
    assert call_counters.probes_lost() == 0


def test_workload_counters_absent_marker_means_lost() -> None:
    test_threading._ingest_workload_counters("OK\n")
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0


@pytest.mark.parametrize(
    "payload",
    ["not-json{{{", '{"C_Login": 1}', "42", "null"],
    ids=["bad-json", "dict", "int", "null"],
)
def test_workload_counters_unusable_marker_means_lost(payload: str) -> None:
    test_threading._ingest_workload_counters(_workload_stdout(payload))
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0


def test_workload_counters_garbage_rows_ignored_channel_ok() -> None:
    # Parity with the coverage channel: a well-shaped marker means the channel
    # worked, even when individual rows are garbage (dropped by ingest).
    payload = json.dumps([["C_Login", 0, 1], "garbage", ["C_Login", "x", 1]])
    test_threading._ingest_workload_counters(_workload_stdout(payload))
    assert call_counters.probes_lost() == 0
    assert call_counters.serialize_current()["total_calls"] == 1


class _FakeWorkloadRaw:
    """Stub RawPKCS11 behind ``from_lib`` so the workload script runs with no provider."""

    def __init__(self, init_rv: int) -> None:
        self._init_rv = init_rv

    def C_Initialize(  # noqa: N802 - mirrors the C_* API name
        self, _args: Any
    ) -> int:
        return self._init_rv

    def C_Finalize(  # noqa: N802 - mirrors the C_* API name
        self, _arg: Any
    ) -> int:
        return int(CKR_OK)

    def C_GetSlotList(  # noqa: N802 - mirrors the C_* API name
        self, _present: int, buf: Any, count_ref: Any
    ) -> int:
        count = ctypes.cast(count_ref, ctypes.POINTER(CK_ULONG))
        if buf is None:
            count.contents.value = 1
        else:
            buf[0] = 7
            count.contents.value = 1
        return int(CKR_OK)

    def C_OpenSession(  # noqa: N802 - mirrors the C_* API name
        self, _slot: int, _flags: int, _cb: Any, _notify: Any, session_ref: Any
    ) -> int:
        ctypes.cast(session_ref, ctypes.POINTER(CK_SESSION_HANDLE)).contents.value = 11
        return int(CKR_OK)

    def C_CloseSession(  # noqa: N802 - mirrors the C_* API name
        self, _session: int
    ) -> int:
        return int(CKR_OK)


def _exec_workload_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], init_rv: int
) -> list[str]:
    """Execute the real ``_WORKLOAD_SCRIPT`` source with stub env + stub module.

    No provider: ``RawPKCS11.from_lib`` is monkeypatched to return the fake.
    Returns the child stdout lines (SystemExit from the early-exit path is
    consumed here after asserting its code).
    """
    monkeypatch.setenv("P11_THREAD_MODULE", "fake-module.so")
    monkeypatch.setenv("P11_THREAD_THREADS", "1")
    monkeypatch.setenv("P11_THREAD_ITERS", "0")
    monkeypatch.setenv("P11_THREAD_WORKLOAD", "random")
    monkeypatch.delenv("P11_THREAD_PIN", raising=False)
    fake = _FakeWorkloadRaw(init_rv)
    monkeypatch.setattr(
        RawPKCS11, "from_lib", classmethod(lambda cls, lib_path, interface="auto": fake)
    )
    namespace: dict[str, Any] = {"__name__": "p11_workload_stub"}
    try:
        exec(test_threading._WORKLOAD_SCRIPT, namespace)
    except SystemExit as exc:
        assert exc.code == 0
    return capsys.readouterr().out.splitlines()


def _workload_marker_payload(lines: list[str]) -> Any:
    marker_lines = [line for line in lines if line.startswith(test_threading._CALL_COUNTERS_MARKER)]
    assert len(marker_lines) == 1
    return json.loads(marker_lines[0].removeprefix(test_threading._CALL_COUNTERS_MARKER))


def test_workload_script_cant_lock_exit_emits_counters_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The CKR_CANT_LOCK early exit prints the marker (executed, not grepped).
    lines = _exec_workload_script(monkeypatch, capsys, int(CKR_CANT_LOCK))
    assert "SKIP_CANT_LOCK" in lines
    assert _workload_marker_payload(lines) == []


def test_workload_script_clean_tail_emits_counters_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The clean tail prints the marker after C_Finalize (executed, not
    # grepped); ITERS=0 runs the session open/close with no workload ops.
    lines = _exec_workload_script(monkeypatch, capsys, int(CKR_OK))
    assert "OK" in lines
    assert _workload_marker_payload(lines) == []


# --- Final fix wave: isolation grandchild channel (I1.4) ---


def test_write_coverage_honors_grandchild_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cov = tmp_path / "gcov.json"
    monkeypatch.delenv("_P11CHECK_SUBPROCESS_COVERAGE", raising=False)
    monkeypatch.setenv(_emit.GRANDCHILD_COVERAGE_ENV, str(cov))
    _emit.write_coverage({"C_Initialize": 1}, {}, call_counters=[["C_Initialize", 0, 1]])
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["call_log"] == {"C_Initialize": 1}
    assert data["call_counters"] == [["C_Initialize", 0, 1]]


def test_write_coverage_prefers_standard_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    std = tmp_path / "std.json"
    gc = tmp_path / "gc.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(std))
    monkeypatch.setenv(_emit.GRANDCHILD_COVERAGE_ENV, str(gc))
    _emit.write_coverage({"C_Initialize": 1}, {})
    assert json.loads(std.read_text(encoding="utf-8"))["call_log"] == {"C_Initialize": 1}
    assert not gc.exists()


def test_mark_python_finalized_honors_grandchild_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cov = tmp_path / "gcov.json"
    monkeypatch.delenv("_P11CHECK_SUBPROCESS_COVERAGE", raising=False)
    monkeypatch.setenv(_emit.GRANDCHILD_COVERAGE_ENV, str(cov))
    _emit.mark_python_finalized()
    assert json.loads(cov.read_text(encoding="utf-8")) == {"python_finalized": True}


class _IsolationRaw:
    """RawPKCS11 double answering CKR_OK to the parent-side isolation calls."""

    def C_Initialize(self, _args: Any) -> int:  # noqa: N802 - mirrors the C_* API name
        return int(CKR_OK)

    def C_CreateObject(self, *args: Any) -> int:  # noqa: N802 - mirrors the C_* API name
        return int(CKR_OK)

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802 - mirrors the C_* API name
        return int(CKR_OK)

    def C_Finalize(self, _args: Any) -> int:  # noqa: N802 - mirrors the C_* API name
        return int(CKR_OK)


def _isolation_ctx() -> SimpleNamespace:
    return SimpleNamespace(
        raw=_IsolationRaw(), slot_id=0, module_path="fake-module.so", interface="auto"
    )


def _stub_isolation_deps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("_P11CHECK_PIN", raising=False)
    monkeypatch.setattr(subprocess_safety_probe, "get_slot_ids", lambda _raw: [7])
    monkeypatch.setattr(subprocess_safety_probe, "open_session", lambda _r, _s, _f: 11)
    monkeypatch.setattr(subprocess_safety_probe, "close_session_quietly", lambda _r, _s: None)


def _fake_grandchild_popen(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any] | None,
    *,
    timeout_first: bool = False,
) -> dict[str, Any]:
    """Stub Popen: capture env, optionally write a grandchild coverage file."""
    seen: dict[str, Any] = {}

    class _Proc:
        returncode = 0

        def __init__(self, argv: object, **kwargs: Any) -> None:
            seen["argv"] = argv
            seen["env"] = kwargs["env"]
            self._calls = 0

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            self._calls += 1
            if timeout_first and self._calls == 1:
                raise subprocess.TimeoutExpired(cmd="fake-grandchild", timeout=timeout)
            if payload is not None:
                gcov = seen["env"][_emit.GRANDCHILD_COVERAGE_ENV]
                Path(gcov).write_text(json.dumps(payload), encoding="utf-8")
            return ("", "")

        def kill(self) -> None:
            seen["killed"] = True

    monkeypatch.setattr(subprocess, "Popen", _Proc)
    return seen


def _grandchild_payload() -> dict[str, Any]:
    return {
        "call_log": {"C_Initialize": 1},
        "mechanism_counts": {},
        "call_log_ok": {},
        "mechanism_rv_counts": {},
        "call_counters": [["C_Initialize", 0, 1], ["C_FindObjectsInit", 0, 1]],
        "probes_lost": 1,
    }


def test_isolation_grandchild_counts_folded_into_probe_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_isolation_deps(monkeypatch)
    seen = _fake_grandchild_popen(monkeypatch, _grandchild_payload())
    try:
        subprocess_safety_probe._session_object_isolation(_isolation_ctx(), {})
    finally:
        _drain_probe_side_effects()
    env = seen["env"]
    assert "_P11CHECK_SUBPROCESS_COVERAGE" not in env  # parent's file still protected
    assert _emit.GRANDCHILD_COVERAGE_ENV in env
    by_fn = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"]
    assert by_fn["C_Initialize"]["calls"] == 1
    assert by_fn["C_FindObjectsInit"]["calls"] == 1
    assert call_counters.probes_lost() == 1  # grandchild loss propagated


def test_isolation_grandchild_missing_counts_as_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_isolation_deps(monkeypatch)
    _fake_grandchild_popen(monkeypatch, None)  # grandchild wrote nothing (crash)
    try:
        subprocess_safety_probe._session_object_isolation(_isolation_ctx(), {})
    finally:
        _drain_probe_side_effects()
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0


def test_isolation_grandchild_timeout_counts_as_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_isolation_deps(monkeypatch)
    seen = _fake_grandchild_popen(monkeypatch, None, timeout_first=True)
    try:
        subprocess_safety_probe._session_object_isolation(_isolation_ctx(), {})
    finally:
        _drain_probe_side_effects()
    assert seen["killed"] is True
    assert call_counters.probes_lost() == 1


# --- Final fix wave: fork-child loss accounting (I1.5) ---

# os.fork() is POSIX-only: on Windows the attribute does not exist, so even
# stubbing it raises AttributeError. Mirrors production's requires_fork gate
# (testcases/test_subprocess_safety.py); fork-safety is inapplicable there.
requires_fork = pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="os.fork() is POSIX-only; fork-safety is inapplicable on this platform",
)


@requires_fork
def test_fork_parent_accounts_untransmitted_child_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fork child dies via os._exit with its calls untransmitted by design;
    # the reaping probe-child parent accounts one lost probe, which rides this
    # child's own coverage write via the wire extension.
    class _Raw:
        def C_Initialize(self, _args: Any) -> int:  # noqa: N802 - mirrors the C_* API name
            return int(CKR_OK)

        def C_Finalize(self, _args: Any) -> int:  # noqa: N802 - mirrors the C_* API name
            return int(CKR_OK)

    monkeypatch.setattr(os, "fork", lambda: 4242)
    monkeypatch.setattr(
        subprocess_safety_probe, "_wait_child_bounded", lambda _pid, _t: ("exit", 0)
    )
    subprocess_safety_probe._fork_after_initialize(SimpleNamespace(raw=_Raw()), {})
    assert call_counters.probes_lost() == 1


# --- Final fix wave: entry/exit pairing corrections (M1, M2) ---


def _make_call_double(stub_map: dict[str, Any]) -> Any:
    """Minimal RawPKCS11 double driving ``_call`` without a provider."""
    from collections import Counter, defaultdict

    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = dict(stub_map)
    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._used_mechanisms = set()
    raw._mechanism_counts = Counter()
    raw._mechanism_rv_counts = defaultdict(Counter)
    raw._journal = None
    raw._rv_trace = None
    raw._rv_trace_total = 0
    return raw


def test_call_missing_function_counts_nothing() -> None:
    # The module was never invoked (no funclist entry), so no counter entry.
    # The legacy call log still records the attempt (its semantics unchanged).
    raw = _make_call_double({})
    with pytest.raises(AttributeError, match="not available"):
        raw._call("C_GetInfo")
    assert call_counters.serialize_current()["total_calls"] == 0
    assert raw.call_log == {"C_GetInfo": 1}


def test_call_crash_counts_entry_without_exit() -> None:
    # Crash-entry semantics are unchanged by the M1 move: a raise inside the
    # module invocation still counts the entry with no RV row.
    def _boom(*args: Any) -> int:
        raise OSError("SEH")

    raw = _make_call_double({"C_GetInfo": _boom})
    with pytest.raises(OSError, match="SEH"):
        raw._call("C_GetInfo")
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GetInfo"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def _make_load_double() -> Any:
    """RawPKCS11 double with just enough state for ``_load_from_lib``."""
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._interface_version = None
    raw._missing_function_list_names = set()
    # The win32 prologue of _load_from_lib appends to this (__init__ line); the
    # guard is sys.platform-based so Linux doubles never noticed its absence.
    raw._dll_dir_handles = []
    return raw


def test_get_interface_raise_counts_entry_only(tmp_path: Path) -> None:
    # A raising C_GetInterface attempt entered the module: entry-only
    # (crash parity), not silence.
    from unittest.mock import patch

    from pkcs11_check.raw.api import RawPKCS11

    def _raising(_name: Any, _version: Any, _iface_pp: Any, _flags: Any) -> int:
        raise OSError("module blew up")

    fake_lib = SimpleNamespace(C_GetInterface=_raising)
    raw = _make_load_double()
    # tmp_path-backed: on win32 _windows_dll_directory resolves the lib's
    # directory and os.add_dll_directory requires it to exist.
    lib_path = str(tmp_path / "fake-module.so")
    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(OSError, match="module blew up"),
    ):
        RawPKCS11._load_from_lib(raw, lib_path, interface="3.2")
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GetInterface"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def test_get_function_list_raise_counts_entry_only(tmp_path: Path) -> None:
    from unittest.mock import patch

    from pkcs11_check.raw.api import RawPKCS11

    def _raising(_fn_list_pp: Any) -> int:
        raise OSError("module blew up")

    # No C_GetInterface attribute: the legacy route is selected, then raises.
    fake_lib = SimpleNamespace(C_GetFunctionList=_raising)
    raw = _make_load_double()
    # tmp_path-backed: on win32 _windows_dll_directory resolves the lib's
    # directory and os.add_dll_directory requires it to exist.
    lib_path = str(tmp_path / "fake-module.so")
    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(OSError, match="module blew up"),
    ):
        RawPKCS11._load_from_lib(raw, lib_path, interface="2.40")
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GetFunctionList"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def test_raw_get_function_list_raise_counts_entry_only() -> None:
    class _Raising:
        def __call__(self, *args: Any) -> int:
            raise RuntimeError("boom")

    lib = SimpleNamespace(C_GetFunctionList=_Raising())
    with pytest.raises(RuntimeError, match="boom"):
        raw_session._get_function_list(cast("ctypes.CDLL", lib))
    entry = _unknown_buckets(call_counters.serialize_current())["session_provisioning"]["by_fn"][
        "C_GetFunctionList"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


# --- Final fix wave: C-call-site guard (R4) ---
#
# Every ctypes library load under src/ is a potential uncounted C-call path
# (I1.1/I1.2 escaped exactly this way). This AST guard fails on any load site
# that is not allowlisted with a counting justification, so future paths
# cannot silently escape counting. Keyed on (file, enclosing scope) plus the
# exact call count per scope, so neither a new site nor a second load in a
# listed scope passes silently; stale entries fail too, keeping the list
# honest. Pure source analysis (no imports of the scanned modules), so it is
# portable across platforms.
#
# Deliberately scoped to library LOADS under src/: scripts/ holds
# operator-run tooling (token-init, vector generation) that is out-of-harness
# by nature (M3 class) and cannot be counted; child spawns (python -c/-m)
# cannot be classified statically, so they stay pinned by mechanism tests
# (workload marker, grandchild fold-in) instead of this guard.


_COUNTED_LOAD_SITES: dict[tuple[str, str], tuple[int, str]] = {
    # (relpath, enclosing scope) -> (expected CDLL-call count, justification)
    ("raw/api.py", "RawPKCS11._load_from_lib"): (
        1,
        "loader: C_GetInterface/C_GetFunctionList recorded as pairs at the call site",
    ),
    ("testcases/_probes/raw_session.py", "_load_cdll"): (
        1,
        "callers wrap: probe_main_raw and counting_cdll apply _CountingCDLL",
    ),
    ("testcases/_probes/ckr_null_params_login.py", "_run"): (1, "counting_cdll wrap (I1.1)"),
    ("testcases/_probes/ckr_null_params_session.py", "_run"): (
        1,
        "counting_cdll wrap (I1.2)",
    ),
}


def _cdll_loads_in_source(source: str) -> list[tuple[str, int]]:
    """Return (enclosing scope, lineno) for every ``ctypes.CDLL(...)`` call."""
    import ast

    tree = ast.parse(source)
    found: list[tuple[str, int]] = []
    stack: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815 - stdlib visitor protocol name

        def visit_Lambda(self, node: ast.Lambda) -> None:
            stack.append("<lambda>")
            self.generic_visit(node)
            stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "CDLL"
                and isinstance(func.value, ast.Name)
                and func.value.id == "ctypes"
            ):
                scope = ".".join(stack) if stack else "<module>"
                found.append((scope, node.lineno))
            self.generic_visit(node)

    _Visitor().visit(tree)
    return found


def _iter_src_cdll_loads() -> Iterator[tuple[str, str, int]]:
    """Yield (relpath, scope, lineno) for every ``ctypes.CDLL`` call under src/."""
    root = Path(__file__).resolve().parent.parent / "src" / "pkcs11_check"
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        for scope, lineno in _cdll_loads_in_source(path.read_text(encoding="utf-8")):
            yield rel, scope, lineno


def test_cdll_load_scanner_finds_only_real_calls() -> None:
    # Negative control for the matcher: comments, string literals, and
    # lookalike names (doubles) must not trip the guard.
    source = (
        "# so = ctypes.CDLL(module)\n"
        'doc = "ctypes.CDLL(not-a-call)"\n'
        "proxy = _StubCDLL()\n"
        "other.CDLL(x)\n"
        "import ctypes\n"
        "def f():\n"
        "    return ctypes.CDLL(p)\n"
    )
    assert _cdll_loads_in_source(source) == [("f", 7)]


def test_all_cdll_load_sites_allowlisted() -> None:
    from collections import Counter

    found: Counter[tuple[str, str]] = Counter()
    locations: dict[tuple[str, str], list[int]] = {}
    for rel, scope, lineno in _iter_src_cdll_loads():
        found[(rel, scope)] += 1
        locations.setdefault((rel, scope), []).append(lineno)
    problems: list[str] = []
    for key in sorted(found):
        lines = ",".join(str(n) for n in locations[key])
        if key not in _COUNTED_LOAD_SITES:
            problems.append(
                f"unlisted C-call load site {key[0]}:{key[1]} (line {lines}): "
                "justify its counting or wrap it, then allowlist it"
            )
        elif found[key] != _COUNTED_LOAD_SITES[key][0]:
            problems.append(
                f"load-count drift at {key[0]}:{key[1]} (lines {lines}): "
                f"found {found[key]}, allowlisted {_COUNTED_LOAD_SITES[key][0]}"
            )
    for key in sorted(_COUNTED_LOAD_SITES):
        if key not in found:
            problems.append(f"stale allowlist entry {key[0]}:{key[1]} (remove it)")
    assert not problems, (
        "uncounted C-call paths may be escaping:\n"
        + "\n".join(f"- {p}" for p in problems)
        + "\nSee docs/call-counters-design.md (Capture section)."
    )


# --- Codex R1 fix round (C1): probe-teardown lifecycle ---


class _LifecycleRaw:
    """RawPKCS11 double whose cleanup advances live state like ``_call`` does.

    The legacy accessors read the LIVE dicts (cleanup traffic lands in them,
    exactly as ``RawPKCS11._call`` mutates ``_call_log``); the counter
    recordings mirror the ``_call`` choke-point wiring.
    """

    def __init__(self) -> None:
        self.live_log: dict[str, int] = {"C_Login": 1}
        self.live_log_ok: dict[str, int] = {"C_Login": 1}

    @property
    def call_log(self) -> dict[str, int]:
        return dict(self.live_log)

    @property
    def mechanism_counts(self) -> dict[int, int]:
        return {}

    @property
    def call_log_ok(self) -> dict[str, int]:
        return dict(self.live_log_ok)

    @property
    def mechanism_rv_counts(self) -> dict[int, dict[int, int]]:
        return {}

    def C_CloseSession(self, session: int) -> int:  # noqa: N802 - mirrors the C_* API name
        del session
        self.live_log["C_CloseSession"] = self.live_log.get("C_CloseSession", 0) + 1
        self.live_log_ok["C_CloseSession"] = self.live_log_ok.get("C_CloseSession", 0) + 1
        call_counters.record_call("C_CloseSession")
        call_counters.record_return("C_CloseSession", 0)
        return 0

    def C_Finalize(self, reserved: Any) -> int:  # noqa: N802 - mirrors the C_* API name
        del reserved
        self.live_log["C_Finalize"] = self.live_log.get("C_Finalize", 0) + 1
        self.live_log_ok["C_Finalize"] = self.live_log_ok.get("C_Finalize", 0) + 1
        call_counters.record_call("C_Finalize")
        call_counters.record_return("C_Finalize", 0)
        return 0


def test_probe_teardown_counters_include_cleanup_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # C1: the coverage write happens AFTER close/finalize, so the flattened
    # counters include cleanup traffic; the legacy fields are snapshotted
    # BEFORE cleanup, so their bytes are unchanged (no C_CloseSession there).
    call_counters.record_direct_call("C_Login", 0)
    raw = _LifecycleRaw()
    teardown = session._ProbeTeardown(raw)  # type: ignore[arg-type]
    teardown.sh = 11
    teardown.initialized = True
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    teardown()
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["call_log"] == {"C_Login": 1}
    assert data["call_log_ok"] == {"C_Login": 1}
    assert raw.live_log == {"C_Login": 1, "C_CloseSession": 1, "C_Finalize": 1}
    rows = data["call_counters"]
    assert ["", "C_Login", 0, 1] in rows
    assert ["", "C_CloseSession", 0, 1] in rows
    assert ["", "C_Finalize", 0, 1] in rows


def test_probe_teardown_cleanup_crash_writes_no_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # C1: a cleanup crash (access violation inside C_Finalize) must not leave
    # a stale payload behind: no write means the launcher accounts one loss.
    class _CrashingRaw(_LifecycleRaw):
        def C_Finalize(self, reserved: Any) -> int:  # noqa: N802 - mirrors the C_* API name
            del reserved
            call_counters.record_call("C_Finalize")
            raise OSError("exception: access violation reading 0x00000000")

    call_counters.record_direct_call("C_Login", 0)
    teardown = session._ProbeTeardown(_CrashingRaw())  # type: ignore[arg-type]
    teardown.sh = 11
    teardown.initialized = True
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    with pytest.raises(OSError, match="access violation"):
        teardown()
    assert not cov.exists()
    assert _subprocess_preamble.ingest_subprocess_coverage(str(cov)) is False


# --- Codex R1 fix round (I1): malformed legacy sections ---


_DrainFn = Callable[[], tuple[Counter[str], Counter[int], Counter[str], dict[int, Counter[int]]]]

_INGEST_DRAIN_FNS: tuple[tuple[_IngestFn, _DrainFn], ...] = (
    (
        _subprocess_preamble.ingest_subprocess_coverage,
        _subprocess_preamble.get_preamble_subprocess_coverage,
    ),
    (_raw_subprocess.ingest_raw_subprocess_coverage, _raw_subprocess.get_raw_subprocess_coverage),
)


@pytest.mark.parametrize(("ingest", "drain"), _INGEST_DRAIN_FNS, ids=["session", "raw"])
def test_ingest_ignores_garbage_legacy_sections(
    ingest: _IngestFn, drain: _DrainFn, tmp_path: Path
) -> None:
    # I1: non-dict legacy sections must not raise (the old code raised
    # TypeError inside Counter.update, aborting before the counters folded);
    # valid counters still fold and the channel reports usable.
    payload = _child_payload()
    payload["call_log"] = 1
    payload["call_log_ok"] = "garbage"
    payload["mechanism_counts"] = 1
    payload["mechanism_rv_counts"] = [2]
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is True
    assert call_counters.serialize_current()["total_calls"] == 3
    assert call_counters.probes_lost() == 0
    func, mech, func_ok, mech_rv = drain()
    assert func == {} and mech == {} and func_ok == {} and mech_rv == {}


@pytest.mark.parametrize(("ingest", "drain"), _INGEST_DRAIN_FNS, ids=["session", "raw"])
def test_ingest_skips_garbage_legacy_values_but_folds_valid(
    ingest: _IngestFn, drain: _DrainFn, tmp_path: Path
) -> None:
    # I1: garbage scalar values inside legacy sections are skipped entry by
    # entry; valid entries in the same section still fold.
    payload = _child_payload()
    payload["call_log"] = {"C_Login": "bogus", "C_Sign": 2, "": 5}
    payload["call_log_ok"] = {"C_Login": 1, "C_Sign": None}
    payload["mechanism_counts"] = {"7": 3, "bogus": 1}
    payload["mechanism_rv_counts"] = {"7": {"0": 2, "x": 1}}
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is True
    assert call_counters.serialize_current()["total_calls"] == 3
    func, mech, func_ok, mech_rv = drain()
    assert func == {"C_Sign": 2}
    assert func_ok == {"C_Login": 1}
    assert mech == {7: 3}
    assert mech_rv == {7: {0: 2}}


def _nested_poison_json(depth: int = 100_000) -> str:
    return '{"call_counters": ' + "[" * depth + "]" * depth + "}"


def _bigint_poison_json(digits: int = 6000) -> str:
    return '{"call_counters": [], "probe": ' + "9" * digits + "}"


@pytest.mark.parametrize(
    "reader",
    [
        _subprocess_preamble.ingest_subprocess_coverage,
        _raw_subprocess.ingest_raw_subprocess_coverage,
    ],
    ids=["preamble", "raw"],
)
@pytest.mark.parametrize(
    "poison",
    [_nested_poison_json(), _bigint_poison_json()],
    ids=["recursion", "bigint"],
)
def test_child_coverage_decoder_poison_is_unusable(
    tmp_path: Path, reader: Callable[[str], bool], poison: str
) -> None:
    # Decoder failures (RecursionError, huge-int ValueError) read as an
    # unusable channel (False -> launcher lost+1), never raise.
    cov = tmp_path / "cov.json"
    cov.write_text(poison, encoding="utf-8")
    assert reader(str(cov)) is False
    assert call_counters.probes_lost() == 0
    assert call_counters.serialize_current()["total_calls"] == 0


def test_run_probe_deep_coverage_json_is_lost_not_abrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Critical R3: deep-JSON coverage must not bypass loss accounting via
    # RecursionError in _finalizer_ran, nor misattribute as an abrupt exit.
    from pkcs11_check.core.process_observation import SUBPROCESS_ABRUPT_EXIT_MARKER

    drain_process_observations()
    poison = _nested_poison_json()

    def _fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        cov_path = str(kwargs["env"]["_P11CHECK_SUBPROCESS_COVERAGE"])
        Path(cov_path).write_text(poison, encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("pkcs11_check.testcases._probes.runner.subprocess.run", _fake_run)
    result = run_probe("_echo", {"module_path": "/x.so"})
    assert result.returncode == 0
    assert SUBPROCESS_ABRUPT_EXIT_MARKER not in result.stderr
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0
    assert result.observation is not None
    assert result.observation["termination"]["kind"] == "exit"


def test_run_probe_empty_coverage_without_traceback_stays_abrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pin: empty coverage + silent rc 0 is still module termination (abrupt),
    # and the missing counters still count as lost.
    from pkcs11_check.core.process_observation import SUBPROCESS_ABRUPT_EXIT_MARKER

    drain_process_observations()
    monkeypatch.setattr(
        "pkcs11_check.testcases._probes.runner.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
    )
    result = run_probe("_echo", {"module_path": "/x.so"})
    assert result.returncode == 0
    assert SUBPROCESS_ABRUPT_EXIT_MARKER in result.stderr
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0


def test_workload_counters_deep_marker_json_is_lost() -> None:
    # Critical R3: deep marker JSON must not escape before loss accounting.
    deep = "[" * 100_000 + "]" * 100_000
    test_threading._ingest_workload_counters(_workload_stdout(deep))
    assert call_counters.probes_lost() == 1
    assert call_counters.serialize_current()["total_calls"] == 0


def _trace_poison_payloads() -> list[str]:
    # Decoder-hostile trace payloads: nesting past the ~1000-frame parse
    # depth (RecursionError) and an int past the 4300-digit limit (ValueError).
    return ["[" * 100_000 + "]" * 100_000, '[{"i": ' + "9" * 6000 + "}]"]


@pytest.mark.parametrize("poison", _trace_poison_payloads(), ids=["recursion", "bigint"])
def test_run_probe_poisoned_trace_keeps_valid_counters(
    monkeypatch: pytest.MonkeyPatch, poison: str
) -> None:
    # Important R4: valid coverage counters must be ingested (and loss
    # accounted) independently of the optional diagnostic rv-trace parse. A
    # poisoned P11_RV_TRACE_JSON marker must neither raise out of run_probe
    # nor cost the child's calls.
    from pkcs11_check.core.subprocess_trace import (
        RV_TRACE_MARKER,
        drain_subprocess_rv_trace,
    )

    drain_subprocess_rv_trace()
    drain_process_observations()

    def _fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        cov_path = str(kwargs["env"]["_P11CHECK_SUBPROCESS_COVERAGE"])
        Path(cov_path).write_text(json.dumps(_child_payload()), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, f"{RV_TRACE_MARKER}{poison}\n", "")

    monkeypatch.setattr("pkcs11_check.testcases._probes.runner.subprocess.run", _fake_run)
    try:
        result = run_probe("_echo", {"module_path": "/x.so"})
    finally:
        _drain_probe_side_effects()
    assert result.returncode == 0
    assert call_counters.probes_lost() == 0
    assert call_counters.serialize_current()["total_calls"] == 3
    assert result.observation is not None
    assert result.observation["termination"]["kind"] == "exit"
    assert drain_subprocess_rv_trace() == []


@pytest.mark.parametrize("poison", _trace_poison_payloads(), ids=["recursion", "bigint"])
def test_extract_subprocess_rv_trace_skips_poisoned_marker(poison: str) -> None:
    # Important R4: one undecodable marker is skipped per-marker, so a valid
    # adjacent trace still parses instead of the whole extraction raising.
    from pkcs11_check.core.subprocess_trace import RV_TRACE_MARKER, extract_subprocess_rv_trace

    valid = '[{"i": 0, "fn": "C_GetInfo", "rv": 7}]'
    text = f"{RV_TRACE_MARKER}{poison}\n{RV_TRACE_MARKER}{valid}\n"
    assert extract_subprocess_rv_trace(text) == [{"i": 0, "fn": "C_GetInfo", "rv": 7}]


@pytest.mark.parametrize("poison", _trace_poison_payloads(), ids=["recursion", "bigint"])
def test_extract_subprocess_rv_trace_poison_only_is_empty(poison: str) -> None:
    # Important R4: poison with no valid marker yields no trace, never raises.
    from pkcs11_check.core.subprocess_trace import RV_TRACE_MARKER, extract_subprocess_rv_trace

    assert extract_subprocess_rv_trace(f"{RV_TRACE_MARKER}{poison}\n") == []


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_drops_negative_rv_rows_but_keeps_channel(ingest: _IngestFn, tmp_path: Path) -> None:
    # Important R5: a negative-RV child row is skipped per-row like other
    # garbage, never folded: serializing it would emit a "-1" RV key the
    # extractor rejects whole-record, discarding valid parent traffic. The
    # channel itself stays usable (True) and valid rows still fold.
    payload = _child_payload()
    payload["call_counters"] = [["C_Login", -1, 2], ["C_Sign", 0, 3]]
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    with call_counters.counted_bucket("test"):
        assert ingest(cov) is True
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 3
    assert set(_unknown_buckets(snap)["test"]["by_fn"]) == {"C_Sign"}
    sign = _unknown_buckets(snap)["test"]["by_fn"]["C_Sign"]
    assert sign["calls"] == 3
    assert sign["by_rv"]["0"]["count"] == 3


# --------------------------------------------------------------------------
# Area F (rc3): coverage wire carries keyed losses
# --------------------------------------------------------------------------

_CHILD_UUID = "c" * 32


def test_write_coverage_embeds_lost_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    keys = [{"parent_uuid": _CHILD_UUID, "probe_seq": 0}]
    _emit.write_coverage(
        {"C_Login": 1}, {}, call_counters=[["C_Login", 0, 1]], probes_lost=1, lost_keys=keys
    )
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert data["lost_keys"] == keys
    assert data["probes_lost"] == 1


def test_write_coverage_omits_empty_lost_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pin-as-is guard: keyless payloads stay byte-stable (legacy readers).
    cov = tmp_path / "cov.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(cov))
    _emit.write_coverage({"C_Login": 1}, {}, call_counters=[["C_Login", 0, 1]], probes_lost=0)
    data = json.loads(cov.read_text(encoding="utf-8"))
    assert "lost_keys" not in data


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_forwards_nested_lost_keys(ingest: _IngestFn, tmp_path: Path) -> None:
    payload = _child_payload()
    payload["probes_lost"] = 3
    payload["lost_keys"] = [
        {"parent_uuid": _CHILD_UUID, "probe_seq": 0},
        {"parent_uuid": _CHILD_UUID, "probe_seq": 1},
    ]
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is True
    assert sorted(
        (key["parent_uuid"], key["probe_seq"]) for key in call_counters.lost_probe_keys()
    ) == [(_CHILD_UUID, 0), (_CHILD_UUID, 1)]
    # Scalar-anchored: 3 total − 2 keyed = 1 unkeyed.
    assert call_counters.probes_lost() == 3


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_drops_keys_when_counters_unusable(ingest: _IngestFn, tmp_path: Path) -> None:
    # Mirrors the scalar rule: an unusable channel drops inner claims
    # (keys and scalar alike); the launcher owns one loss instead.
    payload = _child_payload()
    payload["call_counters"] = "garbage"
    payload["probes_lost"] = 3
    payload["lost_keys"] = [{"parent_uuid": _CHILD_UUID, "probe_seq": 0}]
    cov = _write_coverage_file(tmp_path / "cov.json", payload)
    assert ingest(cov) is False
    assert call_counters.lost_probe_keys() == []
    assert call_counters.probes_lost() == 0


def _set_f2_env(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> None:
    from pkcs11_check.core import _counters_durability as durability

    values = {
        durability.PROBE_PARENT_ENV: "p" * 32,
        durability.PROBE_RUN_ENV: "R1",
        durability.PROBE_UNIT_ENV: "a.py",
        durability.PROBE_ATTEMPT_ENV: "2",
        durability.PROBE_ROLE_ENV: "unit",
        durability.PROBE_ISOLATION_ENV: "file",
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_probe_sidecar_embeds_parent_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core._counters_durability import PROBE_SEQ_ENV, PROBE_SIDECAR_ENV
    from pkcs11_check.testcases._probes._emit import flush_probe_sidecar

    sidecar = tmp_path / "probe-sidecar.json"
    monkeypatch.setenv(PROBE_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv(PROBE_SEQ_ENV, "7")
    _set_f2_env(monkeypatch)
    flush_probe_sidecar([["m", "C_Login", 0, 4]])
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert payload["probe_seq"] == 7
    assert payload["parent_uuid"] == "p" * 32
    assert payload["run_id"] == "R1"
    assert payload["unit"] == "a.py"
    assert payload["attempt"] == 2
    assert payload["role"] == "unit"
    assert payload["isolation"] == "file"


def test_probe_sidecar_omits_identity_when_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core._counters_durability import PROBE_SEQ_ENV, PROBE_SIDECAR_ENV
    from pkcs11_check.testcases._probes._emit import flush_probe_sidecar

    sidecar = tmp_path / "probe-sidecar.json"
    monkeypatch.setenv(PROBE_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv(PROBE_SEQ_ENV, "7")
    flush_probe_sidecar([["m", "C_Login", 0, 4]])
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert "parent_uuid" not in payload
    assert "run_id" not in payload
    assert "unit" not in payload
    assert "attempt" not in payload
    assert "role" not in payload
    assert "isolation" not in payload


def test_probe_sidecar_finalized_flag_round_trips(tmp_path: Path) -> None:
    from pkcs11_check.core._counters_durability import _read_probe_orphan, write_probe_sidecar

    # Codex RC4-R1-1: mid-run snapshots carry finalized:false (fold but
    # never heal); the exit shape omits the key (byte-identical legacy).
    mid = tmp_path / "mid.json"
    write_probe_sidecar(
        mid,
        worker_uuid="b" * 32,
        probe_seq=0,
        counters=[["m", "C_Login", 0, 1]],
        finalized=False,
    )
    final = tmp_path / "final.json"
    write_probe_sidecar(
        final,
        worker_uuid="b" * 32,
        probe_seq=0,
        counters=[["m", "C_Login", 0, 1]],
    )
    assert json.loads(mid.read_text(encoding="utf-8"))["finalized"] is False
    assert "finalized" not in json.loads(final.read_text(encoding="utf-8"))
    mid_read = _read_probe_orphan(mid)
    assert mid_read is not None
    assert mid_read[5] is False
    final_read = _read_probe_orphan(final)
    assert final_read is not None
    assert final_read[5] is True


def test_probe_sidecar_scalar_omitted_when_zero(tmp_path: Path) -> None:
    from pkcs11_check.core._counters_durability import _read_probe_orphan, write_probe_sidecar

    # B2: the unkeyed-loss scalar rides the sidecar wire, omitted when
    # zero (legacy byte-identical); absent reads 0, malformed reads 0
    # (garbage-tolerant like the coverage scalar, counts still fold).
    bare = tmp_path / "bare.json"
    write_probe_sidecar(bare, worker_uuid="b" * 32, probe_seq=0, counters=[["m", "C_Login", 0, 1]])
    assert "probes_lost" not in json.loads(bare.read_text(encoding="utf-8"))
    assert _read_probe_orphan(bare)[6] == 0
    loaded = tmp_path / "loaded.json"
    write_probe_sidecar(
        loaded,
        worker_uuid="b" * 32,
        probe_seq=0,
        counters=[["m", "C_Login", 0, 1]],
        probes_lost=3,
    )
    assert json.loads(loaded.read_text(encoding="utf-8"))["probes_lost"] == 3
    assert _read_probe_orphan(loaded)[6] == 3
    garbage = tmp_path / "garbage.json"
    garbage.write_text(
        json.dumps(
            {
                "worker_uuid": "b" * 32,
                "probe_seq": 0,
                "counters": [["m", "C_Login", 0, 1]],
                "probes_lost": "many",
            }
        ),
        encoding="utf-8",
    )
    assert _read_probe_orphan(garbage)[6] == 0


def test_probe_slot_flush_forwards_nonzero_scalar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core._counters_durability import (
        COUNTERS_DIR_ENV,
        PROBE_SEQ_ENV,
        PROBE_SIDECAR_ENV,
    )

    # Codex R2: the mid-run slot trigger forwards a nonzero scalar,
    # not just counts -- driven in-process (disengaged child shape).
    monkeypatch.delenv(COUNTERS_DIR_ENV, raising=False)
    slot = tmp_path / "probe-slot.json"
    monkeypatch.setenv(PROBE_SIDECAR_ENV, str(slot))
    monkeypatch.setenv(PROBE_SEQ_ENV, "0")
    call_counters.note_lost_probe()
    call_counters.record_call("C_Login", module="m")
    payload = json.loads(slot.read_text(encoding="utf-8"))
    assert payload["probes_lost"] == 1
    assert payload["finalized"] is False


@pytest.mark.parametrize("writer", ["session", "raw"])
def test_probe_exit_flush_forwards_nonzero_scalar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: str
) -> None:
    from pkcs11_check.core._counters_durability import PROBE_SEQ_ENV, PROBE_SIDECAR_ENV

    # Codex R2: both exit-flush paths stamp the child's scalar.
    slot = tmp_path / "probe-sidecar.json"
    monkeypatch.setenv(PROBE_SIDECAR_ENV, str(slot))
    monkeypatch.setenv(PROBE_SEQ_ENV, "3")
    call_counters.note_lost_probe()
    call_counters.record_call("C_Login", module="m")
    if writer == "session":
        session._write_coverage(_fake_raw())
    else:
        raw_session._write_raw_coverage()
    payload = json.loads(slot.read_text(encoding="utf-8"))
    assert payload["probes_lost"] == 1
    assert payload["probe_seq"] == 3
    assert "finalized" not in payload


def test_probe_sidecar_malformed_attempt_omits_attempt_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core import _counters_durability as durability
    from pkcs11_check.core._counters_durability import PROBE_SEQ_ENV, PROBE_SIDECAR_ENV
    from pkcs11_check.testcases._probes._emit import flush_probe_sidecar

    sidecar = tmp_path / "probe-sidecar.json"
    monkeypatch.setenv(PROBE_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv(PROBE_SEQ_ENV, "7")
    _set_f2_env(monkeypatch, **{durability.PROBE_ATTEMPT_ENV: "bogus"})
    flush_probe_sidecar([["m", "C_Login", 0, 4]])
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert "attempt" not in payload
    assert payload["parent_uuid"] == "p" * 32
    assert payload["unit"] == "a.py"


def _probe_child_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, seq: str = "0") -> Path:
    from pkcs11_check.core import _counters_durability as durability

    sidecar = tmp_path / "probe-sidecar.json"
    monkeypatch.delenv(durability.COUNTERS_DIR_ENV, raising=False)
    monkeypatch.setenv(durability.PROBE_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv(durability.PROBE_SEQ_ENV, seq)
    _set_f2_env(monkeypatch)
    return sidecar


def test_probe_child_flushes_sidecar_on_record_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # fw#73 lost-probe recovery (Option B): a disengaged probe child
    # persists its flattened counters to its assigned slot on the record
    # path (K=1 default), so a mid-run kill leaves a foldable snapshot.
    # No registration is created (children never register).
    sidecar = _probe_child_env(monkeypatch, tmp_path)
    call_counters.record_call("C_Login", module="m")
    call_counters.record_return("C_Login", 0, module="m")
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert payload["worker_uuid"] == call_counters.get_worker_uuid()
    assert payload["probe_seq"] == 0
    assert payload["parent_uuid"] == "p" * 32
    assert payload["counters"] == [["m", "C_Login", 0, 1]]
    assert call_counters.registration_info() is None


def test_probe_child_sidecar_cadence_follows_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core import _counters_durability as durability

    sidecar = _probe_child_env(monkeypatch, tmp_path)
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "3")
    call_counters.reset_for_tests()
    call_counters.record_call("C_Login", module="m")
    call_counters.record_call("C_Login", module="m")
    assert not sidecar.exists()
    call_counters.record_call("C_Login", module="m")
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert payload["counters"] == [["m", "C_Login", None, 3]]


def test_probe_child_flush_failure_warns_once_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core import _counters_durability as durability

    # Counter plumbing must never break provider stimulus: a dead slot
    # warns once and the child keeps counting in memory (exit coverage
    # still folds via TMPDIR).
    sidecar = tmp_path / "no-such-dir" / "probe-sidecar.json"
    monkeypatch.delenv(durability.COUNTERS_DIR_ENV, raising=False)
    monkeypatch.setenv(durability.PROBE_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv(durability.PROBE_SEQ_ENV, "0")
    with pytest.warns(UserWarning, match="probe sidecar"):
        call_counters.record_call("C_Login", module="m")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        call_counters.record_call("C_Login", module="m")
    assert call_counters.serialize_current()["total_calls"] == 2


def test_probe_child_broken_slot_never_breaks_stimulus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core import _counters_durability as durability

    # F5: best-effort stays best-effort even under -W error -- the
    # record path must never raise out of provider stimulus. The
    # degradation stays visible as a missing sidecar upstream.
    sidecar = tmp_path / "no-such-dir" / "probe-sidecar.json"
    monkeypatch.delenv(durability.COUNTERS_DIR_ENV, raising=False)
    monkeypatch.setenv(durability.PROBE_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv(durability.PROBE_SEQ_ENV, "0")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        call_counters.record_call("C_Login", module="m")
        call_counters.record_call("C_Login", module="m")
    assert call_counters.serialize_current()["total_calls"] == 2
    assert not sidecar.exists()


def test_registered_process_ignores_probe_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core import _counters_durability as durability

    # A leaked sidecar slot in a registered process: the registration
    # wins (authoritative identity); the probe slot stays untouched.
    counters = tmp_path / "counters"
    monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(counters))
    monkeypatch.setenv(durability.COUNTERS_UNIT_ENV, "a.py")
    monkeypatch.setenv(durability.COUNTERS_ATTEMPT_ENV, "0")
    monkeypatch.setenv(durability.COUNTERS_ROLE_ENV, "unit")
    slot = tmp_path / "leaked-slot.json"
    monkeypatch.setenv(durability.PROBE_SIDECAR_ENV, str(slot))
    monkeypatch.setenv(durability.PROBE_SEQ_ENV, "0")
    call_counters.record_call("C_Login", module="m")
    assert not slot.exists()
    info = call_counters.registration_info()
    assert info is not None
    assert Path(info["sidecar_path"]).exists()


@pytest.mark.timeout(300)
def test_sigkill_mid_probe_run_recovers_flushed_prefix(tmp_path: Path) -> None:
    from pkcs11_check.core import _counters_durability as durability

    # fw#73 lost-probe recovery end to end: a real child records 5 units
    # at K=3 (snapshot lands at 3), is SIGKILLed mid-run, and the
    # parent-side adoption folds the prefix + heals the (parent, seq)
    # claim. The unflushed 2-unit tail stays the parent's keyed loss
    # (covered by the runner's note_lost_probe path, pinned in B).
    root = tmp_path / "counters"
    root.mkdir()
    parent = "c" * 32
    slot = root / f"probe-{parent[:8]}-0-feedface.json"
    src = Path(call_counters.__file__).resolve().parent.parent
    env = dict(os.environ)
    env.pop(durability.COUNTERS_DIR_ENV, None)
    env[durability.PROBE_SIDECAR_ENV] = str(slot)
    env[durability.PROBE_SEQ_ENV] = "0"
    env[durability.PROBE_PARENT_ENV] = parent
    env[durability.PROBE_RUN_ENV] = "R1"
    env[durability.PROBE_UNIT_ENV] = "a.py"
    env[durability.PROBE_ATTEMPT_ENV] = "0"
    env[durability.PROBE_ROLE_ENV] = "unit"
    env[durability.PROBE_ISOLATION_ENV] = "file"
    env[durability.COUNTERS_FLUSH_K_ENV] = "3"
    env["PYTHONPATH"] = str(src) + os.pathsep + env.get("PYTHONPATH", "")
    script = (
        "import time",
        "from pkcs11_check.core import call_counters",
        "for _ in range(5):",
        '    call_counters.record_call("C_Login", module="m")',
        "time.sleep(30)",
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", "\n".join(script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        deadline = time.monotonic() + 20.0
        total = -1
        while time.monotonic() < deadline:
            if slot.exists():
                try:
                    total = sum(
                        row[3] for row in json.loads(slot.read_text(encoding="utf-8"))["counters"]
                    )
                except (OSError, ValueError, KeyError):
                    pass
            if total == 3:
                break
            time.sleep(0.1)
        assert total == 3, "child must flush its 3-unit prefix before the kill"
        proc.kill()
        proc.wait(timeout=30)
        payload = json.loads(slot.read_text(encoding="utf-8"))
        assert payload["probe_seq"] == 0
        assert payload["parent_uuid"] == parent
        merged, claimed, consumed, recovered, _keys, _adopted = durability._adopt_probe_orphans(
            root,
            worker_uuid=parent,
            sidecar=None,
            journal_lines=[],
            claims={},
            known_uuids={parent},
            producer_run="R1",
            producer_unit="a.py",
        )
        assert merged is not None
        assert merged["total_calls"] == 3
        assert claimed == [{"worker_uuid": payload["worker_uuid"], "probe_seq": 0}]
        # Prefix evidence folds but never heals: the 2-unit tail stays
        # the parent's keyed loss (codex RC4-R1-1).
        assert payload["finalized"] is False
        assert recovered == []
        assert consumed == [slot]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
