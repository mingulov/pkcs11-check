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
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.core import call_counters
from pkcs11_check.core.process_observation import drain_process_observations
from pkcs11_check.testcases import _raw_subprocess, _subprocess_preamble
from pkcs11_check.testcases._probes import _ckr_ctypes, _emit, raw_session, session
from pkcs11_check.testcases._probes.runner import run_probe


@pytest.fixture(autouse=True)
def _clean_counters() -> Iterator[None]:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


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
    entry = call_counters.serialize_current()["buckets"]["test"]["by_fn"]["C_Login"]
    assert entry["calls"] == 3
    assert entry["by_rv"]["0"]["count"] == 2
    assert entry["by_rv"]["49"]["count"] == 1


@pytest.mark.parametrize("ingest", _INGEST_FNS, ids=["session", "raw"])
def test_ingest_merges_child_counts_both_paths(ingest: _IngestFn, tmp_path: Path) -> None:
    cov = _write_coverage_file(tmp_path / "cov.json", _child_payload())
    with call_counters.counted_bucket("test"):
        assert ingest(cov) is True
    entry = call_counters.serialize_current()["buckets"]["test"]["by_fn"]["C_Login"]
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
    assert data["call_counters"] == [["C_Initialize", 0, 1], ["C_Login", None, 1]]
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
    entry = call_counters.serialize_current()["buckets"]["test"]["by_fn"]["C_Initialize"]
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
    assert data["call_counters"] == [["C_GetFunctionList", 0, 1]]
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
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"][
        "C_GetFunctionList"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1


def test_get_function_list_records_rejection() -> None:
    lib = _StubGetFunctionList(7)  # CKR_ARGUMENTS_BAD
    funclist_ptr, rv = raw_session._get_function_list(cast("ctypes.CDLL", lib))
    assert rv == 7
    assert funclist_ptr is None
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"][
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
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"]["C_Login"]
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
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"]["C_Seven"]
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
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"]["C_Login"]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def test_proxy_non_integer_result_passes_through_without_exit() -> None:
    # An exotic restype (e.g. c_void_p answering None) must not break the call:
    # the value passes through and only the entry is counted.
    stub = _StubCDLL(None)
    proxy = _proxy_for(stub)
    assert proxy.C_Login() is None
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"]["C_Login"]
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
    entry = call_counters.serialize_current()["buckets"]["session_provisioning"]["by_fn"][
        "C_Initialize"
    ]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1
