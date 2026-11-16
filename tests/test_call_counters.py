"""Tests for the process-global PKCS#11 call counters (fw#73, Task 1)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core import call_counters
from pkcs11_check.core import counters_schema as schema


@pytest.fixture(autouse=True)
def _clean_counters() -> Iterator[None]:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


def _unknown_buckets(snap: dict[str, Any]) -> dict[str, Any]:
    """Inner buckets of the single unknown-module block.

    These tests record without a handle, so every call lands under the ``""``
    module; the helper pins that explicitly instead of hiding it in the
    index chain.
    """
    assert set(snap["by_module"]) == {""}
    return snap["by_module"][""]["buckets"]


def test_entry_exit_counts_and_rv_breakdown() -> None:
    call_counters.reset_for_tests()
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0)
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0x31)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 2
    login = _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_Login"]
    assert login["calls"] == 2
    assert login["by_rv"]["0"]["count"] == 1


def test_record_direct_call_counts_entry_and_exit() -> None:
    call_counters.record_direct_call("C_GetFunctionList", 0)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_GetFunctionList"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}


def test_default_bucket_is_session_provisioning() -> None:
    assert call_counters.current_bucket() == "session_provisioning"
    assert call_counters.current_bucket() == call_counters.DEFAULT_BUCKET
    assert call_counters.BUCKETS == (
        "test",
        "setup_teardown",
        "session_provisioning",
        "module_init",
    )


def test_counted_bucket_pushes_and_pops_with_nesting() -> None:
    with call_counters.counted_bucket("test"):
        assert call_counters.current_bucket() == "test"
        call_counters.record_call("C_Login")
        with call_counters.counted_bucket("module_init"):
            assert call_counters.current_bucket() == "module_init"
            call_counters.record_call("C_Initialize")
        assert call_counters.current_bucket() == "test"
    assert call_counters.current_bucket() == "session_provisioning"
    snap = call_counters.serialize_current()
    assert _unknown_buckets(snap)["test"]["by_fn"]["C_Login"]["calls"] == 1
    assert _unknown_buckets(snap)["module_init"]["by_fn"]["C_Initialize"]["calls"] == 1
    assert _unknown_buckets(snap)["session_provisioning"] == {"calls": 0, "by_fn": {}}
    assert _unknown_buckets(snap)["preflight"] == {"calls": 0, "by_fn": {}}


def test_counted_bucket_pops_on_exception() -> None:
    with pytest.raises(RuntimeError, match="boom"):
        with call_counters.counted_bucket("test"):
            raise RuntimeError("boom")
    assert call_counters.current_bucket() == "session_provisioning"


def test_counted_bucket_rejects_unknown_name() -> None:
    with pytest.raises(ValueError, match="nope"):
        with call_counters.counted_bucket("nope"):
            pass
    assert call_counters.current_bucket() == "session_provisioning"


def test_crash_entry_without_exit_counts_with_empty_rv_breakdown() -> None:
    call_counters.record_call("C_Sign")
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_Sign"]
    assert entry["calls"] == 1
    assert entry["by_rv"] == {}


def test_snapshot_diff_isolates_a_window() -> None:
    call_counters.record_direct_call("C_GetInfo", 0)
    before = call_counters.take_snapshot()
    with call_counters.counted_bucket("test"):
        call_counters.record_direct_call("C_Login", 0)
        call_counters.record_direct_call("C_Login", 0xB3)
    delta = call_counters.diff_snapshots(before, call_counters.take_snapshot())
    assert delta["total_calls"] == 2
    assert set(_unknown_buckets(delta)) == set(schema.BUCKETS_5)
    entry = _unknown_buckets(delta)["test"]["by_fn"]["C_Login"]
    assert entry["calls"] == 2
    assert entry["by_rv"]["0"]["count"] == 1
    assert entry["by_rv"][str(0xB3)]["count"] == 1


def test_snapshot_is_detached_from_later_mutation() -> None:
    call_counters.record_direct_call("C_GetInfo", 0)
    before = call_counters.take_snapshot()
    call_counters.record_direct_call("C_GetInfo", 0)
    assert call_counters.diff_snapshots(before, before)["total_calls"] == 0
    delta = call_counters.diff_snapshots(before, call_counters.take_snapshot())
    assert delta["total_calls"] == 1


def test_diff_of_empty_window_is_empty() -> None:
    snap = call_counters.take_snapshot()
    delta = call_counters.diff_snapshots(snap, snap)
    assert delta == {"total_calls": 0, "by_module": {}}


def test_flatten_current_sorted_wire_format() -> None:
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0)
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0x31)
    call_counters.record_call("C_Sign")
    call_counters.record_direct_call("C_GetInfo", 0)
    assert call_counters.flatten_current() == [
        ["", "C_GetInfo", 0, 1],
        ["", "C_Login", 0, 1],
        ["", "C_Login", 0x31, 1],
        ["", "C_Sign", None, 1],
    ]


def test_flatten_empty_is_empty() -> None:
    assert call_counters.flatten_current() == []


def test_flatten_orphan_return_never_goes_negative() -> None:
    call_counters.record_return("C_Login", 0)
    assert call_counters.flatten_current() == [["", "C_Login", 0, 1]]


def test_flatten_ingest_round_trip() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.record_direct_call("C_Login", 0)
        call_counters.record_direct_call("C_Login", 0x31)
        call_counters.record_call("C_Sign")
    original = call_counters.serialize_current()
    flat = call_counters.flatten_current()
    call_counters.reset_for_tests()
    with call_counters.counted_bucket("test"):
        call_counters.ingest_child_counts(flat)
    assert call_counters.serialize_current() == original


def test_ingest_merges_child_counts_under_active_bucket() -> None:
    from pkcs11_check.raw.rv import ckr_name

    flat = [["C_Login", 0, 2], ["C_Login", 49, 1], ["C_Sign", None, 3]]
    with call_counters.counted_bucket("test"):
        call_counters.ingest_child_counts(flat)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 6
    login = _unknown_buckets(snap)["test"]["by_fn"]["C_Login"]
    assert login["calls"] == 3
    assert login["by_rv"]["0"] == {"name": "CKR_OK", "count": 2}
    assert login["by_rv"]["49"] == {"name": ckr_name(49), "count": 1}
    sign = _unknown_buckets(snap)["test"]["by_fn"]["C_Sign"]
    assert sign["calls"] == 3
    assert sign["by_rv"] == {}


def test_ingest_explicit_bucket_overrides_active_bucket() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.ingest_child_counts([["C_Login", 0, 1]], bucket="module_init")
    snap = call_counters.serialize_current()
    assert _unknown_buckets(snap)["module_init"]["by_fn"]["C_Login"]["calls"] == 1
    assert _unknown_buckets(snap)["test"] == {"calls": 0, "by_fn": {}}


def test_ingest_rejects_unknown_bucket() -> None:
    with pytest.raises(ValueError, match="nope"):
        call_counters.ingest_child_counts([["C_Login", 0, 1]], bucket="nope")
    assert call_counters.serialize_current()["total_calls"] == 0


def test_ingest_ignores_garbage_without_raising() -> None:
    garbage: list[object] = [
        "not-a-row",
        None,
        42,
        ["C_Login", 0],
        ["C_Login", 0, 1, "extra"],
        ["C_Login", "0", 1],
        ["C_Login", 0, "1"],
        ["C_Login", 0, 0],
        ["C_Login", 0, -2],
        ["C_Login", None, 1, None],
        ["", 0, 1],
        [None, 0, 1],
        [123, 0, 1],
        ["C_Login", True, 1],
        ["C_Login", -1, 1],
        ("C_Login", -1, 1),
        ("C_Login", 0, 1),
        ["", "C_Login", 0, 1, "extra"],
        [None, "C_Login", 0, 1],
        [42, "C_Login", 0, 1],
        [["C_Login"], 0, 1],
    ]
    call_counters.ingest_child_counts(garbage)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    assert _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_Login"]["calls"] == 1


def test_ingest_non_list_payload_ignored() -> None:
    call_counters.ingest_child_counts(None)  # type: ignore[arg-type]
    call_counters.ingest_child_counts({"C_Login": 1})  # type: ignore[arg-type]
    assert call_counters.serialize_current() == {"total_calls": 0, "by_module": {}}


def test_ingest_accepts_tuple_payload() -> None:
    call_counters.ingest_child_counts((["C_Login", 0, 2],))  # type: ignore[arg-type]
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 2


def test_merge_module_first_sums_and_returns_target() -> None:
    from pkcs11_check.core.counters_schema import merge_module_first

    call_counters.record_direct_call("C_Login", 0)
    with call_counters.counted_bucket("test"):
        call_counters.record_direct_call("C_Login", 0)
    first = call_counters.serialize_current()
    call_counters.reset_for_tests()
    call_counters.record_direct_call("C_Login", 0x31)
    second = call_counters.serialize_current()
    merged = merge_module_first(first, second)
    assert merged is first
    assert merged["total_calls"] == 3
    buckets = _unknown_buckets(merged)
    assert buckets["session_provisioning"]["calls"] == 2
    assert buckets["test"]["calls"] == 1
    login = buckets["session_provisioning"]["by_fn"]["C_Login"]
    assert login["calls"] == 2
    assert login["by_rv"]["0"]["count"] == 1
    assert login["by_rv"][str(0x31)]["count"] == 1


def test_merge_module_first_creates_missing_keys_without_aliasing() -> None:
    from pkcs11_check.core.counters_schema import merge_module_first

    call_counters.record_direct_call("C_Login", 0)
    incoming = call_counters.serialize_current()
    target: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merged = merge_module_first(target, incoming)
    assert merged == incoming
    leaf = _unknown_buckets(merged)["session_provisioning"]["by_fn"]["C_Login"]["by_rv"]["0"]
    assert leaf == {"name": "CKR_OK", "count": 1}
    leaf["count"] += 10
    assert (
        _unknown_buckets(incoming)["session_provisioning"]["by_fn"]["C_Login"]["by_rv"]["0"][
            "count"
        ]
        == 1
    )


def test_merge_module_first_does_not_touch_globals() -> None:
    from pkcs11_check.core.counters_schema import merge_module_first

    call_counters.record_direct_call("C_Login", 0)
    before = call_counters.serialize_current()
    merge_module_first({"total_calls": 0, "by_module": {}}, before)
    assert call_counters.serialize_current() == before


def test_lost_probe_counter() -> None:
    assert call_counters.probes_lost() == 0
    call_counters.note_lost_probe()
    call_counters.note_lost_probe()
    assert call_counters.probes_lost() == 2


def test_reset_for_tests_clears_everything() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.record_direct_call("C_Login", 0)
    call_counters.note_lost_probe()
    call_counters.reset_for_tests()
    assert call_counters.serialize_current() == {"total_calls": 0, "by_module": {}}
    assert call_counters.flatten_current() == []
    assert call_counters.probes_lost() == 0
    assert call_counters.current_bucket() == "session_provisioning"


def test_report_constants() -> None:
    assert call_counters.CALL_COUNTERS_REPORT_TYPE == "CallCountersReport"
    assert call_counters.CALL_COUNTERS_PROPERTY == "pkcs11_call_counters"
    assert call_counters.ISOLATION_ENV == "PKCS11_CHECK_ISOLATION"


# --- Task 2: raw choke-point integration (fw#73) ---


def _make_raw_double(stub_map: dict[str, Any]) -> Any:
    """Minimal RawPKCS11 double driving ``_call`` without a provider.

    Mirrors the ``object.__new__`` doubles in ``tests/test_raw_api.py``.
    """
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


def test_call_counts_call_and_return_value() -> None:
    def _get_info(*args: Any) -> int:
        return 0

    raw = _make_raw_double({"C_GetInfo": _get_info})
    raw._call("C_GetInfo")
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_GetInfo"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}


def _make_function_list_buffer(major: int, minor: int) -> Any:
    """Zeroed fake CK_FUNCTION_LIST buffer with the given version header.

    All function pointers read back NULL (recorded as missing, never called),
    so the loader path runs end to end with no provider.
    """
    import ctypes

    from pkcs11_check.raw import metadata_std
    from pkcs11_check.raw.api import function_list_header_size

    max_index = max(metadata_std.FUNCTION_INDICES.values())
    size = function_list_header_size() + (max_index + 1) * ctypes.sizeof(ctypes.c_void_p)
    buf = (ctypes.c_ubyte * size)()
    buf[0] = major
    buf[1] = minor
    return buf


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


def test_load_from_lib_records_c_get_interface(tmp_path: Path) -> None:
    import ctypes
    from types import SimpleNamespace
    from unittest.mock import patch

    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CK_INTERFACE, CKR_OK

    buf = _make_function_list_buffer(3, 2)
    iface = CK_INTERFACE()
    iface.pFunctionList = ctypes.addressof(buf)

    def _fake_get_interface(name: Any, version: Any, iface_pp: Any, flags: Any) -> int:
        ctypes.cast(iface_pp, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(iface)
        return int(CKR_OK)

    fake_lib = SimpleNamespace(C_GetInterface=_fake_get_interface)
    raw = _make_load_double()
    # tmp_path-backed: on win32 _windows_dll_directory resolves the lib's
    # directory and os.add_dll_directory requires it to exist.
    lib_path = str(tmp_path / "fake-module.so")
    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, lib_path, interface="3.2")
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_GetInterface"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}


def test_load_from_lib_records_c_get_function_list(tmp_path: Path) -> None:
    import ctypes
    from types import SimpleNamespace
    from unittest.mock import patch

    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CKR_OK

    buf = _make_function_list_buffer(2, 40)

    def _fake_get_function_list(fn_list_pp: Any) -> int:
        ctypes.cast(fn_list_pp, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)
        return int(CKR_OK)

    # No C_GetInterface attribute: AttributeError path selects the legacy route.
    fake_lib = SimpleNamespace(C_GetFunctionList=_fake_get_function_list)
    raw = _make_load_double()
    # tmp_path-backed: on win32 _windows_dll_directory resolves the lib's
    # directory and os.add_dll_directory requires it to exist.
    lib_path = str(tmp_path / "fake-module.so")
    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, lib_path, interface="2.40")
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = _unknown_buckets(snap)["session_provisioning"]["by_fn"]["C_GetFunctionList"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}


def test_reset_call_log_does_not_clear_global_counters() -> None:
    def _get_info(*args: Any) -> int:
        return 0

    raw = _make_raw_double({"C_GetInfo": _get_info})
    raw._call("C_GetInfo")
    raw._call("C_GetInfo")
    assert call_counters.serialize_current()["total_calls"] == 2
    raw.reset_call_log()
    assert raw.call_log == {}
    assert raw.call_count == 0
    after = call_counters.serialize_current()
    assert after["total_calls"] == 2
    assert _unknown_buckets(after)["session_provisioning"]["by_fn"]["C_GetInfo"]["calls"] == 2


def test_call_log_content_unchanged_by_counters() -> None:
    def _get_info(*args: Any) -> int:
        return 0

    raw = _make_raw_double({"C_GetInfo": _get_info})
    raw._call("C_GetInfo")
    raw._call("C_GetInfo")
    assert raw.call_log == {"C_GetInfo": 2}
    assert raw.call_count == 2
    assert raw.call_log_ok == {"C_GetInfo": 2}


def test_reinitialize_attributes_calls_to_module_init() -> None:
    from pkcs11_check.core.loader import P11Module

    def _finalize(*args: Any) -> int:
        return 0

    def _initialize(*args: Any) -> int:
        return 0

    raw = _make_raw_double({"C_Finalize": _finalize, "C_Initialize": _initialize})
    module = P11Module(path=Path("fake.so"), _raw=raw)
    module.reinitialize()
    assert module.reinit_count == 1
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 2
    assert set(_unknown_buckets(snap)) == set(schema.BUCKETS_5)
    assert _unknown_buckets(snap)["module_init"]["by_fn"]["C_Finalize"]["calls"] == 1
    assert _unknown_buckets(snap)["module_init"]["by_fn"]["C_Initialize"]["calls"] == 1


def test_teardown_finalize_attributes_call_to_module_init() -> None:
    from types import SimpleNamespace

    from pkcs11_check._plugin_finalize import _finalize_on_teardown

    def _finalize(*args: Any) -> int:
        return 0

    raw = _make_raw_double({"C_Finalize": _finalize})
    config: Any = SimpleNamespace(stash={})
    outcome = _finalize_on_teardown(config, raw)
    assert outcome == "ok"
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    assert set(_unknown_buckets(snap)) == set(schema.BUCKETS_5)
    assert _unknown_buckets(snap)["module_init"]["by_fn"]["C_Finalize"]["calls"] == 1


# --- Codex R1 fix round (I3): thread attribution ---


def test_overlapping_thread_regions_stay_isolated() -> None:
    # I3: regions are thread-local: two threads recording while BOTH regions
    # are active must each land in their own bucket. The barrier makes the
    # overlap deterministic (both pushes precede both records).
    import threading

    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def _worker(bucket: str, fn: str) -> None:
        try:
            with call_counters.counted_bucket(bucket):
                barrier.wait(timeout=30)
                call_counters.record_call(fn)
                call_counters.record_return(fn, 0)
                barrier.wait(timeout=30)
        except BaseException as exc:  # propagate to the main thread
            errors.append(exc)

    first = threading.Thread(target=_worker, args=("test", "C_ThreadA"))
    second = threading.Thread(target=_worker, args=("module_init", "C_ThreadB"))
    first.start()
    second.start()
    first.join(timeout=60)
    second.join(timeout=60)
    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    snap = call_counters.serialize_current()
    assert set(_unknown_buckets(snap)) == set(schema.BUCKETS_5)
    entry_a = _unknown_buckets(snap)["test"]["by_fn"]["C_ThreadA"]
    assert entry_a["calls"] == 1
    assert entry_a["by_rv"]["0"]["count"] == 1
    entry_b = _unknown_buckets(snap)["module_init"]["by_fn"]["C_ThreadB"]
    assert entry_b["calls"] == 1
    assert entry_b["by_rv"]["0"]["count"] == 1


def test_cross_thread_return_does_not_follow_foreign_region() -> None:
    # I3 (codex scenario): thread A enters under "test" and returns while
    # thread B holds "module_init" -- the exit must not follow B's bucket.
    # Events pin the interleaving: B's region is active during A's return.
    import threading

    hold = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def _holder() -> None:
        try:
            with call_counters.counted_bucket("module_init"):
                hold.set()
                assert release.wait(timeout=30)
        except BaseException as exc:  # propagate to the main thread
            errors.append(exc)

    holder = threading.Thread(target=_holder)
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_Foreign")
        holder.start()
        assert hold.wait(timeout=30)
        call_counters.record_return("C_Foreign", 0)
        release.set()
    holder.join(timeout=60)
    assert not holder.is_alive()
    assert errors == []
    snap = call_counters.serialize_current()
    entry = _unknown_buckets(snap)["test"]["by_fn"]["C_Foreign"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1
    assert _unknown_buckets(snap)["module_init"] == {"calls": 0, "by_fn": {}}


def test_call_binds_return_to_entry_bucket_across_mid_call_switch() -> None:
    # I3: the exit half of a _call lands in the ENTRY-captured bucket even
    # when the bucket switches mid-call (e.g. a module callback re-entering
    # counted scopes between entry and return). Regions alone cannot fix the
    # same-thread case: only binding the return to the captured entry bucket
    # keeps the pair together.
    from contextlib import AbstractContextManager

    switched: list[AbstractContextManager[None, None, None]] = []

    def _switcher(*args: Any) -> int:
        del args
        scope = call_counters.counted_bucket("module_init")
        scope.__enter__()  # left entered: the switch is active at return time
        switched.append(scope)
        return 0

    raw = _make_raw_double({"C_Switch": _switcher})
    try:
        with call_counters.counted_bucket("test"):
            raw._call("C_Switch")
    finally:
        for scope in switched:
            scope.__exit__(None, None, None)
    snap = call_counters.serialize_current()
    entry = _unknown_buckets(snap)["test"]["by_fn"]["C_Switch"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1
    assert _unknown_buckets(snap)["module_init"] == {"calls": 0, "by_fn": {}}


def test_phase_scopes_worker_threads_and_yields_to_regions() -> None:
    # I3: the process-global phase (set by the pytest hooks) is visible to
    # worker threads, while a thread-local region still wins in its own
    # thread; the phase restores on exit, even on exception.
    import threading

    assert call_counters.current_bucket() == "session_provisioning"
    with call_counters._phase("test"):
        assert call_counters.current_bucket() == "test"
        call_counters.record_call("C_Phase")
        call_counters.record_return("C_Phase", 0)
        with call_counters.counted_bucket("module_init"):
            assert call_counters.current_bucket() == "module_init"
            call_counters.record_call("C_Region")
            call_counters.record_return("C_Region", 0)
        assert call_counters.current_bucket() == "test"

        errors: list[BaseException] = []

        def _worker() -> None:
            try:
                assert call_counters.current_bucket() == "test"
                call_counters.record_call("C_Worker")
                call_counters.record_return("C_Worker", 0)
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=_worker)
        worker.start()
        worker.join(timeout=60)
        assert not worker.is_alive()
        assert errors == []
    assert call_counters.current_bucket() == "session_provisioning"
    snap = call_counters.serialize_current()
    assert _unknown_buckets(snap)["test"]["by_fn"]["C_Phase"]["calls"] == 1
    assert _unknown_buckets(snap)["test"]["by_fn"]["C_Worker"]["calls"] == 1
    assert _unknown_buckets(snap)["module_init"]["by_fn"]["C_Region"]["calls"] == 1
    with pytest.raises(ValueError, match="nope"):
        with call_counters._phase("nope"):
            pass
    with pytest.raises(RuntimeError, match="boom"):
        with call_counters._phase("test"):
            raise RuntimeError("boom")
    assert call_counters.current_bucket() == "session_provisioning"


def _rv_block(name: str, count: int, total: int) -> dict[str, Any]:
    return {
        "total_calls": total,
        "by_module": {
            "mod": {
                "calls": total,
                "buckets": {
                    "test": {
                        "calls": total,
                        "by_fn": {
                            "C_Sign": {
                                "calls": total,
                                "by_rv": {"2147483649": {"name": name, "count": count}},
                            }
                        },
                    }
                },
            }
        },
    }


def _mod_leaf(block: dict[str, Any]) -> dict[str, Any]:
    return block["by_module"]["mod"]["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"]["2147483649"]


def test_merge_module_first_prefers_symbolic_rv_name() -> None:
    # Important R3: on leaf-name conflict prefer the non-0x (symbolic) name;
    # both merge orders yield the identical block including the name.
    import json as _json

    from pkcs11_check.core.counters_schema import merge_module_first

    hex_block = _rv_block("0x80000001", 2, 2)
    sym_block = _rv_block("CKR_VENDOR_FOO", 3, 3)
    forward: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merge_module_first(forward, hex_block)
    merge_module_first(forward, sym_block)
    assert _mod_leaf(forward) == {"name": "CKR_VENDOR_FOO", "count": 5}
    backward: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merge_module_first(backward, sym_block)
    merge_module_first(backward, hex_block)
    assert backward == forward
    assert _json.dumps(backward) == _json.dumps(forward)


def test_merge_module_first_rv_name_tie_breaks_lexicographically() -> None:
    # Ties (both symbolic or both hex) resolve to the smallest name, both orders.
    import json as _json

    from pkcs11_check.core.counters_schema import merge_module_first

    first = _rv_block("CKR_B_VENDOR", 1, 1)
    second = _rv_block("CKR_A_VENDOR", 1, 1)
    forward: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merge_module_first(forward, first)
    merge_module_first(forward, second)
    assert _mod_leaf(forward) == {"name": "CKR_A_VENDOR", "count": 2}
    backward: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merge_module_first(backward, second)
    merge_module_first(backward, first)
    assert backward == forward
    assert _json.dumps(backward) == _json.dumps(forward)
    upper = _rv_block("0x80000002", 1, 1)
    lower = _rv_block("0x80000001", 1, 1)
    both_hex: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    merge_module_first(both_hex, upper)
    merge_module_first(both_hex, lower)
    assert _mod_leaf(both_hex) == {"name": "0x80000001", "count": 2}
