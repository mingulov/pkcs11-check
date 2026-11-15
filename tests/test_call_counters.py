"""Tests for the process-global PKCS#11 call counters (fw#73, Task 1)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from pkcs11_check.core import call_counters


@pytest.fixture(autouse=True)
def _clean_counters() -> Iterator[None]:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


def test_entry_exit_counts_and_rv_breakdown() -> None:
    call_counters.reset_for_tests()
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0)
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0x31)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 2
    assert snap["buckets"]["session_provisioning"]["by_fn"]["C_Login"]["calls"] == 2
    assert snap["buckets"]["session_provisioning"]["by_fn"]["C_Login"]["by_rv"]["0"]["count"] == 1


def test_record_direct_call_counts_entry_and_exit() -> None:
    call_counters.record_direct_call("C_GetFunctionList", 0)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = snap["buckets"]["session_provisioning"]["by_fn"]["C_GetFunctionList"]
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
    assert snap["buckets"]["test"]["by_fn"]["C_Login"]["calls"] == 1
    assert snap["buckets"]["module_init"]["by_fn"]["C_Initialize"]["calls"] == 1
    assert "session_provisioning" not in snap["buckets"]


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
    entry = snap["buckets"]["session_provisioning"]["by_fn"]["C_Sign"]
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
    assert set(delta["buckets"]) == {"test"}
    entry = delta["buckets"]["test"]["by_fn"]["C_Login"]
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
    assert delta == {"total_calls": 0, "buckets": {}}


def test_flatten_current_sorted_wire_format() -> None:
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0)
    call_counters.record_call("C_Login")
    call_counters.record_return("C_Login", 0x31)
    call_counters.record_call("C_Sign")
    call_counters.record_direct_call("C_GetInfo", 0)
    assert call_counters.flatten_current() == [
        ["C_GetInfo", 0, 1],
        ["C_Login", 0, 1],
        ["C_Login", 0x31, 1],
        ["C_Sign", None, 1],
    ]


def test_flatten_empty_is_empty() -> None:
    assert call_counters.flatten_current() == []


def test_flatten_orphan_return_never_goes_negative() -> None:
    call_counters.record_return("C_Login", 0)
    assert call_counters.flatten_current() == [["C_Login", 0, 1]]


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
    login = snap["buckets"]["test"]["by_fn"]["C_Login"]
    assert login["calls"] == 3
    assert login["by_rv"]["0"] == {"name": "CKR_OK", "count": 2}
    assert login["by_rv"]["49"] == {"name": ckr_name(49), "count": 1}
    sign = snap["buckets"]["test"]["by_fn"]["C_Sign"]
    assert sign["calls"] == 3
    assert sign["by_rv"] == {}


def test_ingest_explicit_bucket_overrides_active_bucket() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.ingest_child_counts([["C_Login", 0, 1]], bucket="module_init")
    snap = call_counters.serialize_current()
    assert snap["buckets"]["module_init"]["by_fn"]["C_Login"]["calls"] == 1
    assert "test" not in snap["buckets"]


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
        ("C_Login", 0, 1),
    ]
    call_counters.ingest_child_counts(garbage)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    assert snap["buckets"]["session_provisioning"]["by_fn"]["C_Login"]["calls"] == 1


def test_ingest_non_list_payload_ignored() -> None:
    call_counters.ingest_child_counts(None)  # type: ignore[arg-type]
    call_counters.ingest_child_counts({"C_Login": 1})  # type: ignore[arg-type]
    assert call_counters.serialize_current() == {"total_calls": 0, "buckets": {}}


def test_ingest_accepts_tuple_payload() -> None:
    call_counters.ingest_child_counts((["C_Login", 0, 2],))  # type: ignore[arg-type]
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 2


def test_merge_serialized_sums_and_returns_target() -> None:
    call_counters.record_direct_call("C_Login", 0)
    with call_counters.counted_bucket("test"):
        call_counters.record_direct_call("C_Login", 0)
    first = call_counters.serialize_current()
    call_counters.reset_for_tests()
    call_counters.record_direct_call("C_Login", 0x31)
    second = call_counters.serialize_current()
    merged = call_counters.merge_serialized(first, second)
    assert merged is first
    assert merged["total_calls"] == 3
    assert merged["buckets"]["session_provisioning"]["calls"] == 2
    assert merged["buckets"]["test"]["calls"] == 1
    login = merged["buckets"]["session_provisioning"]["by_fn"]["C_Login"]
    assert login["calls"] == 2
    assert login["by_rv"]["0"]["count"] == 1
    assert login["by_rv"][str(0x31)]["count"] == 1


def test_merge_serialized_creates_missing_keys_without_aliasing() -> None:
    call_counters.record_direct_call("C_Login", 0)
    incoming = call_counters.serialize_current()
    target: dict[str, object] = {"total_calls": 0, "buckets": {}}
    merged = call_counters.merge_serialized(target, incoming)
    assert merged == incoming
    leaf = merged["buckets"]["session_provisioning"]["by_fn"]["C_Login"]["by_rv"]["0"]
    assert leaf == {"name": "CKR_OK", "count": 1}
    leaf["count"] += 10
    assert (
        incoming["buckets"]["session_provisioning"]["by_fn"]["C_Login"]["by_rv"]["0"]["count"] == 1
    )


def test_merge_serialized_does_not_touch_globals() -> None:
    call_counters.record_direct_call("C_Login", 0)
    before = call_counters.serialize_current()
    call_counters.merge_serialized({"total_calls": 0, "buckets": {}}, before)
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
    assert call_counters.serialize_current() == {"total_calls": 0, "buckets": {}}
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
    entry = snap["buckets"]["session_provisioning"]["by_fn"]["C_GetInfo"]
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
    return raw


def test_load_from_lib_records_c_get_interface() -> None:
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
    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, "fake-module.so", interface="3.2")
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = snap["buckets"]["session_provisioning"]["by_fn"]["C_GetInterface"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}


def test_load_from_lib_records_c_get_function_list() -> None:
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
    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, "fake-module.so", interface="2.40")
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    entry = snap["buckets"]["session_provisioning"]["by_fn"]["C_GetFunctionList"]
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
    assert after["buckets"]["session_provisioning"]["by_fn"]["C_GetInfo"]["calls"] == 2


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
    from pathlib import Path

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
    assert set(snap["buckets"]) == {"module_init"}
    assert snap["buckets"]["module_init"]["by_fn"]["C_Finalize"]["calls"] == 1
    assert snap["buckets"]["module_init"]["by_fn"]["C_Initialize"]["calls"] == 1


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
    assert set(snap["buckets"]) == {"module_init"}
    assert snap["buckets"]["module_init"]["by_fn"]["C_Finalize"]["calls"] == 1
