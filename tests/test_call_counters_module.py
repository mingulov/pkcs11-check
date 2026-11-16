"""Task-2 module identity: per-handle module ids, module-first records, uuids (plan v8).

Step-1 RED tests: mixed-module workers split exactly (direct + absorbed
child traffic), legacy records normalize to the "" unknown module (never
inferred), row tags appear iff more than one module occurs, and every
emitted record carries the process worker_uuid.
"""

from __future__ import annotations

import ctypes
import json
import os
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import pkcs11_check._plugin_counters as plugin_counters
from pkcs11_check.core import call_counters
from pkcs11_check.core import counters_schema as schema
from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core.call_counters import CALL_COUNTERS_PROPERTY, ISOLATION_ENV
from pkcs11_check.core.merge import merge_shard_dirs

_MOD_A = "/lib/softhsm/libsofthsm2.so"
_MOD_B = "/lib/p11kit-proxy.so"
_UUID_A = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


@pytest.fixture(autouse=True)
def _clean_counters() -> Iterator[None]:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


def _fn_block(calls: int, *, rv: int = 0, name: str = "CKR_OK") -> dict[str, Any]:
    return {"calls": calls, "by_rv": {str(rv): {"name": name, "count": calls}}}


def _buckets(total: int, *, bucket: str = "test", fn: str = "C_Sign") -> dict[str, Any]:
    return {bucket: {"calls": total, "by_fn": {fn: _fn_block(total)}}}


def _module_block(modules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_module: dict[str, Any] = {}
    total = 0
    for module, buckets in modules.items():
        calls = sum(block["calls"] for block in buckets.values())
        by_module[module] = {"calls": calls, "buckets": buckets}
        total += calls
    return {"total_calls": total, "by_module": by_module}


def _legacy_block(total: int, **kwargs: Any) -> dict[str, Any]:
    return {"total_calls": total, "buckets": _buckets(total, **kwargs)}


def _session_record(
    pid: int,
    block: dict[str, Any] | None = None,
    total: int = 10,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "isolation": "file",
        "probes_lost": 0,
    }
    record.update(_legacy_block(total) if block is None else block)
    if extra:
        record.update(extra)
    return record


def _test_entry(
    pid: int, block: dict[str, Any] | None = None, total: int = 6, **extra: Any
) -> dict[str, Any]:
    entry: dict[str, Any] = {"pid": pid}
    entry.update(_legacy_block(total) if block is None else block)
    entry.update(extra)
    return entry


def _test_report(nodeid: str, when: str, entry: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": "passed",
        "duration": 0.1,
        "user_properties": [] if entry is None else [[CALL_COUNTERS_PROPERTY, entry]],
    }


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _hook_item() -> Any:
    item: Any = SimpleNamespace(
        path=Path("/repo/src/pkcs11_check/testcases/test_x.py"),
        nodeid="src/pkcs11_check/testcases/test_x.py::test_y",
        stash=pytest.Stash(),
        config=SimpleNamespace(
            getoption=lambda name, default=None: {"p11_module": "/tmp/fake.so"}.get(name, default)
        ),
    )
    return item


def _function_list_buffer(major: int, minor: int) -> Any:
    import ctypes as _ctypes

    from pkcs11_check.raw import metadata_std
    from pkcs11_check.raw.api import function_list_header_size

    max_index = max(metadata_std.FUNCTION_INDICES.values())
    size = function_list_header_size() + (max_index + 1) * _ctypes.sizeof(_ctypes.c_void_p)
    buf = (_ctypes.c_ubyte * size)()
    buf[0] = major
    buf[1] = minor
    return buf


# --------------------------------------------------------------------------
# Core keys: module-first counting, wire rows, identity allocation
# --------------------------------------------------------------------------


class TestModuleFirstCore:
    def test_direct_calls_with_modules_split_exactly(self) -> None:
        call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
        call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
        call_counters.record_direct_call("C_Sign", 0, module=_MOD_B)
        snap = call_counters.serialize_current()
        assert schema.is_module_first_block(snap) is True
        assert snap["total_calls"] == 3
        assert snap["by_module"][_MOD_A]["calls"] == 2
        assert snap["by_module"][_MOD_B]["calls"] == 1
        assert set(snap) == {"total_calls", "by_module"}

    def test_record_call_and_return_pair_with_module(self) -> None:
        with call_counters.counted_bucket("test"):
            call_counters.record_call("C_Login", module=_MOD_A)
            call_counters.record_return("C_Login", 0, module=_MOD_A)
        snap = call_counters.serialize_current()
        login = snap["by_module"][_MOD_A]["buckets"]["test"]["by_fn"]["C_Login"]
        assert login["calls"] == 1
        assert login["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}

    def test_default_module_is_unknown(self) -> None:
        call_counters.record_direct_call("C_Login", 0)
        snap = call_counters.serialize_current()
        assert set(snap["by_module"]) == {""}
        assert snap["by_module"][""]["calls"] == 1

    def test_record_rejects_non_string_module(self) -> None:
        with pytest.raises(ValueError, match="module"):
            call_counters.record_call("C_Login", module=None)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="module"):
            call_counters.record_return("C_Login", 0, module=42)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="module"):
            call_counters.record_direct_call("C_Login", 0, module=b"x")  # type: ignore[arg-type]
        assert call_counters.serialize_current()["total_calls"] == 0

    def test_empty_serializes_to_empty_module_first(self) -> None:
        assert call_counters.serialize_current() == {"total_calls": 0, "by_module": {}}
        snap = call_counters.take_snapshot()
        assert call_counters.diff_snapshots(snap, snap) == {"total_calls": 0, "by_module": {}}

    def test_snapshot_diff_isolates_module_windows(self) -> None:
        call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
        before = call_counters.take_snapshot()
        call_counters.record_direct_call("C_Sign", 0, module=_MOD_B)
        delta = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        assert delta["total_calls"] == 1
        assert set(delta["by_module"]) == {_MOD_B}

    def test_flatten_emits_module_first_wire_rows(self) -> None:
        call_counters.record_direct_call("C_Login", 0, module=_MOD_B)
        call_counters.record_direct_call("C_Login", 0x31, module=_MOD_A)
        call_counters.record_call("C_Sign", module=_MOD_A)
        assert call_counters.flatten_current() == [
            [_MOD_B, "C_Login", 0, 1],
            [_MOD_A, "C_Login", 0x31, 1],
            [_MOD_A, "C_Sign", None, 1],
        ]

    def test_mixed_module_direct_plus_absorbed_child_splits_exactly(self) -> None:
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
            call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
        call_counters.ingest_child_counts(
            [[_MOD_B, "C_Sign", 0, 3], [_MOD_B, "C_Login", None, 1]], bucket="test"
        )
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 6
        assert snap["by_module"][_MOD_A]["calls"] == 2
        assert snap["by_module"][_MOD_B]["calls"] == 4
        sign = snap["by_module"][_MOD_B]["buckets"]["test"]["by_fn"]["C_Sign"]
        assert sign["calls"] == 3
        assert sign["by_rv"]["0"] == {"name": "CKR_OK", "count": 3}

    def test_flatten_ingest_round_trip_preserves_modules(self) -> None:
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
            call_counters.record_direct_call("C_Sign", 0, module=_MOD_B)
            call_counters.record_call("C_Orphan", module=_MOD_B)
        original = call_counters.serialize_current()
        flat = call_counters.flatten_current()
        call_counters.reset_for_tests()
        with call_counters.counted_bucket("test"):
            call_counters.ingest_child_counts(flat)
        assert call_counters.serialize_current() == original

    def test_ingest_legacy_three_col_rows_normalize_to_unknown(self) -> None:
        call_counters.ingest_child_counts([["C_Login", 0, 2], [_MOD_A, "C_Sign", 0, 1]])
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 3
        assert snap["by_module"][""]["calls"] == 2
        assert snap["by_module"][_MOD_A]["calls"] == 1

    def test_ingest_skips_rows_with_bad_module(self) -> None:
        call_counters.ingest_child_counts(
            [
                [None, "C_Login", 0, 1],
                [42, "C_Login", 0, 1],
                [b"x", "C_Login", 0, 1],
                ["C_Login", 0, 1, "extra-col"],
                [_MOD_A, "C_Login", 0, 2],
            ]
        )
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 2
        assert set(snap["by_module"]) == {_MOD_A}

    def test_worker_uuid_stable_valid_and_reset(self) -> None:
        first = call_counters.get_worker_uuid()
        assert schema.is_worker_uuid(first) is True
        assert call_counters.get_worker_uuid() == first
        call_counters.reset_for_tests()
        second = call_counters.get_worker_uuid()
        assert schema.is_worker_uuid(second) is True
        assert second != first

    def test_worker_uuid_remints_after_fork(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before = call_counters.get_worker_uuid()
        monkeypatch.setattr("os.getpid", lambda: 424242)
        assert call_counters.get_worker_uuid() != before


# --------------------------------------------------------------------------
# Handle binding: RawPKCS11 module id immutable and bound before loader C calls
# --------------------------------------------------------------------------


class TestHandleModuleBinding:
    def test_lib_path_bound_before_loader_c_calls(self, tmp_path: Path) -> None:
        from types import SimpleNamespace
        from unittest.mock import patch

        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import CKR_OK

        buf = _function_list_buffer(2, 40)

        def _fake_get_function_list(fn_list_pp: Any) -> int:
            ctypes.cast(fn_list_pp, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)
            return int(CKR_OK)

        fake_lib = SimpleNamespace(C_GetFunctionList=_fake_get_function_list)
        lib_path = str(tmp_path / "fake-module.so")
        with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
            RawPKCS11(lib_path=lib_path, interface="2.40")
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 1
        assert set(snap["by_module"]) == {lib_path}

    def test_explicit_module_id_for_funclist_handles(self) -> None:
        from pkcs11_check.raw.api import RawPKCS11

        buf = _function_list_buffer(2, 40)
        raw = RawPKCS11(funclist_ptr=ctypes.addressof(buf), module_id=_MOD_A)
        raw._funcs["C_GetInfo"] = lambda *args: 0
        raw._call("C_GetInfo")
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 1
        assert set(snap["by_module"]) == {_MOD_A}

    def test_funclist_handle_without_id_counts_unknown(self) -> None:
        from pkcs11_check.raw.api import RawPKCS11

        buf = _function_list_buffer(2, 40)
        raw = RawPKCS11(funclist_ptr=ctypes.addressof(buf))
        raw._funcs["C_GetInfo"] = lambda *args: 0
        raw._call("C_GetInfo")
        assert set(call_counters.serialize_current()["by_module"]) == {""}

    def test_raw_rejects_non_string_module_id(self) -> None:
        from pkcs11_check.raw.api import RawPKCS11

        buf = _function_list_buffer(2, 40)
        with pytest.raises(ValueError, match="module_id"):
            RawPKCS11(funclist_ptr=ctypes.addressof(buf), module_id=42)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Records: uuid + module-first payloads on session records and per-test entries
# --------------------------------------------------------------------------


class TestModuleFirstRecords:
    def test_session_record_carries_uuid_and_module_first(self) -> None:
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
        record = plugin_counters.build_session_record()
        assert schema.is_session_record(record) is True
        assert schema.is_worker_uuid(record["worker_uuid"]) is True
        assert record["by_module"][_MOD_A]["calls"] == 1
        assert "buckets" not in record
        assert schema.is_secret_free(record) is True

    def test_per_test_entry_carries_uuid_and_module_first(self) -> None:
        item = _hook_item()
        from pkcs11_check._plugin_state import _is_testcase_item

        assert _is_testcase_item(item)
        gen = plugin_counters.pytest_runtest_setup(item)
        next(gen)
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0, module=_MOD_A)
        try:
            gen.send(None)
        except StopIteration:
            pass
        gen = plugin_counters.pytest_runtest_teardown(item, None)
        next(gen)
        try:
            gen.send(None)
        except StopIteration:
            pass
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert schema.is_test_entry(entry) is True
        assert schema.is_worker_uuid(entry["worker_uuid"]) is True
        assert entry["by_module"][_MOD_A]["calls"] == 1
        assert entry["isolation"] == os.environ.get(ISOLATION_ENV, "unknown")


# --------------------------------------------------------------------------
# Extractor: module-first folding, legacy normalization, conditional tags, uuid
# --------------------------------------------------------------------------


class TestModuleFirstExtract:
    def test_mixed_module_session_splits_rows_with_tags(self, tmp_path: Path) -> None:
        block = _module_block(
            {
                _MOD_A: _buckets(6, bucket="test"),
                _MOD_B: _buckets(4, bucket="test", fn="C_Login"),
            }
        )
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, block, extra={"worker_uuid": _UUID_A}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is True
        assert "by_bucket" not in payload
        assert payload["by_module"]["by_module"][_MOD_A]["calls"] == 6
        assert payload["by_module"]["by_module"][_MOD_B]["calls"] == 4
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 4,
                "complete": True,
                "worker_uuid": _UUID_A,
                "module": _MOD_B,
            },
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 6,
                "complete": True,
                "worker_uuid": _UUID_A,
                "module": _MOD_A,
            },
        ]

    def test_single_module_rows_untagged(self, tmp_path: Path) -> None:
        block = _module_block({_MOD_A: _buckets(7, bucket="test")})
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, block, extra={"worker_uuid": _UUID_A}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 7,
                "complete": True,
                "worker_uuid": _UUID_A,
            }
        ]

    def test_legacy_session_normalizes_to_unknown_without_tags(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert set(payload["by_module"]["by_module"]) == {""}
        assert payload["by_module"]["by_module"][""]["calls"] == 10
        assert all("module" not in row for row in payload["by_process"])
        assert all("worker_uuid" not in row for row in payload["by_process"])

    def test_fallback_entry_uuid_folds_onto_row(self, tmp_path: Path) -> None:
        entry = _test_entry(100, _module_block({_MOD_A: _buckets(6)}), worker_uuid=_UUID_A)
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 6
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "unknown",
                "total_calls": 6,
                "complete": False,
                "worker_uuid": _UUID_A,
            }
        ]

    def test_session_uuid_wins_over_entry_uuid(self, tmp_path: Path) -> None:
        uuid_b = "00112233445566778899aabbccddeeff"
        entry = _test_entry(100, total=4, worker_uuid=uuid_b)
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _test_report("a.py::t1", "teardown", entry),
                _session_record(100, total=10, extra={"worker_uuid": _UUID_A}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 10,
                "complete": True,
                "worker_uuid": _UUID_A,
            }
        ]

    def test_malformed_uuid_skips_record(self, tmp_path: Path) -> None:
        # No SessionFinish: the skipped record leaves a marked-but-counterless
        # unfinished scope, which must surface as an incomplete C2b group --
        # a folded record would read total 10 + complete instead.
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10, extra={"worker_uuid": "not-a-uuid"}),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False

    def test_both_or_neither_counters_shape_skipped(self, tmp_path: Path) -> None:
        both = _session_record(100, total=10)
        both["by_module"] = _module_block({_MOD_A: _buckets(10)})["by_module"]
        neither = {
            "$report_type": "CallCountersReport",
            "pid": 100,
            "probes_lost": 0,
            "total_calls": 0,
        }
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                both,
                neither,
                _session_record(200, total=7),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 7
        assert [row["pid"] for row in payload["by_process"]] == [200]

    def test_module_first_total_mismatch_skipped(self, tmp_path: Path) -> None:
        # No SessionFinish (see test_malformed_uuid_skips_record): the skip
        # must surface as an incomplete C2b group, not vanish.
        block = _module_block({_MOD_A: _buckets(6)})
        block["total_calls"] = 99
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, block),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False


# --------------------------------------------------------------------------
# Merge: module-first roll-up with conditional tags, order-independent
# --------------------------------------------------------------------------


class TestModuleFirstMerge:
    def _write_shard(
        self, root: Path, name: str, records: list[dict[str, Any]], target: str = "a.py"
    ) -> Path:
        shard = root / name
        shard.mkdir()
        (shard / "results.json").write_text(
            json.dumps(
                {
                    "tool": "pkcs11-check",
                    "kind": "test-run",
                    "summary": {"passed": 1, "failed": 0},
                    "units": [{"target": target, "status": "passed"}],
                }
            ),
            encoding="utf-8",
        )
        _write_jsonl(
            shard / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker(target, 0),
                *records,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        return shard

    def test_merge_single_module_shards_stay_untagged(self, tmp_path: Path) -> None:
        block_a = _module_block({_MOD_A: _buckets(10)})
        block_b = _module_block({_MOD_A: _buckets(5, fn="C_Login")})
        first = self._write_shard(
            tmp_path, "shard0", [_session_record(100, block_a, extra={"worker_uuid": _UUID_A})]
        )
        second = self._write_shard(
            tmp_path, "shard1", [_session_record(200, block_b)], target="b.py"
        )
        merged_ab = merge_shard_dirs([first, second], tmp_path / "merged_ab")
        merged_ba = merge_shard_dirs([second, first], tmp_path / "merged_ba")
        assert merged_ab["call_counters"] == merged_ba["call_counters"]
        assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
        counters = merged_ab["call_counters"]
        assert counters["total_calls"] == 15
        assert set(counters["by_module"]["by_module"]) == {_MOD_A}
        assert all("module" not in row for row in counters["by_process"])
        assert [row["shard"] for row in counters["by_process"]] == ["shard0", "shard1"]

    def test_merge_retags_single_module_shards_when_mixed(self, tmp_path: Path) -> None:
        block_a = _module_block({_MOD_A: _buckets(10)})
        block_b = _module_block({_MOD_B: _buckets(5, fn="C_Login")})
        first = self._write_shard(tmp_path, "shard0", [_session_record(100, block_a)])
        second = self._write_shard(
            tmp_path, "shard1", [_session_record(200, block_b)], target="b.py"
        )
        merged_ab = merge_shard_dirs([first, second], tmp_path / "merged_ab")
        merged_ba = merge_shard_dirs([second, first], tmp_path / "merged_ba")
        assert merged_ab["call_counters"] == merged_ba["call_counters"]
        assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
        counters = merged_ab["call_counters"]
        assert counters["total_calls"] == 15
        assert sorted(counters["by_module"]["by_module"]) == [_MOD_B, _MOD_A]
        assert [(row["module"], row["total_calls"]) for row in counters["by_process"]] == [
            (_MOD_A, 10),
            (_MOD_B, 5),
        ]


# --------------------------------------------------------------------------
# Probe payloads: module threaded through child-side record sites
# --------------------------------------------------------------------------


class TestProbeModuleThreading:
    def test_counting_cdll_threads_module(self) -> None:
        from unittest.mock import MagicMock

        from pkcs11_check.testcases._probes import raw_session

        func = MagicMock(return_value=0)
        stub = SimpleNamespace(C_Login=func)
        wrapped = raw_session.counting_cdll(stub, module=_MOD_A)  # type: ignore[arg-type]
        wrapped.C_Login(None)
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 1
        assert set(snap["by_module"]) == {_MOD_A}

    def test_make_caller_threads_module(self) -> None:
        from pkcs11_check.testcases._probes import _ckr_ctypes

        callback = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(lambda *args: 0)
        addr = ctypes.cast(callback, ctypes.c_void_p).value
        assert addr is not None
        idx = _ckr_ctypes.FUNC_INDICES["C_Initialize"]
        table = (ctypes.c_void_p * (idx + 1))()
        table[idx] = ctypes.c_void_p(addr)
        base = ctypes.addressof(table) - _ckr_ctypes._HEADER_SIZE
        call_func, _get_func = _ckr_ctypes.make_caller(SimpleNamespace(value=base), module=_MOD_A)
        assert call_func("C_Initialize", ctypes.c_void_p(None)) == 0
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 1
        assert set(snap["by_module"]) == {_MOD_A}

    def test_get_function_list_records_module(self) -> None:
        from pkcs11_check.testcases._probes import raw_session

        lib = SimpleNamespace()
        buf = _function_list_buffer(2, 40)

        def _fake_get_function_list(fn_list_pp: Any) -> int:
            ctypes.cast(fn_list_pp, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)
            return 0

        lib.C_GetFunctionList = _fake_get_function_list
        funclist_ptr, rv = raw_session._get_function_list(lib, module=_MOD_A)  # type: ignore[arg-type]
        assert rv == 0
        assert funclist_ptr is not None
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 1
        assert set(snap["by_module"]) == {_MOD_A}
