"""Task-5 structure: isolation stamps, uniform-5, C2b interplay, merge dedup.

Step-1 RED tests for plan v8 Task 5 (written before the implementation;
the forward-RED ``TestForwardTask5Structure`` contracts go green in the
same task). Pins:

- per-test entries stamp ``isolation`` from the environment (``unknown``
  when unstamped); crash-fallback rows inherit the stamp while
  bare-pytest rows stay ``unknown``;
- every emitted module-first block carries exactly the five bucket keys
  (zero buckets explicit); empty emission stays ``{"total_calls": 0,
  "by_module": {}}`` and legacy sparse input still parses to identical
  totals/flags;
- a lost record suppresses the C2b empty group ONLY on a
  source-association match (origin shard + unit + attempt, worker
  identity carried); cross-source decoys, foreign origins, and legacy
  position-keyed records keep the backstop, while reordered/prepended
  records anchor by association with an assembly-derived scope;
- merge fuses contributions by full ``(shard, run_id, worker_uuid,
  module)`` identity (same shard dir twice fuses); distinct shards
  never fuse even on uuid collision.
"""

from __future__ import annotations

import json
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
from tests._counters_fixtures import (
    _fn_block,
    _legacy_block,
    _module_block,
    _session_record,
)

_R1 = "20261115T120000000000Z-p100-a1b2c3d4"
_R2 = "20261115T130000000000Z-p200-e5f6a7b8"

_UUID_A = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
_UUID_B = "00112233445566778899aabbccddeeff"
_UUID_C = "ffeeddccbbaa99887766554433221100"


def _uniform_module_block(
    total: int, *, bucket: str = "test", fn: str = "C_Sign", module: str = ""
) -> dict[str, Any]:
    buckets = schema.ensure_five_buckets(
        {bucket: {"calls": total, "by_fn": {fn: _fn_block(total)}}}
    )
    return {"total_calls": total, "by_module": {module: {"calls": total, "buckets": buckets}}}


def _test_entry(
    pid: int,
    block: dict[str, Any] | None = None,
    total: int = 6,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"pid": pid}
    entry.update(_legacy_block(total) if block is None else block)
    if extra:
        entry.update(extra)
    return entry


def _test_report(
    nodeid: str, when: str, entry: dict[str, Any] | None, *, outcome: str = "passed"
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": outcome,
        "duration": 0.1,
        "user_properties": [],
    }
    if entry is not None:
        report["user_properties"] = [[CALL_COUNTERS_PROPERTY, entry]]
    return report


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _lost_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersLost",
        "end_state": "crashed",
        "scope_index": 1,
        "worker_uuid": _UUID_A,
        "pid": 100,
        "run_id": _R1,
        "unit": "a.py",
        "attempt": 0,
        "origin_shard": "",
    }
    record.update(overrides)
    return record


def _partial_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersPartial",
        "worker_uuid": _UUID_B,
        "truncated": True,
        "run_id": _R1,
        "unit": "b.py",
        "attempt": 0,
        "pid": 200,
    }
    record.update(_module_block({"": _legacy_block(5)["buckets"]}))
    record.update(overrides)
    return record


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _write_shard(d: Path, target: str, records: list[dict[str, Any]]) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "results.json").write_text(
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
    (d / "report.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )


def _hook_item() -> Any:
    from pkcs11_check._plugin_state import _is_testcase_item

    item: Any = SimpleNamespace(
        path=Path("/repo/src/pkcs11_check/testcases/test_x.py"),
        nodeid="src/pkcs11_check/testcases/test_x.py::test_y",
        stash=pytest.Stash(),
        config=SimpleNamespace(
            getoption=lambda name, default=None: {"p11_module": "/tmp/fake.so"}.get(name, default)
        ),
    )
    assert _is_testcase_item(item)
    return item


def _drive_hook(hook: Any, item: Any, *args: Any, calls: tuple[str, ...] = ()) -> None:
    gen = hook(item, *args)
    next(gen)
    for fn in calls:
        call_counters.record_call(fn)
        call_counters.record_return(fn, 0)
    try:
        gen.send(None)
    except StopIteration:
        return


@pytest.fixture(autouse=True)
def _clean_counters() -> Any:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


class TestIsolationStamp:
    def test_entry_carries_stamped_isolation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ISOLATION_ENV, "file")
        item = _hook_item()
        _drive_hook(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
        _drive_hook(plugin_counters.pytest_runtest_call, item, calls=("C_BodyCall",))
        _drive_hook(plugin_counters.pytest_runtest_teardown, item, None)
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert entry["total_calls"] == 2
        assert entry["isolation"] == "file"
        assert schema.is_test_entry(entry) is True

    def test_entry_isolation_defaults_unknown_without_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(ISOLATION_ENV, raising=False)
        item = _hook_item()
        _drive_hook(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
        _drive_hook(plugin_counters.pytest_runtest_teardown, item, None)
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert entry["isolation"] == "unknown"
        assert schema.is_test_entry(entry) is True

    def test_fallback_row_inherits_stamped_isolation(self, tmp_path: Path) -> None:
        entry = _test_entry(100, total=6, extra={"isolation": "file", "run_id": _R1})
        assert schema.is_test_entry(entry) is True
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
        assert payload["by_process"] == [
            {"pid": 100, "isolation": "file", "total_calls": 6, "complete": False}
        ]

    def test_fallback_row_mistyped_isolation_stays_unknown(self, tmp_path: Path) -> None:
        entry = _test_entry(100, total=6, extra={"isolation": 5})
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
        assert payload["by_process"] == [
            {"pid": 100, "isolation": "unknown", "total_calls": 6, "complete": False}
        ]

    def test_session_isolation_wins_over_fallback(self, tmp_path: Path) -> None:
        session = _session_record(100, total=10, isolation="file")
        entry = _test_entry(100, total=6, extra={"isolation": "none"})
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert [row["isolation"] for row in payload["by_process"]] == ["file"]


class TestUniformFiveEmission:
    def test_serialize_current_emits_five_buckets(self) -> None:
        call_counters.record_direct_call("C_Login", 0)
        snap = call_counters.serialize_current()
        assert snap["total_calls"] == 1
        assert set(snap["by_module"]) == {""}
        buckets = snap["by_module"][""]["buckets"]
        assert set(buckets) == set(schema.BUCKETS_5)
        assert buckets["session_provisioning"]["calls"] == 1
        for name in schema.BUCKETS_5:
            if name != "session_provisioning":
                assert buckets[name] == {"calls": 0, "by_fn": {}}

    def test_diff_window_emits_five_buckets(self) -> None:
        before = call_counters.take_snapshot()
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0)
        delta = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        assert delta["total_calls"] == 1
        buckets = delta["by_module"][""]["buckets"]
        assert set(buckets) == set(schema.BUCKETS_5)
        assert buckets["test"]["calls"] == 1
        assert buckets["preflight"] == {"calls": 0, "by_fn": {}}

    def test_session_record_blocks_uniform_five(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ISOLATION_ENV, "file")
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0)
        record = plugin_counters.build_session_record()
        assert schema.is_session_record(record) is True
        for module_block in record["by_module"].values():
            assert set(module_block["buckets"]) == set(schema.BUCKETS_5)

    def test_entry_blocks_uniform_five(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ISOLATION_ENV, "file")
        item = _hook_item()
        _drive_hook(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
        _drive_hook(plugin_counters.pytest_runtest_teardown, item, None)
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert schema.is_test_entry(entry) is True
        for module_block in entry["by_module"].values():
            assert set(module_block["buckets"]) == set(schema.BUCKETS_5)

    def test_empty_emission_stays_empty(self) -> None:
        assert call_counters.serialize_current() == {"total_calls": 0, "by_module": {}}
        snap = call_counters.take_snapshot()
        assert call_counters.diff_snapshots(snap, snap) == {"total_calls": 0, "by_module": {}}


class TestLegacyParsing:
    def test_legacy_sparse_parses_identical_to_padded(self, tmp_path: Path) -> None:
        sparse = _write_jsonl(tmp_path / "sparse.jsonl", [_session_record(100, total=10)])
        padded_record = _session_record(100, total=10)
        padded_record["buckets"] = {
            **{bucket: {"calls": 0, "by_fn": {}} for bucket in ("setup_teardown",)},
            **padded_record["buckets"],
        }
        padded = _write_jsonl(tmp_path / "padded.jsonl", [padded_record])
        sparse_payload = extract_call_counters_from_jsonl(sparse)
        padded_payload = extract_call_counters_from_jsonl(padded)
        assert sparse_payload is not None and padded_payload is not None
        assert sparse_payload["total_calls"] == padded_payload["total_calls"] == 10
        assert sparse_payload["complete"] == padded_payload["complete"] is True
        assert sparse_payload["by_process"] == padded_payload["by_process"]

    def test_mixed_sparse_and_uniform_merge_exact(self, tmp_path: Path) -> None:
        sparse = _session_record(100, total=10)
        uniform = _session_record(
            200, _uniform_module_block(5, bucket="setup_teardown", fn="C_Login")
        )
        assert schema.is_session_record(uniform) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                sparse,
                uniform,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 15
        assert payload["complete"] is True
        buckets = payload["by_module"]["by_module"][""]["buckets"]
        assert buckets["test"]["by_fn"]["C_Sign"]["calls"] == 10
        assert buckets["setup_teardown"]["by_fn"]["C_Login"]["calls"] == 5


class TestC2bAssociationInterplay:
    def test_matched_lost_suppresses_c2b(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), _lost_record()],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["complete"] is False
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]
        assert list(payload["by_round"]) == [_R1]

    def test_cross_unit_decoy_retains_c2b(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(unit="other.py", worker_uuid=_UUID_B),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        assert payload["unattributed_segments"] == [
            {"scope_index": 1, "unit": "a.py", "attempt": 0}
        ]
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_B]

    def test_cross_attempt_decoy_retains_c2b(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(attempt=9),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        assert payload["unattributed_segments"] == [
            {"scope_index": 1, "unit": "a.py", "attempt": 0}
        ]

    def test_foreign_origin_never_anchors(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(origin_shard="shardX"),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        assert payload["unattributed_segments"] == [
            {"scope_index": 1, "unit": "a.py", "attempt": 0}
        ]
        assert payload["lost_processes"][0]["origin_shard"] == "shardX"

    def test_reordered_lost_anchors_by_association(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _lost_record(),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        # The (a.py, 0) loss anchors scope 1 (not its staged scope 2);
        # the genuinely counterless (b.py, 0) segment keeps its C2b segment.
        assert payload["lost_processes"][0]["scope_index"] == 1
        assert payload["unattributed_segments"] == [
            {"scope_index": 2, "unit": "b.py", "attempt": 0}
        ]
        assert payload["by_round"][_R1]["complete"] is False

    def test_prepended_lost_anchors_by_association(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [_lost_record(), {"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        assert payload["lost_processes"][0]["scope_index"] == 1

    def test_repeated_identical_losts_yield_one_entry(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(),
                _lost_record(),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]
        assert list(payload["by_round"]) == [_R1]

    def test_repeated_resume_anchors_each_attempt(self, tmp_path: Path) -> None:
        session = _session_record(200, total=7, extra={"worker_uuid": _UUID_B, "run_id": _R2})
        assert schema.is_session_record(session) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(),
                {"$report_type": "SessionStart"},
                _marker("a.py", 1),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1, _R2]
        assert payload["by_round"][_R1]["complete"] is False
        assert payload["by_round"][_R1]["lost_processes"][0]["worker_uuid"] == _UUID_A
        assert payload["by_round"][_R2]["complete"] is True
        assert payload["by_round"][_R2]["total_calls"] == 7
        assert "lost_processes" not in payload["by_round"][_R2]

    def test_lost_against_static_skip_stays_fail_visible(self, tmp_path: Path) -> None:
        marker = _marker("a.py", 0)
        marker["reason"] = "missing-provider-capability"
        marker["skipped"] = 3
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, marker, _lost_record()],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        # An explicit loss claim against a never-executed unit is
        # contradictory evidence: anchored (association matches) and
        # incomplete, never silently dropped.
        assert list(payload["by_round"]) == [_R1]
        assert payload["complete"] is False
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]

    def test_legacy_lost_without_association_stays_positional(self, tmp_path: Path) -> None:
        record = _lost_record()
        del record["unit"]
        del record["attempt"]
        assert schema.is_lost_record(record) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), record],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        assert payload["lost_processes"][0]["scope_index"] == 1

    def test_lost_beside_same_producer_session_heals(self, tmp_path: Path) -> None:
        session = _session_record(100, total=10, extra={"worker_uuid": _UUID_A, "run_id": _R1})
        assert schema.is_session_record(session) is True
        # Both record orders: validated same-run authority reconciles the
        # stale loss before anchoring, so it neither dispositions rows nor
        # poisons completeness. Independent losses still fail visible.
        for records in (
            [session, _lost_record()],
            [_lost_record(), session],
        ):
            jsonl = _write_jsonl(
                tmp_path / "report.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    *records,
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            payload = extract_call_counters_from_jsonl(jsonl)
            assert payload is not None
            assert payload["total_calls"] == 10
            assert payload["complete"] is True
            assert "lost_processes" not in payload
            assert payload["by_process"] == [
                {
                    "pid": 100,
                    "isolation": "file",
                    "total_calls": 10,
                    "complete": True,
                    "worker_uuid": _UUID_A,
                }
            ]


class TestMergeIdentityDedup:
    def _rich_records(self) -> list[dict[str, Any]]:
        session_a = _session_record(100, total=10, extra={"worker_uuid": _UUID_A, "run_id": _R1})
        session_c = _session_record(300, total=7, extra={"worker_uuid": _UUID_C, "run_id": _R2})
        partial = _partial_record(receipts=[{"worker_uuid": _UUID_B, "probe_seq": 0}])
        lost = _lost_record(worker_uuid=_UUID_B, pid=200, unit="b.py", end_state="timeout")
        assert schema.is_session_record(session_a) is True
        assert schema.is_session_record(session_c) is True
        assert schema.is_sidecar_partial(partial) is True
        assert schema.is_lost_record(lost) is True
        return [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            session_a,
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("b.py", 0),
            partial,
            lost,
            {"$report_type": "SessionStart"},
            _marker("c.py", 0),
            session_c,
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ]

    def test_same_shard_twice_fuses_identically(self, tmp_path: Path) -> None:
        shard = tmp_path / "shardX"
        _write_shard(shard, "a.py", self._rich_records())
        single = merge_shard_dirs([shard], tmp_path / "merged_single")["call_counters"]
        assert single["total_calls"] == 22
        assert single["complete"] is False
        assert len(single["lost_processes"]) == 1
        assert single["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]
        fused = merge_shard_dirs([shard, shard], tmp_path / "merged_fused")["call_counters"]
        assert fused == single

    def test_same_shard_twice_is_byte_identical(self, tmp_path: Path) -> None:
        shard = tmp_path / "shardX"
        _write_shard(shard, "a.py", self._rich_records())
        single = merge_shard_dirs([shard], tmp_path / "merged_single")["call_counters"]
        fused = merge_shard_dirs([shard, shard], tmp_path / "merged_fused")["call_counters"]
        assert json.dumps(fused) == json.dumps(single)

    def test_distinct_shards_with_uuid_collision_never_fuse(self, tmp_path: Path) -> None:
        records_a = [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _session_record(100, total=10, extra={"worker_uuid": _UUID_A, "run_id": _R1}),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ]
        records_b = [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _session_record(100, total=10, extra={"worker_uuid": _UUID_A, "run_id": _R1}),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ]
        first = tmp_path / "shardA"
        second = tmp_path / "shardB"
        _write_shard(first, "a.py", records_a)
        _write_shard(second, "a.py", records_b)
        merged_ab = merge_shard_dirs([first, second], tmp_path / "merged_ab")["call_counters"]
        merged_ba = merge_shard_dirs([second, first], tmp_path / "merged_ba")["call_counters"]
        assert merged_ab == merged_ba
        assert json.dumps(merged_ab) == json.dumps(merged_ba)
        assert merged_ab["total_calls"] == 20
        assert merged_ab["complete"] is True
        assert [(row["shard"], row["total_calls"]) for row in merged_ab["by_process"]] == [
            ("shardA", 10),
            ("shardB", 10),
        ]
        assert sorted(merged_ab["by_round"]) == [f"shardA/{_R1}", f"shardB/{_R1}"]


def _lost_key(parent: str, seq: int) -> dict[str, Any]:
    return {"parent_uuid": parent, "probe_seq": seq}


class TestMergeLossLedger:
    def test_merge_never_fuses_across_statuses(self, tmp_path: Path) -> None:
        # Same probe folded in one shard and lost-claimed in another:
        # contradictory dispositions stay visible, never fused.
        first = tmp_path / "shardA"
        _write_shard(
            first,
            "a.py",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    100,
                    total=10,
                    extra={
                        "worker_uuid": _UUID_A,
                        "run_id": _R1,
                        "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        second = tmp_path / "shardB"
        _write_shard(
            second,
            "b.py",
            [
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(
                    200,
                    total=7,
                    extra={
                        "worker_uuid": _UUID_B,
                        "run_id": _R1,
                        "probes_lost": 1,
                        "lost_keys": [_lost_key(_UUID_B, 0)],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        merged = merge_shard_dirs([first, second], tmp_path / "merged")["call_counters"]
        assert merged["total_calls"] == 17
        assert merged["probes_lost"] == 1
        assert merged["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"},
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "lost"},
        ]

    def test_merge_sums_disjoint_derived_totals(self, tmp_path: Path) -> None:
        first = tmp_path / "shardA"
        _write_shard(
            first,
            "a.py",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    100,
                    total=10,
                    extra={
                        "worker_uuid": _UUID_A,
                        "run_id": _R1,
                        "probes_lost": 2,
                        "lost_keys": [_lost_key(_UUID_A, 1)],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        second = tmp_path / "shardB"
        _write_shard(
            second,
            "b.py",
            [
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(
                    200,
                    total=7,
                    extra={
                        "worker_uuid": _UUID_C,
                        "run_id": _R1,
                        "probes_lost": 3,
                        "lost_keys": [_lost_key(_UUID_C, 4), _lost_key(_UUID_C, 5)],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        merged = merge_shard_dirs([first, second], tmp_path / "merged")["call_counters"]
        assert merged["total_calls"] == 17
        assert merged["probes_lost"] == 5
        assert merged["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "lost"},
            {"worker_uuid": _UUID_C, "probe_seq": 4, "status": "lost"},
            {"worker_uuid": _UUID_C, "probe_seq": 5, "status": "lost"},
        ]

    def test_merge_zero_rows_flow_without_module_stamp(self, tmp_path: Path) -> None:
        first = tmp_path / "shardA"
        _write_shard(
            first,
            "a.py",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10, extra={"worker_uuid": _UUID_A, "run_id": _R1}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        second = tmp_path / "shardB"
        _write_shard(
            second,
            "b.py",
            [
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _lost_record(worker_uuid=_UUID_B, pid=200, unit="b.py"),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        merged = merge_shard_dirs([first, second], tmp_path / "merged")["call_counters"]
        zero_rows = [row for row in merged["by_process"] if row["pid"] == 200]
        assert len(zero_rows) == 1
        assert "module" not in zero_rows[0]
        assert zero_rows[0]["shard"] == "shardB"
        assert zero_rows[0]["complete"] is False
