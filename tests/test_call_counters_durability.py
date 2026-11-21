"""Task-3 durability subsystem: registry, sidecars, collection, sweep, fence.

Step-1 RED tests for the rc2 durability plan (v8 Task 3): every behavior
below failed before the implementation (missing ``_counters_durability``
surface, no registration/flush/collection paths) and goes green with it.
Real files + real JSONL only — no mocked extractors, no mocked counters.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core import _counters_durability as durability
from pkcs11_check.core import call_counters
from pkcs11_check.core import counters_schema as schema
from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl

_UUID_A = "a" * 32
_UUID_B = "b" * 32
_RUN = "R1"


def _counts_block(
    n: int, *, fn: str = "C_Login", module: str = "m", bucket: str = "test"
) -> dict[str, Any]:
    """A minimal valid module-first block with ``n`` identical calls."""
    if n == 0:
        return {"total_calls": 0, "by_module": {}}
    return {
        "total_calls": n,
        "by_module": {
            module: {
                "calls": n,
                "buckets": {
                    bucket: {
                        "calls": n,
                        "by_fn": {fn: {"calls": n, "by_rv": {"0": {"name": "CKR_OK", "count": n}}}},
                    }
                },
            }
        },
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _session_record(
    pid: int, block: dict[str, Any], *, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "probes_lost": 0,
        "isolation": "file",
    }
    record.update(block)
    if extra:
        record.update(extra)
    return record


def _test_report(nodeid: str, when: str, entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": "passed",
        "user_properties": [["pkcs11_call_counters", entry]],
    }


def _test_entry(
    pid: int, block: dict[str, Any], *, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {"pid": pid}
    entry.update(block)
    if extra:
        entry.update(extra)
    return entry


def _partial_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersPartial",
        "worker_uuid": _UUID_A,
        "truncated": True,
        "run_id": _RUN,
        "unit": "a.py",
        "attempt": 0,
        "pid": 100,
    }
    record.update(_counts_block(5))
    record.update(overrides)
    return record


def _lost_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersLost",
        "end_state": "crashed",
        "scope_index": 1,
        "worker_uuid": _UUID_A,
        "pid": 100,
        "run_id": _RUN,
        "unit": "a.py",
        "attempt": 0,
    }
    record.update(overrides)
    return record


@pytest.fixture
def engaged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Engage durability: counters dir + identity env, clean counter state."""
    call_counters.reset_for_tests()
    root = tmp_path / "counters"
    monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(root))
    monkeypatch.setenv(durability.COUNTERS_UNIT_ENV, "a.py")
    monkeypatch.setenv(durability.COUNTERS_ATTEMPT_ENV, "0")
    monkeypatch.setenv(durability.COUNTERS_ROLE_ENV, "unit")
    monkeypatch.setenv(call_counters.RUN_ID_ENV, _RUN)
    yield root
    call_counters.reset_for_tests()
    monkeypatch.undo()


@pytest.fixture
def disengaged(monkeypatch: pytest.MonkeyPatch) -> None:
    call_counters.reset_for_tests()
    monkeypatch.delenv(durability.COUNTERS_DIR_ENV, raising=False)
    yield
    call_counters.reset_for_tests()


def _record_calls(n: int, *, fn: str = "C_Login") -> None:
    for _ in range(n):
        call_counters.record_call(fn)
        call_counters.record_return(fn, 0)


def _fake_popen_factory(
    *,
    on_spawn: Any = None,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    pid: int = 424242,
) -> Any:
    """Build a subprocess.Popen double honoring the runner's call shape.

    Runs ``on_spawn(*args, **kwargs)`` at construction (may raise to
    fail the spawn, like the old ``subprocess.run`` doubles did),
    then serves ``communicate``/``kill``/``wait``/``poll`` with canned
    output. Context-manager protocol included (the runner uses ``with``).
    """

    class _FakePopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs
            self.pid = pid
            self.returncode: int | None = None
            if on_spawn is not None:
                on_spawn(*args, **kwargs)

        def __enter__(self) -> _FakePopen:
            return self

        def __exit__(self, *exc: Any) -> bool:
            self.wait()
            return False

        def communicate(self, timeout: Any = None) -> tuple[str, str]:
            if self.returncode is None:
                self.returncode = returncode
            return (stdout, stderr)

        def kill(self) -> None:
            self.returncode = -9

        def wait(self, timeout: Any = None) -> int:
            if self.returncode is None:
                self.returncode = returncode
            return self.returncode

        def poll(self) -> int | None:
            return self.returncode

    return _FakePopen


# --------------------------------------------------------------------------
# Registration + admission barrier
# --------------------------------------------------------------------------


class TestRegistration:
    def test_first_provider_call_registers_self_describing_file(self, engaged: Path) -> None:
        call_counters.record_call("C_Initialize")
        registries = list((engaged / "registrations").glob("*.json"))
        assert len(registries) == 1
        content = json.loads(registries[0].read_text(encoding="utf-8"))
        assert schema.is_registry_content(content) is True
        assert content["run_id"] == _RUN
        assert content["unit"] == "a.py"
        assert content["attempt"] == 0
        assert content["pid"] == os.getpid()
        assert content["role"] == "unit"
        assert Path(content["sidecar"]).parent == engaged
        assert schema.is_secret_free(content) is True

    def test_disengaged_records_nothing(self, disengaged: None, tmp_path: Path) -> None:
        _record_calls(25)
        assert call_counters.ensure_registered() is None
        assert call_counters.flush_counters() is False
        assert list(tmp_path.iterdir()) == []

    def test_sealed_registration_blocks_provider_entry_then_releases(self, engaged: Path) -> None:
        durability.seal(engaged, reason="resume-fence-test")
        assert durability.is_sealed(engaged) is True
        with pytest.raises(call_counters.CounterPersistenceError):
            call_counters.record_call("C_Login")
        with pytest.raises(call_counters.CounterPersistenceError):
            call_counters.record_direct_call("C_Login", 0)
        # No registry was created for the rejected producer.
        assert list((engaged / "registrations").glob("*.json")) == []
        # Release: removing the seal admits the producer again.
        durability.unseal(engaged)
        call_counters.record_call("C_Login")
        assert len(list((engaged / "registrations").glob("*.json"))) == 1

    def test_registration_io_failure_is_loud_and_blocks(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _denied(*args: Any, **kwargs: Any) -> Any:
            raise PermissionError("denied")

        monkeypatch.setattr(os, "open", _denied)
        with pytest.raises(call_counters.CounterPersistenceError):
            call_counters.record_call("C_Login")

    def test_counter_persistence_error_lives_on_call_counters(self) -> None:
        assert issubclass(call_counters.CounterPersistenceError, Exception)
        assert call_counters.CounterPersistenceError is durability.CounterPersistenceError

    def test_torn_registry_reads_as_absent(self, engaged: Path) -> None:
        reg_dir = durability.ensure_layout(engaged) / "registrations"
        torn = reg_dir / f"{_UUID_A}.json"
        torn.write_text('{"worker_uuid": "abc', encoding="utf-8")
        assert durability.read_registry_file(torn) is None
        mistyped = reg_dir / f"{_UUID_B}.json"
        mistyped.write_text(json.dumps({"worker_uuid": _UUID_B}), encoding="utf-8")
        assert durability.read_registry_file(mistyped) is None

    def test_fork_child_remints_and_never_reuses_parent_sidecar(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _record_calls(3)
        # K=1: already flushed; the explicit flush is a clean no-op.
        assert call_counters.flush_counters() is False
        info = call_counters.registration_info()
        assert info is not None
        parent_sidecar = Path(info["sidecar_path"])
        assert parent_sidecar.exists()
        parent_uuid = info["worker_uuid"]
        # Simulate a fork: the child pid must re-register with a fresh identity
        # and must never flush into (or overwrite) the parent's sidecar.
        monkeypatch.setattr(os, "getpid", lambda: 424242)
        assert call_counters.flush_counters() is False
        before = parent_sidecar.read_bytes()
        call_counters.record_call("C_ChildCall")
        child_info = call_counters.registration_info()
        assert child_info is not None
        assert child_info["worker_uuid"] != parent_uuid
        assert Path(child_info["sidecar_path"]) != parent_sidecar
        assert parent_sidecar.read_bytes() == before


# --------------------------------------------------------------------------
# Flusher: K cadence + boundary + exit, dirty flag, atomic replace
# --------------------------------------------------------------------------


class TestFlusher:
    def test_k1_flush_cadence_every_record(self, engaged: Path) -> None:
        # K=1 (rc3 Area A): every entry AND every return persists; there is
        # no below-K window anymore. Each step reads the disk, not globals.
        call_counters.record_call("C_Login", module="m")
        info = call_counters.registration_info()
        assert info is not None
        sidecar = Path(info["sidecar_path"])
        assert sidecar.exists()
        first = json.loads(sidecar.read_text(encoding="utf-8"))
        assert first["in_progress"]["total_calls"] == 1
        call_counters.record_return("C_Login", 0, module="m")
        second = json.loads(sidecar.read_text(encoding="utf-8"))
        assert second["in_progress"]["total_calls"] == 1
        assert _sidecar_by_fn(second, "m", "C_Login")["by_rv"]["0"]["count"] == 1
        _record_calls(2)
        third = json.loads(sidecar.read_text(encoding="utf-8"))
        assert third["in_progress"]["total_calls"] == 3

    def test_dirty_flag_skips_clean_flush(self, engaged: Path) -> None:
        # K=1: records auto-flush, so the tree is clean after every record
        # and an explicit flush is a no-op. Dirt only survives a failed
        # flush (see the retain/repair tests); the True arm lives there.
        for _ in range(10):
            call_counters.record_call("C_Login")
        info = call_counters.registration_info()
        assert info is not None
        sidecar = Path(info["sidecar_path"])
        before = sidecar.read_bytes()
        assert call_counters.flush_counters() is False
        assert sidecar.read_bytes() == before
        call_counters.record_call("C_OneMore")
        assert call_counters.flush_counters() is False
        assert sidecar.read_bytes() != before

    def test_boundary_publish_moves_window_to_journal(self, engaged: Path) -> None:
        before = call_counters.take_snapshot()
        _record_calls(3)
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        call_counters.publish_test_window("a.py::test_one", window)
        info = call_counters.registration_info()
        assert info is not None
        journal = Path(info["journal_path"])
        lines = journal.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["nodeid"] == "a.py::test_one"
        assert entry["block"]["total_calls"] == 3
        # No eager clear of the globals: the window is derived, counters stay
        # cumulative, and the next window starts from the new baseline.
        assert call_counters.serialize_current()["total_calls"] == 3
        sidecar = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert sidecar["in_progress"]["total_calls"] == 0
        _record_calls(2)
        call_counters.flush_counters()
        sidecar = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert sidecar["in_progress"]["total_calls"] == 2

    def test_exit_flush_writes_pending_tail(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # K=1: the tail is already current, so the exit flush is a clean
        # no-op — but it still recovers dirt retained by a failed flush.
        _record_calls(3)
        info = call_counters.registration_info()
        assert info is not None
        sidecar = Path(info["sidecar_path"])
        assert json.loads(sidecar.read_text(encoding="utf-8"))["in_progress"]["total_calls"] == 3
        call_counters._exit_flush()
        assert json.loads(sidecar.read_text(encoding="utf-8"))["in_progress"]["total_calls"] == 3
        call_counters.record_call("C_Tail", module="m")
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Tail", 0, module="m")
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        call_counters._exit_flush()
        on_disk = json.loads(sidecar.read_text(encoding="utf-8"))
        assert on_disk["in_progress"]["total_calls"] == 4
        assert _sidecar_by_fn(on_disk, "m", "C_Tail")["by_rv"]["0"]["count"] == 1
        assert call_counters.persistence_pending() is False

    def test_atomic_replace_keeps_old_sidecar_on_failure(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _record_calls(10)
        info = call_counters.registration_info()
        assert info is not None
        sidecar = Path(info["sidecar_path"])
        before = sidecar.read_bytes()

        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise OSError("disk on fire")

        monkeypatch.setattr(os, "replace", _boom)
        # K=1: the record itself attempts the flush, so it raises (rolling
        # the entry back); the old sidecar stays intact, no tmp litter.
        with pytest.raises(call_counters.CounterPersistenceError):
            call_counters.record_call("C_OneMore")
        assert call_counters.serialize_current()["total_calls"] == 10
        assert sidecar.read_bytes() == before
        assert list(engaged.glob("*.tmp-*")) == []

    def test_failed_publish_keeps_window_in_progress(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _record_calls(4)
        before = call_counters.take_snapshot()
        _record_calls(2)
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())

        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise OSError("journal full")

        monkeypatch.setattr(call_counters, "append_journal", _boom)
        with pytest.raises(call_counters.CounterPersistenceError):
            call_counters.publish_test_window("a.py::test_flaky", window)
        # The baseline did not advance: the next publish still covers all 6.
        info = call_counters.registration_info()
        assert info is not None
        assert not Path(info["journal_path"]).exists()
        later = call_counters.take_snapshot()
        full = call_counters.diff_snapshots(before, later)
        assert full["total_calls"] == 2
        assert call_counters.serialize_current()["total_calls"] == 6

    def test_sidecar_journal_payloads_are_secret_free(self, engaged: Path) -> None:
        _record_calls(3, fn="C_SetPIN")
        before = call_counters.take_snapshot()
        _record_calls(7, fn="C_Login")
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        call_counters.publish_test_window("a.py::test_pins", window)
        call_counters.flush_counters()
        info = call_counters.registration_info()
        assert info is not None
        sidecar = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert schema.find_secret_keys(sidecar) == ()
        journal = Path(info["journal_path"]).read_text(encoding="utf-8")
        for line in journal.splitlines():
            assert schema.find_secret_keys(json.loads(line)) == ()


# --------------------------------------------------------------------------
# Atomic ingest transaction (validate -> merge -> receipt -> dirty, one lock)
# --------------------------------------------------------------------------


class _CountingLock:
    """RLock wrapper counting acquisitions (RLock methods are read-only)."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.acquisitions = 0

    def acquire(self, *args: Any, **kwargs: Any) -> Any:
        self.acquisitions += 1
        return self.inner.acquire(*args, **kwargs)

    def release(self) -> Any:
        return self.inner.release()

    def __enter__(self) -> Any:
        self.acquire()
        return self

    def __exit__(self, *args: Any) -> bool:
        self.release()
        return False


class TestIngestTransaction:
    def test_ingest_takes_the_counters_lock_once(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counting = _CountingLock(call_counters._lock)
        monkeypatch.setattr(call_counters, "_lock", counting)
        flat = [["m", "C_Login", 0, 2]]
        call_counters.ingest_child_evidence(flat, 1, [{"worker_uuid": _UUID_A, "probe_seq": 4}])
        assert counting.acquisitions == 1
        assert call_counters.serialize_current()["total_calls"] == 2
        assert call_counters.probes_lost() == 1
        assert call_counters.current_receipts() == [{"worker_uuid": _UUID_A, "probe_seq": 4}]

    def test_ingest_garbage_items_never_poison_valid_channels(self, engaged: Path) -> None:
        flat = [
            ["m", "C_Login", 0, 2],
            ["m", "", 0, 5],
            ["m", "C_Bad", -1, 3],
            "garbage-row",
        ]
        call_counters.ingest_child_evidence(
            flat,
            "not-a-count",  # type: ignore[arg-type]
            [
                {"worker_uuid": _UUID_A, "probe_seq": 1},
                {"worker_uuid": "bogus", "probe_seq": 2},
                {"probe_seq": 3},
            ],
        )
        assert call_counters.serialize_current()["total_calls"] == 2
        assert call_counters.probes_lost() == 0
        assert call_counters.current_receipts() == [{"worker_uuid": _UUID_A, "probe_seq": 1}]

    def test_legacy_ingest_entry_points_stay_single_lock(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counting = _CountingLock(call_counters._lock)
        monkeypatch.setattr(call_counters, "_lock", counting)
        call_counters.ingest_child_counts([["C_Login", 0, 3]])
        assert counting.acquisitions == 1
        counting.acquisitions = 0
        call_counters.add_lost_probes(2)
        assert counting.acquisitions == 1
        assert call_counters.serialize_current()["total_calls"] == 3
        assert call_counters.probes_lost() == 2


# --------------------------------------------------------------------------
# Probe channel: seqno receipts, sidecar fallback, flush-then-delete
# --------------------------------------------------------------------------


def _coverage_payload(
    counters: Any, *, receipt: dict[str, Any] | None = None, receipts: Any = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "call_log": {},
        "mechanism_counts": {},
        "call_log_ok": {},
        "mechanism_rv_counts": {},
        "probes_lost": 0,
    }
    if counters is not None:
        payload["call_counters"] = counters
    if receipt is not None:
        payload["receipt"] = receipt
    if receipts is not None:
        payload["receipts"] = receipts
    return payload


class TestProbeChannel:
    def test_seq_numbers_are_process_unique(self, engaged: Path) -> None:
        first = call_counters.assign_probe_seq()
        second = call_counters.assign_probe_seq()
        assert (first, second) == (0, 1)

    def test_coverage_with_valid_receipt_folds_and_records(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / "probe-0.json"
        sidecar.write_text(json.dumps({"stale": True}), encoding="utf-8")
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert call_counters.serialize_current()["total_calls"] == 4
        assert call_counters.current_receipts() == [{"worker_uuid": _UUID_A, "probe_seq": seq}]
        assert not sidecar.exists(), "flush-then-delete: sidecar goes after commit"

    def test_coverage_without_receipt_folds_legacy(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text(json.dumps(_coverage_payload([["C_Login", 0, 3]])), encoding="utf-8")
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=None) == "folded"
        assert call_counters.serialize_current()["total_calls"] == 3
        assert call_counters.current_receipts() == []

    def test_coverage_with_wrong_seq_rejects_counts(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq + 99},
                )
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=None) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert call_counters.current_receipts() == []

    def test_torn_coverage_falls_back_to_probe_sidecar_partial(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-1.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Login", 0, 6]],
                }
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "partial"
        assert call_counters.serialize_current()["total_calls"] == 6
        # Partial evidence never earns a folded receipt: the receipt is
        # suppressed, and the caller flags the loss via note_lost_probe.
        assert call_counters.current_receipts() == []
        assert not sidecar.exists()

    def test_fallback_replays_probe_tmp_return(self, engaged: Path, tmp_path: Path) -> None:
        """#88R3F1: the live fallback replays a complete probe tmp.

        The child is reaped before ingest (quiescent by construction),
        so its orphan tmp replays returns-only onto the sidecar rows;
        both files go only after the parent checkpoint succeeds.
        """
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-1.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", None, 1]],
                }
            ),
            encoding="utf-8",
        )
        tmp = tmp_path / "probe-1.json.tmp-999"
        tmp.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                }
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "partial"
        block = call_counters.serialize_current()
        assert block["total_calls"] == 1
        leaves = [
            bucket["by_fn"]["C_Digest"]
            for bucket in block["by_module"]["m"]["buckets"].values()
            if "C_Digest" in bucket["by_fn"]
        ]
        assert len(leaves) == 1
        assert leaves[0]["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaves[0]
        assert not sidecar.exists()
        assert not tmp.exists()

    def test_lost_branch_retains_baseless_complete_tmp(self, engaged: Path, tmp_path: Path) -> None:
        """#88R3F1: no baseline keeps a complete tmp for forensics."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-9.json"
        tmp = _plant_probe_tmp(sidecar, _probe_tmp_payload(_UUID_B, seq, [["m", "C_Digest", 0, 1]]))
        with pytest.warns(UserWarning, match="retained"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert tmp.exists()

    def test_fallback_foreign_parent_is_lost_and_retained(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R7-3: live ingest never absorbs a foreign-parent sidecar."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-11.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": "f" * 32,
                    "run_id": "R-foreign",
                    "unit": "b.py",
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="contradict"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert sidecar.exists()

    def test_fallback_foreign_run_is_lost_and_retained(self, engaged: Path, tmp_path: Path) -> None:
        """#88R7-3: live ingest never absorbs a foreign-run sidecar."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        parent = call_counters.get_worker_uuid()
        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-12.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": parent,
                    "run_id": "R-foreign",
                    "unit": "a.py",
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="contradict"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert sidecar.exists()

    def test_mark_probe_consumed_rejects_param_content_clash(self, tmp_path: Path) -> None:
        """#88R7-3: a marker never names one parent with another's body."""
        from pkcs11_check.core._counters_durability import CounterPersistenceError

        pid, birth = _dead_pid_with_birth()
        sidecar = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=3,
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        with pytest.raises(CounterPersistenceError, match="contradict"):
            durability.mark_probe_consumed(sidecar, parent_uuid="f" * 32)
        assert sidecar.exists()

    def test_commit_foreign_sidecar_retained_on_coverage_path(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R8-3: the folded path never marks a foreign body as consumed."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / "probe-13.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": "f" * 32,
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        real_unlink = os.unlink

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _failing_unlink)
        with pytest.warns(UserWarning, match="contradict"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert call_counters.serialize_current()["total_calls"] == 4
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_commit_unreadable_sidecar_retained_on_coverage_path(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R8-3: an unreadable commit body is retained, never renamed blind."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / "probe-14.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        real_unlink = os.unlink
        real_open = open

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        def _eperm_sidecar(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(sidecar):
                raise OSError("injected sidecar EPERM")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _failing_unlink)
        monkeypatch.setattr("builtins.open", _eperm_sidecar)
        with pytest.warns(UserWarning, match="unreadable"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_commit_mismatched_child_retained_on_coverage_path(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R9-3: a sidecar stamped for another child is never marked."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        parent = call_counters.get_worker_uuid()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": parent,
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        real_unlink = os.unlink

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _failing_unlink)
        with pytest.warns(UserWarning, match="contradict"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_commit_unstamped_counters_retained_under_receipt(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R9-3: evidence-shaped but unstamped bodies stay for adjudication."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        real_unlink = os.unlink

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _failing_unlink)
        with pytest.warns(UserWarning, match="receipt|unstamped|attribut"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_commit_loss_only_body_retained_under_receipt(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R10-3: a loss-only body is evidence, not payload-free."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"counters": [], "probes_lost": 1}),
            encoding="utf-8",
        )
        rewrite = sidecar.with_name(f"{sidecar.name}.tmp-4242")
        rewrite.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="evidence but no receipt"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert rewrite.exists(), "retiring the body must not co-delete its rewrite"
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_subsumed_lossless_retires(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4a: exit coverage proved to subsume a stamped body retires it."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                }
            ),
            encoding="utf-8",
        )
        rewrite = sidecar.with_name(f"{sidecar.name}.tmp-4242")
        rewrite.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1], ["m", "C_Login", 0, 4]])),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert call_counters.serialize_current()["total_calls"] == 5
        assert not sidecar.exists()
        assert not rewrite.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    @pytest.mark.parametrize("covered", [True, False])
    def test_legacy_subsumed_keyed_retires_and_absorbs(
        self, engaged: Path, tmp_path: Path, covered: bool
    ) -> None:
        """#88R10-4a: subsumed keyed losses absorb with the coverage (union)."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        key = {"parent_uuid": "c" * 32, "probe_seq": 7}
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "lost_keys": [key],
                }
            ),
            encoding="utf-8",
        )
        cov_payload = _coverage_payload([["m", "C_Digest", 0, 1]])
        if covered:
            cov_payload["lost_keys"] = [key]
        cov = tmp_path / "cov.json"
        cov.write_text(json.dumps(cov_payload), encoding="utf-8")
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert not sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []
        on_disk = _read_sidecar()
        assert key in on_disk.get("lost_keys", [])

    def test_legacy_scalar_body_retained(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4a: a subsumed-shaped body with an unkeyed scalar retains."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "probes_lost": 1,
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="may double-count the overlap"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_nonsubset_retained(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4a: a stamped body the exit coverage does not subsume retains."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 5]],
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="may double-count the overlap"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_seq_mismatch_retained_quietly(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4a: a stamped body for another probe retains (no overlap)."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq + 100,
                    "counters": [["m", "C_Digest", 0, 1]],
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning) as record:
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert any("legacy-quiet coverage" in str(w.message) for w in record.list)
        assert not any("double-count" in str(w.message) for w in record.list)
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_malformed_keys_retained(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4a: stated-but-unparseable loss keys fail closed."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "lost_keys": "garbage",
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="may double-count the overlap"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_swap_between_absorb_and_commit_retained(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R10-4a: the commit re-proves subsumption against a fresh read."""
        import pkcs11_check.testcases._probes.runner as runner_mod
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        first = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [["m", "C_Digest", 0, 1]],
        }
        swapped = {
            "worker_uuid": "c" * 32,
            "probe_seq": seq,
            "counters": [["m", "C_Digest", 0, 9]],
        }
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(json.dumps(first), encoding="utf-8")
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        real_read = runner_mod._read_probe_json
        state = {"sidecar_reads": 0}

        def _swapping_read(path: Any) -> Any:
            if str(path) == str(sidecar):
                state["sidecar_reads"] += 1
                if state["sidecar_reads"] > 1:
                    return dict(swapped)
            return real_read(path)

        monkeypatch.setattr(runner_mod, "_read_probe_json", _swapping_read)
        with pytest.warns(UserWarning, match="may double-count the overlap"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_foreign_body_keys_not_absorbed(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4a: a clashing body contributes no keys to the ingest."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        parent = call_counters.get_worker_uuid()
        seq = call_counters.assign_probe_seq()
        key = {"parent_uuid": "c" * 32, "probe_seq": 7}
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "lost_keys": [key],
                    "parent_uuid": "d" * 32,
                }
            ),
            encoding="utf-8",
        )
        assert parent != "d" * 32
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="contradicts the launcher"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []
        on_disk = _read_sidecar()
        assert key not in on_disk.get("lost_keys", [])

    def test_commit_stated_empty_mismatch_retained_with_tmp(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R11-3: a stated receipt validates even on a payload-free body."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"worker_uuid": "c" * 32, "probe_seq": seq, "counters": []}),
            encoding="utf-8",
        )
        rewrite = sidecar.with_name(f"{sidecar.name}.tmp-4242")
        rewrite.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="contradicts the absorbed receipt"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert rewrite.exists(), "a foreign rewrite never deletes unvalidated"
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_commit_stated_empty_match_proceeds(self, engaged: Path, tmp_path: Path) -> None:
        """#88R11-3: a matching receipt on debris still retires (R3 subsumed)."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"worker_uuid": _UUID_B, "probe_seq": seq, "counters": []}),
            encoding="utf-8",
        )
        rewrite = sidecar.with_name(f"{sidecar.name}.tmp-4242")
        rewrite.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_B, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert not sidecar.exists()
        assert not rewrite.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_stated_empty_mismatch_retained(self, engaged: Path, tmp_path: Path) -> None:
        """#88R11-3: legacy-quiet mismatch retains a stated empty body + tmp."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"worker_uuid": _UUID_B, "probe_seq": seq + 9, "counters": []}),
            encoding="utf-8",
        )
        rewrite = sidecar.with_name(f"{sidecar.name}.tmp-4242")
        rewrite.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="legacy-quiet coverage"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert rewrite.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_stated_empty_match_retires(self, engaged: Path, tmp_path: Path) -> None:
        """#88R11-3: a seq-matching empty body retires by vacuous subsumption."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"worker_uuid": _UUID_B, "probe_seq": seq, "counters": []}),
            encoding="utf-8",
        )
        rewrite = sidecar.with_name(f"{sidecar.name}.tmp-4242")
        rewrite.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert not sidecar.exists()
        assert not rewrite.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_keys_growth_between_absorb_and_commit_retained(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R11-4: a key that landed after absorb is never retired."""
        import pkcs11_check.testcases._probes.runner as runner_mod
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        key1 = {"parent_uuid": "c" * 32, "probe_seq": 7}
        key2 = {"parent_uuid": "d" * 32, "probe_seq": 8}
        first = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [],
            "lost_keys": [key1],
        }
        swapped = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [],
            "lost_keys": [key1, key2],
        }
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(json.dumps(first), encoding="utf-8")
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        real_read = runner_mod._read_probe_json
        state = {"sidecar_reads": 0}

        def _swapping_read(path: Any) -> Any:
            if str(path) == str(sidecar):
                state["sidecar_reads"] += 1
                if state["sidecar_reads"] > 1:
                    return dict(swapped)
            return real_read(path)

        monkeypatch.setattr(runner_mod, "_read_probe_json", _swapping_read)
        with pytest.warns(UserWarning, match="may double-count the overlap"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_legacy_child_swap_between_absorb_and_commit_retained(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R12-2: same rows from another child is another execution."""
        import pkcs11_check.testcases._probes.runner as runner_mod
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        key1 = {"parent_uuid": "c" * 32, "probe_seq": 7}
        rows = [["m", "C_Digest", 0, 1]]
        first = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [list(row) for row in rows],
            "lost_keys": [key1],
        }
        swapped = {
            "worker_uuid": "e" * 32,
            "probe_seq": seq,
            "counters": [list(row) for row in rows],
            "lost_keys": [key1],
        }
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(json.dumps(first), encoding="utf-8")
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        real_read = runner_mod._read_probe_json
        state = {"sidecar_reads": 0}

        def _swapping_read(path: Any) -> Any:
            if str(path) == str(sidecar):
                state["sidecar_reads"] += 1
                if state["sidecar_reads"] > 1:
                    return dict(swapped)
            return real_read(path)

        monkeypatch.setattr(runner_mod, "_read_probe_json", _swapping_read)
        with pytest.warns(UserWarning, match="may double-count the overlap"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []
        on_disk = _read_sidecar()
        assert {"worker_uuid": _UUID_B, "probe_seq": seq} in on_disk.get("consumed_probes", [])

    def test_legacy_keys_shrinkage_retires_absorbed_superset(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R11-4: a commit key set within the absorbed set retires."""
        import pkcs11_check.testcases._probes.runner as runner_mod
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        key1 = {"parent_uuid": "c" * 32, "probe_seq": 7}
        key2 = {"parent_uuid": "d" * 32, "probe_seq": 8}
        first = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [],
            "lost_keys": [key1, key2],
        }
        swapped = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [],
            "lost_keys": [key1],
        }
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(json.dumps(first), encoding="utf-8")
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        real_read = runner_mod._read_probe_json
        state = {"sidecar_reads": 0}

        def _swapping_read(path: Any) -> Any:
            if str(path) == str(sidecar):
                state["sidecar_reads"] += 1
                if state["sidecar_reads"] > 1:
                    return dict(swapped)
            return real_read(path)

        monkeypatch.setattr(runner_mod, "_read_probe_json", _swapping_read)
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert not sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []
        on_disk = _read_sidecar()
        assert key1 in on_disk.get("lost_keys", [])
        assert key2 in on_disk.get("lost_keys", [])

    def test_legacy_proved_absorb_records_consumed_receipt(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R11-4: a proved legacy absorption rides a consumed receipt."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert not sidecar.exists()
        on_disk = _read_sidecar()
        assert {"worker_uuid": _UUID_B, "probe_seq": seq} in on_disk.get("consumed_probes", [])

    def test_legacy_double_fault_no_double_fold(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R11-4: delete+mark failure still suppresses via consumed receipt."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        seq = call_counters.assign_probe_seq()
        sidecar = engaged / f"probe-{call_counters.get_worker_uuid()[:8]}-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", 0, 1]],
                }
            ),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Digest", 0, 1]])),
            encoding="utf-8",
        )
        real_unlink = os.unlink
        real_replace = os.replace

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        def _failing_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            if str(src).endswith(sidecar.name):
                raise PermissionError("injected replace EPERM")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _failing_unlink)
        monkeypatch.setattr(os, "replace", _failing_replace)
        with pytest.raises(durability.CounterPersistenceError):
            ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar)
        assert sidecar.exists()
        monkeypatch.setattr(os, "unlink", real_unlink)
        monkeypatch.setattr(os, "replace", real_replace)
        pid, birth = _dead_pid_with_birth()
        registries = list((engaged / "registrations").glob("*.json"))
        assert len(registries) == 1
        content = json.loads(registries[0].read_text(encoding="utf-8"))
        content["pid"] = pid
        content["birth_token"] = birth
        registries[0].write_text(json.dumps(content), encoding="utf-8")
        call_counters.reset_for_tests()
        records = _collect_crashed88(engaged, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 1, "consumed receipt suppresses the copy"
        assert not sidecar.exists()

    def test_covered_orphan_unions_its_keys(self, engaged: Path, tmp_path: Path) -> None:
        """#88R11-4: suppression still adopts a covered orphan's keyed losses."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, fn="C_Login"),
            receipts=[{"worker_uuid": _UUID_B, "probe_seq": 0}],
        )
        new_key = {"parent_uuid": "c" * 32, "probe_seq": 7}
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            lost_keys=[new_key],
            pid=pid,
            birth=birth,
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(5, fn="C_Login"),
                    extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert new_key in partials[0].get("orphan_keys", [])
        assert not orphan.exists(), "counts suppress; keys adopt"

    def test_commit_legacy_silence_still_marks(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R9-3: legacy-quiet coverage still retires its legacy sidecar."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-aaaaaaaa-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps({"counters": [["m", "C_Digest", 0, 1]]}),
            encoding="utf-8",
        )
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(_coverage_payload([["m", "C_Login", 0, 4]])),
            encoding="utf-8",
        )
        real_unlink = os.unlink

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _failing_unlink)
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "folded"
        assert not sidecar.exists()
        assert len(list(tmp_path.glob("probe-consumed-*.json"))) == 1

    def test_commit_reread_swap_retained(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R9-3: a sidecar swapped between ingest and commit is retained."""
        import pkcs11_check.testcases._probes.runner as runner_mod
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        call_counters.ensure_registered()
        parent = call_counters.get_worker_uuid()
        seq = call_counters.assign_probe_seq()
        sidecar = tmp_path / f"probe-bbbbbbbb-{seq}-feedface.json"
        first = {
            "worker_uuid": _UUID_B,
            "probe_seq": seq,
            "counters": [["m", "C_Digest", 0, 1]],
            "parent_uuid": parent,
        }
        swapped = {
            "worker_uuid": "c" * 32,
            "probe_seq": seq,
            "counters": [["m", "C_Digest", 0, 1]],
            "parent_uuid": parent,
        }
        sidecar.write_text(json.dumps(first), encoding="utf-8")
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        real_read = runner_mod._read_probe_json
        state = {"sidecar_reads": 0}

        def _swapping_read(path: Any) -> Any:
            if str(path) == str(sidecar):
                state["sidecar_reads"] += 1
                if state["sidecar_reads"] > 1:
                    return dict(swapped)
            return real_read(path)

        real_unlink = os.unlink

        def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).endswith(sidecar.name):
                raise PermissionError("injected unlink EPERM")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(runner_mod, "_read_probe_json", _swapping_read)
        monkeypatch.setattr(os, "unlink", _failing_unlink)
        with pytest.warns(UserWarning, match="contradict"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "partial"
        assert call_counters.serialize_current()["total_calls"] == 1
        assert sidecar.exists()
        assert list(tmp_path.glob("probe-consumed-*.json")) == []

    def test_fallback_unreadable_tmp_is_lost_and_retained(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R4-F1a: an unreadable live tmp retains all for file retry."""
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-10.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Digest", None, 1]],
                }
            ),
            encoding="utf-8",
        )
        tmp = _plant_probe_tmp(sidecar, _probe_tmp_payload(_UUID_B, seq, [["m", "C_Digest", 0, 1]]))
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes

        def _eperm_tmp(self: Path, *args: Any, **kwargs: Any) -> str:
            if self.name == tmp.name:
                raise PermissionError("injected tmp EPERM")
            return real_read_text(self, *args, **kwargs)

        def _eperm_tmp_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if self.name == tmp.name:
                raise PermissionError("injected tmp EPERM")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _eperm_tmp)
        monkeypatch.setattr(Path, "read_bytes", _eperm_tmp_bytes)
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert sidecar.exists()
        assert tmp.exists()

    def test_probe_sidecar_with_wrong_seq_retained_for_collection(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # #88R11-3 overturns the batch-1 pin (wrong-seq deleted): a
        # stated-but-mismatched body is attributable evidence under
        # its own identity, so the fallback retains it loudly and
        # file collection folds it exactly.
        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        sidecar = engaged / f"probe-{_UUID_A[:8]}-{seq}-feedface.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq + 7,
                    "counters": [["m", "C_Login", 0, 6]],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="unabsorbed at fallback"):
            assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert sidecar.exists()
        records = _collect_crashed88(engaged, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 11, "5 parent + 6 folded orphan"

    def test_torn_bytes_sidecar_is_deleted(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Batch-1 review minor: unparseable bytes on the sidecar arm
        # are a definitive miss (deleted), unlike unreadable files
        # (retained) -- completing the tri-state matrix.
        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-torn.json"
        sidecar.write_bytes(b"\x00\x01{not json")
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert not sidecar.exists()

    def test_unreadable_sidecar_is_retained_for_retry(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Codex 6.2 F4: a read failure is not a definitive miss -- a
        # transient OSError must retain the sidecar for collection to
        # retry, instead of deleting possibly recoverable evidence.
        # (Parsed-invalid files are still deleted -- see above. A
        # directory would also fail the delete, so the transient fault
        # is injected on open for the sidecar path only; the delete
        # itself runs the real unlink.)
        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-unreadable.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Login", 0, 4]],
                }
            ),
            encoding="utf-8",
        )
        real_open = open

        def _flaky_open(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(sidecar):
                raise OSError("transient read failure")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _flaky_open)
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert sidecar.exists(), "unreadable evidence is retained, not deleted"

    def test_retained_unreadable_orphan_adopts_on_retry(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Codex R2: the retained sidecar is adopted once readable --
        # a single transient read failure costs nothing at ingest
        # level (the run_probe caller would note the live keyed loss);
        # collection folds the evidence exactly once.
        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        engaged.mkdir(parents=True, exist_ok=True)
        sidecar = engaged / "probe-flaky.json"
        sidecar.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Login", 0, 4]],
                }
            ),
            encoding="utf-8",
        )
        real_open = open
        attempts: list[str] = []

        def _flaky_once(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(sidecar) and not attempts:
                attempts.append("read")
                raise OSError("transient read failure")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _flaky_once)
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert attempts == ["read"]
        assert sidecar.exists()
        call_counters.ensure_registered()
        call_counters.record_call("C_Login", module="m")
        live_uuid = call_counters.get_worker_uuid()
        sidecar.rename(sidecar.with_name(f"probe-{live_uuid[:8]}-{seq}-feedface.json"))
        dead_pid, dead_birth = _dead_pid_with_birth()
        reg_files = list((engaged / "registrations").glob("*.json"))
        assert len(reg_files) == 1
        reg_content = json.loads(reg_files[0].read_text(encoding="utf-8"))
        reg_content["pid"] = dead_pid
        reg_content["birth_token"] = dead_birth if dead_birth is not None else 0
        reg_files[0].write_text(json.dumps(reg_content), encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 5, "own call 1 + adopted orphan 4"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5

    def test_grandchild_receipts_propagate_recursively(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 1]],
                    receipt={"worker_uuid": _UUID_A, "probe_seq": seq},
                    receipts=[
                        {"worker_uuid": _UUID_A, "probe_seq": seq},
                        {"worker_uuid": _UUID_B, "probe_seq": 9},
                        {"worker_uuid": "bogus", "probe_seq": 1},
                    ],
                )
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=None) == "folded"
        assert call_counters.current_receipts() == [
            {"worker_uuid": _UUID_A, "probe_seq": seq},
            {"worker_uuid": _UUID_B, "probe_seq": 9},
        ]


# --------------------------------------------------------------------------
# Extractor: partial/lost fold, keyed staging, precedence, scope rebase
# --------------------------------------------------------------------------


class TestExtractorDurability:
    def test_partial_without_pid_folds_counts_but_names_no_row(self, tmp_path: Path) -> None:
        record = _partial_record()
        del record["pid"]
        assert schema.is_sidecar_partial(record) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), record],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["by_process"] == []
        assert list(payload["by_round"]) == [_RUN]

    def test_malformed_partial_and_lost_are_ignored(self, tmp_path: Path) -> None:
        bad_partial = _partial_record(total_calls=999)
        assert schema.is_sidecar_partial(bad_partial) is False
        bad_lost = _lost_record(worker_uuid="not-a-uuid")
        del bad_lost["pid"]
        assert schema.is_lost_record(bad_lost) is False
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                bad_partial,
                bad_lost,
                _session_record(100, _counts_block(10), extra={"run_id": _RUN}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is True
        assert "lost_processes" not in payload

    def test_authoritative_supersedes_partial_with_receipt_union(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "receipts": [
                    {"worker_uuid": _UUID_A, "probe_seq": 1},
                    {"worker_uuid": _UUID_A, "probe_seq": 2},
                ],
            },
        )
        assert schema.is_session_record(session) is True
        partial = _partial_record(
            receipts=[
                {"worker_uuid": _UUID_A, "probe_seq": 2},
                {"worker_uuid": _UUID_A, "probe_seq": 3},
            ]
        )
        assert schema.is_sidecar_partial(partial) is True
        # Both input orders in ONE scope (the real crash-replay shape: a
        # parent crash between commit and consume re-collects the sidecar
        # into the session's own scope): the authoritative session wins.
        # Folded rows follow inclusion, not staging: the superseded
        # partial's receipt 3 earns no row (its counts died to
        # supersede); the session's own 1 and 2 still do (codex R2-F2).
        for records in (
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                partial,
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                partial,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        ):
            jsonl = _write_jsonl(tmp_path / "report.jsonl", records)
            payload = extract_call_counters_from_jsonl(jsonl)
            assert payload is not None
            assert payload["total_calls"] == 10
            assert payload["complete"] is True
            assert payload["probes_detail"] == [
                {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "folded"},
                {"worker_uuid": _UUID_A, "probe_seq": 2, "status": "folded"},
            ]
            assert payload["by_round"][_RUN]["probes_detail"] == payload["probes_detail"]

    def test_staged_partial_covers_its_segment(self, tmp_path: Path) -> None:
        # No TestReports at all: the staged partial is consulted (its group
        # covers the marked segment positionally), so the segment reads as a
        # truncated partial group rather than a C2b empty group. Content-based
        # C2b interplay (decoys, reordered streams) is Task 5's scope.
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), _partial_record()],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert list(payload["by_round"]) == [_RUN]
        assert payload["by_round"][_RUN]["total_calls"] == 5
        assert payload["by_round"][_RUN]["complete"] is False

    def test_conflicting_terminals_become_conflict(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(),
                _lost_record(end_state="timeout"),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["complete"] is False
        assert payload["lost_processes"] == [
            {
                "worker_uuid": _UUID_A,
                "pid": 100,
                "end_state": "conflict",
                "scope_index": 1,
                "run_id": _RUN,
                "unit": "a.py",
                "attempt": 0,
            }
        ]

    def test_duplicate_partials_fold_first_wins(self, tmp_path: Path) -> None:
        # A crash between collection append and consume re-collects the same
        # partial: extractor first-wins keeps it counted exactly once.
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _partial_record(),
                _partial_record(),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "unknown",
                "total_calls": 5,
                "complete": False,
                "worker_uuid": _UUID_A,
                "truncated": True,
            }
        ]

    def test_duplicate_terminals_deduplicate(self, tmp_path: Path) -> None:
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
        assert len(payload["lost_processes"]) == 1
        assert payload["lost_processes"][0]["end_state"] == "crashed"

    def test_scope_index_rebased_at_assembly(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(scope_index=99),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["lost_processes"][0]["scope_index"] == 1

    def test_lost_without_run_id_lands_in_implicit_round(self, tmp_path: Path) -> None:
        record = _lost_record()
        del record["run_id"]
        assert schema.is_lost_record(record) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), record],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["complete"] is False
        assert list(payload["by_round"]) == [""]
        assert "run_id" not in payload["lost_processes"][0]
        assert payload["by_round"][""]["lost_processes"] == payload["lost_processes"]


# --------------------------------------------------------------------------
# Parent-side collection: gap computation, delete-after-commit, adoption
# --------------------------------------------------------------------------


def _plant_producer(
    root: Path,
    *,
    uuid: str,
    unit: str = "a.py",
    attempt: int = 0,
    pid: int,
    birth: int | None,
    run_id: str = _RUN,
    role: str = "unit",
    in_progress: dict[str, Any] | None = None,
    journal: list[dict[str, Any]] | None = None,
    journal_seq: int | None = -1,
    receipts: list[dict[str, Any]] | None = None,
    probes_lost: Any = None,
    isolation: str | None = "file",
    lost_keys: list[dict[str, Any]] | None = None,
) -> dict[str, Path]:
    """Plant registry + sidecar + journal files for a (possibly dead) producer.

    ``journal_seq`` defaults to ``len(journal)`` (a cleanly flushed producer);
    pass ``None`` to omit it from the sidecar (an ambiguity the collector
    reads as conflict when the journal is non-empty, folding the snapshot
    only). ``receipts`` seeds the sidecar's folded-probe receipt list (a
    parent that flushed after ingesting probes). ``probes_lost`` seeds the
    sidecar's loss scalar (omitted when None; pass garbage to plant a
    mistyped scalar). ``isolation`` seeds the registry isolation stamp
    (pass None to plant a legacy isolation-less registry). ``lost_keys``
    seeds the sidecar's keyed-loss set (omitted when None).
    """
    reg_dir = root / "registrations"
    reg_dir.mkdir(parents=True, exist_ok=True)
    sidecar = root / f"{uuid}-nonce1.partial.json"
    journal_path = root / f"{uuid}-nonce1.windows.jsonl"
    content = {
        "worker_uuid": uuid,
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "pid": pid,
        "role": role,
        "timestamp": 1234.5,
        "sidecar": str(sidecar),
        # Birth 0 mirrors real registration on unverifiable platforms
        # (birth_token_for_pid() is None there): the registry stays valid.
        "birth_token": birth if birth is not None else 0,
    }
    if isolation is not None:
        content["isolation"] = isolation
    (reg_dir / f"{uuid}.json").write_text(json.dumps(content), encoding="utf-8")
    if in_progress is not None:
        sidecar_content: dict[str, Any] = {
            "worker_uuid": uuid,
            "run_id": run_id,
            "unit": unit,
            "attempt": attempt,
            "pid": pid,
            "in_progress": in_progress,
            "receipts": list(receipts) if receipts else [],
        }
        seq = len(journal or []) if journal_seq == -1 else journal_seq
        if seq is not None:
            sidecar_content["journal_seq"] = seq
        if probes_lost is not None:
            sidecar_content["probes_lost"] = probes_lost
        if lost_keys is not None:
            sidecar_content["lost_keys"] = lost_keys
        sidecar.write_text(json.dumps(sidecar_content), encoding="utf-8")
    if journal:
        journal_path.write_text(
            "".join(json.dumps(line) + "\n" for line in journal), encoding="utf-8"
        )
    return {"registry": reg_dir / f"{uuid}.json", "sidecar": sidecar, "journal": journal_path}


def _plant_probe_orphan(
    root: Path,
    *,
    parent_uuid: str,
    seq: int,
    child_uuid: str = _UUID_B,
    counters: list[list[Any]] | None = None,
    nonce: str = "feedface",
    lost_keys: list[dict[str, Any]] | None = None,
    identity: dict[str, Any] | None = None,
    probes_lost: Any = None,
    pid: int | None = None,
    birth: int | None = None,
) -> Path:
    """Plant a retained probe sidecar ``probe-<parent8>-<seq>-<nonce>.json``.

    Mirrors the runner's filename (parent uuid prefix, assigned seqno) and
    the child's payload (child uuid, echoed seqno, flat counter rows, and
    the child's own keyed-loss set when given). ``identity`` seeds the F2
    self-describing block (parent_uuid/run_id/unit/attempt/role/isolation);
    omitted entirely for legacy shape (filename carries the only identity).
    ``probes_lost`` seeds the child's unkeyed-loss scalar when given
    (pass garbage to plant a mistyped scalar).
    """
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"probe-{parent_uuid[:8]}-{seq}-{nonce}.json"
    payload: dict[str, Any] = {
        "worker_uuid": child_uuid,
        "probe_seq": seq,
        "counters": counters if counters is not None else [["m", "C_Login", 0, 4]],
    }
    if lost_keys is not None:
        payload["lost_keys"] = lost_keys
    if probes_lost is not None:
        payload["probes_lost"] = probes_lost
    if identity is not None:
        payload.update(identity)
    if pid is not None:
        payload["pid"] = pid
    if birth is not None:
        payload["birth_token"] = birth
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _f2_identity(
    parent: str, run_id: str = _RUN, unit: str = "a.py", attempt: int = 0
) -> dict[str, Any]:
    """Full F2 self-describing block for a planted orphan."""
    return {
        "parent_uuid": parent,
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "role": "unit",
        "isolation": "file",
    }


def _dead_pid_with_birth() -> tuple[int, int | None]:
    """Spawn a short-lived child; return its (pid, birth) for planting."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid = proc.pid
    birth = durability.birth_token_for_pid(pid)
    proc.wait(timeout=30)
    assert proc.poll() is not None
    return pid, birth


class TestCollection:
    def test_killed_before_first_delta_yields_partial_plus_lost(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        partial, lost = records
        assert schema.is_sidecar_partial(partial) is True
        assert schema.is_lost_record(lost) is True
        assert partial["total_calls"] == 5
        assert lost["end_state"] == "killed"
        assert lost["worker_uuid"] == _UUID_A
        assert lost["scope_index"] == 0, "placeholder: the extractor rebases at assembly"
        # Consumed exactly once: a second collection appends nothing.
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
            == []
        )
        assert not planted["registry"].exists()
        assert not planted["sidecar"].exists()
        # End to end: the recovered counts fold exactly once, incomplete.
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["lost_processes"][0]["scope_index"] == 1
        assert payload["lost_processes"][0]["end_state"] == "killed"

    def test_collection_subtracts_jsonl_committed_windows(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        journal = [
            {"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []},
            {
                "nodeid": "a.py::t2",
                "block": _counts_block(4, fn="C_Other"),
                "receipts": [],
            },
        ]
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
            journal=journal,
        )
        # t1's entry committed to the child JSONL; t2's report never made it
        # (death between journal publish and reportlog write).
        entry = _test_entry(pid, _counts_block(3), extra={"worker_uuid": _UUID_A, "run_id": _RUN})
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 6, "t2 (4) + tail (2); t1 excluded"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9, "entry 3 + gap 6, counted exactly once"
        assert payload["complete"] is False

    def test_collection_skips_live_producer(self, engaged: Path, tmp_path: Path) -> None:
        birth = durability.birth_token_for_pid(os.getpid())
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=os.getpid(),
            birth=birth,
            in_progress=_counts_block(5),
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
            == []
        )
        assert planted["registry"].exists()
        assert planted["sidecar"].exists()

    def test_delete_after_commit_for_lived_producer(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(7),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []}],
        )
        session = _session_record(
            pid, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            == []
        )
        assert not planted["registry"].exists()
        assert not planted["sidecar"].exists()
        assert not planted["journal"].exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is True

    def test_corrupt_sidecar_reads_as_absent_with_lost(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        planted["sidecar"].write_text('{"in_progress": ', encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert [rec["$report_type"] for rec in records] == ["CallCountersLost"]
        assert records[0]["end_state"] == "crashed"
        assert not planted["registry"].exists()
        assert not planted["sidecar"].exists()

    def test_torn_registry_with_sidecar_adopts_sidecar_identity(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        planted["registry"].write_text('{"worker_uuid": "torn', encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged,
            unit="a.py",
            child_jsonl=child,
            status="timeout",
            returncode=124,
            timed_out=True,
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[1]["worker_uuid"] == _UUID_A
        assert records[1]["end_state"] == "timeout"
        assert not planted["registry"].exists()
        assert not planted["sidecar"].exists()

    def test_torn_registry_without_sidecar_is_zero_loss_absent(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        reg_dir = engaged / "registrations"
        reg_dir.mkdir(parents=True, exist_ok=True)
        torn = reg_dir / f"{_UUID_A}.json"
        torn.write_text('{"worker_uuid": "torn', encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
            == []
        )
        assert not torn.exists()

    def test_end_state_mapping(self) -> None:
        cases = [
            ({"status": "timeout", "returncode": 124, "timed_out": True}, "timeout"),
            ({"status": "crashed", "returncode": -9, "timed_out": False}, "killed"),
            ({"status": "crashed", "returncode": -11, "timed_out": False}, "crashed"),
            ({"status": "crashed", "returncode": 3, "timed_out": False}, "crashed"),
            ({"status": "failed", "returncode": 1, "timed_out": False}, "unknown"),
            ({"status": "passed", "returncode": 0, "timed_out": False}, "unknown"),
        ]
        for kwargs, expected in cases:
            assert durability.end_state_for_attempt(**kwargs) == expected

    def test_missing_seq_folds_snapshot_only_plus_conflict(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        # A non-empty journal with no journal_seq cannot disambiguate
        # journaled-vs-in-progress overlap: fold the snapshot only (the one
        # exact piece), skip every uncommitted journal window, and mark the
        # producer conflict — recovered, never double-counted, never silent.
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(9), "receipts": []}],
            journal_seq=None,
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 2
        assert records[1]["end_state"] == "conflict"

    def test_torn_journal_tail_is_benign(self, engaged: Path, tmp_path: Path) -> None:
        # A torn TAIL is the crash-mid-append shape: the unpublished window's
        # calls are still in in_progress, so dropping the tail loses nothing.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []}],
        )
        with planted["journal"].open("a", encoding="utf-8") as fh:
            fh.write('{"nodeid": "a.py::t2", "block": ')
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 5
        assert records[1]["end_state"] == "crashed"

    def test_garbage_journal_middle_yields_partial_plus_conflict(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # A torn MIDDLE line cannot come from crash-mid-append (append-only):
        # valid pieces still fold, but the corruption reads as conflict, loud.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []}],
        )
        t2 = {"nodeid": "a.py::t2", "block": _counts_block(4), "receipts": []}
        planted["journal"].write_text(
            planted["journal"].read_text(encoding="utf-8") + "not-json\n" + json.dumps(t2) + "\n",
            encoding="utf-8",
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        # t1 (3) + t2 (4); the stale tail is subsumed by the valid
        # window beyond the mark (single-writer append order), so it folds
        # out while every valid window folds in. The tear still conflicts.
        assert records[0]["total_calls"] == 7
        assert records[1]["end_state"] == "conflict"


# --------------------------------------------------------------------------
# Sweep (idempotent) + incarnation-verified fencing + admission barrier
# --------------------------------------------------------------------------


class TestSweepAndFence:
    def test_sweep_is_idempotent_and_keeps_unattributed_evidence(self, engaged: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        committed = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        other_run = _plant_producer(
            engaged,
            uuid=_UUID_B,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        torn = engaged / "registrations" / f"{'c' * 32}.json"
        torn.write_text('{"worker_uuid": "torn', encoding="utf-8")
        first = durability.sweep_orphans(
            engaged, current_run=_RUN, committed_uuids=frozenset({_UUID_A})
        )
        assert first["removed"] == 3, "registry + sidecar of the committed producer"
        assert first["retained"] == 2, "other-run evidence is never destroyed"
        assert not committed["registry"].exists()
        assert not committed["sidecar"].exists()
        assert not torn.exists()
        assert other_run["registry"].exists()
        assert other_run["sidecar"].exists()
        second = durability.sweep_orphans(
            engaged, current_run=_RUN, committed_uuids=frozenset({_UUID_A})
        )
        assert second == {"removed": 0, "retained": 2}

    def test_sweep_collects_runs_after_resume_collection(self, engaged: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        swept = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert swept == {"removed": 2, "retained": 0}
        assert not planted["registry"].exists()
        assert not planted["sidecar"].exists()

    def test_sweep_skips_retained_uuids(self, engaged: Path) -> None:
        """#88R3F5: barrier-retained uuids survive a collected-run sweep."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        swept = durability.sweep_orphans(
            engaged,
            current_run=_RUN,
            collected_runs=frozenset({"OLD"}),
            retain_uuids=frozenset({_UUID_A}),
        )
        assert swept["removed"] == 0
        assert planted["registry"].exists()
        assert planted["sidecar"].exists()

    def test_resume_sweep_keeps_unreadable_evidence(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R3F5: an unreadable producer survives its run's sweep."""
        pid, birth = _dead_pid_with_birth()
        retained = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        collected = _plant_producer(
            engaged,
            uuid=_UUID_B,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(3),
        )
        registry_name = Path(retained["registry"]).name
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes

        def _eperm_registry(self: Path, *args: Any, **kwargs: Any) -> str:
            if self.name == registry_name:
                raise PermissionError("injected registry EPERM")
            return real_read_text(self, *args, **kwargs)

        def _eperm_registry_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if self.name == registry_name:
                raise PermissionError("injected registry EPERM")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _eperm_registry)
        monkeypatch.setattr(Path, "read_bytes", _eperm_registry_bytes)
        with pytest.warns(UserWarning, match="unreadable registry"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["retained_uuids"] == [_UUID_A]
        durability.sweep_orphans(
            engaged,
            current_run=_RUN,
            collected_runs=frozenset(plan["collected_runs"]),
            retain_uuids=frozenset(plan["unresolved"] + plan["retained_uuids"]),
        )
        assert Path(retained["registry"]).exists()
        assert Path(retained["sidecar"]).exists()
        assert not Path(collected["registry"]).exists()
        assert not Path(collected["sidecar"]).exists()

    def test_sweep_skips_healed_retained_uuid(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R3F5: retention sticks even after the fault heals."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        registry_name = Path(planted["registry"]).name
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes
        blocked = True

        def _flaky_registry(self: Path, *args: Any, **kwargs: Any) -> str:
            if blocked and self.name == registry_name:
                raise PermissionError("injected registry EPERM")
            return real_read_text(self, *args, **kwargs)

        def _flaky_registry_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if blocked and self.name == registry_name:
                raise PermissionError("injected registry EPERM")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _flaky_registry)
        monkeypatch.setattr(Path, "read_bytes", _flaky_registry_bytes)
        with pytest.warns(UserWarning, match="unreadable registry"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["retained_uuids"] == [_UUID_A]
        blocked = False
        durability.sweep_orphans(
            engaged,
            current_run=_RUN,
            collected_runs=frozenset(plan["collected_runs"]),
            retain_uuids=frozenset(plan["retained_uuids"]),
        )
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_sweep_torn_registry_shields_collected_sidecar(self, engaged: Path) -> None:
        """#88R3F5: a present (even torn) registry shields its sidecar."""
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=os.getpid(),
            birth=durability.birth_token_for_pid(os.getpid()),
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        Path(planted["registry"]).write_text('{"worker_uuid": "torn', encoding="utf-8")
        swept = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert swept["removed"] == 0
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_barrier_torn_registry_with_sidecar_reserves_uuid(self, engaged: Path) -> None:
        """#88R3F5: every deferred producer rides the sweep skip set."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        Path(planted["registry"]).write_text('{"worker_uuid": "torn', encoding="utf-8")
        with pytest.warns(UserWarning, match="torn registry"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["retained_uuids"] == [_UUID_A]

    def test_sweep_unreadable_probe_baseline_retained(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R3F5: probe I/O failure retains the baseline and its tmp."""
        (engaged / "registrations").mkdir(parents=True, exist_ok=True)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=3)
        tmp = _plant_probe_tmp(
            orphan,
            _probe_tmp_payload(_UUID_B, 3, [["m", "C_Digest", None, 2]]),
        )
        real_read_text = Path.read_text

        def _eperm_probe(self: Path, *args: Any, **kwargs: Any) -> str:
            if self.name == orphan.name:
                raise PermissionError("injected probe EPERM")
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _eperm_probe)
        swept = durability.sweep_orphans(engaged, current_run=_RUN)
        assert swept["removed"] == 0
        assert orphan.exists()
        assert tmp.exists()

    def test_sweep_collected_sidecar_co_deletes_tmps(self, engaged: Path) -> None:
        """#88R3F5: authoritative sweep leaves no stranded tmps behind."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
            journal=[{"window": 1}],
        )
        sidecar = Path(planted["sidecar"])
        Path(planted["registry"]).unlink()
        complete = _plant_tmp(
            sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
        )
        torn_tmp = _plant_tmp(sidecar, None, raw="torn-bytes", nonce="zzz")
        swept = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert swept["removed"] == 4, "sidecar + journal + both tmps"
        assert not sidecar.exists()
        assert not complete.exists()
        assert not torn_tmp.exists()

    def test_sweep_torn_probe_prunes_tmps(self, engaged: Path) -> None:
        """#88R3F5: a torn probe baseline dies; complete tmps stay loudly."""
        (engaged / "registrations").mkdir(parents=True, exist_ok=True)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=3)
        torn_tmp = _plant_probe_tmp(orphan, None, raw="torn-bytes", pid=999)
        complete = _plant_probe_tmp(
            orphan,
            _probe_tmp_payload(_UUID_B, 3, [["m", "C_Digest", 0, 2]]),
            pid=1000,
        )
        orphan.write_text('{"worker_uuid": "torn', encoding="utf-8")
        with pytest.warns(UserWarning, match="unadjudicated tmp"):
            swept = durability.sweep_orphans(engaged, current_run=_RUN)
        assert swept["removed"] == 2, "torn baseline + torn tmp"
        assert not orphan.exists()
        assert not torn_tmp.exists()
        assert complete.exists()

    def test_barrier_cycles_converge_mutual_debris(self, engaged: Path) -> None:
        """#88R4-F5a: mutual debris converges through real barrier cycles."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        sibling = _plant_producer(
            engaged,
            uuid=_UUID_B,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(3),
        )
        registry = Path(planted["registry"])
        sidecar = Path(planted["sidecar"])
        registry.write_text('{"worker_uuid": "torn', encoding="utf-8")
        sidecar.write_text("torn-bytes", encoding="utf-8")
        for _ in range(2):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            durability.sweep_orphans(
                engaged,
                current_run=_RUN,
                collected_runs=frozenset(plan["collected_runs"]),
                retain_uuids=frozenset(plan["unresolved"] + plan["retained_uuids"]),
            )
        assert not sidecar.exists()
        assert not registry.exists()
        assert not Path(sibling["registry"]).exists()
        assert not Path(sibling["sidecar"]).exists()

    def test_sweep_registry_backed_co_deletes_tmps(self, engaged: Path) -> None:
        """#88R4-F5b: authoritative registry sweep strands no tmps."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        sidecar = Path(planted["sidecar"])
        complete = _plant_tmp(
            sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
        )
        torn_tmp = _plant_tmp(sidecar, None, raw="torn-bytes", nonce="zzz")
        swept = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert swept["removed"] == 4, "registry + sidecar + both tmps"
        assert not Path(planted["registry"]).exists()
        assert not sidecar.exists()
        assert not complete.exists()
        assert not torn_tmp.exists()
        again = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert again == {"removed": 0, "retained": 0}

    def test_sweep_committed_co_deletes_tmps(self, engaged: Path) -> None:
        """#88R4-F5b: the committed sweep strands no tmps either."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        sidecar = Path(planted["sidecar"])
        complete = _plant_tmp(
            sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
        )
        swept = durability.sweep_orphans(
            engaged, current_run=_RUN, committed_uuids=frozenset({_UUID_A})
        )
        assert swept["removed"] == 3, "registry + sidecar + tmp"
        assert not Path(planted["registry"]).exists()
        assert not sidecar.exists()
        assert not complete.exists()

    def test_sweep_failed_tmp_unlink_holds_baseline(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R5-6: a failed tmp unlink keeps the baseline for retry."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        sidecar = Path(planted["sidecar"])
        tmp = _plant_tmp(sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == tmp.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert first["removed"] == 0
        assert Path(planted["registry"]).exists()
        assert sidecar.exists()
        assert tmp.exists()
        blocked = False
        second = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert second["removed"] == 3, "registry + sidecar + tmp"
        assert not Path(planted["registry"]).exists()
        assert not sidecar.exists()
        assert not tmp.exists()

    def test_sweep_failed_probe_tmp_unlink_holds_baseline(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R5-6: a failed probe-tmp unlink keeps the torn baseline."""
        (engaged / "registrations").mkdir(parents=True, exist_ok=True)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=3)
        tmp = _plant_probe_tmp(orphan, None, raw="torn-bytes", pid=999)
        orphan.write_text('{"worker_uuid": "torn', encoding="utf-8")
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == tmp.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.sweep_orphans(engaged, current_run=_RUN)
        assert first["removed"] == 0
        assert orphan.exists()
        assert tmp.exists()
        blocked = False
        second = durability.sweep_orphans(engaged, current_run=_RUN)
        assert second["removed"] == 2, "torn baseline + torn tmp"
        assert not orphan.exists()
        assert not tmp.exists()

    def test_sweep_failed_tmp_counts_all_survivors(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R6-3: a mid-list unlink failure still accounts every survivor."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        sidecar = Path(planted["sidecar"])
        first = _plant_tmp(sidecar, None, raw="torn-bytes", nonce="aaa")
        middle = _plant_tmp(sidecar, None, raw="torn-bytes", nonce="mmm")
        last = _plant_tmp(sidecar, None, raw="torn-bytes", nonce="zzz")
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == middle.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        swept = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert swept == {"removed": 1, "retained": 4}
        assert not first.exists()
        assert middle.exists()
        assert last.exists()
        assert Path(planted["registry"]).exists()
        assert sidecar.exists()
        blocked = False
        again = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert again == {"removed": 4, "retained": 0}
        assert not middle.exists()
        assert not last.exists()

    def test_sweep_unreadable_tmp_holds_torn_baseline(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R6-3: an unclassified tmp keeps its baseline for retry."""
        (engaged / "registrations").mkdir(parents=True, exist_ok=True)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=3)
        tmp = _plant_probe_tmp(orphan, None, raw="torn-bytes", pid=999)
        orphan.write_text('{"worker_uuid": "torn', encoding="utf-8")
        real_read_text = Path.read_text
        blocked = True

        def _flaky_tmp(self: Path, *args: Any, **kwargs: Any) -> str:
            if blocked and self.name == tmp.name:
                raise PermissionError("injected tmp EPERM")
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _flaky_tmp)
        with pytest.warns(UserWarning, match="unadjudicated tmp"):
            first = durability.sweep_orphans(engaged, current_run=_RUN)
        assert first["removed"] == 0
        assert orphan.exists()
        assert tmp.exists()
        blocked = False
        second = durability.sweep_orphans(engaged, current_run=_RUN)
        assert second["removed"] == 2, "torn baseline + torn tmp"
        assert not orphan.exists()
        assert not tmp.exists()

    def test_list_tmp_paths_surfaces_faults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R7-4: tmp enumeration distinguishes empty, missing, and faulty."""
        assert durability._list_tmp_paths(tmp_path / "nope", "x.tmp-") == []
        (tmp_path / "a.partial.json.tmp-1").write_text("{}", encoding="utf-8")
        got = durability._list_tmp_paths(tmp_path, "a.partial.json.tmp-")
        assert got is not None and [path.name for path in got] == ["a.partial.json.tmp-1"]
        assert durability._list_tmp_paths(tmp_path, "b.partial.json.tmp-") == []
        real_scandir = os.scandir

        def _eacces(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(tmp_path):
                raise PermissionError("injected scandir EACCES")
            return real_scandir(path, *args, **kwargs)

        monkeypatch.setattr(os, "scandir", _eacces)
        assert durability._list_tmp_paths(tmp_path, "a.partial.json.tmp-") is None

    def test_sweep_tmp_enumeration_fault_holds_baseline(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R7-4: a tmp listing fault holds the baseline for retry."""
        (engaged / "registrations").mkdir(parents=True, exist_ok=True)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=3)
        tmp = _plant_probe_tmp(orphan, None, raw="torn-bytes", pid=999)
        orphan.write_text('{"worker_uuid": "torn', encoding="utf-8")
        real_list = durability._list_tmp_paths
        blocked = True

        def _flaky_list(directory: Path, prefix: str) -> Any:
            if blocked:
                return None
            return real_list(directory, prefix)

        monkeypatch.setattr(durability, "_list_tmp_paths", _flaky_list)
        first = durability.sweep_orphans(engaged, current_run=_RUN)
        assert first["removed"] == 0
        assert orphan.exists()
        assert tmp.exists()
        blocked = False
        second = durability.sweep_orphans(engaged, current_run=_RUN)
        assert second["removed"] == 2, "torn baseline + torn tmp"
        assert not orphan.exists()
        assert not tmp.exists()

    def test_consume_honors_prune_hold(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R8-4: consumption keeps a baseline its tmps hold."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(1, fn="C_Digest"),
        )
        sidecar = Path(planted["sidecar"])
        tmp = _plant_tmp(sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if self.name == tmp.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        with pytest.warns(UserWarning, match="unadjudicated tmp"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert not Path(planted["registry"]).exists()
        assert sidecar.exists(), "held baseline stays discoverable for retry"
        assert tmp.exists()

    def test_sweep_finishes_held_cleanup(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R8-4: a healed sweep finishes held cleanup without re-emitting."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(1, fn="C_Digest"),
        )
        sidecar = Path(planted["sidecar"])
        tmp = _plant_tmp(sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
        Path(planted["registry"]).unlink()
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == tmp.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert first["removed"] == 0
        assert sidecar.exists()
        assert tmp.exists()
        blocked = False
        second = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert second == {"removed": 2, "retained": 0}
        assert not sidecar.exists()
        assert not tmp.exists()

    def test_barrier_retry_finishes_held_cleanup_without_reemit(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R9-4: a retry retires held files without publishing twice."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
            journal=[
                {
                    "nodeid": "a.py::t1",
                    "block": _counts_block(2, fn="C_Digest"),
                    "receipts": [],
                }
            ],
        )
        sidecar = Path(planted["sidecar"])
        tmp = _plant_tmp(sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == tmp.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert sum(len(records) for records in first["cache_records"].values()) > 0
        assert not Path(planted["registry"]).exists()
        assert sidecar.exists()
        assert tmp.exists()
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert not sidecar.exists()
        assert not tmp.exists()

    def test_barrier_retry_retires_held_registry_without_reemit(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R9-4: a held registry retires on retry without new records."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        registry = Path(planted["registry"])
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == registry.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert sum(len(records) for records in first["cache_records"].values()) > 0
        assert registry.exists()
        assert not Path(planted["sidecar"]).exists()
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert not registry.exists()

    def test_inconsistent_staging_claim_recollects_fresh(self, engaged: Path) -> None:
        """#88R10-4b: a uuid claimed with no staged evidence re-emits loudly."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps({"cache_records": {}, "consumed": 0, "collected_uuids": [_UUID_A]}),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning) as record:
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert any("re-collect as fresh" in str(w.message) for w in record.list)
        assert sum(len(records) for records in plan["cache_records"].values()) > 0
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        restaged = json.loads(staging.read_text(encoding="utf-8"))
        assert restaged["consumed"] == 1
        assert restaged["collected_uuids"] == [_UUID_A]

    @pytest.mark.parametrize("bad", [{}, 0, "", [None], {"x": 1}])
    def test_falsy_malformed_collected_uuids_warns(self, engaged: Path, bad: object) -> None:
        """#88R10-4b: every present-but-malformed uuid list warns (falsy too)."""
        engaged.mkdir(parents=True, exist_ok=True)
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staged_records = {"a.py": [{"worker_uuid": _UUID_A, "note": 1}]}
        staging.write_text(
            json.dumps({"cache_records": staged_records, "consumed": 1, "collected_uuids": bad}),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="malformed collected_uuids"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert plan["cache_records"] == staged_records

    def test_absent_collected_uuids_reads_clean(self, engaged: Path, tmp_path: Path) -> None:
        """#88R10-4b: pre-key staging (no uuid list) applies without uuid warns."""
        import warnings

        engaged.mkdir(parents=True, exist_ok=True)
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staged_records = {"a.py": [{"worker_uuid": _UUID_A, "note": 1}]}
        staging.write_text(
            json.dumps({"cache_records": staged_records, "consumed": 1}),
            encoding="utf-8",
        )
        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert plan["cache_records"] == staged_records
        assert not any(
            "collected_uuids" in str(w.message)
            or "re-collect as fresh" in str(w.message)
            or "per-uuid evidence" in str(w.message)
            for w in record
        )

    def test_consumed_counts_newly_staged_only(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R10-4b: held retries never inflate the consumed count."""
        held_names = set()
        for uuid in (_UUID_A, _UUID_B):
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=uuid,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            held_names.add(Path(planted["registry"]).name)
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name in held_names:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert first["consumed"] == 2
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["consumed"] == 2
        assert second["cache_records"] == first["cache_records"]
        third = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert third["barrier_ok"] is True
        assert third["consumed"] == 2
        assert third["cache_records"] == first["cache_records"]

    def test_count_mismatch_keeps_per_uuid_suppression(self, engaged: Path) -> None:
        """#88R10-4b: a lying count warns but staged evidence still suppresses."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staged_records = {
            "a.py": [
                {
                    "$report_type": "CallCountersPartial",
                    "worker_uuid": _UUID_A,
                    "truncated": True,
                    "total_calls": 0,
                    "by_module": {},
                }
            ]
        }
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": staged_records,
                    "consumed": 5,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning) as record:
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert any("per-uuid evidence still decides" in str(w.message) for w in record.list)
        assert not any("re-collect as fresh" in str(w.message) for w in record.list)
        assert plan["cache_records"] == staged_records
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()

    def test_committed_session_authorizes_suppression_without_records(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R10-4b: a session-backed claim gates without staged records."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(5),
                    extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps({"cache_records": {}, "consumed": 1, "collected_uuids": [_UUID_A]}),
            encoding="utf-8",
        )
        import warnings

        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        assert plan["barrier_ok"] is True
        assert not any("re-collect as fresh" in str(w.message) for w in record)
        assert plan["cache_records"] == {}
        assert plan["consumed"] == 1
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()

    def test_bare_dict_staged_record_authorizes_nothing(self, engaged: Path) -> None:
        """#88R11-5: suppression needs schema-shaped records, not bare dicts."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {"a.py": [{"worker_uuid": _UUID_A}]},
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="re-collect as fresh"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert sum(len(records) for records in plan["cache_records"].values()) > 1
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()

    def test_list_valued_worker_uuid_never_crashes(self, engaged: Path) -> None:
        """#88R11-5: a malformed uuid field degrades, never raises."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": [_UUID_A],
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="re-collect as fresh"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert sum(len(records) for records in plan["cache_records"].values()) > 1
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        again = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert again["barrier_ok"] is True, "the seal never sticks"

    def test_tag_only_staged_record_authorizes_nothing(self, engaged: Path) -> None:
        """#88R12-3: a tag without the schema proves no evidence."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="re-collect as fresh"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert sum(len(records) for records in plan["cache_records"].values()) > 1
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()

    def test_list_valued_report_type_never_crashes(self, engaged: Path) -> None:
        """#88R12-3: a malformed discriminator degrades, never raises."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {"a.py": [{"$report_type": [], "worker_uuid": _UUID_A}]},
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="re-collect as fresh"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert sum(len(records) for records in plan["cache_records"].values()) > 1
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        again = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert again["barrier_ok"] is True, "the seal never sticks"

    def test_value_garbage_partial_authorizes_nothing(self, engaged: Path) -> None:
        """#88R13-1: right keys with extractor-rejected values prove nothing."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                                "truncated": True,
                                "total_calls": "bad",
                                "by_module": {},
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="re-collect as fresh"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert sum(len(records) for records in plan["cache_records"].values()) > 1
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()

    def test_corrupt_consumed_count_self_heals(self, engaged: Path) -> None:
        """#88R11-5: the staged count recomputes from the validated union."""
        import warnings

        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staged_records = {
            "a.py": [
                {
                    "$report_type": "CallCountersPartial",
                    "worker_uuid": _UUID_A,
                    "truncated": True,
                    "total_calls": 0,
                    "by_module": {},
                }
            ]
        }
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": staged_records,
                    "consumed": 42,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="per-uuid evidence still decides"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert plan["cache_records"] == staged_records
        assert plan["consumed"] == 1
        restaged = json.loads(staging.read_text(encoding="utf-8"))
        assert restaged["consumed"] == 1
        assert restaged["collected_uuids"] == [_UUID_A]
        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            again = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert again["barrier_ok"] is True
        assert again["cache_records"] == staged_records
        assert not any("per-uuid evidence still decides" in str(w.message) for w in record)

    def test_post_application_retry_no_double_and_converges(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R10-4c: held cleanup keeps its staging across application."""
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        sidecar = Path(planted["sidecar"])
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == sidecar.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert first["cleanup_held"] == [str(sidecar)]
        state_file = tmp_path / "state.json"
        console = Console(file=StringIO(), force_terminal=False)
        with pytest.warns(UserWarning, match="cleanup target"):
            _apply_counters_barrier_plan(state_file, first, ["a.py"], console)
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        assert staging.exists(), "held cleanup keeps its staging"
        durability.sweep_orphans(
            engaged,
            current_run=_RUN,
            collected_runs=frozenset(first["collected_runs"]),
        )
        assert sidecar.exists()
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert second["cleanup_held"] == []
        assert not sidecar.exists()
        _apply_counters_barrier_plan(state_file, second, ["a.py"], console)
        assert not staging.exists(), "converged cleanup discards its staging"

    def test_parentless_probe_adopted_after_parents_gone(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R10-4c: a held probe converges on retry once its parents went."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        tmp = _plant_probe_tmp(probe, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]))
        held_names = {probe.name, tmp.name}
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name in held_names:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert probe.exists()
        assert tmp.exists()
        assert first["cleanup_held"] != []
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert not probe.exists()
        assert not tmp.exists()

    def test_staged_probe_with_live_writer_not_adopted(self, engaged: Path) -> None:
        """#88R10-4c: adoption never deletes under a live writer."""
        proc = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            pid, dead_birth = _dead_pid_with_birth()
            _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=dead_birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert first["barrier_ok"] is True
            probe = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", 0, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=birth,
            )
            with pytest.warns(UserWarning, match="live writer"):
                second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert second["barrier_ok"] is True
            assert second["cache_records"] == first["cache_records"]
            assert probe.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_unstamped_staged_probe_retained_loud(self, engaged: Path) -> None:
        """#88R10-4c: adoption needs a verifiable writer stamp."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
        )
        with pytest.warns(UserWarning, match="no verifiable writer"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert probe.exists()

    def test_legacy_prefix_probe_adopted_when_unique(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R10-4c/#88R11-6: a listed legacy probe adopts under a unique prefix."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            pid=pid,
            birth=birth,
        )
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == probe.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert probe.exists()
        assert first["cleanup_held"] != []
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert not probe.exists()

    def test_legacy_prefix_probe_ambiguous_retained(self, engaged: Path) -> None:
        """#88R10-4c: a prefix shared by two staged parents never adopts."""
        uuid_b = "aaaaaaaa" + "cd" * 12
        for uuid in (_UUID_A, uuid_b):
            pid, birth = _dead_pid_with_birth()
            _plant_producer(
                engaged,
                uuid=uuid,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert first["consumed"] == 2
        pid, birth = _dead_pid_with_birth()
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            pid=pid,
            birth=birth,
        )
        with pytest.warns(UserWarning, match="ambiguous linkage"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert probe.exists()

    def test_sweep_journal_shield_survives_lookup_fault(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-3: a faulted sidecar shield lookup retains the journal."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(4), "receipts": []}],
        )
        Path(planted["registry"]).unlink()
        journal = Path(planted["journal"])
        sidecar = Path(planted["sidecar"])
        assert journal.exists() and sidecar.exists()
        real_glob = Path.glob
        real_state = durability._path_state
        fired: list[str] = []

        def _flaky_glob(self: Path, pattern: Any, *args: Any, **kwargs: Any) -> Any:
            # Pre-fix shield is a literal glob (swallows faults as []).
            if str(self) == str(engaged) and "*" not in str(pattern) and not fired:
                fired.append("glob")
                return iter([])
            return real_glob(self, pattern, *args, **kwargs)

        def _flaky_state(path: Any) -> Any:
            # Post-fix shield is an exact tri-state lookup.
            if str(path) == str(sidecar) and not fired:
                fired.append("stat")
                return "unreadable"
            return real_state(path)

        monkeypatch.setattr(Path, "glob", _flaky_glob)
        monkeypatch.setattr(durability, "_path_state", _flaky_state)
        with pytest.warns(UserWarning, match="shielded"):
            swept = durability.sweep_orphans(engaged, current_run="run-now")
        assert fired, "the fault must hit the shield lookup"
        assert swept["retained"] >= 1
        assert journal.exists(), "an unprovable sidecar shields its journal"
        assert sidecar.exists()

    def test_terminate_verified_rejects_unrepresentable_pid(self) -> None:
        """#88R26-4: fencing never feeds an unrepresentable pid to a backend."""
        assert durability._terminate_verified(2**32, 424243, 0.0) is False
        assert durability._terminate_verified(2**63, 424243, 0.0) is False

    def test_collect_orphan_unrepresentable_pid_defers(self, engaged: Path) -> None:
        """#88R26-4: a stamped out-of-range orphan pid defers, never crashes."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=2**32,
            birth=424243,
        )
        assert orphan == slot
        with pytest.warns(UserWarning):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert durability.is_sealed(engaged) is False
        assert orphan.exists(), "unfenceable writers defer with evidence kept"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO semantics")
    def test_staged_target_fifo_carries_without_open(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-6: carry-forward never opens non-regular staged targets."""
        import json

        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        fifo = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json.tmp-99"
        os.mkfifo(fifo)
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {},
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                    "cleanup_targets": [{"path": str(fifo), "sha256": "0" * 64}],
                    "skip_held_uuids": [],
                }
            ),
            encoding="utf-8",
        )
        real_hash = durability._sha256_file_hex
        opened: list[str] = []

        def _spy_hash(path: Path) -> Any:
            # Stand in for the open: with real hashing the pre-fix
            # code blocks forever inside read_bytes on the FIFO
            # (reproduced in scratch with a threaded timeout).
            if str(path) == str(fifo):
                opened.append(str(path))
                return "f" * 64
            return real_hash(path)

        monkeypatch.setattr(durability, "_sha256_file_hex", _spy_hash)
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert opened == [], "carry-forward must not open a FIFO"
        carried = json.loads(staging.read_text(encoding="utf-8"))["cleanup_targets"]
        assert str(fifo) in [entry["path"] for entry in carried]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO semantics")
    def test_staged_target_carries_fifo_branch(self, tmp_path: Path) -> None:
        """#88R26-6: non-regular staged targets carry blind, unopened."""
        fifo = tmp_path / "probe-aaaaaaaa-0-feedface.json.tmp-7"
        os.mkfifo(fifo)
        assert durability._staged_target_carries(fifo, "0" * 64) is True
        assert durability._staged_target_carries(tmp_path, "0" * 64) is True

    def test_regular_file_hash_contracts(self, tmp_path: Path) -> None:
        """#88R27-4: fd-verified hashing binds regular files only."""
        import hashlib
        import threading

        plain = tmp_path / "regular.json"
        plain.write_text("{}", encoding="utf-8")
        assert durability._sha256_regular_file_hex(plain) == hashlib.sha256(b"{}").hexdigest()
        assert durability._sha256_regular_file_hex(tmp_path / "gone.json") is None
        assert durability._sha256_regular_file_hex(tmp_path) is None
        if sys.platform == "win32":
            return
        fifo = tmp_path / "pipe.tmp-1"
        os.mkfifo(fifo)
        done: list[bool] = []

        def _hash() -> None:
            done.append(durability._sha256_regular_file_hex(fifo) is None)

        worker = threading.Thread(target=_hash, daemon=True)
        worker.start()
        worker.join(timeout=15)
        assert done == [True], "hashing a FIFO returns None instead of blocking"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO semantics")
    def test_carry_ignores_raced_stat(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R27-4: carry never trusts a stat (a swap cannot plant a block)."""
        import stat
        import threading

        fifo = tmp_path / "probe-aaaaaaaa-0-feedface.json.tmp-9"
        os.mkfifo(fifo)

        class _AlwaysRegular:
            st_mode = stat.S_IFREG | 0o644

        def _lying_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
            return _AlwaysRegular()

        monkeypatch.setattr(os, "stat", _lying_stat)
        done: list[bool] = []

        def _carry() -> None:
            done.append(durability._staged_target_carries(fifo, "0" * 64))

        worker = threading.Thread(target=_carry, daemon=True)
        worker.start()
        worker.join(timeout=15)
        assert done == [True], "a stat/open race must not block carry"

    def test_cleanup_only_pass_stages_retry_and_converges(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-7: a recordless pass still stages its held cleanup durably."""
        import unittest.mock as mock
        import warnings

        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        marker = engaged / f"probe-consumed-{_UUID_A[:8]}-0-feedface.json"
        pid_m, birth_m = _dead_pid_with_birth()
        marker.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": 0,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": _UUID_A,
                    "run_id": _RUN,
                    "unit": "a.py",
                    "pid": pid_m,
                    "birth_token": birth_m,
                    "finalized": False,
                }
            ),
            encoding="utf-8",
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(2, fn="C_Digest"),
                    extra={
                        "worker_uuid": _UUID_A,
                        "run_id": _RUN,
                        "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if self == marker:
                raise OSError("injected unlink failure")
            return real_unlink(self, *args, **kwargs)

        with mock.patch.object(Path, "unlink", _flaky_unlink):
            plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        assert plan1["barrier_ok"] is True
        assert plan1["cache_records"] == {}, "committed silence: no records"
        assert str(marker) in plan1["cleanup_held"]
        assert staging.exists(), "cleanup-pending passes stage for retry"
        # Pass 2 without the prior: targeted validation (not the session)
        # must authorize the adopted retry.
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert not marker.exists(), "the held duplicate converges on retry"
        assert not any("re-collect as fresh" in str(w.message) for w in seen)
        # Pass 3: spent staging discards silently instead of alarming.
        with warnings.catch_warnings(record=True) as seen3:
            warnings.simplefilter("always")
            plan3 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan3["barrier_ok"] is True
        assert not staging.exists(), "spent staging discards once resolved"
        assert not any("re-collect as fresh" in str(w.message) for w in seen3)

    def test_cleanup_hint_never_suppresses_producer_collection(self, engaged: Path) -> None:
        """#88R27-1: cleanup-target validation must not suppress collection."""
        import hashlib

        uuid_b = "aaaaaaaa" + "b" * 24
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        marker = engaged / f"probe-consumed-{uuid_b}-0-bead99.json"
        pid_m, birth_m = _dead_pid_with_birth()
        marker.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": 0,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": uuid_b,
                    "run_id": _RUN,
                    "unit": "a.py",
                    "pid": pid_m,
                    "birth_token": birth_m,
                }
            ),
            encoding="utf-8",
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {},
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                    "cleanup_targets": [
                        {
                            "path": str(marker),
                            "sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
                        }
                    ],
                    "skip_held_uuids": [],
                }
            ),
            encoding="utf-8",
        )
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        partials = [
            rec
            for rec in plan["cache_records"]["a.py"]
            if rec["$report_type"] == "CallCountersPartial"
        ]
        assert sum(rec["total_calls"] for rec in partials) == 2
        assert not Path(planted["registry"]).exists()
        assert marker.exists(), "a foreign-owned marker is not this producer's cleanup"

    def test_held_parent_cleanup_stages_and_retries(self, engaged: Path, tmp_path: Path) -> None:
        """#88R27-3: held parent files stage as targets and retry to done."""
        import unittest.mock as mock
        import warnings

        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(4), "receipts": []}],
        )
        marker = engaged / f"probe-consumed-{_UUID_A[:8]}-0-feedface.json"
        pid_m, birth_m = _dead_pid_with_birth()
        marker.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": 0,
                    "counters": [["m", "C_Digest", 0, 1]],
                    "parent_uuid": _UUID_A,
                    "run_id": _RUN,
                    "unit": "a.py",
                    "pid": pid_m,
                    "birth_token": birth_m,
                    "finalized": False,
                }
            ),
            encoding="utf-8",
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(2, fn="C_Digest"),
                    extra={
                        "worker_uuid": _UUID_A,
                        "run_id": _RUN,
                        "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        parents = {
            str(Path(planted["registry"])),
            str(Path(planted["sidecar"])),
            str(Path(planted["journal"])),
        }
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if str(self) in parents:
                raise OSError("injected parent unlink failure")
            return real_unlink(self, *args, **kwargs)

        with mock.patch.object(Path, "unlink", _flaky_unlink):
            plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        assert plan1["barrier_ok"] is True
        assert plan1["cache_records"] == {}, "committed silence: no records"
        assert parents <= set(plan1["cleanup_held"])
        staged_targets = {
            entry["path"]
            for entry in json.loads(staging.read_text(encoding="utf-8"))["cleanup_targets"]
        }
        assert parents <= staged_targets, "held parents stage as retry targets"
        # Pass 2 without the prior: the staged retry consumes the held
        # parents directly instead of gap re-emitting the producer.
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert plan2["cache_records"] == {}, "retry suppresses, never re-emits"
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        assert not any("re-collect as fresh" in str(w.message) for w in seen)
        # Pass 3: spent staging retires silently.
        with warnings.catch_warnings(record=True) as seen3:
            warnings.simplefilter("always")
            plan3 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan3["barrier_ok"] is True
        assert not staging.exists()
        assert not any("re-collect as fresh" in str(w.message) for w in seen3)

    def test_incomplete_discovery_defers_legacy_producer(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R27-2: a withheld legacy orphan defers its producer (no stranding)."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        pid_o, birth_o = _dead_pid_with_birth()
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            pid=pid_o,
            birth=birth_o,
        )
        reg_dir = engaged / durability.REGISTRY_DIRNAME
        real_glob = Path.glob
        real_scandir = os.scandir
        fired: list[str] = []

        def _flaky_glob(self: Path, pattern: Any, *args: Any, **kwargs: Any) -> Any:
            if str(self) == str(reg_dir) and not fired:
                fired.append(str(self))
                return iter([])
            return real_glob(self, pattern, *args, **kwargs)

        def _flaky_scandir(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(reg_dir) and not fired:
                fired.append(str(path))
                raise PermissionError("injected readdir EACCES")
            return real_scandir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "glob", _flaky_glob)
        monkeypatch.setattr(os, "scandir", _flaky_scandir)
        with pytest.warns(UserWarning, match="deferred"):
            plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert fired, "the fault must hit the identity scan"
        assert plan1["barrier_ok"] is True
        assert _UUID_A in plan1["unresolved"]
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        # Pass 2 healed: parent and orphan collect coherently.
        plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        partials = [
            rec
            for rec in plan2["cache_records"]["a.py"]
            if rec["$report_type"] == "CallCountersPartial"
        ]
        assert sum(rec["total_calls"] for rec in partials) == 3
        assert not orphan.exists()

    def test_identity_scan_reports_completeness(self, engaged: Path) -> None:
        """#88R26-2: the producer scan reports whether discovery completed."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        uuids, complete = durability._known_producer_uuids(engaged)
        assert complete is True
        assert _UUID_A in uuids
        reg_dir = engaged / durability.REGISTRY_DIRNAME
        reg_dir.chmod(0o000)
        try:
            uuids, complete = durability._known_producer_uuids(engaged)
        finally:
            reg_dir.chmod(0o755)
        assert complete is False

    def test_incomplete_discovery_withholds_legacy_attribution(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-2/#88R27-2: a faulted scan defers instead of misattributing."""
        uuid_b = "aaaaaaaa" + "b" * 24
        pid_a, birth_a = _dead_pid_with_birth()
        planted_a = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid_a,
            birth=birth_a,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        pid_b, birth_b = _dead_pid_with_birth()
        planted_b = _plant_producer(
            engaged,
            uuid=uuid_b,
            pid=pid_b,
            birth=birth_b,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        Path(planted_b["sidecar"]).unlink(missing_ok=True)
        Path(planted_b["journal"]).unlink(missing_ok=True)
        pid_o, birth_o = _dead_pid_with_birth()
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=uuid_b,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            pid=pid_o,
            birth=birth_o,
        )
        reg_dir = engaged / durability.REGISTRY_DIRNAME
        real_glob = Path.glob
        real_scandir = os.scandir
        fired: list[str] = []

        def _flaky_glob(self: Path, pattern: Any, *args: Any, **kwargs: Any) -> Any:
            # A readdir EACCES inside glob yields [] (proven against a
            # chmod-000 dir: glob swallows, iterdir raises). Fault the
            # identity scan's listing once, whichever lister it uses;
            # the main inventory still sees the healed dir.
            if str(self) == str(reg_dir) and not fired:
                fired.append(str(self))
                return iter([])
            return real_glob(self, pattern, *args, **kwargs)

        def _flaky_scandir(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(reg_dir) and not fired:
                fired.append(str(path))
                raise PermissionError("injected readdir EACCES")
            return real_scandir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "glob", _flaky_glob)
        monkeypatch.setattr(os, "scandir", _flaky_scandir)
        with pytest.warns(UserWarning, match="ambiguous|incomplete|deferred"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert fired, "the fault must hit the identity scan"
        assert plan["barrier_ok"] is True
        assert _UUID_A in plan["unresolved"], "withhold-then-publish would strand"
        assert orphan.exists(), "no attribution on incomplete discovery"
        assert Path(planted_a["registry"]).exists()
        # Healed retry: the true prefix collision still withholds B's
        # orphan from A, but A itself collects and converges.
        plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        partials = [
            rec
            for rec in plan2["cache_records"]["a.py"]
            if rec["$report_type"] == "CallCountersPartial"
        ]
        assert sum(rec["total_calls"] for rec in partials) == 2
        assert not Path(planted_a["registry"]).exists()
        assert orphan.exists()

    def test_quarantined_probe_never_adopted(self, engaged: Path) -> None:
        """#88R10-4c: quarantined forensics survive staged adoption."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        frozen = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json.quarantined-7"
        frozen.write_text(json.dumps({"note": "forensic"}), encoding="utf-8")
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert frozen.exists()

    def test_withheld_marker_survives_retry(self, engaged: Path) -> None:
        """#88R11-2: a withheld marker is not adoption authority."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]))
        with pytest.warns(UserWarning, match="recovery withheld"):
            first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert marker.exists()
        assert tmp.exists()
        with pytest.warns(UserWarning, match="not a staged cleanup target"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert marker.exists(), "withhold survives the retry"
        assert tmp.exists()

    def test_listed_marker_with_unresolved_slot_retained(self, engaged: Path) -> None:
        """#88R11-2: adoption re-checks the marker's slot before deleting."""
        import hashlib

        engaged.mkdir(parents=True, exist_ok=True)
        marker = engaged / f"probe-consumed-{_UUID_A[:8]}-0-feedface.json"
        pid, birth = _dead_pid_with_birth()
        marker.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": 0,
                    "counters": [["m", "C_Digest", None, 1]],
                    "parent_uuid": _UUID_A,
                    "run_id": _RUN,
                    "unit": "a.py",
                    "pid": pid,
                    "birth_token": birth,
                }
            ),
            encoding="utf-8",
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]))
        digest = hashlib.sha256(marker.read_bytes()).hexdigest()
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                                "truncated": True,
                                "total_calls": 0,
                                "by_module": {},
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                    "cleanup_targets": [{"path": str(marker), "sha256": digest}],
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="keeps an unresolved rewrite"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert marker.exists()
        assert tmp.exists()

    def test_resolved_marker_adopts_its_debris_tmps(self, engaged: Path) -> None:
        """#88R11-2: a resolved slot converges marker and debris together."""
        import hashlib

        engaged.mkdir(parents=True, exist_ok=True)
        marker = engaged / f"probe-consumed-{_UUID_A[:8]}-0-feedface.json"
        pid, birth = _dead_pid_with_birth()
        marker.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": 0,
                    "counters": [["m", "C_Digest", None, 1]],
                    "parent_uuid": _UUID_A,
                    "run_id": _RUN,
                    "unit": "a.py",
                    "pid": pid,
                    "birth_token": birth,
                }
            ),
            encoding="utf-8",
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = slot.with_name(f"{slot.name}.tmp-4242")
        tmp.write_text("{torn", encoding="utf-8")
        digest = hashlib.sha256(marker.read_bytes()).hexdigest()
        tmp_digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                                "truncated": True,
                                "total_calls": 0,
                                "by_module": {},
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                    "cleanup_targets": [
                        {"path": str(marker), "sha256": digest},
                        {"path": str(tmp), "sha256": tmp_digest},
                    ],
                }
            ),
            encoding="utf-8",
        )
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert not marker.exists()
        assert not tmp.exists()

    def test_new_slot_after_barrier_never_adopts(self, engaged: Path) -> None:
        """#88R11-6: parent-level authority cannot delete an unlisted slot."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=1,
            nonce="deadbeef",
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        tmp = _plant_probe_tmp(probe, _probe_tmp_payload(_UUID_B, 1, [["m", "C_Digest", 0, 1]]))
        with pytest.warns(UserWarning, match="not a staged cleanup target"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert probe.exists(), "new evidence is never cleanup"
        assert tmp.exists()

    def test_evolved_listed_slot_retained(self, engaged: Path) -> None:
        """#88R11-6: a listed slot that changed since staging never adopts."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert not probe.exists(), "unheld targets converge immediately"
        evolved = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 9]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        with pytest.warns(UserWarning, match="not a staged cleanup target"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert evolved.exists(), "evolved bytes void the staged digest"

    def test_unlisted_rewrite_holds_its_slot(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R12-4: a rewrite appended after staging is never deleted unread."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == probe.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert probe.exists()
        ghost = _plant_probe_tmp(probe, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 2]]))
        blocked = False
        with pytest.warns(UserWarning, match="unlisted rewrite"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert probe.exists(), "the listed baseline waits with its rewrite"
        assert ghost.exists(), "the unlisted return is never deleted unread"

    def test_registry_retry_ghost_rewrite_preserved(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R13-2: a post-stage ghost is never replayed-and-discarded."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        registry = Path(planted["registry"])
        sidecar = Path(planted["sidecar"])
        held_names = {registry.name, probe.name}
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name in held_names:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert registry.exists()
        assert probe.exists()
        ghost = _plant_probe_tmp(probe, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 5]]))
        blocked = False
        with pytest.warns(UserWarning, match="unlisted rewrite"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert not registry.exists(), "staged parents converge directly"
        assert not sidecar.exists()
        assert probe.exists(), "the ghost holds its whole slot"
        assert ghost.exists(), "the ghost return is never folded-and-dropped"

    def test_stage_time_ghost_never_listed(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R13-2: staging binds adjudicated bytes, never fresh reads."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == probe.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        ghost_holder: dict[str, Any] = {}
        real_stage = durability._write_barrier_staging

        def _ghosting_stage(*args: Any, **kwargs: Any) -> bool:
            ghost_holder["ghost"] = _plant_probe_tmp(
                probe, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 5]])
            )
            return real_stage(*args, **kwargs)

        monkeypatch.setattr(durability, "_write_barrier_staging", _ghosting_stage)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert probe.exists()
        ghost = ghost_holder["ghost"]
        staged = json.loads(
            (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
        )
        assert all(entry["path"] != str(ghost) for entry in staged["cleanup_targets"])
        blocked = False
        with pytest.warns(UserWarning, match="unlisted rewrite"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert second["cache_records"] == first["cache_records"]
        assert probe.exists()
        assert ghost.exists()

    def test_consume_time_evolution_holds_slot(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R13-2: a tmp evolved after verification holds its baseline."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        tmp = _plant_probe_tmp(probe, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]))
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name in {probe.name, tmp.name}:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert probe.exists()
        assert tmp.exists()
        blocked = False
        real_read_bytes = Path.read_bytes
        reads = {"count": 0}

        def _evolving_read_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if self.name == tmp.name:
                reads["count"] += 1
                if reads["count"] > 1:
                    tmp.write_text(
                        json.dumps(_probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 9]])),
                        encoding="utf-8",
                    )
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", _evolving_read_bytes)
        with pytest.warns(UserWarning, match="unadjudicated tmp"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert probe.exists(), "evolution holds the whole set"
        assert tmp.exists()

    def test_skip_hold_survives_in_staging(self, engaged: Path, tmp_path: Path) -> None:
        """#88R14-1: a skip-held parent reunites instead of skip-adopting."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            pid_b, birth_b = _dead_pid_with_birth()
            _plant_producer(
                engaged,
                uuid=_UUID_B,
                unit="b.py",
                pid=pid_b,
                birth=birth_b,
                in_progress=_counts_block(3, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=durability.birth_token_for_pid(proc.pid),
            )
            prior = _write_jsonl(
                tmp_path / "prior.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    _session_record(
                        pid,
                        _counts_block(2, fn="C_Digest"),
                        extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                    ),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="live writer"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert first["barrier_ok"] is True
            assert Path(planted["registry"]).exists()
            assert marker.exists()
            assert orphan.exists()
            staged = json.loads(
                (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
            )
            assert staged["skip_held_uuids"] == [_UUID_A]
            with pytest.warns(UserWarning, match="live writer"):
                second = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert second["barrier_ok"] is True
            assert Path(planted["registry"]).exists(), "skip-held reunites, never adopts"
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert orphan.exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            third = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert third["barrier_ok"] is True
            assert not Path(planted["registry"]).exists()
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
            assert not orphan.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_gated_retry_publishes_new_recovery_key(self, engaged: Path, tmp_path: Path) -> None:
        """#88R15-1: a heal proved after staging still publishes its key."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            nested = {"parent_uuid": "c" * 32, "probe_seq": 7}
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                lost_keys=[nested],
                pid=pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=durability.birth_token_for_pid(proc.pid),
            )
            session = _session_record(
                pid,
                _counts_block(2, fn="C_Digest"),
                extra={
                    "worker_uuid": _UUID_A,
                    "run_id": _RUN,
                    "probes_lost": 1,
                    "lost_keys": [{"parent_uuid": _UUID_A, "probe_seq": 0}],
                },
            )
            prior = _write_jsonl(
                tmp_path / "prior.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    session,
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="live writer"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert first["barrier_ok"] is True
            assert Path(planted["registry"]).exists()
            assert marker.exists()
            assert orphan.exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            second = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert second["barrier_ok"] is True
            deltas = [
                rec for rec in second["cache_records"].get("a.py", []) if rec.get("recovered_keys")
            ]
            assert len(deltas) == 1, "the newly proved heal publishes once"
            assert deltas[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert deltas[0]["total_calls"] == 0
            assert not Path(planted["registry"]).exists()
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
            assert not orphan.exists()
            stream = [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                *first["cache_records"]["a.py"],
                *second["cache_records"]["a.py"],
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ]
            payload = extract_call_counters_from_jsonl(
                _write_jsonl(tmp_path / "merged.jsonl", stream)
            )
            assert payload is not None
            assert payload["probes_lost"] == 1
            assert payload["probes_detail"] == [
                {"worker_uuid": "c" * 32, "probe_seq": 7, "status": "lost"}
            ]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_registryless_skip_held_reunites(self, engaged: Path, tmp_path: Path) -> None:
        """#88R15-2: skip-holds bind the orphan-sidecar path too."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                lost_keys=[{"parent_uuid": "c" * 32, "probe_seq": 7}],
                pid=pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=durability.birth_token_for_pid(proc.pid),
            )
            prior = _write_jsonl(
                tmp_path / "prior.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    _session_record(
                        pid,
                        _counts_block(2, fn="C_Digest"),
                        extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                    ),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="live writer"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert first["barrier_ok"] is True
            staged = json.loads(
                (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
            )
            assert staged["skip_held_uuids"] == [_UUID_A]
            Path(planted["registry"]).unlink()
            with pytest.warns(UserWarning, match="live writer"):
                second = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert second["barrier_ok"] is True
            assert Path(planted["sidecar"]).exists(), "skip-held never skip-adopts"
            assert _UUID_A in second["retained_uuids"]
            assert str(Path(planted["sidecar"])) in second["cleanup_held"]
            assert marker.exists()
            assert orphan.exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            third = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert third["barrier_ok"] is True
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
            assert not orphan.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_registryless_retry_publishes_recovery(self, engaged: Path, tmp_path: Path) -> None:
        """#88R16-1: the orphan-committed route heals like the registry one."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            nested = {"parent_uuid": "c" * 32, "probe_seq": 7}
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                lost_keys=[nested],
                pid=pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=durability.birth_token_for_pid(proc.pid),
            )
            session = _session_record(
                pid,
                _counts_block(2, fn="C_Digest"),
                extra={
                    "worker_uuid": _UUID_A,
                    "run_id": _RUN,
                    "probes_lost": 1,
                    "lost_keys": [{"parent_uuid": _UUID_A, "probe_seq": 0}],
                },
            )
            prior = _write_jsonl(
                tmp_path / "prior.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    session,
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="live writer"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert first["barrier_ok"] is True
            Path(planted["registry"]).unlink()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            second = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert second["barrier_ok"] is True
            deltas = [
                rec for rec in second["cache_records"].get("a.py", []) if rec.get("recovered_keys")
            ]
            assert len(deltas) == 1, "the registryless heal publishes once"
            assert deltas[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
            assert not orphan.exists()
            stream = [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                *first["cache_records"]["a.py"],
                *second["cache_records"]["a.py"],
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ]
            payload = extract_call_counters_from_jsonl(
                _write_jsonl(tmp_path / "merged.jsonl", stream)
            )
            assert payload is not None
            assert payload["probes_lost"] == 1
            assert payload["probes_detail"] == [
                {"worker_uuid": "c" * 32, "probe_seq": 7, "status": "lost"}
            ]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_skip_without_records_stages_hold(self, engaged: Path, tmp_path: Path) -> None:
        """#88R16-2: a record-less skip still persists its hold."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=durability.birth_token_for_pid(proc.pid),
            )
            prior = _write_jsonl(
                tmp_path / "prior.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    _session_record(
                        pid,
                        _counts_block(2, fn="C_Digest"),
                        extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                    ),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="live writer"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert first["barrier_ok"] is True
            staging = engaged / durability.BARRIER_STAGING_FILENAME
            assert staging.exists(), "skip-only staging persists the hold"
            staged = json.loads(staging.read_text(encoding="utf-8"))
            assert staged["skip_held_uuids"] == [_UUID_A]
            assert staged["cache_records"] == {}
            Path(planted["registry"]).unlink()
            with pytest.warns(UserWarning, match="live writer"):
                second = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert second["barrier_ok"] is True
            assert proc.poll() is None, "committed reunion skips, never fences"
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert orphan.exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            third = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert third["barrier_ok"] is True
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
            assert not orphan.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_committed_orphan_never_fences_live_writer(self, engaged: Path, tmp_path: Path) -> None:
        """#88R16-2: committed sessions skip live writers on every route."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=durability.birth_token_for_pid(proc.pid),
            )
            prior = _write_jsonl(
                tmp_path / "prior.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    _session_record(
                        pid,
                        _counts_block(2, fn="C_Digest"),
                        extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                    ),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            Path(planted["registry"]).unlink()
            with pytest.warns(UserWarning, match="live writer"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
            assert plan["barrier_ok"] is True
            assert proc.poll() is None, "no fence on a committed route"
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert orphan.exists()
            assert _UUID_A in plan["retained_uuids"]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_rejected_replay_read_stages_nothing(self, engaged: Path) -> None:
        """#88R16-3: a gate-rejected tmp never inherits authorization."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        foreign = _plant_probe_tmp(
            probe,
            _probe_tmp_payload("c" * 32, 0, [["m", "C_Digest", 0, 9]], parent_uuid=_UUID_A),
        )
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert probe.exists(), "the foreign rewrite holds its slot"
        assert foreign.exists()
        assert plan["cleanup_held"] != []
        staged = json.loads(
            (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
        )
        listed = {entry["path"] for entry in staged["cleanup_targets"]}
        assert str(foreign) not in listed

    def test_orphan_committed_never_heals_uncovered(self, engaged: Path, tmp_path: Path) -> None:
        """#88R17-1: registryless committed routes never heal uncovered orphans."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        session = _session_record(
            pid,
            _counts_block(2, fn="C_Digest"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 1,
                "lost_keys": [{"parent_uuid": _UUID_A, "probe_seq": 0}],
            },
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        Path(planted["registry"]).unlink()
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        assert plan["barrier_ok"] is True
        for rec in plan["cache_records"].get("a.py", []):
            assert rec.get("recovered_keys") in (None, [])
        assert not Path(planted["sidecar"]).exists()
        assert not orphan.exists()
        stream = [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            session,
            *plan["cache_records"]["a.py"],
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ]
        payload = extract_call_counters_from_jsonl(_write_jsonl(tmp_path / "merged.jsonl", stream))
        assert payload is not None
        assert payload["total_calls"] == 2, "session supersedes the refold"
        assert payload["complete"] is False
        assert payload["probes_lost"] == 1

    def test_collect_unit_orphan_committed_skips_live_writer(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R17-2: unit cleanup never fences a committed live writer."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            child = _committed_child(tmp_path, pid, _counts_block(10))
            Path(planted["registry"]).unlink()
            with pytest.warns(UserWarning, match="live writer"):
                durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert proc.poll() is None, "committed reunion skips, never fences"
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert orphan.exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            assert retry != []
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
            assert not orphan.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_collect_unit_orphan_committed_defers_live_uncovered(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R17-2: uncovered live writers defer on the orphan route too."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            child = _committed_child(tmp_path, pid, _counts_block(10))
            Path(planted["registry"]).unlink()
            with pytest.warns(UserWarning, match="deferred"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == []
            assert proc.poll() is None
            assert Path(planted["sidecar"]).exists()
            assert orphan.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_slot_scan_never_authorizes_rejected_returns(self, engaged: Path) -> None:
        """#88R17-3: a foreign complete tmp stays unauthored even when scanned."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        foreign = _plant_probe_tmp(
            probe,
            _probe_tmp_payload("c" * 32, 0, [["m", "C_Digest", 0, 9]], parent_uuid=_UUID_A),
        )
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert marker.exists(), "unresolved recovery withholds the marker"
        assert probe.exists(), "the rejected rewrite holds its slot"
        assert foreign.exists()
        assert plan["cleanup_held"] != []
        staged = json.loads(
            (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
        )
        listed = {entry["path"] for entry in staged["cleanup_targets"]}
        assert str(foreign) not in listed

    def test_committed_marker_with_live_writer_skips(self, engaged: Path, tmp_path: Path) -> None:
        """#88R17-4: a live marker writer withholds recovery on committed paths."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
            tmp = slot.with_name(f"{slot.name}.tmp-4242")
            tmp.write_text("{torn", encoding="utf-8")
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="live writer"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == [], "the heal waits for quiescence"
            assert proc.poll() is None
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert tmp.exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            partials = [rec for rec in retry if rec["$report_type"] == "CallCountersPartial"]
            assert len(partials) == 1
            assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert not Path(planted["registry"]).exists()
            assert not Path(planted["sidecar"]).exists()
            assert not marker.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_postmortem_marker_with_live_writer_fences(self, engaged: Path) -> None:
        """#88R17-4: postmortem fences a live marker writer before healing."""
        proc = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=birth,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            records = _collect_crashed88(engaged, engaged / "child.jsonl")
            assert proc.poll() is not None, "postmortem fences first"
            partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
            assert len(partials) == 1
            assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert not marker.exists()
            assert not Path(planted["registry"]).exists()
            assert not Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_withheld_marker_reconciles_after_replay(self, engaged: Path, tmp_path: Path) -> None:
        """#88R18-1: a replay-proved slot releases its marker in one pass."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        tmp = _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        assert not marker.exists(), "replay proof reconciles the withhold"
        assert not orphan.exists()
        assert not tmp.exists()

    def test_live_marker_holds_its_slot(self, engaged: Path, tmp_path: Path) -> None:
        """#88R18-2: a live marker's hold covers its baseline and tmps."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
            assert orphan == slot
            tmp = slot.with_name(f"{slot.name}.tmp-4242")
            tmp.write_text("{torn", encoding="utf-8")
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="live writer"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == []
            assert proc.poll() is None
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert orphan.exists(), "the stale baseline waits with its marker"
            assert tmp.exists(), "the slot tmp waits with its marker"
            tmp.write_text(
                json.dumps(_probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]])),
                encoding="utf-8",
            )
            os.replace(tmp, slot)
            proc.kill()
            assert proc.wait(timeout=30) is not None
            with pytest.warns(UserWarning, match="rewrite newer than marker coverage"):
                retry = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert retry == []
            assert marker.exists()
            assert slot.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_live_marker_hold_covers_torn_baseline(self, engaged: Path, tmp_path: Path) -> None:
        """#88R19-2: a torn baseline at a held slot waits with its marker."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            orphan = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
            assert orphan == slot
            saved = slot.read_text(encoding="utf-8")
            slot.write_text("{torn", encoding="utf-8")
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="live writer"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == []
            assert proc.poll() is None
            assert slot.exists(), "the torn baseline waits with its live marker"
            assert marker.exists()
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
            slot.write_text(saved, encoding="utf-8")
            proc.kill()
            assert proc.wait(timeout=30) is not None
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            partials = [rec for rec in retry if rec["$report_type"] == "CallCountersPartial"]
            assert len(partials) == 1
            assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert not marker.exists()
            assert not slot.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_withheld_marker_ignores_torn_baseline(self, engaged: Path, tmp_path: Path) -> None:
        """#88R19-1: a debris-consumed baseline proves no receipt."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        slot.write_text("{torn", encoding="utf-8")
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert marker.exists(), "a torn baseline proves nothing about the marker's receipt"
        assert tmp.exists()
        assert slot.exists(), "the unadjudicated tmp holds its baseline for retry"
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_withheld_marker_ignores_foreign_receipt_baseline(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R19-1: a baseline proving another receipt releases nothing."""
        child_c = "c" * 32
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows_b = [["m", "C_Digest", 0, 1]]
        rows_c = [["m", "C_Digest", 0, 2]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows_b],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            child_uuid=child_c,
            counters=[list(row) for row in rows_c],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        assert baseline == slot
        _plant_probe_tmp(baseline, _probe_tmp_payload(child_c, 0, [list(row) for row in rows_c]))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["receipts"] == [{"worker_uuid": child_c, "probe_seq": 0}]
        assert partials[0].get("recovered_keys", []) == []
        assert marker.exists(), "the foreign receipt's fold proves nothing here"
        assert Path(planted["registry"]).exists()

    def test_withheld_marker_waits_for_refused_rewrite(self, engaged: Path, tmp_path: Path) -> None:
        """#88R19-1: an unadjudicated rewrite blocks the reconcile."""
        child_c = "c" * 32
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        tmp = _plant_probe_tmp(orphan, _probe_tmp_payload(child_c, 0, [list(row) for row in rows]))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert marker.exists(), "the refused rewrite stays undecided"
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_changed_marker_rolls_back_receipt_heal(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R19-3: a copy that withholds withdraws its receipt's heal."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            rows = [["m", "C_Digest", None, 1]]
            first_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="aaaa1111",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            first = first_src.with_name(first_src.name.replace("probe-", "probe-consumed-", 1))
            first_src.rename(first)
            second_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="ffff2222",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            second = second_src.with_name(second_src.name.replace("probe-", "probe-consumed-", 1))
            second_src.rename(second)
            assert first.name < second.name
            live_payload = json.loads(second.read_text(encoding="utf-8"))
            live_payload["pid"] = proc.pid
            live_text = json.dumps(live_payload)
            real_read = durability._read_json_evidence_digested
            flipped = False

            def _flipping_read(path: Path) -> tuple[str, Any | None, str | None]:
                nonlocal flipped
                if path == second and not flipped:
                    flipped = True
                    second.write_text(live_text, encoding="utf-8")
                return real_read(path)

            monkeypatch.setattr(durability, "_read_json_evidence_digested", _flipping_read)
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="recovery withheld"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert flipped, "the mid-pass rewrite must have landed"
            assert records == []
            assert first.exists(), "the early heal rolls back with its receipt"
            assert second.exists()
            assert Path(planted["registry"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_live_slot_blocks_receipt_reconcile(self, engaged: Path, tmp_path: Path) -> None:
        """#88R19-5: a receipt-level hold survives the reconcile."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            rows = [["m", "C_Digest", 0, 1]]
            first_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="aaaa1111",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            first = first_src.with_name(first_src.name.replace("probe-", "probe-consumed-", 1))
            first_src.rename(first)
            slot_a = engaged / f"probe-{_UUID_A[:8]}-0-aaaa1111.json"
            baseline_a = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="aaaa1111",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            assert baseline_a == slot_a
            rewrite = _plant_probe_tmp(
                baseline_a, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows])
            )
            second_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="bbbb2222",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            second = second_src.with_name(second_src.name.replace("probe-", "probe-consumed-", 1))
            second_src.rename(second)
            slot_b = engaged / f"probe-{_UUID_A[:8]}-0-bbbb2222.json"
            baseline_b = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="bbbb2222",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            assert baseline_b == slot_b
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="live writer"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == []
            assert first.exists(), "the pinned receipt keeps its marker"
            assert second.exists(), "the rolled-back heal un-consumes its marker"
            assert baseline_b.exists()
            assert not rewrite.exists(), "the replayed rewrite still prunes"
            assert not baseline_a.exists(), "the proved suppression stands; only the heal waits"
            assert Path(planted["registry"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_foreign_markers_cannot_hold_owned_receipt(self, engaged: Path, tmp_path: Path) -> None:
        """#88R19-4: only valid, owned markers feed receipt-level holds."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            rows = [["m", "C_Digest", None, 1]]
            owned_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            owned = owned_src.with_name(owned_src.name.replace("probe-", "probe-consumed-", 1))
            owned_src.rename(owned)
            foreign_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="aaaa1111",
                counters=[list(row) for row in rows],
                identity={**_f2_identity("f" * 32), "run_id": _RUN, "unit": "a.py"},
                pid=proc.pid,
                birth=None,
            )
            foreign = engaged / f"probe-consumed-{_UUID_A}-0-aaaa1111.json"
            foreign_src.rename(foreign)
            stray_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="bbbb2222",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A, run_id="R2"),
                pid=proc.pid,
                birth=None,
            )
            stray = stray_src.with_name(stray_src.name.replace("probe-", "probe-consumed-", 1))
            stray_src.rename(stray)
            invalid_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="cccc3333",
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            invalid = invalid_src.with_name(
                invalid_src.name.replace("probe-", "probe-consumed-", 1)
            )
            invalid_src.rename(invalid)
            broken = json.loads(invalid.read_text(encoding="utf-8"))
            del broken["counters"]
            invalid.write_text(json.dumps(broken), encoding="utf-8")
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="cross-run"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert proc.poll() is None
            partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
            assert len(partials) == 1
            assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert not owned.exists(), "foreign noise must not block the owned copy"
            assert foreign.exists(), "foreign markers retain silently"
            assert stray.exists(), "cross-run markers retain loudly"
            assert not invalid.exists(), "invalid markers stay debris"
            assert not Path(planted["registry"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_postmortem_holds_parents_for_unresolved_marker(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R19-6: an unreconciled marker keeps its retry route on the dead path."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        partial, lost = records
        assert lost["end_state"] == "killed"
        assert partial.get("recovered_keys", []) == []
        assert marker.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists(), "the skip holds its parents"
        assert Path(planted["sidecar"]).exists()
        _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        with pytest.warns(UserWarning, match="recovery withheld"):
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        partials = [rec for rec in retry if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0].get("recovered_keys", []) == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert not marker.exists()
        assert not Path(planted["registry"]).exists()

    def test_barrier_holds_dead_parents_for_unresolved_marker(self, engaged: Path) -> None:
        """#88R19-6: the resume barrier retains dead parents behind a skip."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        with pytest.warns(UserWarning, match="recovery withheld"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert _UUID_A in plan["retained_uuids"]
        assert str(Path(planted["registry"])) in plan["cleanup_held"]
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()
        assert marker.exists()
        assert tmp.exists()

    def test_barrier_holds_fenced_parents_for_unresolved_marker(self, engaged: Path) -> None:
        """#88R19-6: freshly fenced parents keep their hold the same way."""
        proc = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            dead, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=proc.pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            rows = [["m", "C_Digest", 0, 1]]
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=dead,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
            tmp = _plant_probe_tmp(
                slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows])
            )
            with pytest.warns(UserWarning, match="recovery withheld"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert proc.wait(timeout=30) is not None
            assert _UUID_A in plan["retained_uuids"]
            assert str(Path(planted["registry"])) in plan["cleanup_held"]
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
            assert marker.exists()
            assert tmp.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_contradictory_markers_block_reconcile(self, engaged: Path, tmp_path: Path) -> None:
        """#88R20-1: a receipt whose copies disagree never reconciles."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows_entry = [["m", "C_Digest", None, 1]]
        rows_cancel = [["m", "C_Digest", 1, 1]]  # CKR_CANCEL
        final_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[list(row) for row in rows_entry],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        final = final_src.with_name(final_src.name.replace("probe-", "probe-consumed-", 1))
        final_src.rename(final)
        slot_a = engaged / f"probe-{_UUID_A[:8]}-0-aaaa1111.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[list(row) for row in rows_entry],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot_a
        tmp = _plant_probe_tmp(
            baseline, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows_cancel])
        )
        live_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="bbbb2222",
            counters=[list(row) for row in rows_cancel],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        live = live_src.with_name(live_src.name.replace("probe-", "probe-consumed-", 1))
        live_src.rename(live)
        midrun = json.loads(live.read_text(encoding="utf-8"))
        midrun["finalized"] = False
        live.write_text(json.dumps(midrun), encoding="utf-8")
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="contradictory"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert final.exists()
        assert live.exists()
        assert baseline.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_contradictory_markers_withdraw_direct_heal(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R20-1: a contradictory copy withdraws the early heal."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        first_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        first = first_src.with_name(first_src.name.replace("probe-", "probe-consumed-", 1))
        first_src.rename(first)
        second_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="bbbb2222",
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        second = second_src.with_name(second_src.name.replace("probe-", "probe-consumed-", 1))
        second_src.rename(second)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="contradictory"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert first.exists(), "the early heal rolls back with its receipt"
        assert second.exists()
        assert Path(planted["registry"]).exists()

    def test_identical_duplicate_markers_heal_together(self, engaged: Path, tmp_path: Path) -> None:
        """#88R20-1 control: coherent duplicates resolve normally."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", None, 1]]
        for nonce in ("aaaa1111", "bbbb2222"):
            src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce=nonce,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            src.rename(src.with_name(src.name.replace("probe-", "probe-consumed-", 1)))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert not list(engaged.glob("probe-consumed-*.json"))
        assert not Path(planted["registry"]).exists()

    def test_held_co_slot_blocks_clean_copy(self, engaged: Path, tmp_path: Path) -> None:
        """#88R20-2: every slot in the receipt group must resolve first."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        held_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        held = held_src.with_name(held_src.name.replace("probe-", "probe-consumed-", 1))
        held_src.rename(held)
        slot_a = engaged / f"probe-{_UUID_A[:8]}-0-aaaa1111.json"
        tmp = _plant_probe_tmp(slot_a, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        clean_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="bbbb2222",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        clean = clean_src.with_name(clean_src.name.replace("probe-", "probe-consumed-", 1))
        clean_src.rename(clean)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert held.exists()
        assert clean.exists(), "the clean copy waits for its receipt group"
        assert tmp.exists()
        assert Path(planted["registry"]).exists()
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot_a
        with pytest.warns(UserWarning, match="unresolved rewrite"):
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        partials = [rec for rec in retry if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert not held.exists(), "the adjudicated rewrite clears its own hold"
        assert not baseline.exists()
        assert not tmp.exists()
        assert clean.exists(), "the clean copy saw the hold at marker time"
        assert Path(planted["registry"]).exists()
        final = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in final if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert not clean.exists()
        assert not Path(planted["registry"]).exists()

    def test_clean_copy_heal_withdrawn_by_later_hold(self, engaged: Path, tmp_path: Path) -> None:
        """#88R20-2: a later hold withdraws the early group heal."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        clean_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        clean = clean_src.with_name(clean_src.name.replace("probe-", "probe-consumed-", 1))
        clean_src.rename(clean)
        held_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="ffff2222",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        held = held_src.with_name(held_src.name.replace("probe-", "probe-consumed-", 1))
        held_src.rename(held)
        slot_f = engaged / f"probe-{_UUID_A[:8]}-0-ffff2222.json"
        tmp = _plant_probe_tmp(slot_f, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert clean.exists(), "the early heal rolls back with its receipt"
        assert held.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_torn_marker_hold_blocks_same_seq_heal(self, engaged: Path, tmp_path: Path) -> None:
        """#88R20-2: an undecidable marker's hold blocks its seq conservatively."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        torn = engaged / f"probe-consumed-{_UUID_A[:8]}-0-tttt4444.json"
        torn.write_text("{torn", encoding="utf-8")
        slot_t = engaged / f"probe-{_UUID_A[:8]}-0-tttt4444.json"
        tmp = _plant_probe_tmp(slot_t, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        clean_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="cccc3333",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        clean = clean_src.with_name(clean_src.name.replace("probe-", "probe-consumed-", 1))
        clean_src.rename(clean)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert clean.exists(), "the unknown receipt may be this one"
        assert torn.exists(), "the unadjudicated tmp holds its marker"
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_registryless_postmortem_holds_sidecar_for_unresolved_marker(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R20-5: the orphan-sidecar dead route keeps its retry route too."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        Path(planted["registry"]).unlink()
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert marker.exists()
        assert tmp.exists()
        assert Path(planted["sidecar"]).exists(), "the skip holds its sidecar"

    def _plant_unflushed_spawn(self, engaged: Path, planted: dict[str, Any], proc: Any) -> None:
        """Add a live unflushed spawn record to a planted sidecar (#88R22-4)."""
        birth = durability.birth_token_for_pid(proc.pid)
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        assert not slot.exists()
        entry: dict[str, Any] = {"probe_seq": 1, "slot": str(slot), "pid": proc.pid}
        if birth is not None:
            entry["birth_token"] = birth
        sidecar_path = Path(planted["sidecar"])
        payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
        payload["spawned_children"] = [entry]
        sidecar_path.write_text(json.dumps(payload), encoding="utf-8")

    def test_unit_dead_defers_while_child_unflushed(self, engaged: Path, tmp_path: Path) -> None:
        """#88R22-4: postmortem waits for unflushed children (unit route)."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            self._plant_unflushed_spawn(engaged, planted, proc)
            child = _write_jsonl(
                tmp_path / "child.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    {
                        "$report_type": "TestReport",
                        "nodeid": "a.py::test_first",
                        "when": "setup",
                        "outcome": "passed",
                    },
                ],
            )
            with pytest.warns(UserWarning, match="unflushed"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
                )
            assert records == []
            assert proc.poll() is None
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_registryless_dead_defers_while_child_unflushed(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R22-4: orphan postmortem waits too (unit route)."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            self._plant_unflushed_spawn(engaged, planted, proc)
            Path(planted["registry"]).unlink()
            child = _write_jsonl(
                tmp_path / "child.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    {
                        "$report_type": "TestReport",
                        "nodeid": "a.py::test_first",
                        "when": "setup",
                        "outcome": "passed",
                    },
                ],
            )
            with pytest.warns(UserWarning, match="unflushed"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
                )
            assert records == []
            assert proc.poll() is None
            assert Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_barrier_dead_defers_while_child_unflushed(self, engaged: Path) -> None:
        """#88R22-4: barrier reunion waits for unflushed children."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            self._plant_unflushed_spawn(engaged, planted, proc)
            with pytest.warns(UserWarning, match="unflushed"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert _UUID_A in plan["unresolved"]
            assert proc.poll() is None
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_registryless_barrier_holds_sidecar_for_unresolved_marker(self, engaged: Path) -> None:
        """#88R20-5: the resume orphan route retains behind a skip."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        Path(planted["registry"]).unlink()
        with pytest.warns(UserWarning, match="recovery withheld"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert _UUID_A in plan["retained_uuids"]
        assert str(Path(planted["sidecar"])) in plan["cleanup_held"]
        assert Path(planted["sidecar"]).exists()
        assert marker.exists()
        assert tmp.exists()

    def test_barrier_dead_retry_publishes_recovery_delta(self, engaged: Path) -> None:
        """#88R20-4: a held dead producer's later recovery still publishes."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        with pytest.warns(UserWarning, match="recovery withheld"):
            first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert _UUID_A in first["retained_uuids"]
        assert Path(planted["registry"]).exists()
        _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        with pytest.warns(UserWarning, match="recovery withheld"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        deltas = [
            rec for rec in second["cache_records"].get("a.py", []) if rec.get("recovered_keys")
        ]
        assert len(deltas) == 1, "the retry heal publishes once as a delta"
        assert deltas[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert deltas[0]["total_calls"] == 0, "counts never ride a delta"
        assert not marker.exists()
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()

    def test_barrier_fenced_retry_publishes_recovery_delta(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R20-4: the fenced route deltas like the dead one."""
        proc = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            dead, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=proc.pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            rows = [["m", "C_Digest", 0, 1]]
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=dead,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
            _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
            _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=1,
                counters=[["m", "C_Digest", 0, 3]],
                identity=_f2_identity(_UUID_A),
                pid=dead,
                birth=None,
            )
            session = _session_record(
                proc.pid,
                _counts_block(2, fn="C_Digest"),
                extra={"worker_uuid": _UUID_A, "run_id": _RUN},
            )
            prior1 = _write_jsonl(
                tmp_path / "prior1.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    session,
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="recovery withheld"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=prior1)
            assert _UUID_A in first["retained_uuids"]
            assert proc.poll() is None, "the committed route never fences"
            assert Path(planted["registry"]).exists()
            _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=dead,
                birth=None,
            )
            prior2 = _write_jsonl(
                tmp_path / "prior2.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
            with pytest.warns(UserWarning, match="recovery withheld"):
                second = durability.prepare_resume(engaged, prior_merged_jsonl=prior2)
            assert proc.wait(timeout=30) is not None, "the retry fences"
            deltas = [
                rec for rec in second["cache_records"].get("a.py", []) if rec.get("recovered_keys")
            ]
            assert len(deltas) == 1, "the fenced heal publishes once as a delta"
            assert deltas[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert deltas[0]["total_calls"] == 0
            assert not marker.exists()
            assert not Path(planted["registry"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_registryless_barrier_retry_publishes_recovery_delta(self, engaged: Path) -> None:
        """#88R20-4: the orphan dead route deltas too."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        Path(planted["registry"]).unlink()
        with pytest.warns(UserWarning, match="recovery withheld"):
            first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert _UUID_A in first["retained_uuids"]
        assert Path(planted["sidecar"]).exists()
        _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        with pytest.warns(UserWarning, match="recovery withheld"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        deltas = [
            rec for rec in second["cache_records"].get("a.py", []) if rec.get("recovered_keys")
        ]
        assert len(deltas) == 1, "the orphan retry heal publishes once as a delta"
        assert deltas[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert deltas[0]["total_calls"] == 0, "counts never ride a delta"
        assert not marker.exists()
        assert not Path(planted["sidecar"]).exists()

    def test_reconcile_binds_proof_to_receipt(self, engaged: Path, tmp_path: Path) -> None:
        """#88R21-1/#88R22-1: aliased slots freeze instead of healing by turns."""
        child_c = "c" * 32
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        legacy_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            child_uuid=_UUID_B,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        legacy = legacy_src.with_name(legacy_src.name.replace("probe-", "probe-consumed-", 1))
        legacy_src.rename(legacy)
        midrun = json.loads(legacy.read_text(encoding="utf-8"))
        midrun["finalized"] = False
        legacy.write_text(json.dumps(midrun), encoding="utf-8")
        full_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            child_uuid=child_c,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        full = engaged / f"probe-consumed-{_UUID_A}-0-feedface.json"
        full_src.rename(full)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        assert legacy.name != full.name
        assert durability._marker_slot_name(legacy.name) == slot.name
        assert durability._marker_slot_name(full.name) == slot.name
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            child_uuid=_UUID_B,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert full.exists(), "the foreign receipt borrows no proof"
        assert legacy.exists(), "aliased evidence retains for forensics"
        assert baseline.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()
        with pytest.warns(UserWarning, match="recovery withheld"):
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert retry == [], "the freeze is idempotent, never a slow heal"
        assert full.exists()
        assert legacy.exists()
        assert baseline.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_clean_aliased_markers_freeze_at_finalize(self, engaged: Path, tmp_path: Path) -> None:
        """#88R22-1: aliased slots freeze even with no rewrite in sight."""
        child_c = "c" * 32
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        legacy_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            child_uuid=_UUID_B,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        legacy = legacy_src.with_name(legacy_src.name.replace("probe-", "probe-consumed-", 1))
        legacy_src.rename(legacy)
        full_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            child_uuid=child_c,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        full = engaged / f"probe-consumed-{_UUID_A}-0-feedface.json"
        full_src.rename(full)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="another receipt"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert legacy.exists()
        assert full.exists()
        assert Path(planted["registry"]).exists()

    def test_contradictory_live_marker_registers_slot_hold(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R21-5: a live slot stays held even when its counts are contested."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            first_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="aaaa1111",
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            first = first_src.with_name(first_src.name.replace("probe-", "probe-consumed-", 1))
            first_src.rename(first)
            second_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="bbbb2222",
                counters=[["m", "C_Digest", 0, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            second = second_src.with_name(second_src.name.replace("probe-", "probe-consumed-", 1))
            second_src.rename(second)
            slot_b = engaged / f"probe-{_UUID_A[:8]}-0-bbbb2222.json"
            slot_b.write_text("{torn", encoding="utf-8")
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="contradictory"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == []
            assert proc.poll() is None
            assert first.exists()
            assert second.exists()
            assert slot_b.exists(), "the live writer may still publish here"
            assert Path(planted["registry"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_garbage_rows_break_coherence(self, engaged: Path, tmp_path: Path) -> None:
        """#88R21-6: malformed rows never read as an empty snapshot."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        empty_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        empty = empty_src.with_name(empty_src.name.replace("probe-", "probe-consumed-", 1))
        empty_src.rename(empty)
        midrun = json.loads(empty.read_text(encoding="utf-8"))
        midrun["finalized"] = False
        empty.write_text(json.dumps(midrun), encoding="utf-8")
        garbage_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="bbbb2222",
            counters=[["m", "C_Digest", 0, True]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        garbage = garbage_src.with_name(garbage_src.name.replace("probe-", "probe-consumed-", 1))
        garbage_src.rename(garbage)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="contradictory"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert empty.exists()
        assert garbage.exists()
        assert Path(planted["registry"]).exists()

    def test_identical_garbage_never_heals(self, engaged: Path, tmp_path: Path) -> None:
        """#88R21-6: agreed corruption still proves nothing."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, True]]
        for nonce in ("aaaa1111", "bbbb2222"):
            src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce=nonce,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            src.rename(src.with_name(src.name.replace("probe-", "probe-consumed-", 1)))
        child = _committed_child(tmp_path, pid, _counts_block(10))
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert records == []
        assert len(list(engaged.glob("probe-consumed-*.json"))) == 2
        assert Path(planted["registry"]).exists()

    def test_finalize_catches_late_torn_hold(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R21-2: a hold recorded anywhere blocks every affected heal."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        clean_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="cccc3333",
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        clean = clean_src.with_name(clean_src.name.replace("probe-", "probe-consumed-", 1))
        clean_src.rename(clean)
        torn = engaged / f"probe-consumed-{_UUID_A[:8]}-0-tttt4444.json"
        torn.write_text("{torn", encoding="utf-8")
        slot_t = engaged / f"probe-{_UUID_A[:8]}-0-tttt4444.json"
        tmp = _plant_probe_tmp(slot_t, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        real_list_tmps = durability._list_tmp_paths
        calls = 0

        def _hiding_list_tmps(directory: Path, prefix: str) -> list[Path] | None:
            nonlocal calls
            if prefix == f"{slot_t.name}.tmp-":
                calls += 1
                if calls == 1:
                    return []
            return real_list_tmps(directory, prefix)

        monkeypatch.setattr(durability, "_list_tmp_paths", _hiding_list_tmps)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert calls >= 2, "the rewrite must surface mid-pass"
        assert records == []
        assert clean.exists(), "the late hold blocks the early copy"
        assert torn.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_finalize_withholds_late_admitted_rewrite(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R21-2: a rewrite landing after its turn withholds at finalize."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        real_list_tmps = durability._list_tmp_paths
        calls = 0

        def _hiding_list_tmps(directory: Path, prefix: str) -> list[Path] | None:
            nonlocal calls
            if prefix == f"{slot.name}.tmp-":
                calls += 1
                if calls <= 2:
                    return []
            return real_list_tmps(directory, prefix)

        monkeypatch.setattr(durability, "_list_tmp_paths", _hiding_list_tmps)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="keeps an unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert calls >= 3, "the rewrite must surface at finalize"
        assert records == []
        assert marker.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_contradiction_preserves_live_writer_postmortem(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R22-5: contested groups keep their writers and evidence."""
        proc = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            live_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="aaaa1111",
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=birth,
            )
            live = live_src.with_name(live_src.name.replace("probe-", "probe-consumed-", 1))
            live_src.rename(live)
            dead_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="bbbb2222",
                counters=[["m", "C_Digest", 0, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            dead = dead_src.with_name(dead_src.name.replace("probe-", "probe-consumed-", 1))
            dead_src.rename(dead)
            slot_a = engaged / f"probe-{_UUID_A[:8]}-0-aaaa1111.json"
            slot_a.write_text("{torn", encoding="utf-8")
            tmp = _plant_probe_tmp(
                slot_a, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]])
            )
            child = _write_jsonl(
                tmp_path / "child.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    {
                        "$report_type": "TestReport",
                        "nodeid": "a.py::test_first",
                        "when": "setup",
                        "outcome": "passed",
                    },
                ],
            )
            with pytest.warns(UserWarning, match="contradictory"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
                )
            assert [rec["$report_type"] for rec in records] == [
                "CallCountersPartial",
                "CallCountersLost",
            ]
            assert proc.poll() is None, "contested writers are never fenced"
            assert live.exists()
            assert dead.exists()
            assert slot_a.exists()
            assert tmp.exists()
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_garbage_baseline_blocks_suppression_heal(self, engaged: Path, tmp_path: Path) -> None:
        """#88R22-6: corrupt baselines wait instead of proving recovery."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows] + [["m", "C_Digest", 0, True]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="malformed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert marker.exists()
        assert baseline.exists(), "the corrupt baseline waits for forensics"
        assert Path(planted["registry"]).exists()

    def test_garbage_tmp_rewrite_is_refused(self, engaged: Path, tmp_path: Path) -> None:
        """#88R22-6: malformed rewrites never replay into proof."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        tmp = _plant_probe_tmp(
            orphan,
            _probe_tmp_payload(
                _UUID_B, 0, [list(row) for row in rows] + [["m", "C_Digest", 0, True]]
            ),
        )
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="malformed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert marker.exists(), "the refused rewrite blocks the reconcile"
        assert orphan.exists(), "the refused rewrite holds its baseline"
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_malformed_scalar_breaks_coherence(self, engaged: Path, tmp_path: Path) -> None:
        """#88R22-6: loss-scalar validity joins the coherence fingerprint."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        clean_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="aaaa1111",
            counters=[],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        clean = clean_src.with_name(clean_src.name.replace("probe-", "probe-consumed-", 1))
        clean_src.rename(clean)
        midrun = json.loads(clean.read_text(encoding="utf-8"))
        midrun["finalized"] = False
        clean.write_text(json.dumps(midrun), encoding="utf-8")
        dirty_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            nonce="bbbb2222",
            counters=[],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        dirty = dirty_src.with_name(dirty_src.name.replace("probe-", "probe-consumed-", 1))
        dirty_src.rename(dirty)
        payload = json.loads(dirty.read_text(encoding="utf-8"))
        payload["probes_lost"] = True
        dirty.write_text(json.dumps(payload), encoding="utf-8")
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="contradictory"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert clean.exists()
        assert dirty.exists()
        assert Path(planted["registry"]).exists()

    def test_identical_malformed_scalars_never_heal(self, engaged: Path, tmp_path: Path) -> None:
        """#88R22-6: agreed-invalid scalars still prove nothing."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        for nonce in ("aaaa1111", "bbbb2222"):
            src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce=nonce,
                counters=[],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            marker = src.with_name(src.name.replace("probe-", "probe-consumed-", 1))
            src.rename(marker)
            payload = json.loads(marker.read_text(encoding="utf-8"))
            payload["probes_lost"] = True
            marker.write_text(json.dumps(payload), encoding="utf-8")
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="malformed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert len(list(engaged.glob("probe-consumed-*.json"))) == 2
        assert Path(planted["registry"]).exists()

    def test_finalize_sees_post_replay_rewrite(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R22-2: group truth finalizes after orphan reads and replay."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        real_list_tmps = durability._list_tmp_paths
        calls = 0

        def _hiding_list_tmps(directory: Path, prefix: str) -> list[Path] | None:
            nonlocal calls
            if prefix == f"{slot.name}.tmp-":
                calls += 1
                if calls <= 3:
                    return []
            return real_list_tmps(directory, prefix)

        monkeypatch.setattr(durability, "_list_tmp_paths", _hiding_list_tmps)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert calls >= 4, "the rewrite must surface after replay"
        assert records == []
        assert marker.exists(), "the late rewrite withholds at finalize"
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    def test_vanished_rewrite_keeps_its_hold(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R22-3: observed return evidence needs a proved disposition."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        real_list_tmps = durability._list_tmp_paths
        calls = 0

        def _vanishing_list_tmps(directory: Path, prefix: str) -> list[Path] | None:
            nonlocal calls
            if prefix == f"{slot.name}.tmp-":
                calls += 1
                if calls >= 4:
                    return []
            return real_list_tmps(directory, prefix)

        monkeypatch.setattr(durability, "_list_tmp_paths", _vanishing_list_tmps)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert calls >= 4, "the rewrite must vanish after adjudication"
        assert records == []
        assert marker.exists(), "a vanish is not a proof of landing"
        assert Path(planted["registry"]).exists()

    def test_early_vanish_withholds_at_withhold_check(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R22-3: a rewrite vanishing mid-turn holds instead of clearing."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows]))
        real_list_tmps = durability._list_tmp_paths
        calls = 0

        def _vanishing_list_tmps(directory: Path, prefix: str) -> list[Path] | None:
            nonlocal calls
            if prefix == f"{slot.name}.tmp-":
                calls += 1
                if calls >= 2:
                    return []
            return real_list_tmps(directory, prefix)

        monkeypatch.setattr(durability, "_list_tmp_paths", _vanishing_list_tmps)
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="keeps an unresolved rewrite"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert calls >= 2, "the rewrite must vanish after coverage"
        assert records == []
        assert marker.exists()
        assert tmp.exists()
        assert Path(planted["registry"]).exists()

    @pytest.mark.parametrize(
        "shape, expect_outstanding",
        [
            ("flushed_live", False),
            ("unflushed_live", True),
            ("unflushed_dead", False),
            ("unflushed_recycled", False),
            ("unflushed_birthless_live", True),
            ("unflushed_birthless_dead", False),
            ("malformed_entry", True),
            ("malformed_field", True),
            ("no_sidecar", False),
            ("no_field", False),
        ],
    )
    def test_unflushed_live_spawns_table(
        self, tmp_path: Path, shape: str, expect_outstanding: bool
    ) -> None:
        """#88R22-4: only live unflushed spawns defer postmortem."""
        proc = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            dead, dead_birth = _dead_pid_with_birth()
            slot = tmp_path / "probe-aaaaaaaa-0-0-feedface.json"
            entry: Any = {"probe_seq": 0, "slot": str(slot)}
            if shape == "flushed_live":
                slot.write_text("{}", encoding="utf-8")
                entry.update({"pid": proc.pid, "birth_token": birth})
            elif shape == "unflushed_live":
                entry.update({"pid": proc.pid, "birth_token": birth})
            elif shape == "unflushed_dead":
                entry.update({"pid": dead, "birth_token": dead_birth})
            elif shape == "unflushed_recycled":
                entry.update({"pid": proc.pid, "birth_token": (birth or 0) + 1})
            elif shape == "unflushed_birthless_live":
                entry.update({"pid": proc.pid})
            elif shape == "unflushed_birthless_dead":
                entry.update({"pid": dead})
            elif shape == "malformed_entry":
                entry = {"probe_seq": "zero"}
            if shape == "no_sidecar":
                sidecar = None
            elif shape == "malformed_field":
                sidecar = {"spawned_children": {"nope": True}}
            elif shape == "no_field":
                sidecar = {"worker_uuid": _UUID_A}
            else:
                sidecar = {"spawned_children": [entry]}
            if shape == "unflushed_recycled" and birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            outstanding = durability._unflushed_live_spawns(_UUID_A, sidecar, tmp_path)
            assert (len(outstanding) > 0) == expect_outstanding
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_probe_spawn_recorded_and_forgotten(self, engaged: Path) -> None:
        """#88R22-4: launches record durable spawn evidence, absorbs prune it."""
        call_counters.ensure_registered()
        info = call_counters.registration_info()
        assert info is not None
        sidecar_path = Path(info["sidecar_path"])
        call_counters.note_probe_spawned(
            probe_seq=0, slot=str(engaged / "probe-x.json"), pid=12345, birth=678
        )
        payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
        assert payload["spawned_children"] == [
            {
                "probe_seq": 0,
                "slot": str(engaged / "probe-x.json"),
                "pid": 12345,
                "birth_token": 678,
            }
        ]
        call_counters.forget_probe_spawn(0)
        call_counters.record_direct_call("C_Login", 0)
        repayload = json.loads(sidecar_path.read_text(encoding="utf-8"))
        assert repayload.get("spawned_children", []) == []
        with pytest.raises(ValueError, match="probe_seq"):
            call_counters.note_probe_spawned(probe_seq=-1, slot="x", pid=1)
        call_counters.reset_for_tests()
        assert call_counters._spawned_children == []

    def test_attach_failure_reaps_without_draining(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R23-6: a failed spawn record kills and reaps, never drains pipes."""
        from pkcs11_check.testcases._probes import runner as probe_runner
        from pkcs11_check.testcases._probes.runner import run_probe

        calls: list[str] = []

        def _boom(*args: Any, **kwargs: Any) -> None:
            raise durability.CounterPersistenceError("disk full")

        factory = _fake_popen_factory(returncode=0)

        class _RecordingPopen(factory):  # type: ignore[misc,valid-type]
            def communicate(self, timeout: Any = None) -> tuple[str, str]:
                calls.append("communicate")
                return super().communicate(timeout)

            def kill(self) -> None:
                calls.append("kill")
                super().kill()

            def wait(self, timeout: Any = None) -> int:
                calls.append("wait")
                return super().wait(timeout)

        monkeypatch.setattr(subprocess, "Popen", _RecordingPopen)
        monkeypatch.setattr(probe_runner, "note_probe_spawned", _boom)
        with pytest.raises(durability.CounterPersistenceError, match="disk full"):
            run_probe("_echo", {"module_path": "/x.so"})
        # Draining after kill waits for inherited pipes (a grandchild
        # holding stdout delays EOF past the probe timeout); reaping via
        # wait() cannot hang on pipes.
        assert "kill" in calls
        assert "wait" in calls
        assert "communicate" not in calls

    def test_birthless_zombie_resolves_via_incarnation(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-7: an exited-but-unreaped child reads dead, never live."""
        if getattr(os, "pidfd_open", None) is None:
            pytest.skip("pidfd exit detection is Linux-only")
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        try:
            # Prove zombie: exited (state Z) but never waited, so the
            # pid slot is still occupied (kill(pid, 0) succeeds).
            deadline = time.monotonic() + 30
            while True:
                state = (
                    Path(f"/proc/{proc.pid}/stat")
                    .read_text(encoding="ascii")
                    .rsplit(")", 1)[1]
                    .split()[0]
                )
                if state == "Z":
                    break
                assert time.monotonic() < deadline, "child never became a zombie"
                time.sleep(0.01)
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
            )
            # Birthless record (birth unreadable at spawn) naming the
            # zombie; no slot file (the child never flushed).
            slot = engaged / "probe-aaaaaaaa-1-00000000.json"
            assert not slot.exists()
            entry: dict[str, Any] = {"probe_seq": 1, "slot": str(slot), "pid": proc.pid}
            sidecar_path = Path(planted["sidecar"])
            payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
            payload["spawned_children"] = [entry]
            sidecar_path.write_text(json.dumps(payload), encoding="utf-8")
            child = tmp_path / "child.jsonl"
            child.write_text("", encoding="utf-8")
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
            assert any(rec.get("$report_type") == "CallCountersPartial" for rec in records)
            assert not Path(planted["registry"]).exists(), "no defer on a proven exit"
        finally:
            proc.wait(timeout=30)

    def test_direct_heal_rechecks_evidence_validity(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-5: replay-discovered garbage stops a direct heal too."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        # A garbage-only rewrite tmp: unparseable rows never hold the
        # marker turn (they carry no returns), so the marker goes
        # direct -- but the orphan loop's replay refuses the tmp and
        # dirties the receipt before finalization runs.
        _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, True]]))
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        with pytest.warns(UserWarning, match="malformed evidence"):
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert marker.exists(), "a dirtied receipt must not heal direct"

    def test_rewrite_tmp_mistyped_scalar_refuses_replay(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R23-5: a tmp with a corrupt loss scalar replays nothing."""
        pid, _ = _dead_pid_with_birth()
        parent_block = _counts_block(3, fn="C_Digest")
        parent_block["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
            "0": {"name": "CKR_OK", "count": 2}
        }
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=parent_block,
        )
        rows = [["m", "C_Digest", None, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        # Rows identical to the baseline (no advancement, so no
        # rewrite hold) but a mistyped loss scalar: the tmp is corrupt,
        # so it must refuse like garbage rows instead of replaying
        # silently while its scalar drops.
        tmp_payload = _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows])
        tmp_payload["probes_lost"] = True
        _plant_probe_tmp(slot, tmp_payload)
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        with pytest.warns(UserWarning, match="malformed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert marker.exists(), "a scalar-tainted tmp must not authorize a heal"
        for rec in records:
            if rec.get("$report_type") == "CallCountersPartial":
                assert rec.get("in_flight") == [
                    {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
                ], "refused rows stay pending, never adopted"

    def test_producer_tmp_mistyped_scalar_flags_conflict(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R23-5: a producer tmp with a corrupt scalar replays nothing."""
        pid, birth = _dead_pid_with_birth()
        parent_block = _counts_block(3, fn="C_Digest")
        parent_block["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
            "0": {"name": "CKR_OK", "count": 2}
        }
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=parent_block,
        )
        advanced = _counts_block(3, fn="C_Digest")
        tmp_payload = _tmp_payload(_UUID_A, advanced, pid=pid)
        tmp_payload["probes_lost"] = True
        _plant_tmp(Path(planted["sidecar"]), tmp_payload)
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        with pytest.warns(UserWarning, match="malformed loss scalar"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        lost = [rec for rec in records if rec.get("$report_type") == "CallCountersLost"]
        assert len(lost) == 1
        assert lost[0]["end_state"] == "conflict", "tainted replay flags conflict"
        partials = [rec for rec in records if rec.get("$report_type") == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["in_flight"] == [
            {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
        ], "committed wins; the tmp's returns stay pending"

    def test_aliased_torn_marker_retained_for_forensics(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R23-3: an undecidable copy of a contested slot is not debris."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        valid_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="a1b2c3",
        )
        valid = valid_src.with_name(f"probe-consumed-{_UUID_A}-0-a1b2c3.json")
        valid_src.rename(valid)
        torn = engaged / f"probe-consumed-{_UUID_A[:8]}-0-a1b2c3.json"
        torn.write_text("{not valid json", encoding="utf-8")
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")

        def _collect() -> list[dict[str, Any]]:
            with pytest.warns(UserWarning, match="forensics"):
                return durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
                )

        _collect()
        assert torn.exists(), "the contested copy must survive pass 1"
        assert valid.exists(), "the valid copy stays frozen, not healed"
        _collect()
        assert torn.exists(), "the contest never clears by deletion"
        assert valid.exists(), "no silent heal on the emptied slot"

    def test_contested_pair_never_heals_sequentially(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-3: withheld conflicts cannot reconcile-heal one by one."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows1 = [["m", "C_Digest", 0, 1]]
        rows2 = [["m", "C_Digest", 0, 2]]
        m1src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows1],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid=_UUID_B,
        )
        m1 = m1src.with_name(m1src.name.replace("probe-", "probe-consumed-", 1))
        m1src.rename(m1)
        m2src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows2],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid="c" * 32,
        )
        m2 = m2src.with_name(f"probe-consumed-{_UUID_A}-0-d4e5f6.json")
        m2src.rename(m2)
        # A baseline plus a live rewrite tmp withhold both copies, so
        # the reconcile (not just direct finalize) must refuse them.
        slot = engaged / f"probe-{_UUID_A[:8]}-0-d4e5f6.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows1],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid=_UUID_B,
        )
        assert baseline == slot
        _plant_probe_tmp(slot, _probe_tmp_payload(_UUID_B, 0, [list(row) for row in rows1]))
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")

        def _collect() -> None:
            with pytest.warns(UserWarning, match="aliased slot"):
                durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
                )

        _collect()
        assert m1.exists() and m2.exists(), "pass 1 freezes both copies"
        _collect()
        assert m1.exists() and m2.exists(), "pass 2 heals neither copy"

    def test_alias_freeze_flags_conflict_durably(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-3: a frozen contest reads conflict, never clean-complete."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows1 = [["m", "C_Digest", 0, 1]]
        rows2 = [["m", "C_Digest", 0, 2]]
        m1src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows1],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid=_UUID_B,
        )
        m1 = m1src.with_name(m1src.name.replace("probe-", "probe-consumed-", 1))
        m1src.rename(m1)
        m2src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows2],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid="c" * 32,
        )
        m2 = m2src.with_name(f"probe-consumed-{_UUID_A}-0-d4e5f6.json")
        m2src.rename(m2)
        m3src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=1,
            counters=[list(row) for row in rows1],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="0a0b0c",
            child_uuid="d" * 32,
        )
        m3 = m3src.with_name(m3src.name.replace("probe-", "probe-consumed-", 1))
        m3src.rename(m3)
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        with pytest.warns(UserWarning, match="forensics"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        # The clean sibling still heals; the contested pair stays frozen.
        assert not m3.exists()
        assert m1.exists() and m2.exists()
        lost = [rec for rec in records if rec.get("$report_type") == "CallCountersLost"]
        assert len(lost) == 1
        assert lost[0]["end_state"] == "conflict", (
            "the freeze must survive in the durable record, not just warnings"
        )

    def test_alias_freeze_flags_conflict_on_resume(self, engaged: Path) -> None:
        """#88R23-3: the resume barrier flags a frozen contest too."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        # Registryless route: the sidecar loop (not the registry loop)
        # must flag the freeze as well.
        Path(planted["registry"]).unlink()
        rows1 = [["m", "C_Digest", 0, 1]]
        rows2 = [["m", "C_Digest", 0, 2]]
        m1src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows1],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid=_UUID_B,
        )
        m1 = m1src.with_name(m1src.name.replace("probe-", "probe-consumed-", 1))
        m1src.rename(m1)
        m2src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows2],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid="c" * 32,
        )
        m2 = m2src.with_name(f"probe-consumed-{_UUID_A}-0-d4e5f6.json")
        m2src.rename(m2)
        with pytest.warns(UserWarning, match="forensics"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert m1.exists() and m2.exists()
        assert plan["barrier_ok"] is True
        cached = [
            rec
            for records in plan["cache_records"].values()
            for rec in records
            if rec.get("$report_type") == "CallCountersLost"
        ]
        assert len(cached) == 1
        assert cached[0]["end_state"] == "conflict"

    def test_alias_freeze_flags_conflict_orphan_sidecar(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R23-3: the orphan-sidecar route flags a frozen contest too."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        Path(planted["registry"]).unlink()
        rows1 = [["m", "C_Digest", 0, 1]]
        rows2 = [["m", "C_Digest", 0, 2]]
        m1src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows1],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid=_UUID_B,
        )
        m1 = m1src.with_name(m1src.name.replace("probe-", "probe-consumed-", 1))
        m1src.rename(m1)
        m2src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows2],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
            nonce="d4e5f6",
            child_uuid="c" * 32,
        )
        m2 = m2src.with_name(f"probe-consumed-{_UUID_A}-0-d4e5f6.json")
        m2src.rename(m2)
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        with pytest.warns(UserWarning, match="forensics"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert m1.exists() and m2.exists()
        lost = [rec for rec in records if rec.get("$report_type") == "CallCountersLost"]
        assert len(lost) == 1
        assert lost[0]["end_state"] == "conflict"

    def _plant_spawn_file(
        self,
        root: Path,
        *,
        parent_uuid: str,
        seq: int,
        pid: int,
        birth: int | None,
        slot: Path | str,
        nonce: str = "bead01",
        extra: dict[str, Any] | None = None,
    ) -> Path:
        """Plant a child-side spawn record ``spawn-<parent8>-<seq>-<nonce>.json``."""
        path = root / f"spawn-{parent_uuid[:8]}-{seq}-{nonce}.json"
        payload: dict[str, Any] = {
            "parent_uuid": parent_uuid,
            "probe_seq": seq,
            "slot": str(slot),
            "pid": pid,
        }
        if birth is not None:
            payload["birth_token"] = birth
        if extra:
            payload.update(extra)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_spawn_file_defers_while_child_unflushed(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-1: a child-side spawn record waits out a live child."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
            )
            # No parent-side spawn record (the supervisor died before
            # its note flushed); only the child's own spawn file, whose
            # slot never landed and whose child is still running.
            slot = engaged / "probe-aaaaaaaa-1-00000000.json"
            assert not slot.exists()
            child_birth = durability.birth_token_for_pid(proc.pid)
            self._plant_spawn_file(
                engaged,
                parent_uuid=_UUID_A,
                seq=1,
                pid=proc.pid,
                birth=child_birth,
                slot=slot,
            )
            child = tmp_path / "child.jsonl"
            child.write_text("", encoding="utf-8")
            with pytest.warns(UserWarning, match="unflushed"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
                )
            assert records == [], "a live unflushed child defers reunion"
            assert (engaged / "registrations" / f"{_UUID_A}.json").exists()
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=30)

    def test_spawn_file_consumed_on_reunion(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-1: a flushed child's spawn file rides the reunion cleanup."""
        pid, birth = _dead_pid_with_birth()
        parent_block = _counts_block(3, fn="C_Digest")
        parent_block["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
            "0": {"name": "CKR_OK", "count": 2}
        }
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=parent_block,
        )
        rows = [["m", "C_Digest", None, 1]]
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        # No parent-side record; the child's own file names a dead child
        # whose slot landed (flushed before dying).
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = self._plant_spawn_file(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            pid=dead_pid,
            birth=dead_birth,
            slot=slot,
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert not marker.exists(), "the receipt heals with the flushed slot"
        assert not spawn.exists(), "the spawn file reunites with its slot"
        partials = [rec for rec in records if rec.get("$report_type") == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 3

    def test_spawn_file_absorbed_when_child_dies_unflushed(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R23-1: a dead unflushed child's spawn file absorbs away."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        # No parent-side record; the child's file names a dead child
        # with no slot file (killed before flushing anything).
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        assert not slot.exists()
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = self._plant_spawn_file(
            engaged,
            parent_uuid=_UUID_A,
            seq=1,
            pid=dead_pid,
            birth=dead_birth,
            slot=slot,
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert any(rec.get("$report_type") == "CallCountersPartial" for rec in records)
        assert not spawn.exists(), "an absorbed launch leaves no residue"

    def test_spawn_file_live_defers_despite_absorbed_sidecar(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R23-1: the spawn union is fail-closed OR, never sidecar-wins."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
            )
            # The sidecar's record already absorbed (dead child, no
            # slot) while the child's own file names a live child.
            dead_pid, dead_birth = _dead_pid_with_birth()
            slot = engaged / "probe-aaaaaaaa-1-00000000.json"
            sidecar_path = Path(planted["sidecar"])
            payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
            payload["spawned_children"] = [
                {
                    "probe_seq": 1,
                    "slot": str(slot),
                    "pid": dead_pid,
                    **({"birth_token": dead_birth} if dead_birth is not None else {}),
                }
            ]
            sidecar_path.write_text(json.dumps(payload), encoding="utf-8")
            child_birth = durability.birth_token_for_pid(proc.pid)
            self._plant_spawn_file(
                engaged,
                parent_uuid=_UUID_A,
                seq=1,
                pid=proc.pid,
                birth=child_birth,
                slot=slot,
            )
            child = tmp_path / "child.jsonl"
            child.write_text("", encoding="utf-8")
            with pytest.warns(UserWarning, match="unflushed"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
                )
            assert records == [], "either source outstanding defers"
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=30)

    @pytest.mark.parametrize("shape", ["torn", "bad_types", "bad_parent"])
    def test_spawn_file_malformed_defers(self, engaged: Path, tmp_path: Path, shape: str) -> None:
        """#88R23-1: an unreadable spawn file fails closed, never skips."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        path = engaged / f"spawn-{_UUID_A[:8]}-1-bead01.json"
        if shape == "torn":
            path.write_text("{not valid json", encoding="utf-8")
        elif shape == "bad_types":
            path.write_text(
                json.dumps({"parent_uuid": _UUID_A, "probe_seq": "1", "slot": str(slot), "pid": 1}),
                encoding="utf-8",
            )
        else:
            path.write_text(
                json.dumps({"parent_uuid": "zzz", "probe_seq": 1, "slot": str(slot), "pid": 1}),
                encoding="utf-8",
            )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        with pytest.warns(UserWarning, match="unflushed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert records == [], f"a {shape} spawn file must defer reunion"
        assert path.exists(), "corrupt spawn evidence is retained, never consumed"

    def test_spawn_file_foreign_ignored(self, engaged: Path, tmp_path: Path) -> None:
        """#88R23-1: another producer's spawn file never blocks this one."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        self._plant_spawn_file(
            engaged,
            parent_uuid=_UUID_B,
            seq=1,
            pid=pid,
            birth=birth,
            slot=slot,
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert any(rec.get("$report_type") == "CallCountersPartial" for rec in records)

    def test_spawn_file_foreign_named_torn_ignored(self, engaged: Path, tmp_path: Path) -> None:
        """#88R24-2: torn bytes route by filename hint, never block everyone."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        torn = engaged / "spawn-cccccccc-0-feedface.json"
        torn.write_text("{torn", encoding="utf-8")
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert any(rec.get("$report_type") == "CallCountersPartial" for rec in records)
        assert torn.exists(), "foreign debris is not ours to consume"

    def test_spawn_file_mistyped_parent_scoped_by_filename(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R24-2: a parent-mute file defers only its filename owner."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        foreign = engaged / "spawn-cccccccc-1-bead01.json"
        foreign.write_text(
            json.dumps({"parent_uuid": "zzz", "probe_seq": 1, "slot": str(slot), "pid": 1}),
            encoding="utf-8",
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert any(rec.get("$report_type") == "CallCountersPartial" for rec in records)
        assert foreign.exists()

    def test_staged_spawn_cleanup_retries_on_next_barrier(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-3: a held spawn file is adopted, not dropped, on retry."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-0-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": _UUID_A,
            "probe_seq": 0,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        real_unlink = Path.unlink
        fail = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if fail and self.name.startswith("spawn-"):
                raise OSError("injected spawn unlink failure")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        assert str(spawn) in plan1["cleanup_held"]
        assert spawn.exists() and not slot.exists()
        fail = False
        plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert not spawn.exists(), "the retry finishes the staged spawn cleanup"
        assert plan2["cleanup_held"] == []

    def test_sweep_reaps_settled_parentless_spawn(self, engaged: Path) -> None:
        """#88R24-3: a settled parentless spawn file is sweepable debris."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-1-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": _UUID_A,
            "probe_seq": 1,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        Path(planted["registry"]).unlink()
        Path(planted["sidecar"]).unlink()
        swept = durability.sweep_orphans(engaged, current_run="R1")
        assert swept["removed"] == 1
        assert not spawn.exists()

    def test_sweep_retains_live_parentless_spawn(self, engaged: Path) -> None:
        """#88R24-3: a live parentless spawn file retains loudly, counted."""
        proc = _live_sleeper()
        try:
            (engaged / "registrations").mkdir(parents=True, exist_ok=True)
            slot = engaged / "probe-aaaaaaaa-1-00000000.json"
            birth = durability.birth_token_for_pid(proc.pid)
            spawn = engaged / "spawn-aaaaaaaa-1-bead01.json"
            payload: dict[str, Any] = {
                "parent_uuid": _UUID_A,
                "probe_seq": 1,
                "slot": str(slot),
                "pid": proc.pid,
            }
            if birth is not None:
                payload["birth_token"] = birth
            spawn.write_text(json.dumps(payload), encoding="utf-8")
            with pytest.warns(UserWarning, match="spawn"):
                swept = durability.sweep_orphans(engaged, current_run="R1")
            assert swept["removed"] == 0
            assert swept["retained"] >= 1
            assert spawn.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=30)

    def test_sweep_counts_owned_spawn_file(self, engaged: Path) -> None:
        """#88R24-3: an owned spawn file is visible to the sweep, kept."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-1-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": _UUID_A,
            "probe_seq": 1,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        swept = durability.sweep_orphans(engaged, current_run="R1")
        assert swept["removed"] == 0
        assert swept["retained"] == 3, "registry + sidecar + the owned spawn file"
        assert spawn.exists()

    def test_staged_probe_live_writer_retains(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-3: a retained probe adoption rides cleanup_held too."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if self.name == slot.name:
                raise OSError("injected orphan unlink failure")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        assert str(slot) in plan1["cleanup_held"]
        monkeypatch.setattr(Path, "unlink", real_unlink)
        monkeypatch.setattr(durability, "_incarnation_alive", lambda *a: True)
        with pytest.warns(UserWarning, match="live writer"):
            plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert slot.exists()
        assert str(slot) in plan2["cleanup_held"]

    @pytest.mark.parametrize("bad_parent", [[], {}], ids=["list", "dict"])
    def test_staged_spawn_malformed_parent_uuid_retained(
        self, engaged: Path, bad_parent: Any
    ) -> None:
        """#88R25-5: unhashable spawn parent_uuid routes by filename, never raises."""
        import json

        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        # The malformed record lands after collection: pass 2 replays
        # staged adoption over it.
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-0-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": bad_parent,
            "probe_seq": 0,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.warns(UserWarning, match="malformed identity"):
            plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert spawn.exists()
        assert str(spawn) in plan2["cleanup_held"]
        assert not (engaged / durability.SEAL_FILENAME).exists()

    def test_staged_spawn_foreign_malformed_parent_skipped(self, engaged: Path) -> None:
        """#88R25-5: malformed spawn identities outside staged parents skip silently."""
        import json

        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-bbbbbbbb-0-bead02.json"
        payload: dict[str, Any] = {
            "parent_uuid": [],
            "probe_seq": 0,
            "slot": str(engaged / "probe-bbbbbbbb-0-feedface.json"),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert spawn.exists()
        assert str(spawn) not in plan2["cleanup_held"]

    def test_sweep_spawn_unrepresentable_pid_retained(self, engaged: Path) -> None:
        """#88R25-5: parentless spawn with an unrepresentable pid never reaches kill."""
        import json

        engaged.mkdir(parents=True, exist_ok=True)
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        parent = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        spawn = engaged / "spawn-bbbbbbbb-0-bead03.json"
        spawn.write_text(
            json.dumps(
                {
                    "parent_uuid": parent,
                    "probe_seq": 0,
                    "slot": str(engaged / "probe-bbbbbbbb-0-gone.json"),
                    "pid": 2**32,
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="unrepresentable pid"):
            swept = durability.sweep_orphans(engaged, current_run="run-now")
        assert swept["retained"] >= 1
        assert spawn.exists()

    def test_staged_spawn_unrepresentable_pid_retained(self, engaged: Path) -> None:
        """#88R25-5: staged adoption checks pid representability before liveness."""
        import json
        import unittest.mock as mock

        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-0-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": _UUID_A,
            "probe_seq": 0,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if self == spawn:
                raise OSError("injected unlink failure")
            return real_unlink(self, *args, **kwargs)

        with mock.patch.object(Path, "unlink", _flaky_unlink):
            plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        assert str(spawn) in plan1["cleanup_held"]
        payload["pid"] = 2**32
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.warns(UserWarning, match="unrepresentable pid"):
            plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert spawn.exists()
        assert str(spawn) in plan2["cleanup_held"]

    def test_collect_spawn_unrepresentable_pid_no_crash(self, engaged: Path) -> None:
        """#88R25-5: first-pass reunion never feeds an unrepresentable pid to kill."""
        import json

        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        spawn = engaged / "spawn-aaaaaaaa-0-bead04.json"
        spawn.write_text(
            json.dumps(
                {
                    "parent_uuid": _UUID_A,
                    "probe_seq": 0,
                    "slot": str(engaged / "probe-aaaaaaaa-0-missing.json"),
                    "pid": 2**32,
                }
            ),
            encoding="utf-8",
        )
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert spawn.exists()

    def test_pid_representability_contracts(self) -> None:
        """#88R25-5: representability bounds + OverflowError-neutral liveness."""
        assert durability._pid_representable(1) is True
        assert durability._pid_representable(2**31 - 1) is True
        assert durability._pid_representable(0) is False
        assert durability._pid_representable(-1) is False
        assert durability._pid_representable("123") is False  # type: ignore[arg-type]
        if sys.platform == "win32":
            assert durability._pid_representable(2**31) is True
            assert durability._pid_representable(2**32) is False
        else:
            assert durability._pid_representable(2**31) is False
        assert durability._incarnation_alive(2**63, None) is True
        assert durability._pid_exists(2**63) is True
        assert durability.birth_token_for_pid(2**63) is None

    def test_staging_write_refusal_releases_seal(self, engaged: Path) -> None:
        """#88R25-6: a staging write refusal still releases the barrier seal."""
        import unittest.mock as mock

        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        real_replace = os.replace

        def _flaky_replace(src: Any, dst: Any) -> None:
            if Path(dst).name == durability.BARRIER_STAGING_FILENAME:
                raise PermissionError("injected staging EACCES")
            return real_replace(src, dst)

        with mock.patch.object(os, "replace", _flaky_replace):
            with pytest.warns(UserWarning, match="cannot stage recovery evidence"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is False
        assert not (engaged / durability.SEAL_FILENAME).exists()
        assert Path(planted["registry"]).exists()
        assert slot.exists()

    def test_path_is_dir_follows_symlinks(self, tmp_path: Path) -> None:
        """#88R25-7: the tri-state dir check follows links (0.3.0 parity)."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real, target_is_directory=True)
        assert durability._path_is_dir(link) == "present"
        assert durability._path_is_dir(real) == "present"
        plain = tmp_path / "file.json"
        plain.write_text("{}", encoding="utf-8")
        assert durability._path_is_dir(plain) == "missing"
        file_link = tmp_path / "file-link"
        file_link.symlink_to(plain)
        assert durability._path_is_dir(file_link) == "missing"
        broken = tmp_path / "broken"
        broken.symlink_to(tmp_path / "absent")
        assert durability._path_is_dir(broken) == "missing"
        loop_a = tmp_path / "loop-a"
        loop_b = tmp_path / "loop-b"
        loop_a.symlink_to(loop_b)
        loop_b.symlink_to(loop_a)
        assert durability._path_is_dir(loop_a) == "missing"

    def test_symlinked_registrations_dir_collected(self, engaged: Path, tmp_path: Path) -> None:
        """#88R25-7: a symlinked registrations dir still collects its producers."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        reg_dir = engaged / durability.REGISTRY_DIRNAME
        moved = engaged / "registrations-real"
        reg_dir.rename(moved)
        reg_dir.symlink_to(moved, target_is_directory=True)
        records = _collect_crashed88(engaged, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 2

    def test_staged_target_carry_branches(self, engaged: Path) -> None:
        """#88R25-4: carry-forward verdicts per target state."""
        import hashlib

        engaged.mkdir(parents=True, exist_ok=True)
        target = engaged / "probe-aaaaaaaa-0-feedface.json"
        target.write_text("{}", encoding="utf-8")
        digest = hashlib.sha256(b"{}").hexdigest()
        assert durability._staged_target_carries(target, digest) is True
        assert durability._staged_target_carries(target, "0" * 64) is False
        assert durability._staged_target_carries(engaged / "gone.json", digest) is False
        real_state = durability._path_state
        durability._path_state = lambda p: (  # type: ignore[method-assign]
            "unreadable" if p == target else real_state(p)
        )
        try:
            assert durability._staged_target_carries(target, digest) is True
        finally:
            durability._path_state = real_state
        real_sha = durability._sha256_file_hex
        durability._sha256_file_hex = lambda p: None  # type: ignore[method-assign]
        try:
            assert durability._staged_target_carries(target, digest) is True
        finally:
            durability._sha256_file_hex = real_sha

    @pytest.mark.parametrize("kind", ["probe", "spawn"])
    def test_staged_retry_survives_unreadable_pass(self, engaged: Path, kind: str) -> None:
        """#88R25-4: held targets keep their authority across blind passes."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-0-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": _UUID_A,
            "probe_seq": 0,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        target = slot if kind == "probe" else spawn
        # Pass 1: fail only the target's unlink (held + staged).
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if self == target:
                raise OSError("injected unlink failure")
            return real_unlink(self, *args, **kwargs)

        import unittest.mock as mock

        with mock.patch.object(Path, "unlink", _flaky_unlink):
            plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        assert str(target) in plan1["cleanup_held"]
        assert target.exists()
        # Pass 2: the target is unreadable (kept staged, not dropped).
        staged = engaged / durability.BARRIER_STAGING_FILENAME
        assert staged.exists()
        real_read = Path.read_bytes

        def _flaky_read(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self == target:
                raise OSError("injected read failure")
            return real_read(self, *args, **kwargs)

        with mock.patch.object(Path, "read_bytes", _flaky_read):
            with pytest.warns(UserWarning):
                plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert str(target) in plan2["cleanup_held"]
        # Pass 3: restored access converges through staged adoption.
        plan3 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan3["barrier_ok"] is True
        assert not target.exists(), "staged authority survives a blind pass"

    def test_staged_spawn_live_writer_retains(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-3: staged adoption re-proves quiescence (recycle-safe)."""
        pid, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert orphan == slot
        dead_pid, dead_birth = _dead_pid_with_birth()
        spawn = engaged / "spawn-aaaaaaaa-0-bead01.json"
        payload: dict[str, Any] = {
            "parent_uuid": _UUID_A,
            "probe_seq": 0,
            "slot": str(slot),
            "pid": dead_pid,
        }
        if dead_birth is not None:
            payload["birth_token"] = dead_birth
        spawn.write_text(json.dumps(payload), encoding="utf-8")
        real_unlink = Path.unlink

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if self.name.startswith("spawn-"):
                raise OSError("injected spawn unlink failure")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        plan1 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan1["barrier_ok"] is True
        assert str(spawn) in plan1["cleanup_held"]
        # Pass 2: the unlink works now, but the writer reads live
        # (simulating a birthless pid recycle the pass-1 absorb could
        # not see): adoption must retain, not reap.
        monkeypatch.setattr(Path, "unlink", real_unlink)
        monkeypatch.setattr(durability, "_incarnation_alive", lambda *a: True)
        with pytest.warns(UserWarning, match="live writer"):
            plan2 = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan2["barrier_ok"] is True
        assert spawn.exists()
        assert str(spawn) in plan2["cleanup_held"]

    def test_barrier_fenced_defers_while_child_unflushed(self, engaged: Path) -> None:
        """#88R22-4: fenced reunion still waits for unflushed children."""
        producer = _live_sleeper()
        child = _live_sleeper()
        try:
            birth = durability.birth_token_for_pid(producer.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=producer.pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            self._plant_unflushed_spawn(engaged, planted, child)
            with pytest.warns(UserWarning, match="unflushed"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert _UUID_A in plan["unresolved"]
            assert producer.wait(timeout=30) is not None, "the producer fences"
            assert child.poll() is None, "the unflushed child is awaited, not fenced"
            assert Path(planted["registry"]).exists()
            assert Path(planted["sidecar"]).exists()
        finally:
            for proc in (producer, child):
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=30)

    def test_registryless_barrier_defers_while_child_unflushed(self, engaged: Path) -> None:
        """#88R22-4: orphan barrier reunion waits too."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            self._plant_unflushed_spawn(engaged, planted, proc)
            Path(planted["registry"]).unlink()
            with pytest.warns(UserWarning, match="unflushed"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert _UUID_A in plan["unresolved"]
            assert proc.poll() is None
            assert Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_barrier_proceeds_once_child_settles(self, engaged: Path) -> None:
        """#88R22-4: the outstanding wait converges on death or flush."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            self._plant_unflushed_spawn(engaged, planted, proc)
            with pytest.warns(UserWarning, match="unflushed"):
                first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert _UUID_A in first["unresolved"]
            assert proc.poll() is None
            proc.kill()
            assert proc.wait(timeout=30) is not None
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            partials = [
                rec
                for rec in second["cache_records"].get("a.py", [])
                if rec["$report_type"] == "CallCountersPartial"
            ]
            assert len(partials) == 1
            assert partials[0]["total_calls"] == 5
            assert _UUID_A not in second["unresolved"]
            assert _UUID_A not in second["retained_uuids"]
            assert str(Path(planted["registry"])) not in second["cleanup_held"]
            assert str(Path(planted["sidecar"])) not in second["cleanup_held"]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_barrier_shortcut_reunites_on_outstanding(self, engaged: Path) -> None:
        """#88R22-4: staged shortcut yields to unflushed children."""
        proc = _live_sleeper()
        try:
            pid, birth = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=birth,
                in_progress=_counts_block(5),
                lost_keys=[{"parent_uuid": _UUID_A, "probe_seq": 0}],
            )
            rows = [["m", "C_Digest", 0, 1]]
            marker_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
            marker_src.rename(marker)
            _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[list(row) for row in rows],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            sidecar_path = Path(planted["sidecar"])
            saved_sidecar = sidecar_path.read_text(encoding="utf-8")
            first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert _UUID_A not in first["unresolved"]
            assert _UUID_A not in first["retained_uuids"]
            assert len(first["cache_records"].get("a.py", [])) == 2
            # Pass-1 consumed everything; restore the prune-held sidecar
            # shape (registry stays gone so pass-2 routes orphan) with a
            # live unflushed spawn aboard.
            payload = json.loads(saved_sidecar)
            birth = durability.birth_token_for_pid(proc.pid)
            slot = engaged / "probe-aaaaaaaa-1-00000000.json"
            assert not slot.exists()
            entry: dict[str, Any] = {"probe_seq": 1, "slot": str(slot), "pid": proc.pid}
            if birth is not None:
                entry["birth_token"] = birth
            payload["spawned_children"] = [entry]
            sidecar_path.write_text(json.dumps(payload), encoding="utf-8")
            with pytest.warns(UserWarning, match="unflushed"):
                second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            assert _UUID_A in second["unresolved"]
            assert proc.poll() is None
            assert sidecar_path.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_duplicate_markers_resolve_receipt_together(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R18-3: one live copy withholds every marker of its receipt."""
        proc = _live_sleeper()
        try:
            pid, _ = _dead_pid_with_birth()
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=pid,
                birth=424243,
                in_progress=_counts_block(2, fn="C_Digest"),
            )
            live_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=proc.pid,
                birth=None,
            )
            live_marker = engaged / f"probe-consumed-{_UUID_A}-0-feedface.json"
            live_src.rename(live_marker)
            dead_src = _plant_probe_orphan(
                engaged,
                parent_uuid=_UUID_A,
                seq=0,
                nonce="deadbeef",
                counters=[["m", "C_Digest", None, 1]],
                identity=_f2_identity(_UUID_A),
                pid=pid,
                birth=None,
            )
            dead_marker = engaged / f"probe-consumed-{_UUID_A[:8]}-0-deadbeef.json"
            dead_src.rename(dead_marker)
            child = _committed_child(tmp_path, pid, _counts_block(10))
            with pytest.warns(UserWarning, match="live writer"):
                records = durability.collect_unit(
                    engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
                )
            assert records == [], "no copy publishes while one is live"
            assert proc.poll() is None
            assert live_marker.exists()
            assert dead_marker.exists(), "the dead copy waits with the live one"
            assert Path(planted["registry"]).exists()
            proc.kill()
            assert proc.wait(timeout=30) is not None
            retry = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            partials = [rec for rec in retry if rec["$report_type"] == "CallCountersPartial"]
            assert len(partials) == 1
            assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
            assert not live_marker.exists()
            assert not dead_marker.exists()
            assert not Path(planted["registry"]).exists()
            assert not Path(planted["sidecar"]).exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_malformed_skip_held_degrades_loudly(self, engaged: Path) -> None:
        """#88R14-1: corrupt skip-holds are not trusted (loud empty)."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                                "truncated": True,
                                "total_calls": 0,
                                "by_module": {},
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                    "cleanup_targets": [],
                    "skip_held_uuids": "garbage",
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="malformed skip_held_uuids"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert not Path(planted["registry"]).exists(), "empty hold skips adopt"
        assert not Path(planted["sidecar"]).exists()

    def test_rejected_read_never_overwrites_digest(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R14-2: first adjudicated read wins the staged digest."""
        import hashlib

        pid_a, birth_a = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid_a,
            birth=birth_a,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        pid_b, birth_b = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_B,
            pid=pid_b,
            birth=birth_b,
            unit="b.py",
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_B,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_B, unit="b.py"),
            pid=pid_b,
            birth=birth_b,
        )
        pristine = probe.read_bytes()
        pristine_digest = hashlib.sha256(pristine).hexdigest()
        real_digested = durability._read_json_evidence_digested
        reads = {"count": 0}

        def _ghosting_read(path: Path) -> Any:
            if path.name == probe.name:
                reads["count"] += 1
                if reads["count"] > 1:
                    probe.write_text(
                        json.dumps(_probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]])),
                        encoding="utf-8",
                    )
            return real_digested(path)

        monkeypatch.setattr(durability, "_read_json_evidence_digested", _ghosting_read)
        with pytest.warns(UserWarning, match="changed since adjudication"):
            second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert probe.exists(), "the ghost never inherits the adjudication"
        staged = json.loads(
            (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
        )
        listed = {entry["path"]: entry["sha256"] for entry in staged["cleanup_targets"]}
        assert listed.get(str(probe)) == pristine_digest

    def test_listed_prune_reads_once(self, engaged: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """#88R13-2c: listed prune verifies and classifies one read."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        tmp = _plant_probe_tmp(probe, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]))
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name in {probe.name, tmp.name}:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert probe.exists()
        assert tmp.exists()
        blocked = False
        real_read_text = durability._read_text_with_retry
        text_reads = {"count": 0}

        def _counting_read_text(path: Path) -> str:
            if path.name == tmp.name:
                text_reads["count"] += 1
            return real_read_text(path)

        monkeypatch.setattr(durability, "_read_text_with_retry", _counting_read_text)
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert text_reads["count"] == 0, "listed prune never re-reads as text"
        assert not probe.exists()
        assert not tmp.exists()

    def test_marker_slot_debris_listed_for_cleanup(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R14-4: a marker's slot tmps stage with the marker."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        marker_src = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        tmp = slot.with_name(f"{slot.name}.tmp-4242")
        tmp.write_text("{torn", encoding="utf-8")
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == tmp.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert first["barrier_ok"] is True
        assert marker.exists()
        assert tmp.exists()
        staged = json.loads(
            (engaged / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
        )
        listed = {entry["path"] for entry in staged["cleanup_targets"]}
        assert str(marker) in listed
        assert str(tmp) in listed, "slot debris stages with its marker"
        blocked = False
        second = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert not marker.exists()
        assert not tmp.exists()

    def test_malformed_cleanup_targets_disable_adoption(self, engaged: Path) -> None:
        """#88R11-6: malformed targets fail closed with a loud warning."""
        pid, birth = _dead_pid_with_birth()
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                                "truncated": True,
                                "total_calls": 0,
                                "by_module": {},
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                    "cleanup_targets": "garbage",
                }
            ),
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="malformed cleanup_targets"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert probe.exists()

    def test_targets_absent_disables_adoption_silently(self, engaged: Path) -> None:
        """#88R11-6: pre-targets staging adopts nothing (no legacy warn)."""
        import warnings

        pid, birth = _dead_pid_with_birth()
        probe = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text(
            json.dumps(
                {
                    "cache_records": {
                        "a.py": [
                            {
                                "$report_type": "CallCountersPartial",
                                "worker_uuid": _UUID_A,
                                "truncated": True,
                                "total_calls": 0,
                                "by_module": {},
                            }
                        ]
                    },
                    "consumed": 1,
                    "collected_uuids": [_UUID_A],
                }
            ),
            encoding="utf-8",
        )
        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert probe.exists()
        assert any("not a staged cleanup target" in str(w.message) for w in record)
        assert not any("cleanup_targets" in str(w.message) for w in record)

    def test_sweep_mutual_debris_converges(self, engaged: Path) -> None:
        """#88R3F5: torn registry + torn sidecar clear in two passes."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OLD",
            in_progress=_counts_block(5),
        )
        registry = Path(planted["registry"])
        sidecar = Path(planted["sidecar"])
        registry.write_text('{"worker_uuid": "torn', encoding="utf-8")
        sidecar.write_text("torn-bytes", encoding="utf-8")
        durability.sweep_orphans(engaged, current_run=_RUN, collected_runs=frozenset({"OLD"}))
        assert not sidecar.exists()
        assert registry.exists()
        second = durability.sweep_orphans(
            engaged, current_run=_RUN, collected_runs=frozenset({"OLD"})
        )
        assert not registry.exists()
        assert second["removed"] == 1

    def test_deep_json_reads_as_torn(self, engaged: Path) -> None:
        """#88R4-REG2: decoder-limit nesting never escapes evidence reads."""
        engaged.mkdir(parents=True, exist_ok=True)
        deep = "[" * 100_000 + "]" * 100_000
        victim = engaged / "deep.json"
        victim.write_text(deep, encoding="utf-8")
        assert durability.read_json_file(victim) is None
        assert durability._read_json_evidence(victim) == ("torn", None)
        assert durability._parse_registry_content(f"{_UUID_A}.json", deep) is None

    def test_deep_json_tmp_pruned_as_torn(self, engaged: Path) -> None:
        """#88R4-REG2: decoder-limit nesting never escapes tmp pruning."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        sidecar = Path(planted["sidecar"])
        deep = "[" * 100_000 + "]" * 100_000
        tmp = _plant_tmp(sidecar, None, raw=deep)
        removed, retained, hold = durability._prune_sidecar_tmps(sidecar)
        assert (removed, retained, hold) == (1, 0, False)
        assert not tmp.exists()

    def test_deep_json_journal_line_skipped(self, engaged: Path) -> None:
        """#88R4-REG2: a decoder-limit journal window reads as torn."""
        pid, birth = _dead_pid_with_birth()
        deep = "[" * 100_000 + "]" * 100_000
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(1, fn="C_Digest"),
        )
        journal = Path(planted["journal"])
        journal.write_text(deep + "\n", encoding="utf-8")
        records = _collect_crashed88(engaged, engaged / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1

    def test_fence_terminates_a_live_writer(self, engaged: Path) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=proc.pid,
                birth=birth,
                in_progress=_counts_block(5),
            )
            registry = durability.read_registry_file(planted["registry"])
            assert registry is not None
            assert durability.verify_producer(registry) == "alive"
            assert durability.fence_producer(registry, timeout_s=10.0) == "fenced"
            assert proc.wait(timeout=30) is not None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_reuse_before_acquire_never_signals_a_recycled_pid(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=proc.pid,
                birth=birth + 1,
                in_progress=_counts_block(5),
            )
            registry = durability.read_registry_file(planted["registry"])
            assert registry is not None
            assert durability.verify_producer(registry) == "dead"
            signaled: list[str] = []

            def _spy(*args: Any, **kwargs: Any) -> Any:
                signaled.append("signaled")
                raise AssertionError("must not signal a recycled pid")

            monkeypatch.setattr(durability, "_terminate_verified", _spy)
            assert durability.fence_producer(registry) == "fenced"
            assert signaled == []
            assert proc.poll() is None, "the live unrelated process survived"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_unverifiable_producer_is_unresolved_without_signaling(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            planted = _plant_producer(
                engaged,
                uuid=_UUID_A,
                pid=proc.pid,
                birth=12345,
                in_progress=_counts_block(5),
            )
            registry = durability.read_registry_file(planted["registry"])
            assert registry is not None
            monkeypatch.setattr(durability, "birth_token_for_pid", lambda _pid: None)
            assert durability.verify_producer(registry) == "unknown"
            signaled: list[str] = []

            def _spy(*args: Any, **kwargs: Any) -> Any:
                signaled.append("signaled")
                raise AssertionError("must not signal an unverified producer")

            monkeypatch.setattr(durability, "_terminate_verified", _spy)
            with pytest.warns(UserWarning, match="unresolved"):
                assert durability.fence_producer(registry) == "unresolved"
            assert signaled == []
            assert proc.poll() is None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    def test_dead_producer_fences_without_signaling(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        registry = durability.read_registry_file(planted["registry"])
        assert registry is not None
        assert durability.verify_producer(registry) == "dead"
        signaled: list[str] = []

        def _spy(*args: Any, **kwargs: Any) -> Any:
            signaled.append("signaled")
            raise AssertionError("must not signal a dead producer")

        monkeypatch.setattr(durability, "_terminate_verified", _spy)
        assert durability.fence_producer(registry) == "fenced"
        assert signaled == []

    def test_prepare_resume_seals_collects_and_skips_unresolved(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dead_pid, dead_birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=dead_pid,
            birth=dead_birth,
            in_progress=_counts_block(5),
        )
        live = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            live_birth = durability.birth_token_for_pid(live.pid)
            if live_birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            _plant_producer(
                engaged,
                uuid=_UUID_B,
                pid=live.pid,
                birth=live_birth,
                unit="b.py",
                in_progress=_counts_block(3),
            )
            # The live writer cannot be verified on this pass: it goes
            # unresolved, its unit is skipped, and its death is named.
            real_verify = durability.verify_producer

            def _flaky_verify(registry: dict[str, Any]) -> str:
                if registry["worker_uuid"] == _UUID_B:
                    return "unknown"
                return real_verify(registry)

            monkeypatch.setattr(durability, "verify_producer", _flaky_verify)
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
            # The barrier releases even with unresolved producers: their
            # units are skipped, but every other rerun must register.
            assert durability.is_sealed(engaged) is False
            assert plan["unresolved"] == [_UUID_B]
            assert plan["skipped_units"] == ["b.py"]
            assert plan["fenced"] == [_UUID_A]
            assert set(plan["cache_records"]) == {"a.py", "b.py"}
            assert [rec["$report_type"] for rec in plan["cache_records"]["a.py"]] == [
                "CallCountersPartial",
                "CallCountersLost",
            ]
            assert plan["cache_records"]["a.py"][1]["end_state"] == "unknown"
            (lost,) = plan["cache_records"]["b.py"]
            assert lost["$report_type"] == "CallCountersLost"
            assert lost["end_state"] == "unresolved"
            assert lost["worker_uuid"] == _UUID_B
        finally:
            if live.poll() is None:
                live.kill()
                live.wait(timeout=30)

    def test_prepare_resume_releases_seal_for_reruns(self, engaged: Path) -> None:
        dead_pid, dead_birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=dead_pid,
            birth=dead_birth,
            in_progress=_counts_block(5),
        )
        durability.prepare_resume(engaged, prior_merged_jsonl=None)
        # The barrier must release: rerun producers register again.
        assert durability.is_sealed(engaged) is False
        call_counters.record_call("C_Login")
        assert len(list((engaged / "registrations").glob("*.json"))) == 1


# --------------------------------------------------------------------------
# Runner wiring: spawn env, cache collection, recovery supplements, merge
# --------------------------------------------------------------------------


class TestRunnerWiring:
    def test_spawn_env_attempts_match_observation_numbering(self) -> None:
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import (
            _append_process_observation,
            _counters_child_env,
        )

        state = FileRunState(units=["a.py"], fingerprint="fp", results=[])
        base = {durability.COUNTERS_DIR_ENV: "/tmp/counters"}
        first = _counters_child_env(state, base, "a.py", "unit")
        assert first[durability.COUNTERS_ATTEMPT_ENV] == "0"
        _append_process_observation(
            state, {"termination": {"kind": "exit"}}, target="a.py", role="unit"
        )
        second = _counters_child_env(state, base, "a.py", "unit")
        assert second[durability.COUNTERS_ATTEMPT_ENV] == "1"
        retry = _counters_child_env(state, base, "a.py", "retry")
        assert retry[durability.COUNTERS_ATTEMPT_ENV] == "0"
        assert retry[durability.COUNTERS_UNIT_ENV] == "a.py"
        assert retry[durability.COUNTERS_ROLE_ENV] == "retry"
        assert durability.COUNTERS_DIR_ENV in retry

    def test_spawn_env_disengaged_passes_through(self) -> None:
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import _counters_child_env

        state = FileRunState(units=["a.py"], fingerprint="fp", results=[])
        assert _counters_child_env(state, {}, "a.py", "unit") == {}

    def test_cache_attempt_collects_dead_producer_counters_only(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.core import file_runner as file_runner_mod
        from pkcs11_check.core.file_runner import _cache_attempt_report

        monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(engaged))
        # Pin the run-resolved dir too: a previous run in this process may
        # have left the module global pointing at a deleted tmp dir.
        monkeypatch.setattr(file_runner_mod, "_ACTIVE_COUNTERS_DIR", engaged)
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        state_file = tmp_path / "state.json"
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        detail, verified = _cache_attempt_report(
            state_file=state_file,
            unit="a.py",
            jsonl_path=child,
            detail=None,
            status="crashed",
            returncode=-11,
            session_exitstatus=None,
        )
        assert verified is True
        assert detail is None, "counters collection never touches the verdict detail"
        from pkcs11_check.core._report_records import _report_record_cache_path
        from pkcs11_check.core.report_log import iter_report_log_records

        cached = list(iter_report_log_records(_report_record_cache_path(state_file, "a.py")))
        types = [rec.get("$report_type") for rec in cached]
        assert "CallCountersPartial" in types
        assert "CallCountersLost" in types
        payload = extract_call_counters_from_jsonl(_report_record_cache_path(state_file, "a.py"))
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False

    def test_recovery_supplements_fold_the_archived_attempt(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.core._report_records import (
            _report_record_cache_path,
            _write_unit_report_record_cache_from_jsonl_paths,
        )

        _ = engaged  # fixture engages durability (env + clean counters)
        state_file = tmp_path / "state.json"
        archived = _session_record(
            111, _counts_block(4), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        path = durability.write_recovery_supplements(state_file, "a.py", [archived])
        assert path is not None and path.exists()
        rerun = _write_jsonl(
            tmp_path / "rerun.jsonl",
            [
                {"$report_type": "SessionStart"},
                _session_record(
                    222, _counts_block(3), extra={"worker_uuid": _UUID_B, "run_id": _RUN}
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        _write_unit_report_record_cache_from_jsonl_paths(state_file, "a.py", [path, rerun])
        payload = extract_call_counters_from_jsonl(_report_record_cache_path(state_file, "a.py"))
        assert payload is not None
        assert payload["total_calls"] == 7
        assert payload["complete"] is True

    def test_merge_carries_lost_processes_and_probes_detail(self, tmp_path: Path) -> None:
        from pkcs11_check.core.merge import _merge_call_counter_blocks

        left_jsonl = _write_jsonl(
            tmp_path / "left.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), _lost_record()],
        )
        right_jsonl = _write_jsonl(
            tmp_path / "right.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(
                    200,
                    _counts_block(6),
                    extra={
                        "worker_uuid": _UUID_B,
                        "run_id": _RUN,
                        "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        left = extract_call_counters_from_jsonl(left_jsonl)
        right = extract_call_counters_from_jsonl(right_jsonl)
        assert left is not None and right is not None
        merged = _merge_call_counter_blocks(
            [(tmp_path / "shard-a", left), (tmp_path / "shard-b", right)]
        )
        assert merged is not None
        assert merged["total_calls"] == 6
        assert merged["complete"] is False
        assert merged["lost_processes"] == [
            {
                "worker_uuid": _UUID_A,
                "pid": 100,
                "end_state": "crashed",
                "scope_index": 1,
                "run_id": _RUN,
                "unit": "a.py",
                "attempt": 0,
                "shard": "shard-a",
            }
        ]
        assert merged["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]
        assert merged["by_round"][f"shard-a/{_RUN}"]["lost_processes"] == [
            {key: value for key, value in merged["lost_processes"][0].items() if key != "shard"}
        ]
        # Deterministic across merge orders.
        flipped = _merge_call_counter_blocks(
            [(tmp_path / "shard-b", right), (tmp_path / "shard-a", left)]
        )
        assert json.dumps(merged, sort_keys=True) == json.dumps(flipped, sort_keys=True)


# --------------------------------------------------------------------------
# Healthy path: totals byte-identical apart from added identity fields
# --------------------------------------------------------------------------


class TestHealthyPath:
    def test_engaged_session_record_matches_disengaged_plus_identity(self, engaged: Path) -> None:
        from pkcs11_check import _plugin_counters as plugin_counters

        _record_calls(12)
        engaged_record = plugin_counters.build_session_record()
        uuid = engaged_record["worker_uuid"]
        assert schema.is_worker_uuid(uuid) is True
        call_counters.reset_for_tests()
        engaged_record.pop("worker_uuid")
        engaged_record.pop("run_id")
        # Rebuild the identical traffic disengaged for a byte comparison.
        import os as _os

        saved_dir = _os.environ.pop(durability.COUNTERS_DIR_ENV, None)
        saved_run = _os.environ.pop(call_counters.RUN_ID_ENV, None)
        try:
            _record_calls(12)
            bare_record = plugin_counters.build_session_record()
        finally:
            if saved_dir is not None:
                _os.environ[durability.COUNTERS_DIR_ENV] = saved_dir
            if saved_run is not None:
                _os.environ[call_counters.RUN_ID_ENV] = saved_run
        bare_uuid = bare_record.pop("worker_uuid")
        assert schema.is_worker_uuid(bare_uuid) is True
        assert "run_id" not in bare_record
        assert engaged_record["total_calls"] == bare_record["total_calls"] == 12
        assert engaged_record["by_module"] == bare_record["by_module"]
        assert engaged_record["probes_lost"] == bare_record["probes_lost"] == 0

    def test_session_record_carries_folded_receipts(self, engaged: Path) -> None:
        from pkcs11_check import _plugin_counters as plugin_counters

        call_counters.ingest_child_evidence(
            [["m", "C_Login", 0, 2]], 0, [{"worker_uuid": _UUID_A, "probe_seq": 4}]
        )
        record = plugin_counters.build_session_record()
        assert schema.is_session_record(record) is True
        assert record["receipts"] == [{"worker_uuid": _UUID_A, "probe_seq": 4}]

    def test_per_test_entry_carries_window_receipts(self, engaged: Path) -> None:
        from types import SimpleNamespace

        import pytest as _pytest

        from pkcs11_check import _plugin_counters as plugin_counters

        item: Any = SimpleNamespace(
            path=Path("/repo/src/pkcs11_check/testcases/test_x.py"),
            nodeid="src/pkcs11_check/testcases/test_x.py::test_y",
            stash=_pytest.Stash(),
            config=SimpleNamespace(
                getoption=lambda name, default=None: {"p11_module": "/tmp/fake.so"}.get(
                    name, default
                )
            ),
        )
        setup_gen = plugin_counters.pytest_runtest_setup(item)
        next(setup_gen)
        try:
            setup_gen.send(None)
        except StopIteration:
            pass
        call_counters.ingest_child_evidence(
            [["m", "C_Login", 0, 1]], 0, [{"worker_uuid": _UUID_A, "probe_seq": 7}]
        )
        teardown_gen = plugin_counters.pytest_runtest_teardown(item, None)
        next(teardown_gen)
        try:
            teardown_gen.send(None)
        except StopIteration:
            pass
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert schema.is_test_entry(entry) is True
        assert entry["receipts"] == [{"worker_uuid": _UUID_A, "probe_seq": 7}]

    def test_plugin_publish_failure_warns_without_failing_the_test(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        import pytest as _pytest

        from pkcs11_check import _plugin_counters as plugin_counters

        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise durability.CounterPersistenceError("disk gone")

        monkeypatch.setattr(plugin_counters, "publish_test_window", _boom)
        item: Any = SimpleNamespace(
            path=Path("/repo/src/pkcs11_check/testcases/test_x.py"),
            nodeid="src/pkcs11_check/testcases/test_x.py::test_y",
            stash=_pytest.Stash(),
            config=SimpleNamespace(
                getoption=lambda name, default=None: {"p11_module": "/tmp/fake.so"}.get(
                    name, default
                )
            ),
        )
        setup_gen = plugin_counters.pytest_runtest_setup(item)
        next(setup_gen)
        try:
            setup_gen.send(None)
        except StopIteration:
            pass
        teardown_gen = plugin_counters.pytest_runtest_teardown(item, None)
        next(teardown_gen)
        with pytest.warns(UserWarning, match="counter"):
            try:
                teardown_gen.send(None)
            except StopIteration:
                pass
        assert plugin_counters._ENTRY_KEY in item.stash


class TestCliBarrierPlan:
    """C1/C2: the CLI runs the resume barrier early and threads the plan down.

    The in-runner barrier stays as the fallback for programmatic callers and
    must never run twice (``prepare_resume`` consumes producer files). A
    refused resume still lands the already-consumed plan in supplements, so
    a later correct resume folds it instead of silently dropping it.
    """

    def test_counters_dir_for_state_is_state_sibling(self, tmp_path: Path) -> None:
        from pkcs11_check.core._counters_durability import counters_dir_for_state

        state_file = tmp_path / ".pkcs11-check-isolation-state.json"
        assert counters_dir_for_state(state_file) == state_file.with_name(
            ".pkcs11-check-isolation-state.json.counters"
        )

    def test_cli_barrier_plan_is_consumed_not_rerun(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core import file_runner as file_runner_mod
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import _setup_counters_durability

        recorded = tmp_path / "recorded-counters"
        plan = durability.prepare_resume(recorded, prior_merged_jsonl=None)
        assert plan["consumed"] == 0

        def _must_not_run(*args: Any, **kwargs: Any) -> Any:
            pytest.fail("the CLI-provided barrier plan must be consumed, not recomputed")

        monkeypatch.setattr(file_runner_mod, "prepare_resume", _must_not_run)
        saved_active = file_runner_mod._ACTIVE_COUNTERS_DIR
        try:
            state = FileRunState(units=["a.py"], fingerprint="fp", results=[])
            previous = FileRunState(
                units=["a.py"], fingerprint="fp", results=[], counters_dir=str(recorded)
            )
            env: dict[str, str] = {}
            pending = _setup_counters_durability(
                tmp_path / "state.json",
                state,
                ["a.py"],
                True,
                previous,
                _RUN,
                env,
                None,
                Console(file=StringIO(), force_terminal=False),
                barrier_plan=plan,
            )
        finally:
            file_runner_mod._ACTIVE_COUNTERS_DIR = saved_active
        assert pending == ["a.py"]
        assert env[durability.COUNTERS_DIR_ENV] == str(recorded)

    def test_cli_barrier_plan_filters_skipped_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core import file_runner as file_runner_mod
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import _setup_counters_durability

        recorded = tmp_path / "recorded-counters"
        recorded.mkdir()
        lost = _lost_record(end_state="unresolved", unit="b.py")
        plan = durability.prepare_resume(recorded, prior_merged_jsonl=None)
        plan["cache_records"] = {"b.py": [lost]}
        plan["skipped_units"] = ["b.py"]

        def _must_not_run(*args: Any, **kwargs: Any) -> Any:
            pytest.fail("the CLI-provided barrier plan must be consumed, not recomputed")

        monkeypatch.setattr(file_runner_mod, "prepare_resume", _must_not_run)
        saved_active = file_runner_mod._ACTIVE_COUNTERS_DIR
        try:
            state_file = tmp_path / "state.json"
            state = FileRunState(units=["a.py", "b.py"], fingerprint="fp", results=[])
            previous = FileRunState(
                units=["a.py", "b.py"], fingerprint="fp", results=[], counters_dir=str(recorded)
            )
            pending = _setup_counters_durability(
                state_file,
                state,
                ["a.py", "b.py"],
                True,
                previous,
                _RUN,
                {},
                None,
                Console(file=StringIO(), force_terminal=False),
                barrier_plan=plan,
            )
        finally:
            file_runner_mod._ACTIVE_COUNTERS_DIR = saved_active
        assert pending == ["a.py"]
        supplements = durability.supplements_path(state_file, "b.py")
        assert supplements.exists()

    def test_fingerprint_mismatch_applies_cli_plan_before_refusing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core import file_runner as file_runner_mod
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import run_isolated_pytest_units

        recorded = tmp_path / "recorded-counters"
        recorded.mkdir()
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(
                units=["a.py"], fingerprint="WRONG", results=[], counters_dir=str(recorded)
            ),
        )
        plan = durability.prepare_resume(recorded, prior_merged_jsonl=None)
        plan["cache_records"] = {"a.py": [_lost_record(unit="a.py")]}
        saved_active = file_runner_mod._ACTIVE_COUNTERS_DIR
        try:
            with pytest.raises(ValueError, match="different isolated run"):
                run_isolated_pytest_units(
                    ["a.py"],
                    ["--p11-module", "/tmp/module.so"],
                    timeout=12,
                    state_file=state_file,
                    policy_file=None,
                    report_config=None,
                    resume=True,
                    stop_on_failure=False,
                    console=Console(file=StringIO(), force_terminal=False),
                    granularity="file",
                    counters_barrier_plan=plan,
                )
        finally:
            file_runner_mod._ACTIVE_COUNTERS_DIR = saved_active
        supplements = durability.supplements_path(state_file, "a.py")
        lines = supplements.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["$report_type"] == "CallCountersLost"

    def test_reset_clears_supplements_and_counters_dir(self, tmp_path: Path) -> None:
        from pkcs11_check.core._counters_durability import counters_dir_for_state
        from pkcs11_check.core.file_runner import _reset_fresh_run_artifacts

        state_file = tmp_path / "state.json"
        state_file.write_text("{}", encoding="utf-8")
        assert (
            durability.append_supplement_records(state_file, "a.py", [_lost_record(unit="a.py")])
            is True
        )
        supplements = durability.supplements_path(state_file, "a.py")
        assert supplements.exists()
        counters_dir = counters_dir_for_state(state_file)
        (counters_dir / "registrations").mkdir(parents=True)
        (counters_dir / "stale.partial.json").write_text("{}", encoding="utf-8")
        _reset_fresh_run_artifacts(state_file, None)
        assert not supplements.exists()
        # N-C3: the abandoned series' dir is retired with its state (each
        # fresh series allocates its own dir); empty-in-place reuse would
        # let a fresh run absorb a dead series' calls.
        assert not counters_dir.exists()
        assert not state_file.exists()


# --------------------------------------------------------------------------
# R2 round (codex implementation-review findings N-C1/N-C2/N-C3/N-I1)
# --------------------------------------------------------------------------


class TestBarrierFailure:
    """N-C2: a failed seal stops the resume instead of proceeding blind."""

    def test_prepare_resume_reports_seal_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _broken_seal(*args: Any, **kwargs: Any) -> Any:
            raise durability.CounterPersistenceError("EACCES")

        monkeypatch.setattr(durability, "seal", _broken_seal)
        with pytest.warns(UserWarning, match="barrier unavailable"):
            plan = durability.prepare_resume(tmp_path / "counters", prior_merged_jsonl=None)
        assert plan["barrier_ok"] is False
        assert plan["cache_records"] == {}

    def test_runner_barrier_failure_raises_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core import file_runner as file_runner_mod
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import _setup_counters_durability

        def _broken_seal(*args: Any, **kwargs: Any) -> Any:
            raise durability.CounterPersistenceError("EACCES")

        monkeypatch.setattr(durability, "seal", _broken_seal)
        saved_active = file_runner_mod._ACTIVE_COUNTERS_DIR
        try:
            state = FileRunState(units=["a.py"], fingerprint="fp", results=[])
            previous = FileRunState(
                units=["a.py"],
                fingerprint="fp",
                results=[],
                counters_dir=str(tmp_path / "recorded-counters"),
            )
            with pytest.raises(durability.CounterPersistenceError, match="resume barrier"):
                _setup_counters_durability(
                    tmp_path / "state.json",
                    state,
                    ["a.py"],
                    True,
                    previous,
                    _RUN,
                    {},
                    None,
                    Console(file=StringIO(), force_terminal=False),
                    barrier_plan=None,
                )
        finally:
            file_runner_mod._ACTIVE_COUNTERS_DIR = saved_active


class TestProbeConsumedMarker:
    """N-I1: a failed probe-sidecar delete leaves a suppression marker."""

    def test_failed_delete_marks_consumed_and_suppresses_double_fold(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        parent_uuid = call_counters.get_worker_uuid()
        call_counters.record_direct_call("C_Parent", 0)
        probe_sidecar = _plant_probe_orphan(engaged, parent_uuid=parent_uuid, seq=seq)
        real_unlink = os.unlink

        def _fail_probe_delete(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == str(probe_sidecar):
                raise OSError("EACCES")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", _fail_probe_delete)
        assert (
            ingest_probe_payload(tmp_path / "missing-cov.json", seq=seq, sidecar_path=probe_sidecar)
            == "partial"
        )
        markers = list(engaged.glob("probe-consumed-*.json"))
        assert len(markers) == 1
        assert not probe_sidecar.exists()
        info = call_counters.registration_info()
        assert info is not None
        parent_sidecar = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert parent_sidecar["in_progress"]["total_calls"] == 5, "1 parent + 4 probe"
        merged, claimed, consumed, recovered, orphan_keys, adopted, _skipped, _froze = (
            durability._adopt_probe_orphans(
                engaged,
                worker_uuid=parent_uuid,
                sidecar=parent_sidecar,
                journal_lines=[],
                claims={},
                known_uuids={parent_uuid},
                known_complete=True,
                fence_live=True,
            )
        )
        assert merged is None, "parent checkpoint already holds the probe counts"
        assert claimed == []
        assert markers[0] in consumed
        assert recovered == [(parent_uuid, seq)], "marker evidence heals the live claim"
        assert orphan_keys == set()

    def test_failed_rename_is_loud(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        parent_uuid = call_counters.get_worker_uuid()
        call_counters.record_direct_call("C_Parent", 0)
        probe_sidecar = _plant_probe_orphan(engaged, parent_uuid=parent_uuid, seq=seq)
        real_replace = os.replace

        def _fail_probe_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> Any:
            if str(src) == str(probe_sidecar):
                raise OSError("EROFS")
            return real_replace(src, dst, *args, **kwargs)

        def _fail_unlink(path: Any, *args: Any, **kwargs: Any) -> Any:
            raise OSError("EACCES")

        monkeypatch.setattr(os, "unlink", _fail_unlink)
        monkeypatch.setattr(os, "replace", _fail_probe_replace)
        with pytest.raises(durability.CounterPersistenceError, match="consumed"):
            ingest_probe_payload(tmp_path / "missing-cov.json", seq=seq, sidecar_path=probe_sidecar)
        assert probe_sidecar.exists(), "unprotected evidence is retained, not dropped"

    def test_torn_consumed_marker_is_debris(self, engaged: Path) -> None:
        engaged.mkdir(parents=True, exist_ok=True)
        marker = engaged / f"probe-consumed-{_UUID_A[:8]}-3-feedface.json"
        marker.write_text("{torn", encoding="utf-8")
        merged, claimed, consumed, recovered, orphan_keys, adopted, _skipped, _froze = (
            durability._adopt_probe_orphans(
                engaged,
                worker_uuid=_UUID_A,
                sidecar=None,
                journal_lines=[],
                claims={},
                known_uuids={_UUID_A},
                known_complete=True,
                fence_live=True,
            )
        )
        assert merged is None
        assert claimed == []
        assert marker in consumed
        assert recovered == []
        assert orphan_keys == set()

    def test_missing_sidecar_counts_as_deleted(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        parent_uuid = call_counters.get_worker_uuid()
        call_counters.record_direct_call("C_Parent", 0)
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 3]],
                    receipt={"worker_uuid": _UUID_B, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        # The writer suppresses I/O failures: valid coverage may arrive
        # with no sidecar at all. That is success, not a rename target.
        missing = engaged / f"probe-{parent_uuid[:8]}-{seq}-feedface.json"
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=missing) == "folded"
        assert list(engaged.glob("probe-consumed-*.json")) == []

    def test_foreign_sidecar_name_is_loud_on_delete_failure(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        call_counters.get_worker_uuid()
        call_counters.record_direct_call("C_Parent", 0)
        weird = engaged / "weird-sidecar.json"
        weird.write_text(
            json.dumps(
                {
                    "worker_uuid": _UUID_B,
                    "probe_seq": seq,
                    "counters": [["m", "C_Login", 0, 4]],
                }
            ),
            encoding="utf-8",
        )

        def _fail_unlink(path: Any, *args: Any, **kwargs: Any) -> Any:
            raise OSError("EACCES")

        monkeypatch.setattr(os, "unlink", _fail_unlink)
        with pytest.raises(durability.CounterPersistenceError, match="consumed"):
            ingest_probe_payload(tmp_path / "missing-cov.json", seq=seq, sidecar_path=weird)
        assert weird.exists()


class TestRunSpecificCountersDir:
    """N-C3: each fresh series gets its own counters dir; no cross-run leaks."""

    def test_run_dir_helper_is_suffixed_sibling(self, tmp_path: Path) -> None:
        from pkcs11_check.core._counters_durability import counters_run_dir_for_state

        state_file = tmp_path / ".pkcs11-check-isolation-state.json"
        assert counters_run_dir_for_state(state_file, "abc123ef") == state_file.with_name(
            ".pkcs11-check-isolation-state.json.counters.abc123ef"
        )

    def test_reset_retires_previous_dir_and_legacy_canonical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.core._counters_durability import counters_dir_for_state
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import _reset_fresh_run_artifacts

        state_file = tmp_path / "state.json"
        previous = tmp_path / "state.json.counters.deadbeef"
        (previous / "registrations").mkdir(parents=True)
        (previous / "stale.partial.json").write_text("{}", encoding="utf-8")
        save_run_state(
            state_file,
            FileRunState(units=["a.py"], fingerprint="fp", results=[], counters_dir=str(previous)),
        )
        canonical = counters_dir_for_state(state_file)
        canonical.mkdir(parents=True)
        (canonical / "legacy.partial.json").write_text("{}", encoding="utf-8")
        current = tmp_path / "state.json.counters.live1234"
        current.mkdir(parents=True)
        (current / "sentinel").write_text("x", encoding="utf-8")
        monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(current))
        _reset_fresh_run_artifacts(state_file, None)
        assert not previous.exists(), "abandoned series dir goes with its state"
        assert not canonical.exists(), "legacy canonical dir is retired"
        assert (current / "sentinel").exists(), "the live dir is never touched"

    def test_reset_never_signals_live_producer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from pkcs11_check.core.file_runner import _reset_fresh_run_artifacts

        state_file = tmp_path / "state.json"
        previous = tmp_path / "state.json.counters.deadbeef"
        previous.mkdir(parents=True)
        monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(tmp_path / "new.counters.1"))
        live = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            birth = durability.birth_token_for_pid(live.pid)
            _plant_producer(
                previous, uuid=_UUID_A, pid=live.pid, birth=birth, in_progress=_counts_block(5)
            )
            save_run_state(
                state_file,
                FileRunState(
                    units=["a.py"], fingerprint="fp", results=[], counters_dir=str(previous)
                ),
            )
            _reset_fresh_run_artifacts(state_file, None)
            assert not previous.exists()
            assert live.poll() is None, "fresh reset abandons files; it never signals"
        finally:
            if live.poll() is None:
                live.kill()
                live.wait(timeout=30)

    def test_collect_unit_skips_foreign_run_registry(self, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        root = tmp_path / "counters"
        planted = _plant_producer(
            root,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="OTHER-RUN",
            in_progress=_counts_block(5),
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            root,
            unit="a.py",
            child_jsonl=child,
            status="passed",
            returncode=0,
            current_run=_RUN,
        )
        assert records == []
        assert Path(planted["registry"]).exists(), "foreign-run files are retained"
        control = durability.collect_unit(
            root,
            unit="a.py",
            child_jsonl=child,
            status="passed",
            returncode=0,
            current_run="OTHER-RUN",
        )
        assert control != []

    def test_reset_spares_hostile_lookalike_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.core.file_runner import _reset_fresh_run_artifacts

        state_file = tmp_path / "state.json"
        state_file.write_text("{}", encoding="utf-8")
        hostile = tmp_path / "state.json.counters.backup"
        hostile.mkdir()
        (hostile / "sentinel").write_text("x", encoding="utf-8")
        current = tmp_path / "state.json.counters.live1234"
        current.mkdir()
        monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(current))
        with pytest.warns(UserWarning, match="left in place"):
            _reset_fresh_run_artifacts(state_file, None)
        assert (hostile / "sentinel").exists()


class TestBarrierStaging:
    """N-C1: the barrier plan stages durably before sources are consumed."""

    def _dead_unit(self, root: Path, *, uuid: str, unit: str) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            root, uuid=uuid, unit=unit, pid=pid, birth=birth, in_progress=_counts_block(5)
        )

    def test_barrier_stages_plan_before_consuming(self, tmp_path: Path) -> None:
        root = tmp_path / "counters"
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            root, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        staging = json.loads(
            (root / durability.BARRIER_STAGING_FILENAME).read_text(encoding="utf-8")
        )
        assert set(staging["cache_records"]) == {"a.py"}
        assert staging["cache_records"] == plan["cache_records"]
        assert not Path(planted["registry"]).exists()

    def test_crash_between_barrier_and_apply_recovers_from_staging(self, tmp_path: Path) -> None:
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        first = durability.prepare_resume(root, prior_merged_jsonl=None)
        staged_n = sum(len(records) for records in first["cache_records"].values())
        assert staged_n > 0
        del first  # the controller dies before _apply runs
        second = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert second["barrier_ok"] is True
        assert sum(len(records) for records in second["cache_records"].values()) == staged_n
        state_file = tmp_path / "state.json"
        pending = _apply_counters_barrier_plan(
            state_file, second, ["a.py"], Console(file=StringIO(), force_terminal=False)
        )
        assert pending == ["a.py"]
        lines = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert len(lines) == staged_n
        assert not (root / durability.BARRIER_STAGING_FILENAME).exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
    def test_apply_failure_retains_staging_and_is_loud(self, tmp_path: Path) -> None:
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import (
            _apply_counters_barrier_plan,
            _report_record_cache_path,
        )

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        self._dead_unit(root, uuid=_UUID_B, unit="b.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert set(plan["cache_records"]) == {"a.py", "b.py"}
        state_file = tmp_path / "state.json"
        console = Console(file=StringIO(), force_terminal=False)
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(durability.CounterPersistenceError, match="staging retained"):
                _apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        finally:
            tmp_path.chmod(0o755)
        assert (root / durability.BARRIER_STAGING_FILENAME).exists()
        recovered = durability.prepare_resume(root, prior_merged_jsonl=None)
        _apply_counters_barrier_plan(state_file, recovered, ["a.py"], console)
        a_lines = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert len(a_lines) == len(plan["cache_records"]["a.py"])
        b_cache = _report_record_cache_path(state_file, "b.py")
        assert b_cache.exists()
        assert not (root / durability.BARRIER_STAGING_FILENAME).exists()

    def test_double_apply_is_idempotent(self, tmp_path: Path) -> None:
        """#88R11-7: re-applying an applied batch appends nothing."""
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        state_file = tmp_path / "state.json"
        console = Console(file=StringIO(), force_terminal=False)
        _apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        once = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert len(once) > 0
        _apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        twice = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert twice == once, "a cleanup retry must not republish"
        assert not (root / durability.BARRIER_STAGING_FILENAME).exists()

    def test_extractor_absorbs_manual_duplicates(self, tmp_path: Path) -> None:
        """Guard: extractor dedup still absorbs duplicates from other sources."""
        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        lines = plan["cache_records"]["a.py"]
        assert len(lines) > 0

        def _fold(records: list[dict[str, Any]], name: str) -> dict[str, Any]:
            stream = [{"$report_type": "SessionStart"}, _marker("a.py", 0), *records]
            payload = extract_call_counters_from_jsonl(
                _write_jsonl(tmp_path / f"{name}.jsonl", stream)
            )
            assert payload is not None
            return payload

        single, double = _fold(lines, "single"), _fold([*lines, *lines], "double")
        assert double["total_calls"] == single["total_calls"]
        assert double["complete"] == single["complete"]
        assert double["lost_processes"] == single["lost_processes"]

    def test_partial_batch_appends_only_missing(self, tmp_path: Path) -> None:
        """#88R11-7: a crash-window partial batch completes without dupes."""
        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        records = plan["cache_records"]["a.py"]
        assert len(records) >= 2
        state_file = tmp_path / "state.json"
        assert durability.append_supplement_records(state_file, "a.py", records[:1])
        assert durability.append_supplement_records(state_file, "a.py", records)
        lines = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert len(lines) == len(records)
        assert [json.loads(line) for line in lines] == records

    def test_recovery_cache_write_is_idempotent(self, tmp_path: Path) -> None:
        """#88R11-7: cache write-through skips already-cached records."""
        from pkcs11_check.core.file_runner import (
            _report_record_cache_path,
            _write_counters_recovery_cache,
        )

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="b.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        records = plan["cache_records"]["b.py"]
        assert len(records) > 0
        state_file = tmp_path / "state.json"
        assert _write_counters_recovery_cache(state_file, "b.py", records)
        once = _report_record_cache_path(state_file, "b.py").read_text(encoding="utf-8")
        assert _write_counters_recovery_cache(state_file, "b.py", records)
        twice = _report_record_cache_path(state_file, "b.py").read_text(encoding="utf-8")
        assert twice == once

    def test_torn_tail_isolated_before_append(self, tmp_path: Path) -> None:
        """#88R12-5: an unterminated fragment never glues the next record."""
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        records = plan["cache_records"]["a.py"]
        assert len(records) >= 2
        state_file = tmp_path / "state.json"
        supplements = durability.supplements_path(state_file, "a.py")
        supplements.parent.mkdir(parents=True, exist_ok=True)
        supplements.write_text("{fragment", encoding="utf-8")
        console = Console(file=StringIO(), force_terminal=False)
        with pytest.warns(UserWarning, match="torn record"):
            pending = _apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        assert pending == ["a.py"]
        lines = supplements.read_text(encoding="utf-8").splitlines()
        assert lines[0] == "{fragment"
        assert [json.loads(line) for line in lines[1:]] == records
        assert not (root / durability.BARRIER_STAGING_FILENAME).exists()

    @pytest.mark.parametrize("pending", [True, False])
    def test_verify_application_reads_destination(self, tmp_path: Path, pending: bool) -> None:
        """#88R12-5: readability verification covers both destinations."""
        from pkcs11_check.core.file_runner import (
            _report_record_cache_path,
            _verify_counters_application,
            _write_unit_report_record_cache,
        )

        state_file = tmp_path / "state.json"
        records = [{"n": 1}, {"n": 2}]
        assert not _verify_counters_application(state_file, "b.py", records, pending=pending)
        if pending:
            path = durability.supplements_path(state_file, "b.py")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(json.dumps(rec) + "\n" for rec in records), encoding="utf-8")
        else:
            _write_unit_report_record_cache(state_file, "b.py", records)
        assert _verify_counters_application(state_file, "b.py", records, pending=pending)
        if pending:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("{torn")
        else:
            cache = _report_record_cache_path(state_file, "b.py")
            with open(cache, "a", encoding="utf-8") as fh:
                fh.write("{torn\n")
        assert _verify_counters_application(state_file, "b.py", records, pending=pending)

    def test_unreadable_landing_retains_staging(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R12-5: an unverifiable landing fails loud with staging kept."""
        from io import StringIO

        from rich.console import Console

        import pkcs11_check.core.file_runner as file_runner_mod

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="b.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert plan["cache_records"]["b.py"] != []
        state_file = tmp_path / "state.json"
        console = Console(file=StringIO(), force_terminal=False)
        monkeypatch.setattr(
            file_runner_mod, "_write_unit_report_record_cache", lambda *a, **k: None
        )
        with pytest.raises(durability.CounterPersistenceError, match="staging retained"):
            with pytest.warns(UserWarning, match="not readable after landing"):
                file_runner_mod._apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        assert (root / durability.BARRIER_STAGING_FILENAME).exists()

    def test_separator_glued_record_not_deduped(self, tmp_path: Path) -> None:
        """#88R13-5: dedup uses production splitting (0x1e never splits)."""
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

        root = tmp_path / "counters"
        self._dead_unit(root, uuid=_UUID_A, unit="a.py")
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        records = plan["cache_records"]["a.py"]
        assert len(records) >= 1
        state_file = tmp_path / "state.json"
        supplements = durability.supplements_path(state_file, "a.py")
        supplements.parent.mkdir(parents=True, exist_ok=True)
        supplements.write_bytes(b"{fragment\x1e" + json.dumps(records[0]).encode("utf-8") + b"\n")
        console = Console(file=StringIO(), force_terminal=False)
        pending = _apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        assert pending == ["a.py"]
        from pkcs11_check.core.report_log import iter_report_log_records

        readable = list(iter_report_log_records(supplements))
        assert records[0] in readable, "the glued copy never counted as applied"
        assert [rec for rec in readable if rec == records[0]] == [records[0]]

    def test_verify_rejects_separator_glued_record(self, tmp_path: Path) -> None:
        """#88R13-5: verification reads what production reads."""
        from pkcs11_check.core.file_runner import _verify_counters_application

        state_file = tmp_path / "state.json"
        record = {"n": 1}
        path = durability.supplements_path(state_file, "b.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{fragment\x1e" + json.dumps(record).encode("utf-8") + b"\n")
        assert not _verify_counters_application(state_file, "b.py", [record], pending=True)

    def test_healed_retry_apply_stays_single_copy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R11-7: held-through-apply then healed still lands once."""
        from io import StringIO

        from rich.console import Console

        from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

        root = tmp_path / "counters"
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            root,
            uuid=_UUID_A,
            unit="a.py",
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        sidecar = Path(planted["sidecar"])
        real_unlink = Path.unlink
        blocked = True

        def _flaky_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
            if blocked and self.name == sidecar.name:
                raise PermissionError("injected unlink EPERM")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        first = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert first["cleanup_held"] == [str(sidecar)]
        state_file = tmp_path / "state.json"
        console = Console(file=StringIO(), force_terminal=False)
        _apply_counters_barrier_plan(state_file, first, ["a.py"], console)
        staged_n = sum(len(records) for records in first["cache_records"].values())
        assert staged_n > 0
        blocked = False
        second = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert second["cache_records"] == first["cache_records"]
        _apply_counters_barrier_plan(state_file, second, ["a.py"], console)
        lines = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert len(lines) == staged_n, "the healed retry appends nothing twice"

    def test_staging_write_failure_keeps_sources_pristine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "counters"
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            root, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        monkeypatch.setattr(durability, "_write_barrier_staging", lambda *a, **k: False)
        plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is False
        assert Path(planted["registry"]).exists(), "no consume without durable staging"
        # A handled staging refusal releases the seal (#88R25-6): the
        # seal blocks registration (provider entry), not the retry
        # (the next barrier reseals idempotently), so holding it
        # would turn a transient EACCES into a run-wide outage while
        # the retained sources wait untouched.
        assert durability.is_sealed(root) is False

    def test_torn_staging_warns_and_proceeds(self, tmp_path: Path) -> None:
        root = tmp_path / "counters"
        root.mkdir(parents=True)
        staging_path = root / durability.BARRIER_STAGING_FILENAME
        staging_path.write_text("{torn", encoding="utf-8")
        with pytest.warns(UserWarning, match="staging"):
            plan = durability.prepare_resume(root, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert not staging_path.exists(), "torn staging is debris once warned about"


# --------------------------------------------------------------------------
# Batch 2 (rc2 review findings C3/C4/C6/I4)
# --------------------------------------------------------------------------


def _race_seal_between_check_and_create(
    monkeypatch: pytest.MonkeyPatch,
) -> list[list[str]]:
    """Patch ensure_layout so the barrier seals+enumerates mid-registration.

    The wrapper delegates to the real layout builder, then lands the seal
    file and snapshots the registrations dir (the barrier's enumeration)
    before ``register_worker`` publishes its O_EXCL registry file. Returns
    the snapshots taken (one per ensure_layout call).
    """
    real_ensure_layout = durability.ensure_layout
    snapshots: list[list[str]] = []

    def _racing_ensure_layout(root: Path | str) -> Path:
        out = real_ensure_layout(root)
        seal_path = Path(root) / durability.SEAL_FILENAME
        seal_path.write_text(json.dumps({"sealed": True}), encoding="utf-8")
        snapshots.append(sorted(p.name for p in (Path(root) / "registrations").iterdir()))
        return out

    monkeypatch.setattr(durability, "ensure_layout", _racing_ensure_layout)
    return snapshots


def _register_self(root: Path) -> durability.Registration:
    return durability.register_worker(
        root,
        run_id=_RUN,
        unit="a.py",
        attempt=0,
        role="unit",
        isolation="file",
        worker_uuid=_UUID_A,
        pid=os.getpid(),
    )


class TestLateRegistrationRace:
    """C3: publish-then-recheck closes the seal race in register_worker."""

    def test_seal_between_check_and_create_unlinks_and_blocks(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snapshots = _race_seal_between_check_and_create(monkeypatch)
        with pytest.raises(durability.CounterPersistenceError, match="seal"):
            _register_self(engaged)
        # The late registry was published, then retracted: no trace remains.
        assert list((engaged / "registrations").glob("*.json")) == []
        assert snapshots == [[]], "barrier snapshot predates our publish"

    def test_barrier_sees_no_trace_of_late_registrant(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _race_seal_between_check_and_create(monkeypatch)
        with pytest.raises(durability.CounterPersistenceError, match="seal"):
            _register_self(engaged)
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["cache_records"] == {}
        assert plan["fenced"] == []
        assert plan["unresolved"] == []
        assert durability.is_sealed(engaged) is False


class TestCommittedAuthority:
    """C4: JSONL authority must equal extractor acceptance."""

    def test_empty_run_id_session_does_not_consume_live_producer(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        birth = durability.birth_token_for_pid(os.getpid())
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        live_a = _plant_producer(
            engaged, uuid=_UUID_A, pid=os.getpid(), birth=birth, in_progress=_counts_block(5)
        )
        live_b = _plant_producer(
            engaged,
            uuid=_UUID_B,
            unit="b.py",
            pid=os.getpid(),
            birth=birth,
            in_progress=_counts_block(7),
        )
        bad_session = _session_record(
            os.getpid(), _counts_block(5), extra={"worker_uuid": _UUID_A, "run_id": ""}
        )
        good_session = _session_record(
            os.getpid(), _counts_block(7), extra={"worker_uuid": _UUID_B, "run_id": _RUN}
        )
        assert schema.is_session_record(bad_session) is False
        assert schema.is_session_record(good_session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                bad_session,
                _marker("b.py", 0),
                good_session,
            ],
        )
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            == []
        )
        assert (
            durability.collect_unit(
                engaged, unit="b.py", child_jsonl=child, status="passed", returncode=0
            )
            == []
        )
        assert live_a["registry"].exists() and live_a["sidecar"].exists(), "no-consume"
        assert not live_b["registry"].exists() and not live_b["sidecar"].exists(), "committed"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 7, "invalid session folds nothing"

    def test_session_missing_total_calls_still_recovers_gap(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        bad = {
            "$report_type": "CallCountersReport",
            "pid": pid,
            "probes_lost": 0,
            "worker_uuid": _UUID_A,
            "run_id": _RUN,
            "by_module": _counts_block(5)["by_module"],
        }
        assert schema.is_session_record(bad) is False
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), bad],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 5
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False

    def test_malformed_entry_does_not_suppress_journal_window(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        block = _counts_block(3)
        journal = [{"nodeid": "a.py::t1", "block": block, "receipts": []}]
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
            journal=journal,
        )
        bad_entry = {
            "pid": pid,
            "worker_uuid": _UUID_A,
            "run_id": _RUN,
            "by_module": block["by_module"],
        }
        assert schema.is_test_entry(bad_entry) is False
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::t1",
                    "when": "teardown",
                    "outcome": "passed",
                    "user_properties": [["pkcs11_call_counters", bad_entry]],
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 5, "window 3 + tail 2; malformed entry hides nothing"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False

    def test_duplicate_entry_props_grant_first_match_only(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        block = _counts_block(3)
        journal = [{"nodeid": "a.py::t1", "block": block, "receipts": []}]
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(0),
            journal=journal,
        )
        first_bad = {
            "pid": pid,
            "worker_uuid": _UUID_A,
            "run_id": _RUN,
            "by_module": block["by_module"],
        }
        second_good = _test_entry(pid, block, extra={"worker_uuid": _UUID_A, "run_id": _RUN})
        assert schema.is_test_entry(first_bad) is False
        assert schema.is_test_entry(second_good) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::t1",
                    "when": "teardown",
                    "outcome": "passed",
                    "user_properties": [
                        ["pkcs11_call_counters", first_bad],
                        ["pkcs11_call_counters", second_good],
                    ],
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        # The extractor folds the first match only (invalid: skipped), so the
        # gate must grant nothing either: the window stays in the gap.
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 3
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 3
        assert payload["complete"] is False


class TestPidfdTerminate:
    """C6: pidfd re-verification + narrowed signal excepts."""

    def test_recycled_pid_between_open_and_signal_is_not_signaled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 999, raising=False)

        def _explode(fd: int, sig: int) -> None:
            raise AssertionError("must not signal a recycled incarnation")

        monkeypatch.setattr(signal, "pidfd_send_signal", _explode, raising=False)
        monkeypatch.setattr(durability, "_linux_starttime", lambda pid: 777)
        closes: list[int] = []
        monkeypatch.setattr(os, "close", lambda fd: closes.append(fd))
        assert durability._terminate_pidfd(424242, 776, 5.0) is True
        assert closes == [999]

    def test_pidfd_open_lookup_error_is_fenced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _gone(pid: int, flags: int) -> int:
            raise ProcessLookupError(pid)

        monkeypatch.setattr(os, "pidfd_open", _gone, raising=False)
        assert durability._terminate_pidfd(424242, 776, 5.0) is True

    def test_pidfd_open_eperm_is_unresolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _denied(pid: int, flags: int) -> int:
            raise PermissionError("denied")

        monkeypatch.setattr(os, "pidfd_open", _denied, raising=False)
        assert durability._terminate_pidfd(424242, 776, 5.0) is False

    def test_pidfd_open_enosys_is_unresolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _no_syscall(pid: int, flags: int) -> int:
            raise OSError(errno.ENOSYS, "Function not implemented")

        monkeypatch.setattr(os, "pidfd_open", _no_syscall, raising=False)
        assert durability._terminate_pidfd(424242, 776, 5.0) is False

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_pidfd_signal_eperm_is_unresolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 999, raising=False)
        monkeypatch.setattr(durability, "_linux_starttime", lambda pid: 776)

        def _denied(fd: int, sig: int) -> None:
            raise PermissionError("denied")

        monkeypatch.setattr(signal, "pidfd_send_signal", _denied, raising=False)
        closes: list[int] = []
        monkeypatch.setattr(os, "close", lambda fd: closes.append(fd))
        assert durability._terminate_pidfd(424242, 776, 5.0) is False
        assert closes == [999]

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_pidfd_signal_lookup_error_is_fenced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 999, raising=False)
        monkeypatch.setattr(durability, "_linux_starttime", lambda pid: 776)

        def _gone(fd: int, sig: int) -> None:
            raise ProcessLookupError(fd)

        monkeypatch.setattr(signal, "pidfd_send_signal", _gone, raising=False)
        closes: list[int] = []
        monkeypatch.setattr(os, "close", lambda fd: closes.append(fd))
        assert durability._terminate_pidfd(424242, 776, 5.0) is True
        assert closes == [999]

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_terminate_pidfd_kills_real_child(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            assert durability._terminate_pidfd(proc.pid, birth, 10.0) is True
            assert proc.wait(timeout=30) is not None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_pidfd_undead_child_with_proc_eperm_is_unresolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R3: a /proc fault never reports a running process fenced."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            birth = durability.birth_token_for_pid(proc.pid)
            if birth is None:
                pytest.skip("birth tokens unavailable on this platform")
            signaled: list[int] = []

            def _no_kill(fd: int, sig: int) -> None:
                signaled.append(fd)

            monkeypatch.setattr(signal, "pidfd_send_signal", _no_kill, raising=False)
            real_open = open
            proc_reads = 0

            def _eperm_proc(*args: Any, **kwargs: Any) -> Any:
                nonlocal proc_reads
                if str(args[0]).startswith("/proc/"):
                    proc_reads += 1
                    if proc_reads > 1:
                        raise PermissionError("injected /proc EPERM")
                return real_open(*args, **kwargs)

            monkeypatch.setattr("builtins.open", _eperm_proc)
            assert durability._terminate_pidfd(proc.pid, birth, 0.2) is False
            assert signaled, "birth re-read must succeed so the wait is exercised"
            assert proc.poll() is None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_pidfd_exited_live_child_is_false(self) -> None:
        """#88R3: the pidfd wait reads live as unresolved, dead as fenced."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            fd = os.pidfd_open(proc.pid, 0)
            try:
                assert durability._pidfd_exited(fd, 0.0) is False
            finally:
                os.close(fd)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_pidfd_exited_bad_fd_is_unresolved(self) -> None:
        """#88R3: a poll failure never reports fenced."""
        assert durability._pidfd_exited(-1, 0.0) is False

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd fencing is Linux-only")
    def test_pidfd_exited_closed_fd_is_unresolved(self) -> None:
        """#88R3F7: POLLNVAL (not exit readiness) never reports fenced."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            fd = os.pidfd_open(proc.pid, 0)
            os.close(fd)
            assert durability._pidfd_exited(fd, 0.0) is False
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)


class _FakeKernel32:
    """Scriptable kernel32 double behind the _kernel32 seam."""

    def __init__(
        self,
        *,
        open_result: int = 0xABCD,
        creation: int = 9876543210,
        get_times_ok: bool = True,
        terminate_ok: bool = True,
        wait_result: int = 0,
        last_error: int = 0,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self._open_result = open_result
        self._creation = creation
        self._get_times_ok = get_times_ok
        self._terminate_ok = terminate_ok
        self._wait_result = wait_result
        self._last_error = last_error

    def OpenProcess(  # noqa: N802 - mirrors the Win32 API name
        self, access: int, inherit: bool, pid: int
    ) -> int:
        self.calls.append(("OpenProcess", access, inherit, pid))
        return self._open_result

    def GetProcessTimes(  # noqa: N802 - mirrors the Win32 API name
        self, handle: int, creation_ptr: Any, *rest: Any
    ) -> bool:
        self.calls.append(("GetProcessTimes", handle))
        if not self._get_times_ok:
            return False
        ctypes.cast(
            creation_ptr, ctypes.POINTER(ctypes.c_ulonglong)
        ).contents.value = self._creation
        return True

    def TerminateProcess(  # noqa: N802 - mirrors the Win32 API name
        self, handle: int, code: int
    ) -> bool:
        self.calls.append(("TerminateProcess", handle, code))
        return self._terminate_ok

    def WaitForSingleObject(  # noqa: N802 - mirrors the Win32 API name
        self, handle: int, timeout_ms: int
    ) -> int:
        self.calls.append(("WaitForSingleObject", handle, timeout_ms))
        return self._wait_result

    def CloseHandle(  # noqa: N802 - mirrors the Win32 API name
        self, handle: int
    ) -> bool:
        self.calls.append(("CloseHandle", handle))
        return True

    def GetLastError(self) -> int:  # noqa: N802 - mirrors the Win32 API name
        self.calls.append(("GetLastError",))
        return self._last_error

    def terminated(self) -> bool:
        return any(call[0] == "TerminateProcess" for call in self.calls)


class TestWindowsKernel32:
    """I4: one kernel32 declaration site; access-denied never reads dead."""

    def test_helper_declares_pointer_sized_handles(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Any] = {}

        class _FakeFunc:
            def __init__(self) -> None:
                self.argtypes: Any = None
                self.restype: Any = None

        class _FakeDLL:
            def __init__(self) -> None:
                for entry_point in (
                    "OpenProcess",
                    "GetProcessTimes",
                    "TerminateProcess",
                    "CloseHandle",
                    "WaitForSingleObject",
                    "GetLastError",
                ):
                    setattr(self, entry_point, _FakeFunc())

        def _factory(name: str, *, use_last_error: bool) -> _FakeDLL:
            seen["name"] = name
            seen["use_last_error"] = use_last_error
            return _FakeDLL()

        monkeypatch.setattr(ctypes, "WinDLL", _factory, raising=False)
        kernel32 = durability._kernel32()
        assert seen == {"name": "kernel32", "use_last_error": True}
        assert kernel32.OpenProcess.restype is ctypes.c_void_p
        assert kernel32.OpenProcess.argtypes == [ctypes.c_uint, ctypes.c_bool, ctypes.c_uint]
        assert kernel32.GetProcessTimes.restype is ctypes.c_bool
        assert kernel32.TerminateProcess.restype is ctypes.c_bool
        assert kernel32.CloseHandle.restype is ctypes.c_bool
        assert kernel32.WaitForSingleObject.restype == ctypes.c_uint
        assert kernel32.GetLastError.restype == ctypes.c_uint

    def test_pid_exists_access_denied_reads_alive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeKernel32(open_result=0, last_error=5)
        monkeypatch.setattr(durability.sys, "platform", "win32")
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._pid_exists(424242) is True

    def test_pid_exists_not_found_reads_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeKernel32(open_result=0, last_error=87)
        monkeypatch.setattr(durability.sys, "platform", "win32")
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._pid_exists(424242) is False

    def test_pid_exists_unrepresentable_never_reaches_windows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-5: out-of-range pids never reach OpenProcess (no wrap-to-dead)."""
        fake = _FakeKernel32(open_result=0, last_error=87)
        monkeypatch.setattr(durability.sys, "platform", "win32")
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._pid_exists(2**32) is True
        assert durability._pid_exists(2**63) is True
        assert fake.calls == []

    def test_pid_exists_open_handle_closes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeKernel32(open_result=0xABCD)
        monkeypatch.setattr(durability.sys, "platform", "win32")
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._pid_exists(424242) is True
        assert ("CloseHandle", 0xABCD) in fake.calls

    def test_windows_creation_time_round_trips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeKernel32(creation=123456789012345)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._windows_creation_time(424242) == 123456789012345
        assert ("CloseHandle", 0xABCD) in fake.calls

    def test_windows_creation_time_open_failure_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeKernel32(open_result=0, last_error=5)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._windows_creation_time(424242) is None

    def test_terminate_handle_access_denied_is_unresolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeKernel32(open_result=0, last_error=5)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 9876543210, 5.0) is False
        assert fake.terminated() is False

    def test_terminate_handle_not_found_is_fenced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeKernel32(open_result=0, last_error=87)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 9876543210, 5.0) is True
        assert fake.terminated() is False

    def test_terminate_handle_recycled_incarnation_not_signaled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeKernel32(creation=111)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 222, 5.0) is True
        assert fake.terminated() is False
        assert ("CloseHandle", 0xABCD) in fake.calls

    def test_terminate_handle_terminate_failure_is_unresolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeKernel32(creation=222, terminate_ok=False)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 222, 5.0) is False

    def test_terminate_handle_wait_timeout_is_unresolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeKernel32(creation=222, wait_result=0x102)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 222, 5.0) is False

    def test_terminate_handle_happy_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeKernel32(creation=222)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 222, 5.0) is True
        assert fake.terminated() is True
        assert ("CloseHandle", 0xABCD) in fake.calls

    def test_get_process_times_receives_no_null_out_pointers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GetProcessTimes writes all four out-params: NULL would AV (CI windows)."""

        class _StrictKernel32(_FakeKernel32):
            def GetProcessTimes(  # noqa: N802 - mirrors the Win32 API name
                self, handle: int, creation_ptr: Any, *rest: Any
            ) -> bool:
                if any(ptr is None for ptr in rest):
                    raise OSError("exception: access violation writing 0x0000000000000000")
                return super().GetProcessTimes(handle, creation_ptr, *rest)

        fake = _StrictKernel32()
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._windows_creation_time(424242) == 9876543210

    def test_terminate_reverify_receives_no_null_out_pointers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fence re-verify honors the same no-NULL rule (CI windows)."""

        class _StrictKernel32(_FakeKernel32):
            def GetProcessTimes(  # noqa: N802 - mirrors the Win32 API name
                self, handle: int, creation_ptr: Any, *rest: Any
            ) -> bool:
                if any(ptr is None for ptr in rest):
                    raise OSError("exception: access violation writing 0x0000000000000000")
                return super().GetProcessTimes(handle, creation_ptr, *rest)

        fake = _StrictKernel32(creation=222)
        monkeypatch.setattr(durability, "_kernel32", lambda: fake)
        assert durability._terminate_handle(424242, 222, 5.0) is True
        assert fake.terminated() is True


def _broken_writer(path: Any, payload: Any) -> None:
    """A sidecar writer that always fails (K-boundary rollback tests)."""
    raise durability.CounterPersistenceError("disk full")


def _rv_total(flat: list[list[Any]], rv: int | None) -> int:
    """Sum wire-row counts for one RV (None = entries that never returned)."""
    return sum(int(row[3]) for row in flat if row[2] == rv)


# --------------------------------------------------------------------------
# C5: K-boundary rollback (record_* raises before the provider runs)
# --------------------------------------------------------------------------


class TestKBoundaryRollback:
    def test_k_boundary_write_failure_leaves_provider_and_counters_unchanged(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # K=1: every admission is a K boundary. Break the writer before the
        # first call: the entry raises before the provider runs and rolls
        # back the just-admitted counts (strong exception guarantee). The
        # direct-call arm moved to TestRetainNotRollback: post-hoc counts
        # retain, they never roll back.
        provider_calls = 0

        def provider() -> int:
            nonlocal provider_calls
            provider_calls += 1
            return 0

        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_call("C_Login")
            provider()  # Unreachable: the record raises first.
        assert provider_calls == 0, "the call never reached the provider"
        current = call_counters.serialize_current()
        assert current["total_calls"] == 0, "entry rolled back"
        flat = call_counters.flatten_current()
        assert _rv_total(flat, 0) == 0, "no exits admitted"
        assert _rv_total(flat, None) == 0
        info = call_counters.registration_info()
        assert info is not None
        sidecar = Path(info["sidecar_path"])
        assert not sidecar.exists(), "the failed K flush leaves no durable trace"
        assert call_counters.persistence_pending() is False, "nothing retained, nothing pending"
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.flush_counters()
        # Repairing the writer lets the call land, flushed immediately.
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        call_counters.record_call("C_Login")
        provider()
        call_counters.record_return("C_Login", 0)
        assert provider_calls == 1
        assert call_counters.serialize_current()["total_calls"] == 1
        assert json.loads(sidecar.read_text(encoding="utf-8"))["in_progress"]["total_calls"] == 1, (
            "retry flushes immediately under K=1"
        )

    def test_record_return_retry_failure_retains_exit_and_marks_pending(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # rc3 Area A flips this contract: a return whose flush fails KEEPS
        # its exit (the provider already returned — rolling back would hide
        # real traffic) and marks the undurable evidence pending. There is
        # no re-record: the exit was never unadmitted.
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        # Post-hoc child evidence still admits without rollback by design.
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.ingest_child_evidence([["m", "C_Login", 0, 10]])
        assert call_counters.serialize_current()["total_calls"] == 10
        assert call_counters.persistence_pending() is True
        # A return now retries the failed flush; its own exit is retained.
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Done", 0)
        flat = call_counters.flatten_current()
        assert _rv_total(flat, 0) == 11, "the retried exit stays admitted"
        assert sum(int(row[3]) for row in flat if row[1] == "C_Done") == 1
        # Repair: the next entry covers everything (marker clears) and the
        # retained exit lands exactly once — never re-recorded.
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        call_counters.record_call("C_Next")
        assert call_counters.persistence_pending() is False
        flat = call_counters.flatten_current()
        assert _rv_total(flat, 0) == 11
        assert sum(int(row[3]) for row in flat if row[1] == "C_Done") == 1


# --------------------------------------------------------------------------
# I1 (live half): probe ingest flushes the parent before deleting the sidecar
# --------------------------------------------------------------------------


class TestProbeFlushCommit:
    def test_probe_fold_commits_parent_checkpoint(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        parent_uuid = call_counters.get_worker_uuid()
        call_counters.record_direct_call("C_Parent", 0)
        info = call_counters.registration_info()
        assert info is not None
        sidecar = Path(info["sidecar_path"])
        # K=1: the parent call already flushed; the probe fold still commits
        # (flush-then-delete) with the folded counts.
        assert json.loads(sidecar.read_text(encoding="utf-8"))["in_progress"]["total_calls"] == 1
        probe_sidecar = _plant_probe_orphan(engaged, parent_uuid=parent_uuid, seq=seq)
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 3]],
                    receipt={"worker_uuid": _UUID_B, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=probe_sidecar) == "folded"
        assert not probe_sidecar.exists(), "flush-then-delete: sidecar goes after commit"
        assert sidecar.exists(), "below-K fold must flush the parent checkpoint"
        on_disk = json.loads(sidecar.read_text(encoding="utf-8"))
        assert on_disk["in_progress"]["total_calls"] == 4, "1 parent + 3 probe"
        assert {"worker_uuid": _UUID_B, "probe_seq": seq} in on_disk["receipts"]

    def test_partial_path_flushes_before_delete(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        parent_uuid = call_counters.get_worker_uuid()
        info_before = call_counters.registration_info()
        assert info_before is None, "no provider call yet: unregistered"
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        probe_sidecar = _plant_probe_orphan(
            engaged,
            parent_uuid=parent_uuid,
            seq=seq,
            counters=[["m", "C_Login", 0, 6]],
        )
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=probe_sidecar) == "partial"
        assert not probe_sidecar.exists()
        info = call_counters.registration_info()
        assert info is not None
        on_disk = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert on_disk["in_progress"]["total_calls"] == 6
        assert on_disk["receipts"] == [], "partial evidence never earns a receipt"

    def test_probe_sidecar_retained_when_parent_flush_fails(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        parent_uuid = call_counters.get_worker_uuid()
        probe_sidecar = _plant_probe_orphan(engaged, parent_uuid=parent_uuid, seq=seq)
        cov = tmp_path / "cov.json"
        cov.write_text(
            json.dumps(
                _coverage_payload(
                    [["m", "C_Login", 0, 4]],
                    receipt={"worker_uuid": _UUID_B, "probe_seq": seq},
                )
            ),
            encoding="utf-8",
        )
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            ingest_probe_payload(cov, seq=seq, sidecar_path=probe_sidecar)
        assert probe_sidecar.exists(), "retain the probe sidecar on flush failure"
        assert call_counters.serialize_current()["total_calls"] == 4
        # The retained evidence flushes on demand once the writer recovers.
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        assert call_counters.flush_counters() is True
        info = call_counters.registration_info()
        assert info is not None
        on_disk = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert on_disk["in_progress"]["total_calls"] == 4
        assert {"worker_uuid": _UUID_B, "probe_seq": seq} in on_disk["receipts"]


# --------------------------------------------------------------------------
# I1 (collector half): probe-*.json orphan adoption in collect/sweep
# --------------------------------------------------------------------------


class TestProbeOrphanAdoption:
    def test_fallback_ingest_persists_consumed_identity(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Codex RC4-R1-2 (write half): a fallback absorption records its
        # (child, seq) identity into the checkpoint it flushes with.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        status = ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan))
        assert status == "partial"
        assert not orphan.exists(), "commit deletes after flushing"
        sidecar = _read_sidecar()
        assert sidecar["consumed_probes"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]

    def test_publish_window_carries_consumed_proof(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Codex RC4-R2 (writer pin): the journal window carries the
        # consumed proof alongside the counts it journals.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        call_counters.publish_test_window("a.py::t1", None)
        info = call_counters.registration_info()
        assert info is not None
        lines = Path(info["journal_path"]).read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        window = json.loads(lines[0])
        assert window["block"]["total_calls"] == 4
        assert window["consumed_probes"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]

    def test_k100_failed_commit_journal_window_still_suppresses(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Codex RC4-R2 (live interrupt): K=100 keeps the fallback
        # memory-only; the explicit commit fails (orphan retained,
        # sidecar stays at its pre-ingest stale mark); teardown
        # publishes the window to the journal and the boundary sidecar
        # replacement fails too -- the process "dies" with
        # journal-first counts. Collection must fold the window once,
        # exclude the subsumed stale snapshot, and suppress the
        # orphan (6, never 10).
        monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "100")
        _record_calls(2)
        assert call_counters.flush_counters() is True
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan))
        assert orphan.exists(), "failed commit retains the orphan"
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.publish_test_window("a.py::t1", None)
        info = call_counters.registration_info()
        assert info is not None
        stale = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert stale["journal_seq"] == 0
        assert stale["in_progress"]["total_calls"] == 2
        # Post-death surgery: the live test process registered
        # itself, but collection only reaps dead producers. The
        # orphan is also re-prefixed to the live producer (a real
        # child slots under its own parent; the plant used _UUID_A).
        live_uuid = call_counters.get_worker_uuid()
        orphan.rename(orphan.with_name(f"probe-{live_uuid[:8]}-0-feedface.json"))
        dead_pid, dead_birth = _dead_pid_with_birth()
        reg_files = list((engaged / "registrations").glob("*.json"))
        assert len(reg_files) == 1
        reg_content = json.loads(reg_files[0].read_text(encoding="utf-8"))
        reg_content["pid"] = dead_pid
        reg_content["birth_token"] = dead_birth if dead_birth is not None else 0
        reg_files[0].write_text(json.dumps(reg_content), encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 6
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 6

    def test_first_checkpoint_already_carries_consumed_identity(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Codex RC4-R1-2 (atomicity pin): the consumed identity rides
        # inside the ingest transaction, so even the FIRST checkpoint
        # the fallback writes already carries it -- a parent death
        # between the ingest auto-flush and the commit can never
        # strand counts ahead of their anti-double-fold proof.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        snapshots: list[dict[str, Any]] = []
        real_flush = call_counters._flush_locked

        def _spy() -> None:
            real_flush()
            info = call_counters.registration_info()
            assert info is not None
            snapshots.append(json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8")))

        monkeypatch.setattr(call_counters, "_flush_locked", _spy)
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        assert snapshots, "fallback must checkpoint at least once"
        first = snapshots[0]
        assert first["in_progress"]["total_calls"] == 4
        assert first["consumed_probes"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]

    def test_fallback_absorbs_child_unkeyed_scalar(self, engaged: Path, tmp_path: Path) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # B2: the sidecar's unkeyed-loss scalar crosses the fallback
        # with the counts (scalar-anchored remainder rule), so a
        # finalized heal later cannot drop a loss that exists nowhere.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, probes_lost=2)
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        assert call_counters.probes_lost() == 2
        assert call_counters.serialize_current()["total_calls"] == 4

    def test_adopted_orphan_scalar_reaches_partial_and_report(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # B2: an orphan folded at collection carries its unkeyed scalar
        # remainder into the partial and the extracted report (never
        # silently dropped, never double-counted against a live absorb
        # -- folded implies uncovered implies unabsorbed, outside the
        # disclosed triple-fault window where the proof never lands).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, probes_lost=2)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9
        assert partials[0]["probes_lost"] == 2
        assert schema.is_sidecar_partial(partials[0]) is True
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["probes_lost"] == 2
        assert payload["complete"] is False

    def test_adopted_keyed_scalar_counts_once_not_twice(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Batch-2 Important: the sidecar scalar is the child's TOTAL
        # (keyed + unkeyed) while nested keys union separately, so
        # adoption must forward the remainder -- a 1-key/1-scalar
        # orphan reports exactly 1, never 1 keyed + 1 phantom-unkeyed.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            probes_lost=1,
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": 7}],
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0].get("probes_lost", 0) == 0, "remainder 1-1, not total 1"
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["probes_lost"] == 1

    def test_fallback_scalar_applies_remainder_over_keys(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Batch-2 review: the absorbed scalar is the child's TOTAL, so
        # the live leg applies the remainder over the absorbed keys
        # (3 total, 1 keyed -> 2 unkeyed + 1 keyed = 3, never 4).
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            probes_lost=3,
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": 7}],
        )
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        assert call_counters.probes_lost() == 3
        assert call_counters.lost_probe_keys() == [{"parent_uuid": _UUID_B, "probe_seq": 7}]

    def test_fallback_garbage_scalar_folds_counts_without_loss(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Batch-2 review: a malformed scalar never breaks the absorb
        # nor invents a loss -- counts still fold, scalar reads 0.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, probes_lost="many")
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        assert call_counters.serialize_current()["total_calls"] == 4
        assert call_counters.probes_lost() == 0

    def test_absorbed_scalar_not_doubled_when_orphan_retained(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Batch-2 review: live-absorbed scalar + retained duplicate
        # orphan (died after persisting, before the delete) -- the
        # orphan suppresses via the checkpoint proof, so the scalar
        # counts once (2), never sidecar 2 + orphan 2.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, probes_lost=2)
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        assert not orphan.exists()
        live_uuid = call_counters.get_worker_uuid()
        retained = _plant_probe_orphan(engaged, parent_uuid=live_uuid, seq=0, probes_lost=2)
        dead_pid, dead_birth = _dead_pid_with_birth()
        reg_files = list((engaged / "registrations").glob("*.json"))
        assert len(reg_files) == 1
        reg_content = json.loads(reg_files[0].read_text(encoding="utf-8"))
        reg_content["pid"] = dead_pid
        reg_content["birth_token"] = dead_birth if dead_birth is not None else 0
        reg_files[0].write_text(json.dumps(reg_content), encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 4
        assert partials[0]["probes_lost"] == 2
        assert not retained.exists(), "covered orphan consumes without folding"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["probes_lost"] == 2

    def test_run_probe_notes_loss_when_commit_fails(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from pkcs11_check.testcases._probes.runner import run_probe

        # Codex 6.2 F1: a commit failure must not skip the keyed loss
        # note the success path records -- note, then re-raise, so the
        # killed probe's unflushed tail can never read complete.
        seen_seq: list[int] = []

        def _killed(*args: Any, **kwargs: Any) -> None:
            env = kwargs["env"]
            Path(env["_P11CHECK_SUBPROCESS_COVERAGE"]).write_bytes(b"{torn")
            seq = int(env[durability.PROBE_SEQ_ENV])
            seen_seq.append(seq)
            Path(env[durability.PROBE_SIDECAR_ENV]).write_text(
                json.dumps(
                    {
                        "worker_uuid": _UUID_B,
                        "probe_seq": seq,
                        "counters": [["m", "C_Login", 0, 4]],
                    }
                ),
                encoding="utf-8",
            )

        def _fail_commit_only(path: Any, payload: Any) -> None:
            total = (payload.get("in_progress") or {}).get("total_calls", 0)
            if total > 0:
                raise durability.CounterPersistenceError("disk full")
            durability.write_sidecar_atomic(path, payload)

        monkeypatch.setattr(
            subprocess, "Popen", _fake_popen_factory(on_spawn=_killed, returncode=-9)
        )
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _fail_commit_only)
        with pytest.raises(durability.CounterPersistenceError):
            run_probe("_echo", {"module_path": "/x.so"})
        assert seen_seq != []
        parent = call_counters.get_worker_uuid()
        assert call_counters.probes_lost() == 1
        assert call_counters.lost_probe_keys() == [
            {"parent_uuid": parent, "probe_seq": seen_seq[0]}
        ]
        assert call_counters.serialize_current()["total_calls"] == 4

    def test_empty_fallback_still_persists_consumed_identity(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        # Variant of the R1-2 window: an empty snapshot absorbs zero
        # counts, so ONLY the consumed identity dirties the producer --
        # the commit must still persist the anti-double-fold proof.
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, counters=[])
        cov = tmp_path / "cov.json"
        cov.write_bytes(b"{oops")
        assert ingest_probe_payload(str(cov), seq=0, sidecar_path=str(orphan)) == "partial"
        assert not orphan.exists()
        sidecar = _read_sidecar()
        assert sidecar["in_progress"]["total_calls"] == 0
        assert sidecar["consumed_probes"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]

    def test_garbage_consumed_probe_ignored(self, engaged: Path) -> None:
        # Garbage tolerance: a malformed consumed identity never
        # breaks the ingest it rides with, and persists nothing.
        for garbage in (
            "not-a-pair",
            ("not-a-uuid", 0),
            (_UUID_B, -1),
            (_UUID_B, 0, "extra"),
            {"worker_uuid": _UUID_B, "probe_seq": 0},
        ):
            call_counters.ingest_child_evidence(
                [["m", "C_Login", 0, 1]], 0, (), consumed_probe=garbage
            )
        sidecar = _read_sidecar()
        assert sidecar["consumed_probes"] == []
        assert sidecar["in_progress"]["total_calls"] == 5

    def test_consumed_orphan_suppresses_instead_of_doubling(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex RC4-R1-2 (read half): parent persisted the fallback
        # prefix, then died before deleting the sidecar. Collection
        # folds the checkpoint gap once and suppresses the retained
        # orphan (3, never 6).
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(3)
        )
        sidecar_path = Path(planted["sidecar"])
        content = json.loads(sidecar_path.read_text(encoding="utf-8"))
        content["consumed_probes"] = [{"worker_uuid": _UUID_B, "probe_seq": 0}]
        sidecar_path.write_text(json.dumps(content), encoding="utf-8")
        _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, counters=[["m", "C_Login", 0, 3]])
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 3

    def test_empty_orphan_still_heals_and_unions_keys(self, engaged: Path) -> None:
        # Robustness M1: a zero-counters orphan carries no counts but its
        # identity still heals the parent's live claim and its nested keys
        # still union -- healing must not gate on having counts to fold.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[],
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": 1}],
        )
        sidecar = durability.read_json_file(planted["sidecar"])
        merged, claimed, consumed, recovered, orphan_keys, adopted, _skipped, _froze = (
            durability._adopt_probe_orphans(
                engaged,
                worker_uuid=_UUID_A,
                sidecar=sidecar,
                journal_lines=[],
                claims={},
                known_uuids={_UUID_A},
                known_complete=True,
                producer_run=_RUN,
                producer_unit="a.py",
                fence_live=True,
            )
        )
        assert merged is None
        assert claimed == []
        assert recovered == [(_UUID_A, 0)]
        assert orphan_keys == {(_UUID_B, 1)}

    def test_dead_worker_orphan_folds_exactly_once(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        partial = records[0]
        assert schema.is_sidecar_partial(partial) is True
        assert partial["worker_uuid"] == _UUID_A, "orphan folds under the parent uuid"
        assert partial["total_calls"] == 9, "gap 5 + orphan 4, counted once"
        buckets = partial["by_module"]["m"]["buckets"]
        assert buckets["setup_teardown"]["calls"] == 5
        assert buckets["test"]["calls"] == 4, "recovery attribution for orphan traffic"
        assert partial["receipts"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]
        assert not orphan.exists(), "folded orphans are consumed"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["complete"] is False
        assert payload["probes_lost"] == 0, "no lost-probe inflation"
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]

    def test_receipt_covered_orphan_is_suppressed(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        # The parent flushed AFTER ingesting the probe (died between the
        # flush and the delete): the gap holds the counts and the receipt.
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(9),
            receipts=[{"worker_uuid": _UUID_B, "probe_seq": 0}],
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert records[0]["total_calls"] == 9, "covered orphan adds nothing"
        assert records[0]["receipts"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]
        assert not orphan.exists(), "covered orphans are consumed silently"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["probes_lost"] == 0
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]

    def test_entry_covered_orphan_is_suppressed_not_doubled(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        # Journal publish failed (the warn path): the sidecar is pre-window
        # and the journal empty, but the entry committed with the probe's
        # counts and receipt. Folding the orphan as well would double-count.
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        entry = _test_entry(
            pid,
            _counts_block(4),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
            },
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert records[0]["total_calls"] == 2, "tail only; the entry holds the probe"
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 6, "entry 4 + tail 2, counted exactly once"
        assert payload["probes_lost"] == 0
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]

    def test_entry_consumed_proof_suppresses_orphan_without_rows(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        # Codex RC4-R3: journal publish failed (the warn path) after a
        # fallback absorb, but the teardown entry committed with the
        # probe's counts and its consumed proof. The entry claim must
        # suppress the retained orphan (4, never 8) while earning no
        # folded detail row for the consumed pair.
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        entry = _test_entry(
            pid,
            _counts_block(4),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "consumed_probes": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
            },
        )
        assert schema.is_test_entry(entry) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
        )
        assert records[0]["total_calls"] == 2, "tail only; the entry holds the probe"
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 6, "entry 4 + tail 2, counted exactly once"
        assert payload["probes_lost"] == 0
        assert payload.get("probes_detail", []) == []

    def test_committed_unabsorbed_orphan_never_heals(self, engaged: Path, tmp_path: Path) -> None:
        # Codex R2-F1: a session never absorbed this orphan (transient
        # live miss + retained sidecar), so the committed path must not
        # heal the parent's loss claim -- the partial's counts die to
        # session-supersede while heals pierce it, and healing would
        # report complete with real calls silently missing. The loss
        # stands (fail-visible); exact recovery awaits the heal-linkage
        # design (total 5 pins the honest-degraded contract, not 9).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, probes_lost=2)
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 4
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False
        # No folded row for the superseded orphan: folded means counts
        # included (codex R2-F2), and the session dropped this block.
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 0, "status": "lost"},
        ]

    def test_committed_empty_orphan_still_heals(self, engaged: Path, tmp_path: Path) -> None:
        # Codex R2-F1 exception: vacuous evidence (zero counts, zero
        # scalar) heals soundly on the committed path -- the session
        # trivially contains nothing, so the claim resolves complete.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0, counters=[])
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert [rec["$report_type"] for rec in records] == ["CallCountersPartial"]
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 0
        assert payload["complete"] is True

    def test_mistyped_session_never_heals_nor_supersedes_silently(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R2-F1b: collect rejects this session (strict schema)
        # while extraction stages it (lenient isolation default), so
        # the gap path runs but must not heal -- otherwise the partial
        # dies to supersede while the heal pierces it (silent 5/True).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "isolation": 123,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        assert schema.is_session_record(session) is False
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9, "gap folds tail 5 + orphan 4"
        assert partials[0].get("recovered_keys", []) == [], "but never heals it"
        assert not orphan.exists(), "gap path still consumes the adopted orphan"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_read_jsonl_lines_missing_file_reads_none(self, tmp_path: Path) -> None:
        # The tri-state's failure leg is a real I/O miss, not a mock
        # artifact: a missing file reads None (absent path handled by
        # callers), a present file reads its raw lines.
        assert durability._read_jsonl_lines(tmp_path / "nope.jsonl") is None
        child = tmp_path / "child.jsonl"
        child.write_bytes(b'{"a": 1}\n{"b": 2}\n')
        assert durability._read_jsonl_lines(child) == [b'{"a": 1}', b'{"b": 2}', b""]

    def test_unreadable_registry_retained_for_later_pass(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R3: reaping must target provably-torn content, never an
        # unreadable file -- a transient registry read fault with no
        # parent checkpoint yet must retain the registry (deleting it
        # would orphan the retained probe sidecar from every later
        # pass). A healed re-collection then adopts it exactly once.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        failing: list[bool] = [True]
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes

        def _flaky_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
            if failing[0] and self == Path(planted["registry"]):
                raise OSError("transient read failure")
            return real_read_text(self, *args, **kwargs)

        def _flaky_read_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if failing[0] and self == Path(planted["registry"]):
                raise OSError("transient read failure")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _flaky_read_text)
        monkeypatch.setattr(Path, "read_bytes", _flaky_read_bytes)
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
            == []
        )
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        failing[0] = False
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 4
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 4

    def test_oneshot_registry_failure_retains_valid_registry(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R5: when the collect-loop read fails transiently but the
        # reaper's own read succeeds on valid content, the registry must
        # be retained (it is provably healthy, not torn) -- reaping it
        # would strand the retained orphan from every later pass.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes
        attempts: list[str] = []

        def _flaky_twice(self: Path, *args: Any, **kwargs: Any) -> str:
            # Fail the pre-loop scan and the loop read; the reaper's
            # own read then succeeds on valid content.
            if len(attempts) < 2 and self == Path(planted["registry"]):
                attempts.append("read")
                raise OSError("transient read failure")
            return real_read_text(self, *args, **kwargs)

        def _flaky_twice_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if len(attempts) < 2 and self == Path(planted["registry"]):
                attempts.append("read")
                raise OSError("transient read failure")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _flaky_twice)
        monkeypatch.setattr(Path, "read_bytes", _flaky_twice_bytes)
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert attempts == ["read", "read"], "fault was exercised twice"
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        assert records == []

    def test_sweep_retains_registry_on_transient_read_failure(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R6: the sweep must use the same validity triage as
        # collection -- a transient registry read failure with no
        # parent checkpoint must retain (deleting would strand the
        # retained probe sidecar from every later pass).
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth)
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        real_read_text = Path.read_text

        def _flaky_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
            if self == Path(planted["registry"]):
                raise OSError("transient read failure")
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _flaky_read_text)
        result = durability.sweep_orphans(engaged, current_run=_RUN)
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        assert result["removed"] == 0

    def test_undecodable_registry_reaps_when_nothing_adopts_it(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R5: undecodable bytes are provably torn (the project
        # writes strict UTF-8), so reaping still applies when no
        # sidecar could adopt -- only I/O failure retains.
        engaged.mkdir(parents=True, exist_ok=True)
        reg = engaged / "registrations" / f"{_UUID_A}.json"
        reg.parent.mkdir(parents=True, exist_ok=True)
        reg.write_bytes(b'{"worker_uuid": "\xff"}')
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert records == []
        assert not reg.exists()

    def test_cross_round_session_never_consumes_foreign_gap(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R5: session authority is (run, uuid), never uuid alone
        # -- an R2 session for this producer's uuid must not divert
        # the R1 checkpoint into the committed path (which would drop
        # its gap while deleting its files). The gap folds; both runs
        # keep their own evidence.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="R1",
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid,
            _counts_block(7),
            extra={"worker_uuid": _UUID_A, "run_id": "R2"},
        )
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9, "R1 gap 5 + adopted orphan 4"
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}], (
            "gap heals still fire (evidence folds here)"
        )
        assert not orphan.exists()
        assert Path(planted["sidecar"]).exists() is False
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 16, "R1 gap 9 + R2 session 7"
        assert payload["complete"] is False

    def test_unreadable_child_degrades_to_retain_all_plus_conflict(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R2-F1a: an unreadable child JSONL blinds sessions,
        # entries, and claims together -- collection must fold nothing
        # (any fold risks doubling what extraction later sees), retain
        # every file for a later pass, and name the conflict loudly.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        failing: list[bool] = [True]
        real_read_lines = durability._read_jsonl_lines

        def _flaky_read_lines(path: Path) -> Any:
            if failing[0] and path == child:
                return None
            return real_read_lines(path)

        monkeypatch.setattr(durability, "_read_jsonl_lines", _flaky_read_lines)
        with pytest.warns(UserWarning, match="cannot read"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert [rec["$report_type"] for rec in records] == ["CallCountersLost"]
        assert records[0]["end_state"] == "conflict"
        assert Path(planted["sidecar"]).exists()
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        failing[0] = False
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False

    def test_committed_malformed_scalar_never_heals(self, engaged: Path, tmp_path: Path) -> None:
        # Codex R2-F3: a corrupt scalar is not evidence of zero -- an
        # empty-counters orphan with a malformed scalar must not heal
        # on the committed path (its losses are unknown, not absent).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged, parent_uuid=_UUID_A, seq=0, counters=[], probes_lost="many"
        )
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        # No heal, no counts, no keys: nothing to emit. The session's
        # own loss claim stands (see below); the orphan still consumes.
        assert records == []
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_committed_garbage_rows_never_heals(self, engaged: Path, tmp_path: Path) -> None:
        # Codex R3-F3: vacuous needs a genuinely empty wire list -- rows
        # present-but-unparseable prove nothing about zero calls, so the
        # claim stands even though no block folds.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Login", 0, "4"]],
        )
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert records == []
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_u2028_in_session_string_does_not_split_collect_read(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R3-F1: framing must match the extractor (binary LF
        # split), not str.splitlines (which splits U+2028): a session
        # carrying a literal U+2028 must be visible to collection's
        # lenient set, or the gap heal pierces the supersede the
        # extractor applies (silent 5/True).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "isolation": "a\u2028b",
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        lines = [
            json.dumps({"$report_type": "SessionStart"}),
            json.dumps(_marker("a.py", 0)),
            json.dumps(session, ensure_ascii=False),
            json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}),
        ]
        child = tmp_path / "child.jsonl"
        child.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert "\u2028" in child.read_text(encoding="utf-8"), "literal U+2028 on disk"
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert all(rec.get("recovered_keys", []) == [] for rec in records)
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_nbsp_prefixed_session_visible_to_collection(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R4: collection must strip lines before parsing exactly
        # like extraction -- an NBSP-prefixed session line must land in
        # the lenient set, or the gap heal pierces the supersede the
        # extractor applies (silent 5/True).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        lines = [
            json.dumps({"$report_type": "SessionStart"}).encode(),
            json.dumps(_marker("a.py", 0)).encode(),
            "\u00a0".encode() + json.dumps(session).encode(),
            json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}).encode(),
        ]
        child = tmp_path / "child.jsonl"
        child.write_bytes(b"\n".join(lines) + b"\n")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert all(rec.get("recovered_keys", []) == [] for rec in records)
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_bad_byte_line_skipped_identically_both_sides(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R3-F1: an undecodable line is skipped by collection
        # exactly like extraction (strict per-line decode), so both
        # sides agree the session is absent and the gap path folds
        # tail + orphan coherently (9, complete) instead of diverging
        # (collect-sees/supersede-drops vs extract-blind).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "isolation": "ISOMARK",
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        lines = [
            json.dumps({"$report_type": "SessionStart"}).encode(),
            json.dumps(_marker("a.py", 0)).encode(),
            json.dumps(session).encode().replace(b"ISOMARK", b"a\xffb"),
            json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}).encode(),
        ]
        child = tmp_path / "child.jsonl"
        child.write_bytes(b"\n".join(lines) + b"\n")
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["complete"] is False, "crash record still dispositions"

    def test_committed_malformed_keys_never_heal(self, engaged: Path, tmp_path: Path) -> None:
        # Codex R5-F3: corrupt loss metadata is not evidence of zero --
        # malformed nested keys degrade to unkeyed losses (visible) and
        # block the vacuous heal (their losses are unknown, not absent).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[],
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": "7"}],
        )
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert all(rec.get("recovered_keys", []) == [] for rec in records)
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        # Standing claim only: the adopted bump dies to supersede with
        # the claim partial (session authoritative) -- exact surfacing
        # of adopted scalars on this path awaits the heal-linkage
        # design; what matters here is the claim stands (no heal).
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_committed_zero_scalar_malformed_keys_never_heal(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R6: an explicit-zero scalar does not make corrupt keys
        # vacuous -- the corruption blocks the heal (the total floors
        # loud to 1 here, R7-F3), and the committed path never heals
        # non-vacuous orphans (their counts die to supersede).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[],
            probes_lost=0,
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": "7"}],
        )
        session = _session_record(
            pid,
            _counts_block(5, bucket="setup_teardown"),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "lost_keys": [_lost_key(_UUID_A, 0)],
            },
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert all(rec.get("recovered_keys", []) == [] for rec in records)
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_gap_malformed_keys_surface_as_unkeyed(self, engaged: Path, tmp_path: Path) -> None:
        # Codex R5: on the gap path (no supersede) the degraded bump
        # surfaces numerically -- one malformed nested key reads as
        # one unkeyed loss in the partial and the report.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": "7"}],
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9
        assert partials[0]["probes_lost"] == 1
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_gap_malformed_keys_not_double_counted_in_scalar(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R6: a valid scalar already includes every loss the
        # child counted -- including ones whose keys later corrupted
        # -- so malformed items must not bump it again (1 total + 1
        # malformed key reads 1 unkeyed, never 2).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            probes_lost=1,
            lost_keys=[{"parent_uuid": _UUID_B, "probe_seq": "7"}],
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9
        assert partials[0]["probes_lost"] == 1
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["probes_lost"] == 1

    def test_gap_absent_scalar_mixed_keys_keep_malformed_loss(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R7-F3: without a usable total the malformed bump is a
        # floor, not a total -- valid keys were never inside it, so the
        # remainder must not subtract them (1 valid + 1 malformed reads
        # 1 keyed + 1 unkeyed, never 1 keyed + 0).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            lost_keys=[
                {"parent_uuid": _UUID_B, "probe_seq": 7},
                {"parent_uuid": _UUID_B, "probe_seq": "7"},
            ],
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9
        assert partials[0]["probes_lost"] == 1
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["probes_lost"] == 2

    def test_torn_unknown_run_never_collides_with_named_round(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R7-F1/R8-F1: a null run stamps the "unknown"
        # sentinel, never str(None) and never implicit -- a null-run
        # checkpoint plus a literal-"None" session are disjoint
        # evidence (5 + 7), not one round. The unknown round reads
        # truncated (dead producer, no session); pre-R7 True was
        # supersede laundering the death into the live round.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        planted["registry"].unlink()
        sidecar_data = json.loads(planted["sidecar"].read_text(encoding="utf-8"))
        sidecar_data["run_id"] = None
        planted["sidecar"].write_text(json.dumps(sidecar_data), encoding="utf-8")
        session = _session_record(
            pid,
            _counts_block(7),
            extra={"worker_uuid": _UUID_A, "run_id": "None"},
        )
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["run_id"] == "unknown"
        assert partials[0]["total_calls"] == 5
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 12
        assert payload["complete"] is False

    def test_torn_null_run_never_merges_into_implicit_session(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex R8-F1: explicit-null and absent are different rounds --
        # a null-run checkpoint plus a runless session for the same
        # uuid are disjoint evidence (5 + 7); merging them into the
        # implicit round would let the session supersede the
        # checkpoint silently (7, complete).
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        planted["registry"].unlink()
        sidecar_data = json.loads(planted["sidecar"].read_text(encoding="utf-8"))
        sidecar_data["run_id"] = None
        planted["sidecar"].write_text(json.dumps(sidecar_data), encoding="utf-8")
        session = _session_record(pid, _counts_block(7), extra={"worker_uuid": _UUID_A})
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["run_id"] == "unknown"
        assert partials[0]["total_calls"] == 5
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 12
        assert payload["complete"] is False

    def test_torn_absent_run_merges_into_implicit_session(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Companion: a legacy runless checkpoint plus a runless
        # session ARE one implicit round -- the session supersedes
        # the gap (7, complete), never doubling to 12. This is why
        # absent reads implicit while explicit-null reads "unknown".
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, bucket="setup_teardown"),
        )
        planted["registry"].unlink()
        sidecar_data = json.loads(planted["sidecar"].read_text(encoding="utf-8"))
        del sidecar_data["run_id"]
        planted["sidecar"].write_text(json.dumps(sidecar_data), encoding="utf-8")
        session = _session_record(pid, _counts_block(7), extra={"worker_uuid": _UUID_A})
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert "run_id" not in partials[0]
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 7
        assert payload["complete"] is True

    def test_collect_retains_registry_on_sticky_read_failure(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R7-F2: the torn-twin cleanup funnels through the same
        # validity triage as the sweep -- a registry that fails every
        # read is retained (a fault must never destroy the producer
        # record). #88R2 refines: unreadable is never torn, so the
        # sidecar is retained unadopted too -- a live producer's
        # evidence waits a later pass instead of folding as an orphan
        # (which also named false in-flight losses).
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes

        def _sticky_fault(self: Path, *args: Any, **kwargs: Any) -> str:
            if self == Path(planted["registry"]):
                raise OSError("sticky read failure")
            return real_read_text(self, *args, **kwargs)

        def _sticky_fault_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if self == Path(planted["registry"]):
                raise OSError("sticky read failure")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _sticky_fault)
        monkeypatch.setattr(Path, "read_bytes", _sticky_fault_bytes)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        with pytest.warns(UserWarning, match="unreadable registry"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert records == []
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_barrier_never_credits_junk_run_to_sweep(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R8-F2: sweep authority needs a genuine stamp -- a
        # null-run checkpoint adopted by the barrier must not credit
        # "None" to collected_runs, or the sweep deletes a "None"-
        # stamped checkpoint it never staged (unreadable during the
        # barrier scan, readable again before the sweep).
        pid_a, birth_a = _dead_pid_with_birth()
        planted_a = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid_a, birth=birth_a, in_progress=_counts_block(5)
        )
        planted_a["registry"].unlink()
        sidecar_a = json.loads(planted_a["sidecar"].read_text(encoding="utf-8"))
        sidecar_a["run_id"] = None
        planted_a["sidecar"].write_text(json.dumps(sidecar_a), encoding="utf-8")
        pid_b, birth_b = _dead_pid_with_birth()
        planted_b = _plant_producer(
            engaged, uuid=_UUID_B, pid=pid_b, birth=birth_b, in_progress=_counts_block(5)
        )
        planted_b["registry"].unlink()
        sidecar_b = json.loads(planted_b["sidecar"].read_text(encoding="utf-8"))
        sidecar_b["run_id"] = "None"
        planted_b["sidecar"].write_text(json.dumps(sidecar_b), encoding="utf-8")
        fault_on = True
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes

        def _gated_fault(self: Path, *args: Any, **kwargs: Any) -> str:
            if fault_on and self == Path(planted_b["sidecar"]):
                raise OSError("transient barrier-phase fault")
            return real_read_text(self, *args, **kwargs)

        def _gated_fault_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if fault_on and self == Path(planted_b["sidecar"]):
                raise OSError("transient barrier-phase fault")
            return real_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _gated_fault)
        monkeypatch.setattr(Path, "read_bytes", _gated_fault_bytes)
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert plan["barrier_ok"] is True
        assert "None" not in plan["collected_runs"]
        fault_on = False
        durability.sweep_orphans(
            engaged,
            current_run=_RUN,
            collected_runs=frozenset(plan["collected_runs"]),
        )
        assert Path(planted_b["sidecar"]).exists()

    def test_reject_reserved_run_id_contract(self) -> None:
        # Codex R9-F2: the "unknown" round sentinel is reserved --
        # only that exact value raises; unset, empty, and named runs
        # all pass.
        with pytest.raises(call_counters.CounterPersistenceError, match="reserved run_id"):
            durability.reject_reserved_run_id("unknown")
        durability.reject_reserved_run_id(None)
        durability.reject_reserved_run_id("")
        durability.reject_reserved_run_id("R1")

    def test_registration_rejects_reserved_unknown_run_id(self, engaged: Path) -> None:
        # Codex R9-F2: no live producer may run under the sentinel --
        # its session would silently supersede corrupt checkpoints
        # sharing its uuid. Loud at registration, before any provider
        # work, with no registry left behind.
        with pytest.raises(call_counters.CounterPersistenceError, match="reserved run_id"):
            durability.register_worker(
                engaged,
                run_id="unknown",
                unit="a.py",
                attempt=0,
                role="unit",
                isolation="file",
                worker_uuid=_UUID_A,
                pid=os.getpid(),
            )
        assert list((engaged / "registrations").glob("*.json")) == []

    def test_session_record_rejects_reserved_unknown_run_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Codex R9-F2: direct-pytest sessions stamp the ambient run id
        # without registering, so the session record guards the
        # reservation itself -- no "unknown" session can ever be
        # emitted to authorize a silent merge.
        from pkcs11_check import _plugin_counters as plugin_counters
        from pkcs11_check.core.call_counters import RUN_ID_ENV

        monkeypatch.setenv(RUN_ID_ENV, "unknown")
        with pytest.raises(call_counters.CounterPersistenceError, match="reserved run_id"):
            plugin_counters.build_session_record()

    def test_sweep_empty_collected_runs_sweeps_no_run_match(self, engaged: Path) -> None:
        # Codex R9-F1 blast radius: fresh runs sweep with empty
        # collected_runs, so the run-match branches are dead code
        # there -- a prior-run checkpoint retains unconditionally
        # (the run-granular residual needs a resume barrier's plan).
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="R0",
            in_progress=_counts_block(5),
        )
        planted["registry"].unlink()
        result = durability.sweep_orphans(engaged, current_run=_RUN)
        assert Path(planted["sidecar"]).exists()
        assert result["removed"] == 0

    def test_committed_producer_orphan_suppressed_when_session_claims(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(9),
            receipts=[{"worker_uuid": _UUID_B, "probe_seq": 0}],
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid,
            _counts_block(9),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
            },
        )
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        assert (
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
            == []
        ), "committed producers stay silent"
        assert not orphan.exists()
        assert not planted["registry"].exists()
        assert not planted["sidecar"].exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 9
        assert payload["complete"] is True
        assert "lost_processes" not in payload
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]

    def test_committed_producer_orphan_claims_receipt_when_session_lacks_it(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(9)
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        # The session holds the counts (ingest succeeded in memory) but not
        # the receipt (partial-path suppression + failed flush): the orphan
        # fold claims it, and the partial is superseded, so counts stay
        # exact. The claim earns no folded ROW: folded means counts
        # included, and this block was dropped (codex R2-F2) -- the
        # absorbed-unflushed attribution gap is documented, not silent.
        # (No loss claim rides this plant; real retained orphans always
        # come with a parent note -- see the never-heals pin -- which
        # would stand here and read incomplete.)
        session = _session_record(
            pid, _counts_block(13), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        assert schema.is_session_record(session) is True
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert [rec["$report_type"] for rec in records] == ["CallCountersPartial"]
        assert records[0]["worker_uuid"] == _UUID_A
        assert records[0]["receipts"] == [{"worker_uuid": _UUID_B, "probe_seq": 0}]
        assert not orphan.exists()
        assert not planted["registry"].exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 13, "session supersedes the claim partial"
        assert payload["complete"] is True
        assert payload.get("probes_detail", []) == []

    def test_sweep_reaps_torn_probe_files_and_retains_valid(self, engaged: Path) -> None:
        durability.ensure_layout(engaged)
        torn = engaged / "probe-aaaaaaaa-0-deadbeef.json"
        torn.write_text("{torn json", encoding="utf-8")
        retained_invalid = engaged / "probe-aaaaaaaa-1-deadbeef.json"
        retained_invalid.write_text(json.dumps({"stale": True}), encoding="utf-8")
        valid = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=2)
        result = durability.sweep_orphans(engaged, current_run="OTHER")
        assert result == {"removed": 1, "retained": 2}
        assert not torn.exists()
        assert retained_invalid.exists(), "dict-shaped files are retained, never destroyed"
        assert valid.exists(), "valid orphans wait for collection"

    def test_adoption_retains_unattributable_orphans(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        # Dict-shaped but schema-invalid: retained like an invalid sidecar.
        invalid = engaged / f"probe-{_UUID_A[:8]}-0-badshape.json"
        invalid.write_text(json.dumps({"stale": True}), encoding="utf-8")
        # No producer carries this prefix: parentless, evidence preserved.
        parentless = _plant_probe_orphan(engaged, parent_uuid="c" * 32, seq=0, nonce="beefcafe")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert records[0]["total_calls"] == 5, "gap only; no orphan folded"
        assert invalid.exists()
        assert parentless.exists()

    def test_ambiguous_prefix_orphan_is_retained(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        first = "a" * 31 + "0"
        second = "a" * 31 + "1"
        _plant_producer(engaged, uuid=first, pid=pid, birth=birth, in_progress=_counts_block(5))
        _plant_producer(engaged, uuid=second, pid=pid, birth=birth, in_progress=_counts_block(7))
        orphan = _plant_probe_orphan(engaged, parent_uuid=first, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                {
                    "$report_type": "TestReport",
                    "nodeid": "a.py::test_first",
                    "when": "setup",
                    "outcome": "passed",
                },
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert sorted(rec["total_calls"] for rec in records if "total_calls" in rec) == [5, 7]
        assert orphan.exists(), "a colliding prefix must not misattribute evidence"


# --------------------------------------------------------------------------
# I2: stale losses reconcile against validated authority
# --------------------------------------------------------------------------


class TestLostReconciliation:
    def test_authoritative_session_heals_stale_loss(self, tmp_path: Path) -> None:
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        assert schema.is_session_record(session) is True
        orders = (
            [session, _partial_record(), _lost_record()],
            [_lost_record(), _partial_record(), session],
            [_partial_record(), _lost_record(), session],
        )
        for records in orders:
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
            assert "lost_processes" not in payload, "the stale loss is healed"
            assert payload["by_process"] == [
                {
                    "pid": 100,
                    "isolation": "file",
                    "total_calls": 10,
                    "complete": True,
                    "worker_uuid": _UUID_A,
                }
            ]

    def test_healed_producer_plus_unrelated_loss_stays_incomplete(self, tmp_path: Path) -> None:
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        assert schema.is_session_record(session) is True
        unrelated = _lost_record(worker_uuid=_UUID_B, pid=200, unit="b.py")
        for records in (
            [session, _partial_record(), _lost_record(), unrelated],
            [unrelated, _lost_record(), _partial_record(), session],
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
            assert payload["complete"] is False
            assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_B], (
                "only the independent loss survives"
            )

    def test_pid_only_loss_never_healed_by_session(self, tmp_path: Path) -> None:
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        assert schema.is_session_record(session) is True
        pid_only = _lost_record()
        del pid_only["worker_uuid"]
        assert schema.is_lost_record(pid_only) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                pid_only,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is False
        assert payload["lost_processes"] == [
            {
                "pid": 100,
                "end_state": "crashed",
                "scope_index": 1,
                "run_id": _RUN,
                "unit": "a.py",
                "attempt": 0,
            }
        ]

    def test_loss_in_other_round_not_healed(self, tmp_path: Path) -> None:
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        assert schema.is_session_record(session) is True
        other_round = _lost_record(run_id="R2")
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                other_round,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is False
        assert payload["by_round"][_RUN]["complete"] is True
        assert payload["by_round"]["R2"]["complete"] is False
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]


# --------------------------------------------------------------------------
# Area A (rc3): K=1 cadence — every record persists immediately
# --------------------------------------------------------------------------


def _sidecar_by_fn(on_disk: dict[str, Any], module: str, fn: str) -> dict[str, Any]:
    """Find one function's block in an on-disk sidecar payload (any bucket)."""
    modules = on_disk["in_progress"]["by_module"]
    assert module in modules
    for bucket_block in modules[module]["buckets"].values():
        by_fn = bucket_block.get("by_fn", {})
        if fn in by_fn:
            return by_fn[fn]
    raise AssertionError(f"{fn} missing from on-disk module {module!r}")


def _read_sidecar() -> dict[str, Any]:
    info = call_counters.registration_info()
    assert info is not None
    return json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))


class TestK1Cadence:
    def test_flush_window_is_one(self) -> None:
        assert durability.FLUSH_WINDOW_K == 1

    def test_every_entry_flushes_immediately(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        on_disk = _read_sidecar()
        assert on_disk["in_progress"]["total_calls"] == 1
        assert call_counters.flush_counters() is False

    def test_every_return_flushes_immediately(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        call_counters.record_return("C_Login", 0, module="m")
        # The RV is durable before any next call runs: a kill here keeps
        # the return. Read the sidecar, never the globals.
        on_disk = _read_sidecar()
        assert on_disk["in_progress"]["total_calls"] == 1
        assert _sidecar_by_fn(on_disk, "m", "C_Login")["by_rv"]["0"]["count"] == 1
        assert call_counters.flush_counters() is False

    def test_direct_call_flushes_immediately(self, engaged: Path) -> None:
        call_counters.record_direct_call("C_Login", 0, module="m")
        on_disk = _read_sidecar()
        assert on_disk["in_progress"]["total_calls"] == 1
        assert _sidecar_by_fn(on_disk, "m", "C_Login")["by_rv"]["0"]["count"] == 1

    def test_note_lost_probe_flushes_scalar_immediately(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        call_counters.note_lost_probe()
        assert _read_sidecar().get("probes_lost") == 1
        assert call_counters.flush_counters() is False

    def test_add_lost_probes_flushes_scalar_immediately(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        call_counters.add_lost_probes(3)
        assert _read_sidecar().get("probes_lost") == 3
        assert call_counters.flush_counters() is False

    def test_receipt_only_ingest_persists_receipts_immediately(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        receipt = {"worker_uuid": _UUID_B, "probe_seq": 0}
        call_counters.ingest_child_evidence([], 0, [receipt])
        assert receipt in _read_sidecar()["receipts"]
        assert call_counters.flush_counters() is False

    def test_loss_only_ingest_flushes_immediately(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        call_counters.ingest_child_evidence([], 2, [])
        assert _read_sidecar().get("probes_lost") == 2
        assert call_counters.flush_counters() is False

    def test_zero_call_mutation_flush_failure_is_loud(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_counters.record_call("C_Login", module="m")
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.note_lost_probe()
        # Retained, marked, and loud: the loss is not silently dropped.
        assert call_counters.probes_lost() == 1
        assert call_counters.persistence_pending() is True

    def test_repeated_publish_flush_failure_then_success_converges(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The journal leg covers retained evidence even when the sidecar
        # leg fails: a failed publish-flush raises (fail-visible) but sets
        # no pending marker, and a later success converges the mark.
        original = call_counters.write_sidecar_atomic
        for nodeid in ("a.py::t1", "a.py::t2"):
            before = call_counters.take_snapshot()
            _record_calls(1)
            window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
            monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
            with pytest.raises(durability.CounterPersistenceError):
                call_counters.publish_test_window(nodeid, window)
            monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
            assert call_counters.persistence_pending() is False
        before = call_counters.take_snapshot()
        _record_calls(1)
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        call_counters.publish_test_window("a.py::t3", window)
        info = call_counters.registration_info()
        assert info is not None
        journal_lines = Path(info["journal_path"]).read_text(encoding="utf-8").splitlines()
        assert len(journal_lines) == 3
        assert _read_sidecar()["journal_seq"] == 3
        assert call_counters.persistence_pending() is False


# --------------------------------------------------------------------------
# Area A (rc3): retain-not-rollback + pending-failure protocol
# --------------------------------------------------------------------------


class TestRetainNotRollback:
    def test_failed_return_flush_retains_exit_and_sets_pending(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_counters.record_call("C_Login", module="m")
        call_counters.record_return("C_Login", 0, module="m")
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Done", 0, module="m")
        # The provider already returned: the exit stays admitted (never
        # rolled back), and the undurable evidence is marked pending.
        flat = call_counters.flatten_current()
        assert _rv_total(flat, 0) == 2
        assert sum(int(row[3]) for row in flat if row[1] == "C_Done") == 1
        assert call_counters.persistence_pending() is True

    def test_pending_marker_blocks_next_entry_until_recovered(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_counters.record_call("C_Login", module="m")
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Login", 0, module="m")
        assert call_counters.persistence_pending() is True
        # The next entry retries persistence first and blocks while the
        # writer is still broken: the provider never runs, nothing admits.
        provider_calls = 0
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_call("C_Blocked", module="m")
            provider_calls += 1  # Unreachable: the record raises first.
        assert provider_calls == 0
        assert call_counters.serialize_current()["total_calls"] == 1
        assert call_counters.persistence_pending() is True
        # Repair: the next entry recovers (retry covers, marker clears)
        # and the blocked call lands exactly once.
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        call_counters.record_call("C_Blocked", module="m")
        assert call_counters.persistence_pending() is False
        assert call_counters.serialize_current()["total_calls"] == 2
        assert _read_sidecar()["in_progress"]["total_calls"] == 2

    def test_failed_direct_flush_retains_both_halves(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Direct calls count post-hoc: the provider RAN before the record,
        # so a failed flush retains (never rolls back) and marks pending.
        provider_calls = 0
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            provider_calls += 1
            call_counters.record_direct_call("C_Login", 0, module="m")
        assert provider_calls == 1
        current = call_counters.serialize_current()
        assert current["total_calls"] == 1
        flat = call_counters.flatten_current()
        assert _rv_total(flat, 0) == 1
        assert call_counters.persistence_pending() is True

    def test_entry_failure_still_rolls_back_and_blocks(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # K=1: every admission is a K boundary. A failed entry flush rolls
        # back (the provider never ran) and sets no marker: nothing is
        # retained, so nothing is pending.
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        provider_calls = 0
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_call("C_Login", module="m")
            provider_calls += 1  # Unreachable: the record raises first.
        assert provider_calls == 0
        assert call_counters.serialize_current()["total_calls"] == 0
        assert call_counters.persistence_pending() is False

    def test_publish_clears_preexisting_marker_via_journal_leg(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_counters.record_call("C_Login", module="m")
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Login", 0, module="m")
        assert call_counters.persistence_pending() is True
        # A publish whose append lands covers the retained evidence: the
        # marker clears even though this publish's own sidecar leg fails.
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        before = call_counters.take_snapshot()
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        call_counters.publish_test_window("a.py::t1", window)
        assert call_counters.persistence_pending() is False

    def test_publish_clears_marker_despite_failing_boundary_flush(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The journal leg covers retained evidence: the append clears the
        # marker even though this publish's own sidecar flush then fails
        # (fail-visible, no new marker); a later healthy publish converges.
        call_counters.record_call("C_Login", module="m")
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Login", 0, module="m")
        assert call_counters.persistence_pending() is True
        before = call_counters.take_snapshot()
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.publish_test_window("a.py::t1", window)
        assert call_counters.persistence_pending() is False
        info = call_counters.registration_info()
        assert info is not None
        assert len(Path(info["journal_path"]).read_text(encoding="utf-8").splitlines()) == 1
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        before = call_counters.take_snapshot()
        _record_calls(1)
        window = call_counters.diff_snapshots(before, call_counters.take_snapshot())
        call_counters.publish_test_window("a.py::t2", window)
        assert _read_sidecar()["journal_seq"] == 2
        assert call_counters.persistence_pending() is False

    def test_repaired_evidence_recovers_exactly(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_counters.record_call("C_Login", module="m")
        original = call_counters.write_sidecar_atomic
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Login", 0, module="m")
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", original)
        call_counters.record_call("C_Next", module="m")
        call_counters.record_return("C_Next", 0, module="m")
        # No re-record, no double count, no loss: on-disk equals memory.
        on_disk = _read_sidecar()
        assert on_disk["in_progress"]["total_calls"] == 2
        assert _sidecar_by_fn(on_disk, "m", "C_Login")["by_rv"]["0"]["count"] == 1
        assert _sidecar_by_fn(on_disk, "m", "C_Next")["by_rv"]["0"]["count"] == 1
        assert call_counters.serialize_current()["total_calls"] == 2


# --------------------------------------------------------------------------
# Area A (rc3): surviving marker forces counter-specific incomplete
# --------------------------------------------------------------------------


class TestPendingMarkerEmission:
    def test_surviving_marker_forces_session_incomplete(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "persistence_pending": {"checkpoint": "return", "unit": "a.py", "attempt": 0},
            },
        )
        assert schema.is_session_record(session) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        # The counts are present and exact — but durability degraded, so
        # the counters read incomplete with the persistence reason shown.
        assert payload["total_calls"] == 10
        assert payload["complete"] is False
        assert payload["by_round"][_RUN]["complete"] is False
        rows = payload["by_process"]
        assert rows and all(row["complete"] is False for row in rows)
        assert all(row.get("persistence_pending") is True for row in rows)

    def test_failed_unit_without_marker_keeps_complete_counters(self, tmp_path: Path) -> None:
        # R3-2 regression pin: counter completeness derives from the
        # persistence marker, never from generic unit status. An ordinary
        # provider failure with clean persistence keeps complete counters.
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        assert schema.is_session_record(session) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 1},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is True

    def test_malformed_marker_reads_as_pending_not_clean(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={"worker_uuid": _UUID_A, "run_id": _RUN, "persistence_pending": "bogus"},
        )
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        # Fail closed: an unreadable marker cannot prove clean persistence.
        assert payload["total_calls"] == 10
        assert payload["complete"] is False

    def test_live_marker_reaches_session_record(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # End to end through the real emission path: a failed return at
        # the tail (no next entry to block) rides to the session record.
        from pkcs11_check._plugin_counters import build_session_record

        call_counters.record_call("C_Login", module="m")
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.record_return("C_Login", 0, module="m")
        assert call_counters.persistence_pending() is True
        session = build_session_record()
        assert session["persistence_pending"]["checkpoint"] == "return"
        assert session["total_calls"] == 1


# --------------------------------------------------------------------------
# Area A (rc3): validated-count mark rule
# --------------------------------------------------------------------------


def _block_fn_count(block: dict[str, Any], module: str, fn: str) -> int:
    """Sum one function's calls across all buckets of a module-first block."""
    total = 0
    for bucket_block in block["by_module"][module]["buckets"].values():
        entry = bucket_block.get("by_fn", {}).get(fn)
        if entry is not None:
            total += entry["calls"]
    return total


def _collect_dead(engaged: Path, tmp_path: Path, name: str = "child.jsonl") -> list[dict[str, Any]]:
    child = _write_jsonl(
        tmp_path / name,
        [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
    )
    return durability.collect_unit(
        engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
    )


class TestMarkRule:
    def test_older_mark_folds_all_valid_and_excludes_stale(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Multi-publish crash: two publishes' sidecar flushes failed, so the
        # journal ran ahead (3 valid windows, mark still 1). The stale
        # snapshot is subsumed by journal[1] (failed appends never reset),
        # so the gap folds every valid window and excludes the snapshot:
        # 3+4+5, with fn_A exactly once (no double count, no under-count).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(3, fn="C_A"),
            journal=[
                {"nodeid": "a.py::t1", "block": _counts_block(3, fn="C_A"), "receipts": []},
                {"nodeid": "a.py::t2", "block": _counts_block(4, fn="C_B"), "receipts": []},
                {"nodeid": "a.py::t3", "block": _counts_block(5, fn="C_C"), "receipts": []},
            ],
            journal_seq=1,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 12
        assert _block_fn_count(records[0], "m", "C_A") == 3
        assert _block_fn_count(records[0], "m", "C_B") == 4
        assert _block_fn_count(records[0], "m", "C_C") == 5
        assert records[1]["end_state"] == "crashed"

    def test_newer_mark_is_conflict_without_partial(self, engaged: Path, tmp_path: Path) -> None:
        # Pin-as-is: a vanished append (mark ahead of the journal) stays a
        # corruption conflict with a lost record only.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []}],
            journal_seq=5,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == ["CallCountersLost"]
        assert records[0]["end_state"] == "conflict"

    def test_mark_without_journal_is_conflict_without_partial(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # A nonzero mark with no journal file means every append vanished
        # (deleted/truncated journal): corruption, lost record only.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2),
            journal_seq=3,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == ["CallCountersLost"]
        assert records[0]["end_state"] == "conflict"

    def test_newer_mark_with_scalar_emits_loss_partial_plus_conflict(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # The newer-mark arm drops counts, but the sidecar scalar (no window-
        # overlap ambiguity: it never lived in any journal window) still
        # flows as a zero-call loss partial beside the conflict.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2),
            journal=[{"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []}],
            journal_seq=5,
            probes_lost=3,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 0
        assert records[0]["probes_lost"] == 3
        assert records[1]["end_state"] == "conflict"

    def test_self_heal_failed_append_recovers_all_plus_conflict(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Pin-as-is: [A, torn-failed-B, C] with seq=2. B's append raised
        # loudly at runtime (no reset), C's superset window recovered B's
        # calls, and the tear still flags conflict. Everything folds.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Tail"),
            journal=[
                {"nodeid": "a.py::t1", "block": _counts_block(3), "receipts": []},
                {"nodeid": "a.py::t3", "block": _counts_block(4), "receipts": []},
            ],
        )
        lines = planted["journal"].read_text(encoding="utf-8").splitlines()
        planted["journal"].write_text(
            lines[0] + "\n{" + '"nodeid": "a.py::t2", "block": ' + "\n" + lines[1] + "\n",
            encoding="utf-8",
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 9
        assert records[1]["end_state"] == "conflict"


# --------------------------------------------------------------------------
# Area A (rc3): loss-scalar pipeline (sidecar → partial → extract)
# --------------------------------------------------------------------------


class TestLossScalarPipeline:
    def test_dead_producer_scalar_folds_into_partial(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            probes_lost=3,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 5
        assert records[0]["probes_lost"] == 3

    def test_partial_scalar_folds_into_extract_totals(self, tmp_path: Path) -> None:
        partial = _partial_record(worker_uuid=_UUID_A, run_id=_RUN, attempt=0, probes_lost=3)
        partial.update(_counts_block(5))
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                partial,
                _lost_record(),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 3
        assert payload["complete"] is False

    def test_committed_producer_scalar_not_double_folded(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Pin-as-is guard: when the session is authoritative, a stale
        # sidecar scalar must never inflate the loss total.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            probes_lost=7,
        )
        session = _session_record(
            pid,
            _counts_block(5),
            extra={"worker_uuid": _UUID_A, "run_id": _RUN, "probes_lost": 1},
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), session],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                *records,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["probes_lost"] == 1

    def test_mistyped_scalar_is_conflict_not_counts(self, engaged: Path, tmp_path: Path) -> None:
        # Fail closed: an unreadable loss scalar conflicts loudly instead
        # of inventing (or silently dropping) a loss count.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            probes_lost="bogus",
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 5
        assert records[0].get("probes_lost", 0) == 0
        assert records[1]["end_state"] == "conflict"

    def test_zero_call_scalar_still_emits_loss_partial(self, engaged: Path, tmp_path: Path) -> None:
        # A producer with no calls but real losses still emits its scalar:
        # dropping it would silently under-count losses.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(0),
            probes_lost=2,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 0
        assert records[0]["probes_lost"] == 2


# --------------------------------------------------------------------------
# Area A (rc3): bounded transient retry inside persistence writes
# --------------------------------------------------------------------------


class TestTransientWriteRetry:
    def test_sidecar_transient_failure_absorbed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0
        real_replace = os.replace

        def _flaky(src: Any, dst: Any) -> None:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise OSError(errno.EAGAIN, "try again")
            real_replace(src, dst)

        monkeypatch.setattr(os, "replace", _flaky)
        durability.write_sidecar_atomic(tmp_path / "s.json", {"a": 1})
        assert json.loads((tmp_path / "s.json").read_text(encoding="utf-8")) == {"a": 1}
        assert calls == 3

    def test_sidecar_permanent_failure_raises_fast(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0

        def _denied(src: Any, dst: Any) -> None:
            nonlocal calls
            calls += 1
            raise OSError(errno.ENOSPC, "no space left")

        monkeypatch.setattr(os, "replace", _denied)
        with pytest.raises(durability.CounterPersistenceError):
            durability.write_sidecar_atomic(tmp_path / "s.json", {"a": 1})
        assert calls == 1, "permanent errors never retry"

    def test_sidecar_persistent_transient_raises_bounded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0

        def _always_busy(src: Any, dst: Any) -> None:
            nonlocal calls
            calls += 1
            raise OSError(errno.EAGAIN, "busy")

        monkeypatch.setattr(os, "replace", _always_busy)
        with pytest.raises(durability.CounterPersistenceError):
            durability.write_sidecar_atomic(tmp_path / "s.json", {"a": 1})
        assert calls == 3, "transient errors retry boundedly, then raise"

    def test_journal_transient_open_failure_absorbed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A transient open failure (the win32-AV shape) retries the whole
        # open: nothing landed, so nothing can duplicate.
        real_open = os.open
        calls = 0

        def _flaky_open(path: Any, flags: int, mode: int = 0o666) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EAGAIN, "try again")
            return real_open(path, flags, mode)

        monkeypatch.setattr(os, "open", _flaky_open)
        journal = tmp_path / "w.windows.jsonl"
        durability.append_journal(journal, {"nodeid": "a.py::t1", "block": _counts_block(2)})
        assert calls == 2
        assert journal.read_text(encoding="utf-8").count("a.py::t1") == 1

    def test_record_absorbs_transient_os_replace_failure(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0
        real_replace = os.replace

        def _flaky(src: Any, dst: Any) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EAGAIN, "try again")
            real_replace(src, dst)

        monkeypatch.setattr(os, "replace", _flaky)
        call_counters.record_call("C_Login")
        assert call_counters.persistence_pending() is False
        assert _read_sidecar()["in_progress"]["total_calls"] == 1

    def test_transient_predicate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        is_transient = durability._is_transient_write_error
        # Both halves force the platform: on real Windows sys.platform is
        # already "win32", which would flip the POSIX EACCES assert below.
        monkeypatch.setattr(sys, "platform", "linux")
        assert is_transient(OSError(errno.EAGAIN, "try again")) is True
        assert is_transient(OSError(errno.EWOULDBLOCK, "would block")) is True
        assert is_transient(OSError(errno.ENOSPC, "no space")) is False
        assert is_transient(OSError(errno.EACCES, "denied")) is False
        monkeypatch.setattr(sys, "platform", "win32")
        assert is_transient(OSError(errno.EACCES, "denied")) is True
        assert is_transient(OSError(errno.EPERM, "denied")) is True
        assert is_transient(OSError(errno.ENOSPC, "no space")) is False

    def test_journal_partial_write_completes_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Faithful POSIX fakes: short writes return counts (no error); a
        # raising write accepts zero bytes. A failed attempt retries only
        # the unwritten remainder, never the whole line, so no duplicate
        # window can land (close cannot complete an unbuffered write).
        real_write = os.write
        calls = 0

        def _flaky_write(fd: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:10])
            if calls == 2:
                raise OSError(errno.EAGAIN, "try again")
            return real_write(fd, data)

        monkeypatch.setattr(os, "write", _flaky_write)
        journal = tmp_path / "w.windows.jsonl"
        durability.append_journal(journal, {"nodeid": "a.py::t1", "block": _counts_block(2)})
        lines = journal.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["nodeid"] == "a.py::t1"

    def test_journal_close_error_after_landing_does_not_duplicate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Bytes that left the process are page-cache durable (this module's
        # whole scope), so a close error after a complete write is success:
        # retrying would duplicate the window, and raising would make the
        # next publish double-count via its superset window.
        real_close = os.close
        calls = 0

        def _flaky_close(fd: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EIO, "close commit failed")
            real_close(fd)

        monkeypatch.setattr(os, "close", _flaky_close)
        journal = tmp_path / "w.windows.jsonl"
        durability.append_journal(journal, {"nodeid": "a.py::t1", "block": _counts_block(2)})
        assert calls == 1, "no retry on close errors"
        lines = journal.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["nodeid"] == "a.py::t1"

    def test_journal_permanent_write_failure_raises_without_landing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pin-as-is guard: a permanent write failure raises at once (no
        # retry, nothing landed) so the publish-level superset self-heals.
        def _denied(fd: int, data: bytes) -> int:
            raise OSError(errno.ENOSPC, "no space left")

        monkeypatch.setattr(os, "write", _denied)
        journal = tmp_path / "w.windows.jsonl"
        with pytest.raises(durability.CounterPersistenceError):
            durability.append_journal(journal, {"nodeid": "a.py::t1", "block": _counts_block(2)})
        assert journal.read_text(encoding="utf-8") == ""


# --------------------------------------------------------------------------
# Area D (rc3): isolation/role on worker partials + lost
# --------------------------------------------------------------------------


class TestRegistryIsolationStamp:
    def test_registration_records_isolation_env(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(call_counters.ISOLATION_ENV, "file")
        call_counters.record_call("C_Login")
        registries = sorted((engaged / "registrations").glob("*.json"))
        assert len(registries) == 1
        content = json.loads(registries[0].read_text(encoding="utf-8"))
        assert content.get("isolation") == "file"
        assert schema.is_registry_content(content) is True

    def test_registration_defaults_isolation_unknown(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(call_counters.ISOLATION_ENV, raising=False)
        call_counters.record_call("C_Login")
        registries = sorted((engaged / "registrations").glob("*.json"))
        assert len(registries) == 1
        content = json.loads(registries[0].read_text(encoding="utf-8"))
        assert content.get("isolation") == "unknown"
        assert schema.is_registry_content(content) is True


class TestPartialLostAttribution:
    def test_dead_producer_records_carry_role_and_isolation(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            role="retry",
            isolation="file",
            in_progress=_counts_block(5),
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["role"] == "retry"
        assert records[0]["isolation"] == "file"
        assert records[1]["role"] == "retry"
        assert records[1]["isolation"] == "file"
        assert schema.is_sidecar_partial(records[0]) is True
        assert schema.is_lost_record(records[1]) is True

    def test_default_attribution_stays_omitted(self, engaged: Path, tmp_path: Path) -> None:
        # Pin-as-is guard: default attribution stays omitted (absent reads
        # as the default), so default-shaped records are byte-stable.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            isolation="unknown",
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert "role" not in records[0]
        assert "isolation" not in records[0]
        assert "role" not in records[1]
        assert "isolation" not in records[1]

    def test_isolation_less_registry_adopts_orphan_without_attribution(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # A registry without the required stamp reads as absent, but the
        # evidence is not lost: the sidecar adopts through the orphan path
        # (attribution honestly unknown).
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            isolation=None,
        )
        records = _collect_dead(engaged, tmp_path)
        assert [rec["$report_type"] for rec in records] == [
            "CallCountersPartial",
            "CallCountersLost",
        ]
        assert records[0]["total_calls"] == 5
        assert "role" not in records[0]
        assert "isolation" not in records[0]
        assert "role" not in records[1]
        assert "isolation" not in records[1]

    def test_partial_role_and_isolation_reach_rows(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            role="retry",
            isolation="file",
            in_progress=_counts_block(5),
        )
        collected = _collect_dead(engaged, tmp_path, name="child.jsonl")
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                *collected,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        assert payload["complete"] is False
        rows = payload["by_process"]
        assert len(rows) == 1
        assert rows[0]["isolation"] == "file"
        assert rows[0]["role"] == "retry"
        assert rows[0]["truncated"] is True

    def test_committed_partial_carries_role_and_isolation(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            role="retry",
            isolation="file",
            in_progress=_counts_block(9),
        )
        _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        session = _session_record(
            pid, _counts_block(13), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert [rec["$report_type"] for rec in records] == ["CallCountersPartial"]
        assert records[0]["role"] == "retry"
        assert records[0]["isolation"] == "file"


class TestLostAttributionOutput:
    def test_lost_processes_entries_carry_role_and_isolation(self, tmp_path: Path) -> None:
        lost = _lost_record(role="retry", isolation="file")
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                lost,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["complete"] is False
        entries = payload["lost_processes"]
        assert len(entries) == 1
        assert entries[0]["role"] == "retry"
        assert entries[0]["isolation"] == "file"

    def test_malformed_lost_role_skips_record(self, tmp_path: Path) -> None:
        # A distinct uuid proves the skip is the malformation (not healing:
        # a well-formed claim here would anchor an entry).
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        lost = _lost_record(worker_uuid=_UUID_B, pid=200, role="janitor", isolation="file")
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                lost,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        # Fail closed like sessions: a forged attribution tag must not fold.
        assert "lost_processes" not in payload

    def test_malformed_lost_isolation_tolerated(self, tmp_path: Path) -> None:
        # Pin-as-is guard: isolation is informational everywhere, so a
        # mistyped value drops the key, never the record.
        lost = _lost_record(role="retry", isolation=123)
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                lost,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        entries = payload["lost_processes"]
        assert len(entries) == 1
        assert entries[0]["role"] == "retry"
        assert "isolation" not in entries[0]


def _lost_key(parent: str, seq: int) -> dict[str, Any]:
    return {"parent_uuid": parent, "probe_seq": seq}


# --------------------------------------------------------------------------
# Area F (rc3): live loss ledger (keyed + unkeyed, derived total)
# --------------------------------------------------------------------------


class TestLiveLossLedger:
    def test_note_with_identity_is_keyed(self, engaged: Path) -> None:
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=3)
        assert call_counters.lost_probe_keys() == [_lost_key(_UUID_A, 3)]
        assert call_counters.probes_lost() == 1

    def test_note_without_identity_is_unkeyed(self, engaged: Path) -> None:
        call_counters.note_lost_probe()
        assert call_counters.lost_probe_keys() == []
        assert call_counters.probes_lost() == 1

    def test_note_mixed_identity_falls_back_to_unkeyed(self, engaged: Path) -> None:
        call_counters.note_lost_probe(parent_uuid=_UUID_A)
        call_counters.note_lost_probe(probe_seq=3)
        call_counters.note_lost_probe(parent_uuid="bogus", probe_seq=1)
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=-1)
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=True)
        assert call_counters.lost_probe_keys() == []
        assert call_counters.probes_lost() == 5

    def test_duplicate_key_counts_once(self, engaged: Path) -> None:
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=3)
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=3)
        assert call_counters.lost_probe_keys() == [_lost_key(_UUID_A, 3)]
        assert call_counters.probes_lost() == 1

    def test_probes_lost_derived_total(self, engaged: Path) -> None:
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=1)
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=2)
        call_counters.note_lost_probe()
        call_counters.add_lost_probes(2)
        assert len(call_counters.lost_probe_keys()) == 2
        assert call_counters.probes_lost() == 5

    def test_reset_clears_ledger(self, engaged: Path) -> None:
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=1)
        call_counters.note_lost_probe()
        call_counters.reset_for_tests()
        assert call_counters.lost_probe_keys() == []
        assert call_counters.probes_lost() == 0


# --------------------------------------------------------------------------
# Area F (rc3): ingest ledger (union + source-scoped idempotency)
# --------------------------------------------------------------------------


class TestIngestLedger:
    def test_ingest_unions_keys_and_remainder(self, engaged: Path) -> None:
        call_counters.ingest_child_evidence(
            [["m", "C_Login", 0, 6]],
            5,
            [],
            lost_keys=[_lost_key(_UUID_A, 1), _lost_key(_UUID_A, 2)],
            source=(_UUID_B, 0),
        )
        assert sorted(
            (key["parent_uuid"], key["probe_seq"]) for key in call_counters.lost_probe_keys()
        ) == [(_UUID_A, 1), (_UUID_A, 2)]
        # Scalar-anchored: 5 total − 2 keyed = 3 unkeyed.
        assert call_counters.probes_lost() == 5
        assert call_counters.serialize_current()["total_calls"] == 6

    def test_ingest_duplicate_source_adds_nothing(self, engaged: Path) -> None:
        kwargs: dict[str, Any] = {
            "lost_keys": [_lost_key(_UUID_A, 1)],
            "source": (_UUID_B, 0),
        }
        call_counters.ingest_child_evidence([["m", "C_Login", 0, 6]], 3, [], **kwargs)
        call_counters.ingest_child_evidence([["m", "C_Login", 0, 6]], 3, [], **kwargs)
        assert call_counters.serialize_current()["total_calls"] == 6
        assert call_counters.probes_lost() == 3
        assert len(call_counters.lost_probe_keys()) == 1

    def test_ingest_legacy_scalar_is_unkeyed(self, engaged: Path) -> None:
        call_counters.ingest_child_evidence([["m", "C_Login", 0, 6]], 4, [])
        assert call_counters.lost_probe_keys() == []
        assert call_counters.probes_lost() == 4

    def test_ingest_clamps_keys_over_scalar(self, engaged: Path) -> None:
        # Inconsistent child: identities win (fail closed toward
        # incomplete), the scalar never pulls the total below them.
        call_counters.ingest_child_evidence(
            [],
            1,
            [],
            lost_keys=[_lost_key(_UUID_A, 1), _lost_key(_UUID_A, 2), _lost_key(_UUID_A, 3)],
            source=(_UUID_B, 0),
        )
        assert len(call_counters.lost_probe_keys()) == 3
        assert call_counters.probes_lost() == 3

    def test_ingest_skips_malformed_keys_itemwise(self, engaged: Path) -> None:
        call_counters.ingest_child_evidence(
            [],
            5,
            [],
            lost_keys=[
                _lost_key(_UUID_A, 1),
                {"parent_uuid": "bogus", "probe_seq": 2},
                {"parent_uuid": _UUID_A},
                "garbage",
                _lost_key(_UUID_A, 3),
            ],
            source=(_UUID_B, 0),
        )
        assert len(call_counters.lost_probe_keys()) == 2
        # Scalar-anchored total conserved: 5 − 2 keyed = 3 unkeyed.
        assert call_counters.probes_lost() == 5

    def test_ingest_malformed_only_marks_dirty(self, engaged: Path) -> None:
        # First-tier R7: the malformed floor mutates the ledger, so a
        # malformed-only ingest must mark dirty like every sibling
        # bump path -- otherwise a crash before the next dirty event
        # loses the floored loss with no trace.
        call_counters.ingest_child_evidence(
            [],
            0,
            [],
            lost_keys=[{"bogus": 1}],
            source=(_UUID_B, 0),
        )
        assert call_counters.probes_lost() == 1
        info = call_counters.registration_info()
        assert info is not None
        sidecar = json.loads(Path(info["sidecar_path"]).read_text(encoding="utf-8"))
        assert sidecar["probes_lost"] == 1

    def test_ingest_unknown_source_never_skips(self, engaged: Path) -> None:
        # Documents the residual: sourceless payloads cannot dedupe, so
        # repeats accumulate (no fresh-run vector re-ingests them).
        call_counters.ingest_child_evidence([["m", "C_Login", 0, 6]], 3, [])
        call_counters.ingest_child_evidence([["m", "C_Login", 0, 6]], 3, [])
        assert call_counters.serialize_current()["total_calls"] == 12
        assert call_counters.probes_lost() == 6

    def test_ingest_invalid_source_treated_as_unknown(self, engaged: Path) -> None:
        call_counters.ingest_child_evidence([["m", "C_Login", 0, 6]], 3, [], source=("bogus", 0))
        assert call_counters.serialize_current()["total_calls"] == 6
        assert call_counters.probes_lost() == 3


# --------------------------------------------------------------------------
# Area F (rc3): loss emission (sidecar + session carry keys)
# --------------------------------------------------------------------------


class TestLossEmission:
    def test_sidecar_carries_keys(self, engaged: Path) -> None:
        call_counters.record_call("C_Login", module="m")
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=1)
        call_counters.note_lost_probe()
        on_disk = _read_sidecar()
        assert on_disk["lost_keys"] == [_lost_key(_UUID_A, 1)]
        assert on_disk["probes_lost"] == 2

    def test_session_emission_carries_keys(self, engaged: Path) -> None:
        from pkcs11_check._plugin_counters import build_session_record

        call_counters.record_call("C_Login", module="m")
        call_counters.note_lost_probe(parent_uuid=_UUID_A, probe_seq=1)
        call_counters.note_lost_probe()
        session = build_session_record()
        assert session["lost_keys"] == [_lost_key(_UUID_A, 1)]
        assert session["probes_lost"] == 2
        assert schema.is_session_record(session) is True

    def test_empty_keys_omitted_on_wire(self, engaged: Path) -> None:
        # Pin-as-is guard: keyless sessions stay byte-stable.
        from pkcs11_check._plugin_counters import build_session_record

        call_counters.record_call("C_Login", module="m")
        session = build_session_record()
        assert "lost_keys" not in session
        assert session["probes_lost"] == 0


# --------------------------------------------------------------------------
# Area F (rc3): extractor ledger (supersede, union, clamp, legacy)
# --------------------------------------------------------------------------


def _extract_report(records: list[dict[str, Any]], tmp_path: Path) -> dict[str, Any] | None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            *records,
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    return extract_call_counters_from_jsonl(jsonl)


class TestExtractorLedger:
    def test_session_keys_derive_total(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 5,
                "lost_keys": [_lost_key(_UUID_A, 1), _lost_key(_UUID_A, 2)],
            },
        )
        assert schema.is_session_record(session) is True
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["probes_lost"] == 5
        assert payload["complete"] is False
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "lost"},
            {"worker_uuid": _UUID_A, "probe_seq": 2, "status": "lost"},
        ]

    def test_session_supersedes_partial_keys_both_orders(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 1,
                "lost_keys": [_lost_key(_UUID_A, 9)],
            },
        )
        partial = _partial_record(
            worker_uuid=_UUID_A,
            run_id=_RUN,
            attempt=0,
            probes_lost=5,
            lost_keys=[_lost_key(_UUID_A, 1), _lost_key(_UUID_A, 2)],
        )
        partial.update(_counts_block(4))
        for records in ([session, partial], [partial, session]):
            payload = _extract_report(records, tmp_path)
            assert payload is not None
            assert payload["total_calls"] == 10, "session counts win"
            assert payload["probes_lost"] == 1, "session keys win"
            assert payload["complete"] is False
            assert payload["probes_detail"] == [
                {"worker_uuid": _UUID_A, "probe_seq": 9, "status": "lost"}
            ], "superseded partial keys never surface"

    def test_mixed_keyed_unkeyed(self, tmp_path: Path) -> None:
        keyed = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 5,
                "lost_keys": [_lost_key(_UUID_A, 1), _lost_key(_UUID_A, 2)],
            },
        )
        unkeyed = _session_record(200, _counts_block(7), extra={"run_id": _RUN, "probes_lost": 4})
        payload = _extract_report([keyed, unkeyed], tmp_path)
        assert payload is not None
        assert payload["total_calls"] == 17
        assert payload["probes_lost"] == 9
        assert payload["complete"] is False
        # Only keyed losses get detail rows; unkeyed fold into the total.
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "lost"},
            {"worker_uuid": _UUID_A, "probe_seq": 2, "status": "lost"},
        ]

    def test_legacy_scalar_never_heals(self, tmp_path: Path) -> None:
        session = _session_record(
            100, _counts_block(10), extra={"worker_uuid": _UUID_A, "run_id": _RUN, "probes_lost": 5}
        )
        recovered = _partial_record(
            worker_uuid=_UUID_A,
            run_id=_RUN,
            attempt=0,
            recovered_keys=[_lost_key(_UUID_A, 1)],
        )
        recovered.update(_counts_block(0))
        payload = _extract_report([session, recovered], tmp_path)
        assert payload is not None
        # Scalar-only losses have no identity to cancel: the total stands.
        # Pin-as-is shape (identical pre/post): guards recovery against
        # ever touching unkeyed totals.
        assert payload["probes_lost"] == 5
        assert payload["complete"] is False
        assert "probes_detail" not in payload

    def test_clamp_keys_over_scalar(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 1,
                "lost_keys": [_lost_key(_UUID_A, 1), _lost_key(_UUID_A, 2)],
            },
        )
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        # Inconsistent producer: identities win (fail closed toward
        # incomplete), the scalar never pulls below them.
        assert payload["probes_lost"] == 2
        assert payload["complete"] is False
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "lost"},
            {"worker_uuid": _UUID_A, "probe_seq": 2, "status": "lost"},
        ]

    def test_uuidless_duplicate_replaces(self, tmp_path: Path) -> None:
        session = _session_record(100, _counts_block(10), extra={"run_id": _RUN, "probes_lost": 5})
        payload = _extract_report([session, dict(session)], tmp_path)
        assert payload is not None
        # Same scope twice is a torn-append retry: losses counted once.
        # (Counts still sum for uuid-less repeats: pre-existing behavior,
        # out of the loss-ledger scope.)
        assert payload["total_calls"] == 20
        assert payload["probes_lost"] == 5

    def test_uuidless_distinct_scopes_sum(self, tmp_path: Path) -> None:
        first = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, _counts_block(10), extra={"run_id": _RUN, "probes_lost": 5}),
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(100, _counts_block(7), extra={"run_id": _RUN, "probes_lost": 4}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(first)
        assert payload is not None
        assert payload["total_calls"] == 17
        assert payload["probes_lost"] == 9


# --------------------------------------------------------------------------
# Area F (rc3): orphan recovery (recovered_keys subtract exactly once)
# --------------------------------------------------------------------------


class TestOrphanRecovery:
    def test_gap_keys_net_against_adopted_orphan(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        parent = call_counters.get_worker_uuid()
        _plant_producer(
            engaged,
            uuid=parent,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            probes_lost=1,
            lost_keys=[_lost_key(parent, 0)],
        )
        _plant_probe_orphan(engaged, parent_uuid=parent, seq=0)
        collected = _collect_dead(engaged, tmp_path, name="child.jsonl")
        partials = [rec for rec in collected if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        # The gap carries both the live-claimed key and the orphan recovery.
        assert partials[0]["lost_keys"] == [_lost_key(parent, 0)]
        assert partials[0]["recovered_keys"] == [_lost_key(parent, 0)]
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                *collected,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        # Net zero losses — but the producer is dead, so truncated shape
        # keeps the run honestly incomplete.
        assert payload["probes_lost"] == 0
        assert payload["complete"] is False

    def test_seq_mismatch_suppresses_recovery(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        parent = call_counters.get_worker_uuid()
        _plant_producer(
            engaged,
            uuid=parent,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            probes_lost=1,
            lost_keys=[_lost_key(parent, 0)],
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=parent, seq=0)
        content = json.loads(orphan.read_text(encoding="utf-8"))
        content["probe_seq"] = 7
        orphan.write_text(json.dumps(content), encoding="utf-8")
        collected = _collect_dead(engaged, tmp_path, name="child.jsonl")
        partials = [rec for rec in collected if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        # Counts still fold best-effort, but a filename/content mismatch
        # must not cancel a loss claim (fail closed toward incomplete).
        assert "recovered_keys" not in partials[0]
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                *collected,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_marker_orphan_emits_recovery(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        parent = call_counters.get_worker_uuid()
        _plant_producer(
            engaged,
            uuid=parent,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
            probes_lost=1,
            lost_keys=[_lost_key(parent, 0)],
        )
        orphan = _plant_probe_orphan(engaged, parent_uuid=parent, seq=0)
        marker = orphan.with_name(orphan.name.replace("probe-", "probe-consumed-", 1))
        orphan.rename(marker)
        collected = _collect_dead(engaged, tmp_path, name="child.jsonl")
        partials = [rec for rec in collected if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["recovered_keys"] == [_lost_key(parent, 0)]
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                *collected,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        assert payload["probes_lost"] == 0
        assert payload["complete"] is False

    def test_adopted_orphan_keys_union_into_gap(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        parent = call_counters.get_worker_uuid()
        _plant_producer(engaged, uuid=parent, pid=pid, birth=birth, in_progress=_counts_block(5))
        _plant_probe_orphan(engaged, parent_uuid=parent, seq=0, lost_keys=[_lost_key(_UUID_B, 4)])
        collected = _collect_dead(engaged, tmp_path, name="child.jsonl")
        partials = [rec for rec in collected if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        # The orphan's own keyed losses ride the gap partial separately from
        # the gap set (union-always: fresh info no session could hold).
        assert partials[0]["orphan_keys"] == [_lost_key(_UUID_B, 4)]
        assert "lost_keys" not in partials[0]
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                *collected,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False

    def test_committed_orphan_keys_union_despite_supersede(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        pid, birth = _dead_pid_with_birth()
        parent = call_counters.get_worker_uuid()
        _plant_producer(engaged, uuid=parent, pid=pid, birth=birth, in_progress=_counts_block(9))
        _plant_probe_orphan(engaged, parent_uuid=parent, seq=0, lost_keys=[_lost_key(_UUID_B, 4)])
        session = _session_record(
            pid, _counts_block(13), extra={"worker_uuid": parent, "run_id": _RUN}
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert [rec["$report_type"] for rec in records] == ["CallCountersPartial"]
        # Claim-only: orphan evidence rides orphan_keys; no gap set (the
        # session is authoritative for this producer's own keys).
        assert "lost_keys" not in records[0]
        assert records[0]["orphan_keys"] == [_lost_key(_UUID_B, 4)]
        report = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                session,
                *records,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(report)
        assert payload is not None
        assert payload["total_calls"] == 13, "session counts win"
        assert payload["probes_lost"] == 1, "orphan keys union despite supersede"
        assert payload["complete"] is False


# --------------------------------------------------------------------------
# Area F (rc3): probes_detail with lost rows (legacy prefix-stable)
# --------------------------------------------------------------------------


class TestProbesDetailLost:
    def test_lost_rows_follow_folded(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 1,
                "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
                "lost_keys": [_lost_key(_UUID_A, 1)],
            },
        )
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"},
            {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "lost"},
        ]

    def test_folded_only_shape_unchanged(self, tmp_path: Path) -> None:
        # Pin-as-is guard: receipts without losses render exactly as before.
        session = _session_record(
            100,
            _counts_block(10),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 0}],
            },
        )
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_B, "probe_seq": 0, "status": "folded"}
        ]


# --------------------------------------------------------------------------
# Area F (rc3): zero rows for evidenced-but-moduleless pids
# --------------------------------------------------------------------------


class TestZeroRows:
    def test_end_states_only_pid_gets_module_less_row(self, tmp_path: Path) -> None:
        lost = _lost_record(worker_uuid=_UUID_B, pid=200, role="retry", isolation="file")
        payload = _extract_report([lost], tmp_path)
        assert payload is not None
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 200,
                "isolation": "file",
                "total_calls": 0,
                "complete": False,
                "worker_uuid": _UUID_B,
                "role": "retry",
                "end_state": "crashed",
            }
        ]

    def test_clean_zero_session_renders_complete_row(self, tmp_path: Path) -> None:
        # fw#78 item 5: a ran-zero session renders its row (complete) so it
        # reads distinctly from a missing process.
        session = _session_record(
            100, _counts_block(0), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is True
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 0,
                "complete": True,
                "worker_uuid": _UUID_A,
            }
        ]

    def test_zero_call_session_with_loss_gets_row(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _counts_block(0),
            extra={"worker_uuid": _UUID_A, "run_id": _RUN, "probes_lost": 3},
        )
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 0,
                "complete": False,
                "worker_uuid": _UUID_A,
                "probes_lost": 3,
            }
        ]

    def test_module_less_fallback_used_forces_incomplete(self, tmp_path: Path) -> None:
        # B3: the module-less complete formula's fallback_used arm --
        # a ran-zero pid with a session in one scope and fallback
        # evidence in another reads incomplete, never complete. (The
        # zero-count entry is synthetic -- the production writer omits
        # claimless zeros -- but foreign evidence can carry the shape,
        # and the arm must hold regardless.)
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    100, _counts_block(0), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
                ),
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _test_report(
                    "b.py::t1",
                    "teardown",
                    _test_entry(
                        100, _counts_block(0), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
                    ),
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        rows = [row for row in payload["by_process"] if row["pid"] == 100]
        assert len(rows) == 1
        assert rows[0]["total_calls"] == 0
        assert rows[0]["complete"] is False

    def test_module_less_session_with_end_states_forces_incomplete(self, tmp_path: Path) -> None:
        # B3: the module-less complete formula's end_states arm for a
        # session-backed pid -- a ran-zero session with a reconciled
        # crash disposition reads incomplete.
        session = _session_record(
            100, _counts_block(0), extra={"worker_uuid": _UUID_A, "run_id": _RUN}
        )
        lost = _lost_record()
        del lost["worker_uuid"]
        assert schema.is_lost_record(lost) is True
        payload = _extract_report([session, lost], tmp_path)
        assert payload is not None
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 0,
                "complete": False,
                "worker_uuid": _UUID_A,
                "end_state": "crashed",
            }
        ]

    def test_module_less_session_with_marker_forces_incomplete(self, tmp_path: Path) -> None:
        # B3: the module-less complete formula's persistence arm -- a
        # durability-degraded ran-zero pid reads incomplete with the
        # reason shown (the module-row twin is pinned elsewhere).
        session = _session_record(
            100,
            _counts_block(0),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "persistence_pending": {"checkpoint": "return", "unit": "a.py", "attempt": 0},
            },
        )
        assert schema.is_session_record(session) is True
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 0,
                "complete": False,
                "worker_uuid": _UUID_A,
                "persistence_pending": True,
            }
        ]

    def test_probes_lost_repeats_on_each_module_row(self, tmp_path: Path) -> None:
        # B3: pid-level losses repeat on EACH of the pid's rows
        # (do-not-sum), so per-pid reconciliation never under-reads.
        m1 = _counts_block(5, module="m1")["by_module"]["m1"]
        m2 = _counts_block(5, module="m2")["by_module"]["m2"]
        session = _session_record(
            100,
            {"total_calls": 10, "by_module": {"m1": m1, "m2": m2}},
            extra={"worker_uuid": _UUID_A, "run_id": _RUN, "probes_lost": 2},
        )
        assert schema.is_session_record(session) is True
        payload = _extract_report([session], tmp_path)
        assert payload is not None
        assert payload["complete"] is False
        rows = payload["by_process"]
        assert len(rows) == 2
        assert all(row.get("probes_lost") == 2 for row in rows)

    def test_strip_tolerates_mixed_rows(self) -> None:
        from pkcs11_check.core._jsonl_extract import _strip_single_module_tag

        single = [
            {"pid": 100, "module": "m", "total_calls": 5},
            {"pid": 200, "total_calls": 0},
        ]
        assert _strip_single_module_tag(single) == [
            {"pid": 100, "total_calls": 5},
            {"pid": 200, "total_calls": 0},
        ]
        multi = [
            {"pid": 100, "module": "m1", "total_calls": 5},
            {"pid": 200, "total_calls": 0},
            {"pid": 300, "module": "m2", "total_calls": 7},
        ]
        assert _strip_single_module_tag(multi) == multi


# --------------------------------------------------------------------------
# Area F (rc3): conflict-adjacent partial folding (pinned as-is)
# --------------------------------------------------------------------------


class TestConflictExtractAsIs:
    def test_conflict_pair_folds_loud(self, tmp_path: Path) -> None:
        partial = _partial_record(worker_uuid=_UUID_A, run_id=_RUN, attempt=0)
        partial.update(_counts_block(5))
        lost = _lost_record(end_state="conflict")
        payload = _extract_report([partial, lost], tmp_path)
        assert payload is not None
        # Approximate counts fold; the conflict marker keeps them loud.
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["lost_processes"][0]["end_state"] == "conflict"


# --------------------------------------------------------------------------
# Area B (rc3): eager registration at probe-sidecar assignment
# --------------------------------------------------------------------------


class TestEagerProbeRegistration:
    def test_run_probe_registers_before_spawn(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes.runner import run_probe

        def _boom(*args: Any, **kwargs: Any) -> None:
            raise OSError("no spawn")

        monkeypatch.setattr(subprocess, "Popen", _fake_popen_factory(on_spawn=_boom))
        with pytest.raises(OSError, match="no spawn"):
            run_probe("_echo", {"module_path": "/x.so"})
        # The parent registered before the (failed) spawn: a child that
        # dies instantly still leaves attributable evidence.
        assert list((engaged / "registrations").glob("*.json")) != []

    def test_run_probe_sealed_fails_before_spawn(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from pkcs11_check.testcases._probes.runner import run_probe

        durability.seal(engaged, reason="test")
        calls: list[Any] = []

        def _spy(*args: Any, **kwargs: Any) -> None:
            calls.append(1)

        monkeypatch.setattr(subprocess, "Popen", _fake_popen_factory(on_spawn=_spy))
        with pytest.raises(durability.CounterPersistenceError):
            run_probe("_echo", {"module_path": "/x.so"})
        assert calls == [], "sealed probes never spawn (fail fast, no phantom traffic)"

    def test_run_probe_strips_ambient_probe_context_when_disengaged(
        self, disengaged: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from pkcs11_check.testcases._probes.runner import run_probe

        f2_keys = (
            durability.PROBE_PARENT_ENV,
            durability.PROBE_RUN_ENV,
            durability.PROBE_UNIT_ENV,
            durability.PROBE_ATTEMPT_ENV,
            durability.PROBE_ROLE_ENV,
            durability.PROBE_ISOLATION_ENV,
        )
        for key in f2_keys:
            monkeypatch.setenv(key, "ambient-leak")
        seen: dict[str, str] = {}

        def _capture(*args: Any, **kwargs: Any) -> None:
            seen.update(kwargs.get("env", {}))

        monkeypatch.setattr(subprocess, "Popen", _fake_popen_factory(on_spawn=_capture))
        result = run_probe("_echo", {"module_path": "/x.so"})
        assert result.returncode == 0
        for key in f2_keys:
            assert key not in seen, "ambient probe context never leaks (H gap pin)"

    def test_run_probe_child_inherits_flush_k(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from pkcs11_check.testcases._probes.runner import run_probe

        # Cadence policy inherits: the child batches (or not) exactly
        # like its parent run (default 1 when unset anywhere).
        monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "9")
        seen: dict[str, str] = {}

        def _capture(*args: Any, **kwargs: Any) -> None:
            seen.update(kwargs.get("env", {}))

        monkeypatch.setattr(subprocess, "Popen", _fake_popen_factory(on_spawn=_capture))
        run_probe("_echo", {"module_path": "/x.so"})
        assert seen[durability.COUNTERS_FLUSH_K_ENV] == "9"

    def test_run_probe_exports_parent_context(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from pkcs11_check.testcases._probes.runner import run_probe

        monkeypatch.setenv(call_counters.ISOLATION_ENV, "file")
        seen: dict[str, str] = {}

        def _capture(*args: Any, **kwargs: Any) -> None:
            seen.update(kwargs.get("env", {}))

        monkeypatch.setattr(subprocess, "Popen", _fake_popen_factory(on_spawn=_capture))
        result = run_probe("_echo", {"module_path": "/x.so"})
        assert result.returncode == 0
        parent = call_counters.get_worker_uuid()
        assert seen[durability.PROBE_PARENT_ENV] == parent
        assert seen[durability.PROBE_RUN_ENV] == _RUN
        assert seen[durability.PROBE_UNIT_ENV] == "a.py"
        assert seen[durability.PROBE_ATTEMPT_ENV] == "0"
        assert seen[durability.PROBE_ROLE_ENV] == "unit"
        assert seen[durability.PROBE_ISOLATION_ENV] == "file"


# --------------------------------------------------------------------------
# Area B (rc3): content-exact orphan reunion (F3)
# --------------------------------------------------------------------------


class TestContentExactReunion:
    def test_ambiguity_healed_by_content_match(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        first = "a" * 31 + "0"
        second = "a" * 31 + "1"
        _plant_producer(engaged, uuid=first, pid=pid, birth=birth, in_progress=_counts_block(5))
        _plant_producer(engaged, uuid=second, pid=pid, birth=birth, in_progress=_counts_block(7))
        orphan = _plant_probe_orphan(
            engaged, parent_uuid=first, seq=0, identity=_f2_identity(first)
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        by_producer = {rec["worker_uuid"]: rec for rec in records if "total_calls" in rec}
        assert by_producer[first]["total_calls"] == 9, "orphan reunited by full identity"
        assert by_producer[second]["total_calls"] == 7, "sibling untouched"
        assert not orphan.exists(), "adopted orphan consumes"

    def test_legacy_ambiguous_retained_and_warned(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        first = "a" * 31 + "0"
        second = "a" * 31 + "1"
        _plant_producer(engaged, uuid=first, pid=pid, birth=birth, in_progress=_counts_block(5))
        _plant_producer(engaged, uuid=second, pid=pid, birth=birth, in_progress=_counts_block(7))
        orphan = _plant_probe_orphan(engaged, parent_uuid=first, seq=0)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        with pytest.warns(UserWarning, match="ambiguous"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert sorted(rec["total_calls"] for rec in records if "total_calls" in rec) == [5, 7]
        assert orphan.exists(), "unattributable legacy orphan stays for a later pass"

    def test_cross_run_orphan_skipped(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            identity=_f2_identity(_UUID_A, run_id="R-prior"),
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        with pytest.warns(UserWarning, match="cross-run"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert [rec["total_calls"] for rec in records if "total_calls" in rec] == [5]
        assert orphan.exists(), "stale-run evidence stays for the barrier, never misfolds"

    def test_mid_pass_orphan_excluded_from_this_pass(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pin-as-is guard: adoption snapshots the directory (glob list), so
        # a sidecar landing mid-pass waits for the next pass (TOCTOU-safe).
        pid, birth = _dead_pid_with_birth()
        parent = call_counters.get_worker_uuid()
        _plant_producer(engaged, uuid=parent, pid=pid, birth=birth, in_progress=_counts_block(5))
        _plant_probe_orphan(engaged, parent_uuid=parent, seq=0)
        real_parse = durability._parse_probe_orphan_payload
        planted: list[bool] = []

        def _planting_parse(data: Any) -> Any:
            if not planted:
                planted.append(True)
                _plant_probe_orphan(engaged, parent_uuid=parent, seq=1)
            return real_parse(data)

        monkeypatch.setattr(durability, "_parse_probe_orphan_payload", _planting_parse)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        assert planted == [True]
        assert [rec["total_calls"] for rec in records if "total_calls" in rec] == [9]
        leftovers = sorted(p.name for p in engaged.glob("probe-*.json") if "consumed" not in p.name)
        assert len(leftovers) == 1 and "-1-" in leftovers[0]


class TestStaleProducerSidecarFilter:
    def test_cross_run_sidecar_skipped_and_warned(self, engaged: Path, tmp_path: Path) -> None:
        # Torn registry (deleted) + valid sidecar from a prior run: the
        # sidecar must not fold into this run (the barrier owns prior runs).
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            run_id="R-prior",
            in_progress=_counts_block(5),
        )
        Path(planted["registry"]).unlink()
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        with pytest.warns(UserWarning, match="cross-run"):
            records = durability.collect_unit(
                engaged,
                unit="a.py",
                child_jsonl=child,
                status="crashed",
                returncode=-9,
                current_run=_RUN,
            )
        assert [rec for rec in records if "total_calls" in rec] == []
        assert Path(planted["sidecar"]).exists(), "stale evidence retained, never misfolded"

    def test_cross_unit_sidecar_skipped_and_warned(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            unit="b.py",
            in_progress=_counts_block(5),
        )
        Path(planted["registry"]).unlink()
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        with pytest.warns(UserWarning, match="cross-unit"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
            )
        assert [rec for rec in records if "total_calls" in rec] == []
        assert Path(planted["sidecar"]).exists()


class TestBarrierAdoptionE2E:
    def test_barrier_adopts_orphan_with_prior_claims(self, tmp_path: Path) -> None:
        # Pin-as-is guard: resume barrier adoption (present claims that do
        # not cover the orphan must not block it).
        root = tmp_path / "counters"
        pid, birth = _dead_pid_with_birth()
        _plant_producer(root, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        orphan = _plant_probe_orphan(
            root,
            parent_uuid=_UUID_A,
            seq=0,
            identity=_f2_identity(_UUID_A),
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    999,
                    _counts_block(3),
                    extra={
                        "worker_uuid": _UUID_B,
                        "run_id": "R-prior",
                        "receipts": [{"worker_uuid": _UUID_B, "probe_seq": 9}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        plan = durability.prepare_resume(root, prior_merged_jsonl=prior)
        assert plan["barrier_ok"] is True
        staged = plan["cache_records"]["a.py"]
        partials = [rec for rec in staged if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 9, "gap plus adopted orphan"
        assert not orphan.exists()


class TestTornSidecarRoleRecovery:
    def test_flush_payload_carries_role_and_isolation(self, engaged: Path) -> None:
        # Robustness N1: the sidecar carries the registration's
        # attribution stamp so registryless adoption recovers it.
        call_counters.record_call("C_Login", module="m")
        sidecar = _read_sidecar()
        assert sidecar["role"] == "unit"
        assert sidecar["isolation"] == "unknown"

    def test_torn_sidecar_recovers_role_and_isolation(self, engaged: Path, tmp_path: Path) -> None:
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        Path(planted["registry"]).unlink()
        sidecar_path = Path(planted["sidecar"])
        content = json.loads(sidecar_path.read_text(encoding="utf-8"))
        content["role"] = "preflight"
        content["isolation"] = "file"
        sidecar_path.write_text(json.dumps(content), encoding="utf-8")
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["role"] == "preflight"
        assert partials[0]["isolation"] == "file"
        lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
        assert len(lost) == 1
        assert lost[0]["role"] == "preflight"
        assert lost[0]["isolation"] == "file"


class TestLossNoteSelfRegistration:
    def test_note_lost_probe_registers_first(self, engaged: Path) -> None:
        # Codex CX5: a loss note is a zero-call mutation, so it
        # self-registers like record_* -- otherwise an engaged but
        # fresh process would lose the evidence on death.
        call_counters.note_lost_probe()
        assert list((engaged / "registrations").glob("*.json")) != []
        assert _read_sidecar()["probes_lost"] == 1

    def test_add_lost_probes_registers_first(self, engaged: Path) -> None:
        call_counters.add_lost_probes(2)
        assert list((engaged / "registrations").glob("*.json")) != []
        assert _read_sidecar()["probes_lost"] == 2

    def test_note_lost_probe_sealed_raises_before_admitting(self, engaged: Path) -> None:
        durability.seal(engaged, reason="test")
        with pytest.raises(durability.CounterPersistenceError):
            call_counters.note_lost_probe()
        assert call_counters.probes_lost() == 0

    def test_add_lost_probes_garbage_stays_silent_when_sealed(self, engaged: Path) -> None:
        # Garbage parses out before registration: a hostile payload
        # value can never break ingest, even when sealed.
        durability.seal(engaged, reason="test")
        call_counters.add_lost_probes("garbage")
        assert list((engaged / "registrations").glob("*.json")) == []


class TestCommittedRecoveryOnlyClaim:
    def _committed_session(self, pid: int) -> dict[str, Any]:
        return _session_record(
            pid,
            _counts_block(5),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _RUN,
                "probes_lost": 1,
                "lost_keys": [{"parent_uuid": _UUID_A, "probe_seq": 0}],
            },
        )

    def test_marker_recovery_emits_zero_claim_and_heals(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Codex CX2: a consumed marker carries recovery identity but no
        # counts; the committed path must still emit its zero-call claim
        # partial, so the session's loss claim heals at extraction
        # instead of being deleted with the marker.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        durability.mark_probe_consumed(orphan)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                self._committed_session(pid),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 0
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is True
        assert payload["probes_lost"] == 0
        assert payload.get("probes_detail", []) == []

    @pytest.mark.parametrize(
        ("flag", "heals"),
        [
            (None, False),  # explicit null: malformed, never heals
            (0, False),  # explicit 0: malformed, never heals
            ("false", False),  # explicit string: malformed, never heals
            (False, False),  # mid-run prefix: folds, never heals
            (True, True),  # explicit finalized: heals
            ("<absent>", True),  # legacy/exit shape: heals
        ],
    )
    def test_finalized_flag_shape_decides_healing(
        self, engaged: Path, tmp_path: Path, flag: Any, heals: bool
    ) -> None:
        # Codex RC4-R1-1 hardening: only absent-or-true reads
        # finalized; any other present value fails closed toward a
        # named loss rather than a healed one.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        if flag != "<absent>":
            content = json.loads(orphan.read_text(encoding="utf-8"))
            content["finalized"] = flag
            orphan.write_text(json.dumps(content), encoding="utf-8")
        durability.mark_probe_consumed(orphan)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                self._committed_session(pid),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        if heals:
            partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
            assert len(partials) == 1
            assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        else:
            assert records == [], "non-finalized recovery emits nothing; the loss stands"

    def test_prefix_marker_suppresses_without_healing(self, engaged: Path, tmp_path: Path) -> None:
        # Codex RC4-R1-1: a mid-run (prefix) marker suppresses duplicates
        # but must never heal: the tail it never saw stays a named loss.
        # (A finalized marker heals -- see the tests above.)
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        content = json.loads(orphan.read_text(encoding="utf-8"))
        content["finalized"] = False
        orphan.write_text(json.dumps(content), encoding="utf-8")
        marker = durability.mark_probe_consumed(orphan)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(5),
                    extra={
                        "worker_uuid": _UUID_A,
                        "run_id": _RUN,
                        "probes_lost": 1,
                        "lost_keys": [{"parent_uuid": _UUID_A, "probe_seq": 0}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert records == [], "prefix recovery emits nothing; the loss stands"
        assert not marker.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["probes_lost"] == 1
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 0, "status": "lost"}
        ]

    def test_finalized_marker_withholds_recovery_over_stranded_rewrite(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # #88R10-2: a finalized marker never heals over a stranded
        # rewrite: the baseline is gone but a complete rewrite tmp
        # survives, so recovery withholds (loud), the marker stays for
        # retry, and the loss stands.
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        marker = durability.mark_probe_consumed(orphan)
        assert not orphan.exists()
        tmp = _plant_probe_tmp(
            engaged / orphan.name,
            _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]),
        )
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(5),
                    extra={
                        "worker_uuid": _UUID_A,
                        "run_id": _RUN,
                        "probes_lost": 1,
                        "lost_keys": [{"parent_uuid": _UUID_A, "probe_seq": 0}],
                    },
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        with pytest.warns(UserWarning, match="recovery withheld"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == [], "withheld recovery emits nothing; the loss stands"
        assert marker.exists(), "marker retained for retry"
        assert tmp.exists(), "stranded rewrite retained for forensics"
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["probes_lost"] == 1
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 0, "status": "lost"}
        ]

    def test_torn_committed_recovery_emits_zero_claim_and_heals(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        # Same CX2 rule through the registryless committed path.
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        Path(planted["registry"]).unlink()
        orphan = _plant_probe_orphan(engaged, parent_uuid=_UUID_A, seq=0)
        durability.mark_probe_consumed(orphan)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                self._committed_session(pid),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        records = durability.collect_unit(
            engaged, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 0
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is True
        assert payload["probes_lost"] == 0


# --------------------------------------------------------------------------
# Issue #88: orphan-tmp adoption + named in-flight rows
# --------------------------------------------------------------------------


def _entry_only_block(
    n: int, *, fn: str = "C_Digest", module: str = "m", bucket: str = "test"
) -> dict[str, Any]:
    """A minimal valid block with ``n`` entries and no returns."""
    return {
        "total_calls": n,
        "by_module": {
            module: {
                "calls": n,
                "buckets": {bucket: {"calls": n, "by_fn": {fn: {"calls": n, "by_rv": {}}}}},
            }
        },
    }


def _fn_leaf(partial: dict[str, Any], fn: str) -> dict[str, Any]:
    """Find one fn leaf across all module/bucket blocks (bucket-agnostic)."""
    for module_block in partial["by_module"].values():
        for bucket_block in module_block["buckets"].values():
            if fn in bucket_block["by_fn"]:
                return bucket_block["by_fn"][fn]
    raise AssertionError(f"fn {fn} missing from partial")


def _lost_returns(partial: dict[str, Any]) -> int:
    """Entries minus summed RV counts over the whole partial block."""
    missing = 0
    for module_block in partial["by_module"].values():
        for bucket_block in module_block["buckets"].values():
            for leaf in bucket_block["by_fn"].values():
                missing += leaf["calls"] - sum(item["count"] for item in leaf["by_rv"].values())
    return missing


def _plant_tmp(
    sidecar: Path, payload: dict[str, Any] | None, *, nonce: str = "abc", raw: str | None = None
) -> Path:
    """Plant an orphan rewrite tmp next to a sidecar (complete or torn)."""
    tmp = sidecar.with_name(f"{sidecar.name}.tmp-999-{nonce}")
    if raw is not None:
        tmp.write_text(raw, encoding="utf-8")
    else:
        assert payload is not None
        tmp.write_text(json.dumps(payload), encoding="utf-8")
    return tmp


def _tmp_payload(
    uuid: str,
    block: dict[str, Any],
    *,
    pid: int = 999,
    journal_seq: int | None = 0,
    run_id: str = _RUN,
    unit: str = "a.py",
    attempt: int = 0,
) -> dict[str, Any]:
    """A complete rewrite-tmp payload carrying one in-progress snapshot."""
    payload: dict[str, Any] = {
        "worker_uuid": uuid,
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "pid": pid,
        "in_progress": block,
        "receipts": [],
    }
    if journal_seq is not None:
        payload["journal_seq"] = journal_seq
    return payload


def _collect_crashed88(
    root: Path, child: Path, *, status: str = "crashed", returncode: int | None = -11
) -> list[dict[str, Any]]:
    _write_jsonl(child, [{"$report_type": "SessionStart"}, _marker("a.py", 0)])
    return durability.collect_unit(
        root, unit="a.py", child_jsonl=child, status=status, returncode=returncode
    )


def test_unreadable_registry_reserves_uuid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R2: an I/O-failed registry suppresses orphan adoption (live kept)."""
    birth = durability.birth_token_for_pid(os.getpid())
    if birth is None:
        pytest.skip("birth tokens unavailable on this platform")
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=os.getpid(),
        birth=birth,
        in_progress=_counts_block(2, fn="C_Digest"),
    )
    registry_name = Path(planted["registry"]).name
    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def _eperm_once(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == registry_name:
            raise PermissionError("injected registry EPERM")
        return real_read_text(self, *args, **kwargs)

    def _eperm_once_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if self.name == registry_name:
            raise PermissionError("injected registry EPERM")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_once)
    monkeypatch.setattr(Path, "read_bytes", _eperm_once_bytes)
    with pytest.warns(UserWarning, match="unreadable"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert Path(planted["sidecar"]).exists()


def test_healed_registry_skips_orphan_adoption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R2: a registry readable at adoption time is owned, never orphan."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    real_read = durability.read_registry_file
    real_digested = durability._read_registry_file_digested
    calls = 0

    def _flaky(path: Path | str) -> dict[str, Any] | None:
        # Fail the known-uuids pre-read and the main-loop read; the
        # adoption-time probe then sees the healed registry.
        nonlocal calls
        calls += 1
        if calls <= 2:
            return None
        return real_read(path)

    def _flaky_digested(path: Path) -> tuple[dict[str, Any] | None, str | None]:
        nonlocal calls
        calls += 1
        if calls <= 2:
            return None, None
        return real_digested(path)

    monkeypatch.setattr(durability, "read_registry_file", _flaky)
    monkeypatch.setattr(durability, "_read_registry_file_digested", _flaky_digested)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert Path(planted["sidecar"]).exists()


def test_torn_sidecar_live_pid_skips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R2: a torn-sidecar whose pid is alive is retained, never named."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=0,
            in_progress=_entry_only_block(1),
        )
        Path(planted["registry"]).unlink()
        sidecar_data = json.loads(Path(planted["sidecar"]).read_text(encoding="utf-8"))
        sidecar_data["pid"] = proc.pid
        Path(planted["sidecar"]).write_text(json.dumps(sidecar_data), encoding="utf-8")
        # #88R3F5: even with birth unreadable (blind collector), a live
        # pid retains -- presence alone never proves death.
        monkeypatch.setattr(durability, "birth_token_for_pid", lambda _pid: None)
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert records == []
        assert Path(planted["sidecar"]).exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_resume_torn_gap_names_in_flight(engaged: Path) -> None:
    """#88R2: resume's torn-gap partial names missing returns too."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        engaged,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    Path(planted["registry"]).unlink()
    plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
    partials = [
        rec for rec in plan["cache_records"]["a.py"] if rec["$report_type"] == "CallCountersPartial"
    ]
    assert len(partials) == 1
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_tmp_enumeration_fault_defers_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R7-4: a tmp listing fault defers like an unreadable tmp."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    tmp = _plant_tmp(
        planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    )
    real_list = durability._list_tmp_paths
    blocked = True

    def _flaky_list(directory: Path, prefix: str) -> Any:
        if blocked:
            return None
        return real_list(directory, prefix)

    monkeypatch.setattr(durability, "_list_tmp_paths", _flaky_list)
    with pytest.warns(UserWarning, match="deferred"):
        first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert first == []
    assert Path(planted["registry"]).exists()
    assert tmp.exists()
    blocked = False
    second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}


def test_unreadable_tmp_defers_producer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R4-F1a (supersedes #88R3F1): an unreadable tmp defers everything.

    Retaining the tmp while emitting the parent's records would strand
    the return (the prune would delete the healed tmp as adjudicated);
    deferral keeps the whole producer state for a coherent retry.
    """
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    tmp = _plant_tmp(
        planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    )
    real_read_text = Path.read_text

    def _eperm_tmp(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name.endswith(".tmp-999-abc"):
            raise PermissionError("injected tmp EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_tmp)
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert Path(planted["sidecar"]).exists()
    assert tmp.exists()


def test_healed_tmp_replays_after_defer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R4-F1a: a transient tmp fault loses no return across passes."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    real_read_text = Path.read_text
    blocked = True

    def _flaky_tmp(self: Path, *args: Any, **kwargs: Any) -> str:
        if blocked and self.name.endswith(".tmp-999-abc"):
            raise PermissionError("injected tmp EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _flaky_tmp)
    with pytest.warns(UserWarning, match="deferred"):
        first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert first == []
    blocked = False
    second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}


def test_unreadable_probe_baseline_defers_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R4-F1b: an unreadable probe baseline keeps its association."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    tmp = _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]))
    real_read_text = Path.read_text
    blocked = True

    def _flaky_baseline(self: Path, *args: Any, **kwargs: Any) -> str:
        if blocked and self.name == orphan.name:
            raise PermissionError("injected baseline EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _flaky_baseline)
    with pytest.warns(UserWarning, match="deferred"):
        first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert first == []
    assert Path(planted["registry"]).exists()
    assert orphan.exists()
    assert tmp.exists()
    blocked = False
    second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1
    assert not orphan.exists()


def test_foreign_stamped_marker_not_consumed(tmp_path: Path) -> None:
    """#88R5-4: a marker stamped for another parent heals nothing here."""
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=uuid_a,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Digest"),
    )
    src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_b,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(uuid_b, run_id="R-prior", unit="b.py"),
        pid=pid,
        birth=None,
    )
    marker = src.with_name(src.name.replace("probe-", "probe-consumed-", 1))
    src.rename(marker)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0].get("recovered_keys", []) == []
    assert marker.exists(), "another producer's pass owns it"


def test_cross_run_marker_skipped_loudly(tmp_path: Path) -> None:
    """#88R5-4: a same-parent cross-run marker warns and stays."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Digest"),
    )
    src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A, run_id="R-prior"),
        pid=pid,
        birth=None,
    )
    marker = src.with_name(src.name.replace("probe-", "probe-consumed-", 1))
    src.rename(marker)
    with pytest.warns(UserWarning, match="cross-run"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0].get("recovered_keys", []) == []
    assert marker.exists()


def test_unreadable_owned_marker_defers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R5-4: an unreadable owned marker (full-uuid name) defers."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Digest"),
    )
    src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = durability.mark_probe_consumed(src)
    assert marker.name.startswith(f"probe-consumed-{_UUID_A}-")
    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def _eperm_marker(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == marker.name:
            raise PermissionError("injected marker EPERM")
        return real_read_text(self, *args, **kwargs)

    def _eperm_marker_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if self.name == marker.name:
            raise PermissionError("injected marker EPERM")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_marker)
    monkeypatch.setattr(Path, "read_bytes", _eperm_marker_bytes)
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert marker.exists()


def test_unreadable_foreign_marker_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R5-4: an unreadable foreign marker (full-uuid name) never defers."""
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=uuid_a,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Digest"),
    )
    src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_b,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(uuid_b, unit="b.py"),
        pid=pid,
        birth=None,
    )
    marker = durability.mark_probe_consumed(src)
    assert marker.name.startswith(f"probe-consumed-{uuid_b}-")
    real_read_text = Path.read_text

    def _eperm_marker(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == marker.name:
            raise PermissionError("injected marker EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_marker)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 5
    assert not Path(planted["registry"]).exists()
    assert marker.exists()


def test_mark_probe_consumed_uses_full_uuid(tmp_path: Path) -> None:
    """#88R5-4: new markers carry the full parent uuid for routing."""
    pid, birth = _dead_pid_with_birth()
    stamped = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=3,
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marked = durability.mark_probe_consumed(stamped)
    assert marked.name == f"probe-consumed-{_UUID_A}-3-feedface.json"
    assert durability._parse_consumed_probe_filename(marked.name) == (_UUID_A, 3)
    legacy = _plant_probe_orphan(tmp_path, parent_uuid=_UUID_A, seq=4, nonce="bead1234")
    marked_legacy = durability.mark_probe_consumed(legacy)
    assert marked_legacy.name == f"probe-consumed-{_UUID_A[:8]}-4-bead1234.json"
    assert durability._parse_consumed_probe_filename(marked_legacy.name) == (
        _UUID_A[:8],
        4,
    )


def test_covered_legacy_orphan_suppressed_despite_ambiguity(tmp_path: Path) -> None:
    """#88R6-2a: a marker-covered legacy copy never folds elsewhere later."""
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=uuid_a,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    _plant_producer(
        tmp_path,
        uuid=uuid_b,
        pid=pid,
        birth=birth,
        unit="b.py",
        in_progress=_counts_block(3, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_a,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(uuid_a),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    legacy = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_a,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        nonce="bead1234",
    )
    first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials_a = [rec for rec in first if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials_a) == 1
    assert _fn_leaf(partials_a[0], "C_Login")["calls"] == 5
    with pytest.raises(AssertionError, match="C_Digest"):
        _fn_leaf(partials_a[0], "C_Digest")
    assert not marker.exists()
    assert not legacy.exists(), "covered by the marker: suppress, never strand"
    child_b = _write_jsonl(
        tmp_path / "child-b.jsonl",
        [{"$report_type": "SessionStart"}, _marker("b.py", 0)],
    )
    second = durability.collect_unit(
        tmp_path, unit="b.py", child_jsonl=child_b, status="crashed", returncode=-11
    )
    partials_b = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials_b) == 1
    assert _fn_leaf(partials_b[0], "C_Login")["calls"] == 3
    with pytest.raises(AssertionError, match="C_Digest"):
        _fn_leaf(partials_b[0], "C_Digest")


def test_legacy_marker_foreign_run_skipped(tmp_path: Path) -> None:
    """#88R6-2b: a legacy marker still honors a stated foreign run."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        pid=pid,
        birth=None,
    )
    payload = json.loads(src.read_text(encoding="utf-8"))
    payload["run_id"] = "R-prior"
    src.write_text(json.dumps(payload), encoding="utf-8")
    marker = src.with_name(src.name.replace("probe-", "probe-consumed-", 1))
    src.rename(marker)
    with pytest.warns(UserWarning, match="cross-run"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0].get("recovered_keys", []) == []
    assert marker.exists()


def test_legacy_marker_foreign_unit_skipped(tmp_path: Path) -> None:
    """#88R6-2b: a legacy marker still honors a stated foreign unit."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        pid=pid,
        birth=None,
    )
    payload = json.loads(src.read_text(encoding="utf-8"))
    payload["unit"] = "b.py"
    src.write_text(json.dumps(payload), encoding="utf-8")
    marker = src.with_name(src.name.replace("probe-", "probe-consumed-", 1))
    src.rename(marker)
    with pytest.warns(UserWarning, match="cross-unit"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0].get("recovered_keys", []) == []
    assert marker.exists()


def test_legacy_orphan_foreign_run_skipped(tmp_path: Path) -> None:
    """#88R6-2b: a legacy orphan still honors a stated foreign run."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        pid=pid,
        birth=None,
    )
    payload = json.loads(orphan.read_text(encoding="utf-8"))
    payload["run_id"] = "R-prior"
    orphan.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.warns(UserWarning, match="cross-run"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Login")["calls"] == 5
    with pytest.raises(AssertionError, match="C_Digest"):
        _fn_leaf(partials[0], "C_Digest")
    assert orphan.exists()


def test_legacy_orphan_foreign_unit_skipped(tmp_path: Path) -> None:
    """#88R6-2b: a legacy orphan still honors a stated foreign unit."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        pid=pid,
        birth=None,
    )
    payload = json.loads(orphan.read_text(encoding="utf-8"))
    payload["unit"] = "b.py"
    orphan.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.warns(UserWarning, match="cross-unit"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Login")["calls"] == 5
    with pytest.raises(AssertionError, match="C_Digest"):
        _fn_leaf(partials[0], "C_Digest")
    assert orphan.exists()


def test_mark_probe_consumed_prefers_parent_param(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R6-2c: the caller's uuid survives a stamp-read fault."""
    pid, birth = _dead_pid_with_birth()
    sidecar = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=3,
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    real_read_text = Path.read_text

    def _eperm_sidecar(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == sidecar.name:
            raise PermissionError("injected sidecar EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_sidecar)
    marked = durability.mark_probe_consumed(sidecar, parent_uuid=_UUID_A)
    assert marked.name == f"probe-consumed-{_UUID_A}-3-feedface.json"


def test_mark_probe_consumed_legacy_without_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R6-2c: no param and no readable stamp keeps the legacy name."""
    sidecar = _plant_probe_orphan(tmp_path, parent_uuid=_UUID_A, seq=4, nonce="bead1234")
    real_read_text = Path.read_text

    def _eperm_sidecar(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == sidecar.name:
            raise PermissionError("injected sidecar EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_sidecar)
    marked = durability.mark_probe_consumed(sidecar)
    assert marked.name == f"probe-consumed-{_UUID_A[:8]}-4-bead1234.json"


def test_commit_marks_full_uuid_despite_transient_fault(
    engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R6-2c: the live mark path never downgrades on a transient."""
    from pkcs11_check.testcases._probes.runner import _commit_probe_sidecar

    parent = call_counters.get_worker_uuid()
    pid, birth = _dead_pid_with_birth()
    sidecar = _plant_probe_orphan(
        tmp_path,
        parent_uuid=parent,
        seq=3,
        identity=_f2_identity(parent),
        pid=pid,
        birth=None,
    )
    real_unlink = os.unlink
    real_read_text = Path.read_text
    state = {"left": 1}

    def _failing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if str(path).endswith(sidecar.name):
            raise PermissionError("injected unlink EPERM")
        return real_unlink(path, *args, **kwargs)

    def _flaky_read(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == sidecar.name and state["left"] > 0:
            state["left"] -= 1
            raise PermissionError("injected transient EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    monkeypatch.setattr(Path, "read_text", _flaky_read)
    _commit_probe_sidecar(str(sidecar), expected=(_UUID_B, 3))
    markers = list(tmp_path.glob("probe-consumed-*.json"))
    assert len(markers) == 1
    assert markers[0].name == f"probe-consumed-{parent}-3-feedface.json"


def _plant_covered_collision(
    tmp_path: Path, *, writer_pid: int, writer_birth: int | None
) -> tuple[str, str, Path, Path]:
    """Collision pair: A's exact marker + a legacy orphan with a rewrite tmp.

    Returns (uuid_a, uuid_b, marker, tmp). The orphan carries (child, seq)
    covered by the marker, an entry-only baseline, and a complete tmp
    holding the second return; the writer stamps ride the orphan.
    """
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    pid, _ = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=uuid_a,
        pid=pid,
        birth=424243,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    _plant_producer(tmp_path, uuid=uuid_b, pid=pid, birth=424244, unit="b.py")
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_a,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(uuid_a),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_a,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        nonce="bead1234",
        pid=writer_pid,
        birth=writer_birth,
    )
    tmp = _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]], parent_uuid=uuid_a),
        pid=999,
    )
    return uuid_a, uuid_b, marker, tmp


def test_covered_ambiguous_live_writer_defers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R7-1: a covered ambiguous slot never kills/collects a live writer."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        uuid_a, _, marker, tmp = _plant_covered_collision(
            tmp_path, writer_pid=proc.pid, writer_birth=birth
        )
        monkeypatch.setattr(durability, "_terminate_verified", lambda *a: False)
        with pytest.warns(UserWarning, match="deferred"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert records == []
        assert proc.poll() is None
        assert marker.exists()
        assert tmp.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_covered_ambiguous_new_rewrite_defers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R7-1: a marker-covered rewrite delta defers loudly, never drops."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        uuid_a, _, marker, tmp = _plant_covered_collision(
            tmp_path, writer_pid=proc.pid, writer_birth=birth
        )
        with pytest.warns(UserWarning, match="deferred"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert proc.poll() is not None, "postmortem fence terminates the writer"
        assert records == []
        assert marker.exists()
        assert tmp.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_covered_owned_new_rewrite_defers(tmp_path: Path) -> None:
    """#88R7-1: a covered owned rewrite delta defers too (no silent drop)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    tmp = _plant_probe_tmp(
        orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]), pid=999
    )
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert marker.exists()
    assert orphan.exists()
    assert tmp.exists()


def test_covered_ambiguous_foreign_run_retained(tmp_path: Path) -> None:
    """#88R7-2: coverage never bypasses an explicit scope contradiction."""
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    pid, _ = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=uuid_a,
        pid=pid,
        birth=424243,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    _plant_producer(tmp_path, uuid=uuid_b, pid=pid, birth=424244, unit="b.py")
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_a,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(uuid_a),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=uuid_a,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        nonce="bead1234",
        pid=pid,
        birth=None,
    )
    payload = json.loads(orphan.read_text(encoding="utf-8"))
    payload["run_id"] = "R-prior"
    orphan.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.warns(UserWarning, match="cross-run"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert orphan.exists()
    assert not marker.exists(), "A's own marker consumes normally"


def test_fence_race_replacement_defers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R8-1: a replace landing during the fence is never folded stale."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        real_terminate = durability._terminate_verified

        def _racing_fence(pid: int, birth: int, timeout: float) -> bool:
            payload = json.loads(orphan.read_text(encoding="utf-8"))
            payload["counters"] = [["m", "C_Digest", 0, 1]]
            orphan.write_text(json.dumps(payload), encoding="utf-8")
            return real_terminate(pid, birth, timeout)

        monkeypatch.setattr(durability, "_terminate_verified", _racing_fence)
        with pytest.warns(UserWarning, match="deferred"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert records == []
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        assert json.loads(orphan.read_text(encoding="utf-8"))["counters"] == [
            ["m", "C_Digest", 0, 1]
        ]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_covered_advanced_baseline_defers(tmp_path: Path) -> None:
    """#88R8-1: a baseline newer than its marker is preserved, not dropped."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="bead1234",
    )
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert marker.exists()
    assert orphan.exists()


def test_covered_stale_baseline_suppresses(tmp_path: Path) -> None:
    """#88R8-1: a baseline within its marker snapshot still suppresses."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="bead1234",
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Login")["calls"] == 5
    assert not Path(planted["registry"]).exists()
    assert not marker.exists()


def test_covered_divergent_defers(tmp_path: Path) -> None:
    """#88R8-2: a covered divergence preserves baseline, marker, and claim."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 2]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 2]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="bead1234",
    )
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 2]]), pid=999)
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 1, 2]]), pid=1000)
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert marker.exists()
    assert orphan.exists()


def test_committed_covered_live_writer_skipped(tmp_path: Path) -> None:
    """#88R10-1/#88R11-1/#88R12-1: a skip keeps marker, heal, and parent."""
    proc = _live_sleeper()
    try:
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        marker_src = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=None,
        )
        pristine = orphan.read_bytes()
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="live writer"):
            records = durability.collect_unit(
                tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == [], "the heal waits for the retry"
        assert proc.poll() is None, "detection never signals"
        assert Path(planted["registry"]).exists(), "skip retains the parent"
        assert Path(planted["sidecar"]).exists(), "skip retains the parent"
        assert marker.exists(), "skip rolls back the marker consume"
        assert orphan.exists()
        proc.kill()
        assert proc.wait(timeout=30) is not None
        advanced = dict(json.loads(pristine.decode("utf-8")))
        advanced["counters"] = [["m", "C_Digest", 0, 1], ["m", "C_Digest", None, 1]]
        orphan.write_text(json.dumps(advanced), encoding="utf-8")
        with pytest.warns(UserWarning, match="rewrite newer than marker coverage"):
            retry = durability.collect_unit(
                tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert retry == []
        assert marker.exists()
        assert orphan.exists()
        assert Path(planted["registry"]).exists()
        orphan.write_bytes(pristine)
        converged = durability.collect_unit(
            tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in converged if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["recovered_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 0}]
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        assert not marker.exists()
        assert not orphan.exists()
        payload = extract_call_counters_from_jsonl(child)
        assert payload is not None
        assert payload["total_calls"] == 10
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_barrier_skip_excluded_from_sweep_then_converges(tmp_path: Path) -> None:
    """#88R12-1: the sweep spares skip-held parents while the writer lives."""
    proc = _live_sleeper()
    try:
        root = tmp_path / "counters"
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            root,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        marker_src = _plant_probe_orphan(
            root,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=birth,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        orphan = _plant_probe_orphan(
            root,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=durability.birth_token_for_pid(proc.pid),
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(2, fn="C_Digest"),
                    extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        with pytest.warns(UserWarning, match="live writer"):
            plan = durability.prepare_resume(root, prior_merged_jsonl=prior)
        assert plan["barrier_ok"] is True
        assert _UUID_A in plan["retained_uuids"]
        swept = durability.sweep_orphans(
            root,
            current_run=_RUN,
            collected_runs=frozenset(plan["collected_runs"]),
            retain_uuids=frozenset(plan.get("unresolved", []) + plan.get("retained_uuids", [])),
        )
        assert swept["removed"] == 0
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()
        assert marker.exists()
        assert orphan.exists()
        proc.kill()
        assert proc.wait(timeout=30) is not None
        again = durability.prepare_resume(root, prior_merged_jsonl=prior)
        assert again["barrier_ok"] is True
        assert not Path(planted["registry"]).exists()
        assert not Path(planted["sidecar"]).exists()
        assert not marker.exists()
        assert not orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_committed_uncovered_live_writer_defers(tmp_path: Path) -> None:
    """#88R16-4: a live writer defers even without any coverage."""
    proc = _live_sleeper()
    try:
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=None,
        )
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="deferred"):
            records = durability.collect_unit(
                tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert proc.poll() is None, "deferral never signals"
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()
        assert orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_committed_durable_covered_live_writer_defers(tmp_path: Path) -> None:
    """#88R11-1: durable coverage without a snapshot cannot skip safely."""
    proc = _live_sleeper()
    try:
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(5, fn="C_Login"),
            receipts=[{"worker_uuid": _UUID_B, "probe_seq": 0}],
        )
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=None,
        )
        child = _committed_child(tmp_path, pid, _counts_block(10))
        with pytest.warns(UserWarning, match="deferred"):
            records = durability.collect_unit(
                tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
            )
        assert records == []
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()
        assert orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_committed_unstamped_advance_skips_and_retains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R11-1: the fold reread catches an unstamped writer's advance."""
    pid, _ = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=424243,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    advanced = dict(json.loads(orphan.read_text(encoding="utf-8")))
    advanced["counters"] = [["m", "C_Digest", 0, 1]]
    real_replay = durability._replay_probe_tmp_rows

    def _advancing_replay(*args: Any, **kwargs: Any) -> Any:
        result = real_replay(*args, **kwargs)
        orphan.write_text(json.dumps(advanced), encoding="utf-8")
        return result

    monkeypatch.setattr(durability, "_replay_probe_tmp_rows", _advancing_replay)
    child = _committed_child(tmp_path, pid, _counts_block(10))
    with pytest.warns(UserWarning, match="advanced during collection"):
        records = durability.collect_unit(
            tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
    assert records == [], "the heal waits for the retry"
    assert Path(planted["registry"]).exists(), "skip retains the parent"
    assert Path(planted["sidecar"]).exists()
    assert orphan.exists(), "the advanced return is never deleted"
    assert json.loads(orphan.read_text(encoding="utf-8"))["counters"] == [["m", "C_Digest", 0, 1]]


def test_postmortem_advance_between_rereads_defers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R11-1: postmortem never skips; a late advance defers."""
    pid, _ = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=424243,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    advanced = dict(json.loads(orphan.read_text(encoding="utf-8")))
    advanced["counters"] = [["m", "C_Digest", 0, 1]]
    real_replay = durability._replay_probe_tmp_rows

    def _advancing_replay(*args: Any, **kwargs: Any) -> Any:
        result = real_replay(*args, **kwargs)
        orphan.write_text(json.dumps(advanced), encoding="utf-8")
        return result

    monkeypatch.setattr(durability, "_replay_probe_tmp_rows", _advancing_replay)
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert orphan.exists()


def test_liveness_recycled_pid_reads_dead(tmp_path: Path) -> None:
    """#88R10-1: a mismatched birth proves recycle no matter the pid state."""
    if sys.platform != "linux":
        pytest.skip("birth tokens are Linux-only")
    own_birth = durability.birth_token_for_pid(os.getpid())
    assert own_birth is not None
    pid, _ = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=424243,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=os.getpid(),
        birth=own_birth + 1,
    )
    child = _committed_child(tmp_path, pid, _counts_block(10))
    records = durability.collect_unit(
        tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
    )
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert not Path(planted["registry"]).exists()
    assert not marker.exists()


def test_liveness_zombie_reads_dead(tmp_path: Path) -> None:
    """#88R10-1: an unreaped zombie holds no writer (pidfd exit wins)."""
    if sys.platform != "linux":
        pytest.skip("pidfd exit detection is Linux-only")
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        zombie_birth = durability.birth_token_for_pid(proc.pid)
        assert zombie_birth is not None
        deadline = time.monotonic() + 30
        while True:
            state = (
                Path(f"/proc/{proc.pid}/stat")
                .read_text(encoding="ascii")
                .rsplit(")", 1)[1]
                .split()[0]
            )
            if state == "Z":
                break
            assert time.monotonic() < deadline, "child never became a zombie"
            time.sleep(0.01)
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        marker_src = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
        marker_src.rename(marker)
        _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=zombie_birth,
        )
        child = _committed_child(tmp_path, pid, _counts_block(10))
        records = durability.collect_unit(
            tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert not Path(planted["registry"]).exists()
        assert not marker.exists()
    finally:
        proc.wait(timeout=30)


def test_snapshot_compare_is_type_strict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R9-1b: true -> 1 across the fence counts as a change."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", True, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        real_terminate = durability._terminate_verified

        def _racing_fence(pid: int, birth: int, timeout: float) -> bool:
            payload = json.loads(orphan.read_text(encoding="utf-8"))
            payload["counters"] = [["m", "C_Digest", 1, 1]]
            orphan.write_text(json.dumps(payload), encoding="utf-8")
            return real_terminate(pid, birth, timeout)

        monkeypatch.setattr(durability, "_terminate_verified", _racing_fence)
        with pytest.warns(UserWarning, match="deferred"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert records == []
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_nan_snapshot_compares_stable(tmp_path: Path) -> None:
    """#88R9-1b: identical NaN payloads never read as changed."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    payload = json.loads(orphan.read_text(encoding="utf-8"))
    payload["x_probe_note"] = float("nan")
    orphan.write_text(json.dumps(payload), encoding="utf-8")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1
    assert not Path(planted["registry"]).exists()


def test_gone_baseline_with_tmp_warns_and_proceeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R9-1c: a vanished baseline with a surviving tmp stays loud."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5, fn="C_Login"),
        )
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        tmp = _plant_probe_tmp(
            orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]), pid=999
        )
        real_terminate = durability._terminate_verified

        def _vanishing_fence(pid: int, birth: int, timeout: float) -> bool:
            orphan.unlink()
            return real_terminate(pid, birth, timeout)

        monkeypatch.setattr(durability, "_terminate_verified", _vanishing_fence)
        with pytest.warns(UserWarning, match="vanished"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert _fn_leaf(partials[0], "C_Login")["calls"] == 5
        assert not Path(planted["registry"]).exists()
        assert tmp.exists(), "surviving rewrite retained for forensics"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_covered_new_loss_key_defers(tmp_path: Path) -> None:
    """#88R9-2: a covered orphan with a new loss key is preserved, not dropped."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="bead1234",
        lost_keys=[_lost_key(_UUID_A, 7)],
    )
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert marker.exists()
    assert orphan.exists()


def test_covered_larger_loss_scalar_defers(tmp_path: Path) -> None:
    """#88R9-2: a covered orphan with a larger unkeyed loss is preserved."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="bead1234",
        probes_lost=2,
    )
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert Path(planted["registry"]).exists()
    assert marker.exists()
    assert orphan.exists()


def test_transient_baseline_fault_folds_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R5-1: one read fault heals inside a single retrying read."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    real_read_text = Path.read_text
    state = {"left": 1}

    def _flaky_baseline(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == orphan.name and state["left"] > 0:
            state["left"] -= 1
            raise PermissionError("injected transient EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _flaky_baseline)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1
    assert not Path(planted["registry"]).exists()
    assert not orphan.exists()


def test_transient_marker_fault_keeps_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R5-1: a healed marker still suppresses its covered orphan."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(6, fn="C_Digest"),
    )
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 6]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 6]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="deadbeef",
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    real_read_text = Path.read_text
    state = {"left": 1}

    def _flaky_marker(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == marker.name and state["left"] > 0:
            state["left"] -= 1
            raise PermissionError("injected transient EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _flaky_marker)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 6
    assert not marker.exists()
    assert not orphan.exists()


def test_unreadable_producer_sidecar_defers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R4-F1b: an unreadable producer baseline defers (no journal-only gap)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(2, fn="C_Digest"),
    )
    sidecar = Path(planted["sidecar"])
    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes
    blocked = True

    def _flaky_sidecar(self: Path, *args: Any, **kwargs: Any) -> str:
        if blocked and self.name == sidecar.name:
            raise PermissionError("injected sidecar EPERM")
        return real_read_text(self, *args, **kwargs)

    def _flaky_sidecar_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if blocked and self.name == sidecar.name:
            raise PermissionError("injected sidecar EPERM")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _flaky_sidecar)
    monkeypatch.setattr(Path, "read_bytes", _flaky_sidecar_bytes)
    with pytest.warns(UserWarning, match="deferred"):
        first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert first == []
    assert Path(planted["registry"]).exists()
    assert sidecar.exists()
    blocked = False
    second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 2


def test_unreadable_journal_defers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R4-F1b: an unreadable journal defers (no sidecar-only gap)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(2, fn="C_Digest"),
        journal=[
            {
                "nodeid": "a.py::t1",
                "block": _counts_block(2, fn="C_Digest"),
                "receipts": [],
            }
        ],
    )
    journal = Path(planted["journal"])
    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes
    blocked = True

    def _flaky_journal(self: Path, *args: Any, **kwargs: Any) -> str:
        if blocked and self.name == journal.name:
            raise PermissionError("injected journal EPERM")
        return real_read_text(self, *args, **kwargs)

    def _flaky_journal_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if blocked and self.name == journal.name:
            raise PermissionError("injected journal EPERM")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _flaky_journal)
    monkeypatch.setattr(Path, "read_bytes", _flaky_journal_bytes)
    with pytest.warns(UserWarning, match="deferred"):
        first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert first == []
    assert Path(planted["registry"]).exists()
    assert journal.exists()
    blocked = False
    second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1


def test_consume_retains_baseless_complete_tmp(tmp_path: Path) -> None:
    """#88R3F1: a complete tmp without a baseline is kept for forensics."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    sidecar = Path(planted["sidecar"])
    assert not sidecar.exists()
    tmp = _plant_tmp(sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert partials == []
    assert tmp.exists()


def test_unreadable_registry_uuid_taxonomy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R2: reservation fires on I/O errors, never on torn content."""
    reg = tmp_path / f"{_UUID_A}.json"
    reg.write_text("{torn", encoding="utf-8")
    assert durability._unreadable_registry_uuid(reg) is None
    assert durability._unreadable_registry_uuid(tmp_path / "missing.json") is None
    reg.write_text(json.dumps({"worker_uuid": _UUID_A}), encoding="utf-8")
    assert durability._unreadable_registry_uuid(reg) is None

    def _eperm(self: Path, *args: Any, **kwargs: Any) -> str:
        raise PermissionError("injected")

    monkeypatch.setattr(Path, "read_text", _eperm)
    assert durability._unreadable_registry_uuid(reg) == _UUID_A


def test_in_flight_rows_name_missing_returns() -> None:
    """#88: entries without RVs become sorted named rows."""
    block = {
        "total_calls": 3,
        "by_module": {
            "m": {
                "calls": 3,
                "buckets": {
                    "test": {
                        "calls": 3,
                        "by_fn": {
                            "C_Digest": {"calls": 2, "by_rv": {}},
                            "C_Login": {
                                "calls": 1,
                                "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                            },
                        },
                    }
                },
            }
        },
    }
    assert durability._in_flight_rows(block) == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 2}
    ]


def test_in_flight_rows_empty_when_complete() -> None:
    """#88: fully returned calls produce no rows (field stays omitted)."""
    assert durability._in_flight_rows(_counts_block(3)) == []
    assert durability._in_flight_rows({"total_calls": 0, "by_module": {}}) == []


def test_orphan_tmp_superset_adopted(tmp_path: Path) -> None:
    """#88: a complete orphan tmp replays its returns (lost_returns=0)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaf
    assert _lost_returns(partials[0]) == 0
    assert "in_flight" not in partials[0]
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_orphan_tmp_stale_ignored(tmp_path: Path) -> None:
    """#88: a tmp older than the committed sidecar never rewinds it."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(2, fn="C_Digest"),
    )
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 2
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_orphan_tmp_wrong_uuid_ignored(tmp_path: Path) -> None:
    """#88: a tmp from another producer is never adopted."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_B, _counts_block(5, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_orphan_tmp_torn_ignored(tmp_path: Path) -> None:
    """#88: an unparseable tmp reads as absent (committed sidecar wins)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(planted["sidecar"], None, raw='{"in_progress": {"total_calls": 1,')
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_orphan_tmp_newest_wins(tmp_path: Path) -> None:
    """#88: among complete tmps the largest snapshot replays."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(2),
    )
    older = _counts_block(2, fn="C_Digest")
    older["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"]["0"]["count"] = 1
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, older, pid=pid), nonce="aaa")
    newer = _counts_block(2, fn="C_Digest")
    newer["total_calls"] = 3
    newer["by_module"]["m"]["calls"] = 3
    newer["by_module"]["m"]["buckets"]["test"]["calls"] = 3
    newer["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Login"] = {
        "calls": 1,
        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
    }
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, newer, pid=pid), nonce="bbb")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 2
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 2}}, leaf
    assert "in_flight" not in partials[0]
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_orphan_tmp_excess_returns_capped(tmp_path: Path) -> None:
    """#88R1: replayed returns never exceed committed entries (leaf kept)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(3, fn="C_Digest"), pid=pid),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["calls"] == 1, leaf
    assert leaf["by_rv"] == {}, leaf
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_orphan_tmp_older_window_ignored(tmp_path: Path) -> None:
    """#88R1: a pre-reset tmp never displaces the current window's tail."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
        journal=[{"nodeid": "w", "block": _counts_block(2, fn="C_Login")}],
        journal_seq=1,
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(2, fn="C_Digest"), pid=pid, journal_seq=0),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 3
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_orphan_tmp_wrong_run_ignored(tmp_path: Path) -> None:
    """#88R1: a tmp from another run is never adopted."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(5, fn="C_Digest"), pid=pid, run_id="R2"),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}


def test_orphan_tmp_wrong_unit_ignored(tmp_path: Path) -> None:
    """#88R1: a tmp from another unit is never adopted."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(5, fn="C_Digest"), pid=pid, unit="b.py"),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1


def test_orphan_tmp_wrong_pid_ignored(tmp_path: Path) -> None:
    """#88R1: a tmp from another pid is never adopted."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(5, fn="C_Digest"), pid=pid + 100000),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1


def test_orphan_tmp_missing_seq_ignored(tmp_path: Path) -> None:
    """#88R1: a tmp without a window mark cannot prove its window."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(5, fn="C_Digest"), pid=pid, journal_seq=None),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1


def test_orphan_tmp_phantom_entry_not_adopted(tmp_path: Path) -> None:
    """#88R1: a rolled-back entry in the tmp never becomes a call."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _entry_only_block(2), pid=pid),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_orphan_tmp_preserves_committed_returns(tmp_path: Path) -> None:
    """#88R1: an older same-window tmp never erases committed returns."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(1, fn="C_Digest"),
    )
    _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _entry_only_block(1), pid=pid),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaf
    assert "in_flight" not in partials[0]


def test_orphan_tmp_replays_returns_only(tmp_path: Path) -> None:
    """#88R1: tmp returns replay onto committed entries; new fns ignored."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    replay_block = _counts_block(1, fn="C_Digest")
    replay_block["total_calls"] = 2
    replay_block["by_module"]["m"]["calls"] = 2
    replay_block["by_module"]["m"]["buckets"]["test"]["calls"] = 2
    replay_block["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Login"] = {
        "calls": 1,
        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
    }
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, replay_block, pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaf
    assert "in_flight" not in partials[0]


def test_orphan_tmp_divergent_conflicts(tmp_path: Path) -> None:
    """#88R3F3: irreconcilable tmps keep committed and flag conflict."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(2),
    )
    block_a = _entry_only_block(2)
    block_a["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "0": {"name": "CKR_OK", "count": 2}
    }
    block_b = _entry_only_block(2)
    block_b["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "1": {"name": "CKR_CANCEL", "count": 2}
    }
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_a, pid=pid), nonce="aaa")
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_b, pid=pid), nonce="bbb")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 2}
    ]
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert lost[0]["end_state"] == "conflict"


def test_orphan_tmp_unkeyed_ingest_skipped(tmp_path: Path) -> None:
    """#88R3F2: unkeyed new entries never donate their returns."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    unkeyed = _entry_only_block(2)
    unkeyed["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "0": {"name": "CKR_OK", "count": 1}
    }
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, unkeyed, pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_orphan_tmp_lost_keys_dont_block_replay(tmp_path: Path) -> None:
    """#88R3F2: new loss metadata never blocks a genuine return replay."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    payload = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload["lost_keys"] = [{"parent_uuid": _UUID_B, "probe_seq": 3}]
    _plant_tmp(planted["sidecar"], payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaf
    assert partials[0].get("lost_keys") == [{"parent_uuid": _UUID_B, "probe_seq": 3}]


def test_probe_tmp_population_mismatch_skipped(tmp_path: Path) -> None:
    """#88R3F2: probe replay needs matching entry populations too."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", None, 1], ["m", "C_Digest", 0, 1]]),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_orphan_tmp_ingest_checkpoint_skipped(tmp_path: Path) -> None:
    """#88R3F2: a tmp with new coverage never replays (orphan folds)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    payload = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload["consumed_probes"] = [{"worker_uuid": _UUID_B, "probe_seq": 9}]
    _plant_tmp(planted["sidecar"], payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_orphan_tmp_scalar_maxes_across_candidates(tmp_path: Path) -> None:
    """#88R3F3: tied returns still adopt the newest loss scalar."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    payload_a = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload_a["probes_lost"] = 1
    payload_b = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload_b["probes_lost"] = 3
    _plant_tmp(planted["sidecar"], payload_a, nonce="aaa")
    _plant_tmp(planted["sidecar"], payload_b, nonce="bbb")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}
    assert partials[0]["probes_lost"] == 3


def test_orphan_tmp_divergent_quarantined(tmp_path: Path) -> None:
    """#88R3F3: divergent tmps are preserved, not consumed."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(2),
    )
    block_a = _entry_only_block(2)
    block_a["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "0": {"name": "CKR_OK", "count": 2}
    }
    block_b = _entry_only_block(2)
    block_b["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "1": {"name": "CKR_CANCEL", "count": 2}
    }
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_a, pid=pid), nonce="aaa")
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_b, pid=pid), nonce="bbb")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert lost[0]["end_state"] == "conflict"
    quarantined = sorted(tmp_path.glob("*.quarantined-*"))
    assert len(quarantined) == 2, [path.name for path in tmp_path.iterdir()]
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_loss_only_tmp_adopts_metadata(tmp_path: Path) -> None:
    """#88R4-F2: a loss-only rewrite still lands its key and scalar."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(1, fn="C_Digest"),
    )
    payload = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload["lost_keys"] = [{"parent_uuid": _UUID_A, "probe_seq": 4}]
    payload["probes_lost"] = 1
    _plant_tmp(planted["sidecar"], payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["lost_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 4}]
    assert partials[0]["probes_lost"] == 1


def test_loss_only_tmp_union_across_candidates(tmp_path: Path) -> None:
    """#88R4-F2: loss metadata unions over every gated candidate."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(1, fn="C_Digest"),
    )
    payload_a = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload_a["lost_keys"] = [{"parent_uuid": _UUID_A, "probe_seq": 4}]
    payload_a["probes_lost"] = 1
    _plant_tmp(planted["sidecar"], payload_a, nonce="aaa")
    payload_b = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload_b["lost_keys"] = [{"parent_uuid": _UUID_A, "probe_seq": 5}]
    payload_b["probes_lost"] = 3
    _plant_tmp(planted["sidecar"], payload_b, nonce="bbb")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["lost_keys"] == [
        {"parent_uuid": _UUID_A, "probe_seq": 4},
        {"parent_uuid": _UUID_A, "probe_seq": 5},
    ]
    assert partials[0]["probes_lost"] == 3


def test_loss_only_deep_extension_no_recursion(tmp_path: Path) -> None:
    """#88R5-5: loss-only replay never deep-copies the sidecar."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(1, fn="C_Digest"),
    )
    sidecar = Path(planted["sidecar"])
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    nested: Any = 0
    for _ in range(700):
        nested = [nested]
    payload["x_extension"] = nested
    sidecar.write_text(json.dumps(payload), encoding="utf-8")
    tmp_payload = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    tmp_payload["lost_keys"] = [{"parent_uuid": _UUID_A, "probe_seq": 4}]
    tmp_payload["probes_lost"] = 1
    _plant_tmp(sidecar, tmp_payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["lost_keys"] == [{"parent_uuid": _UUID_A, "probe_seq": 4}]
    assert partials[0]["probes_lost"] == 1


def test_loss_only_tmp_keeps_coverage_guard(tmp_path: Path) -> None:
    """#88R4-F2: an ingest checkpoint's loss stays unadopted with its coverage."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(1, fn="C_Digest"),
    )
    payload = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    payload["receipts"] = [{"worker_uuid": _UUID_B, "probe_seq": 0}]
    payload["lost_keys"] = [{"parent_uuid": _UUID_A, "probe_seq": 4}]
    payload["probes_lost"] = 1
    _plant_tmp(planted["sidecar"], payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0].get("lost_keys", []) == []
    assert partials[0].get("probes_lost", 0) == 0


def _quarantine_planted(tmp: Path) -> Path:
    """Rename a planted tmp exactly like _quarantine_tmp (crash simulation)."""
    target = tmp.with_name(tmp.name.replace(".tmp-", ".quarantined-", 1))
    tmp.rename(target)
    return target


def test_partial_quarantine_retry_holds_conflict(tmp_path: Path) -> None:
    """#88R4-F3: a crash between renames never publishes one side."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(2),
    )
    block_a = _entry_only_block(2)
    block_a["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "0": {"name": "CKR_OK", "count": 2}
    }
    block_b = _entry_only_block(2)
    block_b["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "1": {"name": "CKR_CANCEL", "count": 2}
    }
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_a, pid=pid), nonce="aaa")
    straggler = _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_b, pid=pid), nonce="bbb")
    first = _quarantine_planted(
        planted["sidecar"].with_name(f"{planted['sidecar'].name}.tmp-999-aaa")
    )
    with pytest.warns(UserWarning, match="conflict"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert lost[0]["end_state"] == "conflict"
    assert first.exists()
    assert not straggler.exists()
    assert straggler.with_name(straggler.name.replace(".tmp-", ".quarantined-", 1)).exists()


def test_full_quarantine_retry_keeps_conflict(tmp_path: Path) -> None:
    """#88R4-F3: a fully quarantined checkpoint still reports conflict."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(2),
    )
    block_a = _entry_only_block(2)
    block_a["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Digest"]["by_rv"] = {
        "0": {"name": "CKR_OK", "count": 2}
    }
    tmp = _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, block_a, pid=pid))
    _quarantine_planted(tmp)
    with pytest.warns(UserWarning, match="conflict"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert lost[0]["end_state"] == "conflict"


def test_stale_window_quarantine_does_not_veto(tmp_path: Path) -> None:
    """#88R5-3: a quarantine from another window binds nothing."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    stale = _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid, journal_seq=99),
        nonce="old",
    )
    _quarantine_planted(stale)
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert lost[0]["end_state"] == "crashed"


def test_foreign_child_quarantine_does_not_veto(tmp_path: Path) -> None:
    """#88R5-3: a quarantine from another child binds nothing."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    stale = _plant_probe_tmp(
        orphan, _probe_tmp_payload("c" * 32, 0, [["m", "C_Digest", 0, 1]]), pid=998
    )
    _quarantine_planted(stale)
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]), pid=999)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}


def test_cross_run_quarantine_does_not_veto(tmp_path: Path) -> None:
    """#88R6-1: a quarantine failing today's gates binds nothing (run)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    stale = _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid, run_id="R-other"),
        nonce="old",
    )
    _quarantine_planted(stale)
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}


def test_cross_pid_quarantine_does_not_veto(tmp_path: Path) -> None:
    """#88R6-1: a quarantine failing today's gates binds nothing (pid)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    stale = _plant_tmp(
        planted["sidecar"],
        _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid + 1),
        nonce="old",
    )
    _quarantine_planted(stale)
    _plant_tmp(planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}


def test_cross_birth_quarantine_does_not_veto(tmp_path: Path) -> None:
    """#88R6-1: a probe quarantine with a clashing birth binds nothing."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=424243,
    )
    stale_payload = _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]])
    stale_payload["pid"] = pid
    stale_payload["birth_token"] = 999999
    stale = _plant_probe_tmp(orphan, stale_payload, pid=998)
    _quarantine_planted(stale)
    live_payload = _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]])
    live_payload["pid"] = pid
    live_payload["birth_token"] = 424243
    _plant_probe_tmp(orphan, live_payload, pid=999)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}


def test_unreadable_quarantine_defers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R5-3: an unreadable quarantine vetoes nothing silently (defer)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    tmp = _plant_tmp(
        planted["sidecar"], _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid)
    )
    quarantined = _quarantine_planted(tmp)
    real_read_text = Path.read_text

    def _eperm_quarantine(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == quarantined.name:
            raise PermissionError("injected quarantine EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_quarantine)
    with pytest.warns(UserWarning, match="deferred"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    assert records == []
    assert quarantined.exists()


def test_partial_probe_quarantine_retry_holds(tmp_path: Path) -> None:
    """#88R4-F3: a crashed probe quarantine never publishes one side."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 2]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 2]]), pid=999)
    straggler = _plant_probe_tmp(
        orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 1, 2]]), pid=1000
    )
    first = _quarantine_planted(orphan.with_name(f"{orphan.name}.tmp-999"))
    with pytest.warns(UserWarning, match="[Qq]uarantin"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert first.exists()
    assert not straggler.exists()
    assert straggler.with_name(straggler.name.replace(".tmp-", ".quarantined-", 1)).exists()


def test_orphan_tmp_missing_committed_retained(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    """#88R1 (superseded by #88R3F1): with no committed sidecar a tmp cannot
    replay, but it is retained loudly for forensics (it may belong to a
    later incarnation), never deleted or replayed blindly."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    sidecar = Path(planted["sidecar"])
    assert not sidecar.exists()
    _plant_tmp(sidecar, _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid))
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert partials == []
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert len(list(tmp_path.glob("*.tmp-*"))) == 1
    assert any(
        "retained" in str(warn.message) and "unadjudicated" in str(warn.message)
        for warn in recwarn.list
    )


def test_torn_tmp_names_in_flight_row(tmp_path: Path) -> None:
    """#88: a torn rewrite names its lost return (never silent)."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    _plant_tmp(planted["sidecar"], None, raw="torn-bytes")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]
    assert _lost_returns(partials[0]) == 1
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_dead_producer_unknown_module_named(tmp_path: Path) -> None:
    """#88R4: the unknown-module sentinel rows like any module."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1, module=""),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["in_flight"] == [
        {"module": "", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]
    assert schema.is_sidecar_partial(partials[0]) is True


def test_dead_producer_missing_returns_named(tmp_path: Path) -> None:
    """#88/#87-item-6: died-inside-the-call names the in-flight fn."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_entry_only_block(1),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def _plant_probe_tmp(
    orphan: Path, payload: dict[str, Any] | None, *, raw: str | None = None, pid: int = 999
) -> Path:
    """Plant an orphan probe-rewrite tmp (probe tmps carry no nonce)."""
    tmp = orphan.with_name(f"{orphan.name}.tmp-{pid}")
    if raw is not None:
        tmp.write_text(raw, encoding="utf-8")
    else:
        assert payload is not None
        tmp.write_text(json.dumps(payload), encoding="utf-8")
    return tmp


def _probe_tmp_payload(
    child_uuid: str,
    seq: int,
    counters: list[list[Any]],
    *,
    parent_uuid: str = _UUID_A,
    finalized: bool = True,
    run_id: str = _RUN,
    unit: str = "a.py",
    attempt: int = 0,
) -> dict[str, Any]:
    """A complete probe-rewrite tmp payload (mirrors write_probe_sidecar)."""
    payload: dict[str, Any] = {
        "worker_uuid": child_uuid,
        "probe_seq": seq,
        "counters": counters,
        "parent_uuid": parent_uuid,
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "role": "unit",
        "isolation": "file",
    }
    if not finalized:
        payload["finalized"] = False
    return payload


def test_probe_orphan_missing_returns_named(tmp_path: Path) -> None:
    """#88: probe-folded entries without RVs name in-flight rows too."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_probe_tmp_replays_return(tmp_path: Path) -> None:
    """#88: a complete probe tmp replays its return onto orphan entries."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaf
    assert "in_flight" not in partials[0]
    assert list(tmp_path.glob("probe-*.tmp-*")) == []


def test_probe_tmp_torn_ignored(tmp_path: Path) -> None:
    """#88: a torn probe tmp reads as absent (orphan wins, row names it)."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(orphan, None, raw="torn-bytes")
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]
    assert list(tmp_path.glob("probe-*.tmp-*")) == []


def test_probe_tmp_wrong_seq_ignored(tmp_path: Path) -> None:
    """#88: a probe tmp from another seq never replays."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 7, [["m", "C_Digest", 0, 1]]),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_probe_tmp_wrong_run_ignored(tmp_path: Path) -> None:
    """#88R3F6: a probe tmp from another run never replays."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]], run_id="R2"),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 1}
    ]


def test_probe_tmp_bool_seq_ignored(tmp_path: Path) -> None:
    """#88R3F6: a JSON true never equals sequence 1."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=1,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    payload = _probe_tmp_payload(_UUID_B, True, [["m", "C_Digest", 0, 1]])
    _plant_probe_tmp(orphan, payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}


def test_probe_tmp_foreign_parent_legacy_orphan_ignored(tmp_path: Path) -> None:
    """#88R3F6: a legacy orphan cannot launder a cross-producer tmp."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
    )
    _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]], parent_uuid=_UUID_B),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}


def test_orphan_tmp_bool_attempt_ignored(tmp_path: Path) -> None:
    """#88R3F6: a JSON true never equals attempt 1."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        attempt=1,
        in_progress=_entry_only_block(1),
    )
    payload = _tmp_payload(_UUID_A, _counts_block(1, fn="C_Digest"), pid=pid, attempt=True)
    _plant_tmp(planted["sidecar"], payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}


def test_probe_tmp_wrong_unit_ignored(tmp_path: Path) -> None:
    """#88R3F6: a probe tmp from another unit never replays."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(
        orphan,
        _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]], unit="b.py"),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}


def test_probe_tmp_divergent_warns_and_keeps_orphan(tmp_path: Path) -> None:
    """#88R3F3: irreconcilable probe tmps warn loudly and replay nothing."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 2]],
        identity=_f2_identity(_UUID_A),
    )
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 2]]), pid=1001)
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 1, 2]]), pid=1002)
    with pytest.warns(UserWarning, match="divergent"):
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}
    assert partials[0]["in_flight"] == [
        {"module": "m", "bucket": "test", "fn": "C_Digest", "count": 2}
    ]
    quarantined = sorted(tmp_path.glob("probe-*.quarantined-*"))
    assert len(quarantined) == 2, [path.name for path in tmp_path.iterdir()]
    assert list(tmp_path.glob("probe-*.tmp-*")) == []


def test_probe_sidecar_stamps_writer_incarnation(tmp_path: Path) -> None:
    """#88R3F4: probe writes bind the slot to the writer's incarnation."""
    path = tmp_path / "probe-abcdef12-0-feedface.json"
    durability.write_probe_sidecar(
        path,
        worker_uuid=_UUID_B,
        probe_seq=0,
        counters=[["m", "C_Login", 0, 1]],
        pid=4242,
        birth=9876543210,
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["pid"] == 4242
    assert payload["birth_token"] == 9876543210
    legacy = tmp_path / "probe-abcdef12-1-feedface.json"
    durability.write_probe_sidecar(legacy, worker_uuid=_UUID_B, probe_seq=1, counters=[])
    assert "pid" not in json.loads(legacy.read_text(encoding="utf-8"))


def _live_sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_live_probe_orphan_fenced_and_folded(tmp_path: Path) -> None:
    """#88R3F4: a live writer on a dead path is fenced, then folded."""
    if not sys.platform.startswith("linux") and sys.platform != "win32":
        pytest.skip("verified fencing needs pidfd or a process handle")
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert proc.poll() is not None, "fence must terminate the live writer"
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 1
        assert not orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_unfenceable_probe_defers_whole_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R3F4: an unfenceable live writer defers everything (no records)."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        monkeypatch.setattr(durability, "_terminate_verified", lambda *a: False)
        with pytest.warns(UserWarning, match="deferred"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert records == []
        assert proc.poll() is None
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_deferred_probe_collects_after_child_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R3F4: pass 2 collects a deferred parent + probe coherently."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )

        def _fence_like_reality(pid: int, birth: int, timeout: float) -> bool:
            return proc.poll() is not None

        monkeypatch.setattr(durability, "_terminate_verified", _fence_like_reality)
        with pytest.warns(UserWarning, match="deferred"):
            first = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert first == []
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        proc.kill()
        assert proc.wait(timeout=30) is not None
        second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1
        assert not Path(planted["registry"]).exists()
        assert not orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_live_writer_without_birth_defers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R3F4: a present pid with unverifiable identity stays unresolved."""
    proc = _live_sleeper()
    try:
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=None,
        )
        tmp = _plant_probe_tmp(
            orphan,
            _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]]),
        )
        signaled: list[tuple[int, int]] = []
        real_terminate = durability._terminate_verified

        def _spy(pid: int, birth: int, timeout: float) -> bool:
            signaled.append((pid, birth))
            return real_terminate(pid, birth, timeout)

        monkeypatch.setattr(durability, "_terminate_verified", _spy)
        with pytest.warns(UserWarning, match="deferred"):
            records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        assert records == []
        assert signaled == [], "unverifiable writers are never signaled"
        assert proc.poll() is None
        assert Path(planted["registry"]).exists()
        assert orphan.exists()
        assert tmp.exists()
        proc.kill()
        assert proc.wait(timeout=30) is not None
        second = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        partials = [rec for rec in second if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_foreign_probe_never_defers_unrelated_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recwarn: pytest.WarningsRecorder
) -> None:
    """#88R4-REG1: ownership precedes pid checks (no foreign defer)."""
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    proc = _live_sleeper()
    try:
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path, uuid=uuid_a, pid=pid, birth=424243, in_progress=_counts_block(5)
        )
        _plant_producer(tmp_path, uuid=uuid_b, pid=pid, birth=424244, unit="b.py")
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=uuid_b,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(uuid_b, unit="b.py"),
            pid=proc.pid,
            birth=None,
        )
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 5
        assert not Path(planted["registry"]).exists()
        assert orphan.exists(), "another producer's pass owns it"
        assert not [w for w in recwarn.list if "deferred" in str(w.message)]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_foreign_probe_never_fenced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R4-REG1: ownership precedes fencing (no foreign signal)."""
    uuid_a = "12345678" + "a" * 24
    uuid_b = "12345678" + "b" * 24
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            tmp_path, uuid=uuid_a, pid=pid, birth=424243, in_progress=_counts_block(5)
        )
        _plant_producer(tmp_path, uuid=uuid_b, pid=pid, birth=424244, unit="b.py")
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=uuid_b,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(uuid_b, unit="b.py"),
            pid=proc.pid,
            birth=birth,
        )
        fenced: list[int] = []

        def _spy(pid: int, birth: int, timeout: float) -> bool:
            fenced.append(pid)
            return True

        monkeypatch.setattr(durability, "_terminate_verified", _spy)
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert fenced == []
        assert proc.poll() is None
        assert not Path(planted["registry"]).exists()
        assert orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_deferred_unit_joins_skipped_units(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R4-F4: resume never schedules a unit with deferred evidence."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        monkeypatch.setattr(durability, "_terminate_verified", lambda *a: False)
        with pytest.warns(UserWarning, match="deferred"):
            plan = durability.prepare_resume(tmp_path, prior_merged_jsonl=None)
        assert plan["unresolved"] == [_UUID_A]
        assert plan["skipped_units"] == ["a.py"]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def _committed_child(
    tmp_path: Path, pid: int, block: dict[str, Any], *, name: str = "child.jsonl"
) -> Path:
    """A child JSONL whose session commits producer _UUID_A (run _RUN)."""
    session = _session_record(pid, block, extra={"worker_uuid": _UUID_A, "run_id": _RUN})
    return _write_jsonl(
        tmp_path / name,
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            session,
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )


def test_committed_unreadable_probe_defers_collect_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R5-2: committed-path deferral retains and never escapes."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5),
    )
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    real_read_text = Path.read_text

    def _eperm_probe(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == orphan.name:
            raise PermissionError("injected probe EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_probe)
    child = _committed_child(tmp_path, pid, _counts_block(10))
    with pytest.warns(UserWarning, match="deferred"):
        records = durability.collect_unit(
            tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
    assert records == []
    assert Path(planted["registry"]).exists()
    assert Path(planted["sidecar"]).exists()
    assert orphan.exists()


def test_committed_unreadable_probe_defers_barrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R5-2: barrier deferral skips the unit and releases the seal."""
    pid, birth = _dead_pid_with_birth()
    planted = _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(5),
    )
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", 0, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    real_read_text = Path.read_text

    def _eperm_probe(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == orphan.name:
            raise PermissionError("injected probe EPERM")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _eperm_probe)
    prior = _committed_child(tmp_path, pid, _counts_block(10), name="prior.jsonl")
    with pytest.warns(UserWarning, match="deferred"):
        plan = durability.prepare_resume(tmp_path, prior_merged_jsonl=prior)
    assert plan["barrier_ok"] is True
    assert plan["unresolved"] == [_UUID_A]
    assert plan["skipped_units"] == ["a.py"]
    assert not durability.is_sealed(tmp_path)
    assert Path(planted["registry"]).exists()
    assert orphan.exists()


def test_deferred_evidence_message_not_live(tmp_path: Path) -> None:
    """#88R8-5: an evidence skip never reports a running producer."""
    from io import StringIO

    from rich.console import Console

    from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

    pid, _ = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=424243,
        in_progress=_counts_block(5, fn="C_Login"),
    )
    marker_src = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 2]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    marker = marker_src.with_name(marker_src.name.replace("probe-", "probe-consumed-", 1))
    marker_src.rename(marker)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 2]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
        nonce="bead1234",
    )
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 2]]), pid=999)
    _plant_probe_tmp(orphan, _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 1, 2]]), pid=1000)
    with pytest.warns(UserWarning, match="deferred"):
        plan = durability.prepare_resume(tmp_path, prior_merged_jsonl=None)
    assert plan["skipped_units"] == ["a.py"]
    assert plan["skipped_live"] == []
    stream = StringIO()
    pending = _apply_counters_barrier_plan(
        tmp_path / "state.json", plan, ["a.py"], Console(file=stream, force_terminal=False)
    )
    assert pending == []
    text = " ".join(stream.getvalue().split())
    assert "still running" not in text
    assert "undecided" in text


def test_deferred_live_writer_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#88R8-5: a live-writer skip keeps the running-producer message."""
    from io import StringIO

    from rich.console import Console

    from pkcs11_check.core.file_runner import _apply_counters_barrier_plan

    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        monkeypatch.setattr(durability, "_terminate_verified", lambda *a: False)
        with pytest.warns(UserWarning, match="deferred"):
            plan = durability.prepare_resume(tmp_path, prior_merged_jsonl=None)
        assert plan["skipped_units"] == ["a.py"]
        assert plan["skipped_live"] == ["a.py"]
        stream = StringIO()
        pending = _apply_counters_barrier_plan(
            tmp_path / "state.json", plan, ["a.py"], Console(file=stream, force_terminal=False)
        )
        assert pending == []
        assert "still running" in " ".join(stream.getvalue().split())
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_dead_writer_without_birth_proceeds(tmp_path: Path) -> None:
    """#88R3F4: a proven-dead pid needs no birth token to collect."""
    pid, _ = _dead_pid_with_birth()
    planted = _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=pid,
        birth=None,
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["calls"] == 1
    assert not Path(planted["registry"]).exists()
    assert not orphan.exists()


def test_committed_path_never_fences_live_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R3F4: a live producer's probe is never fenced (no sabotage)."""
    proc = _live_sleeper()
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth,
        )
        signaled: list[tuple[int, int]] = []
        real_terminate = durability._terminate_verified

        def _spy(pid: int, birth: int, timeout: float) -> bool:
            signaled.append((pid, birth))
            return real_terminate(pid, birth, timeout)

        monkeypatch.setattr(durability, "_terminate_verified", _spy)
        child = _write_jsonl(
            tmp_path / "child.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(7),
                    extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        durability.collect_unit(
            tmp_path, unit="a.py", child_jsonl=child, status="passed", returncode=0
        )
        assert signaled == []
        assert proc.poll() is None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_recycled_probe_pid_proceeds(tmp_path: Path) -> None:
    """#88R3F4: a mismatched birth proves the writer dead (adopt)."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        birth = durability.birth_token_for_pid(proc.pid)
        if birth is None:
            pytest.skip("birth tokens unavailable on this platform")
        pid, _ = _dead_pid_with_birth()
        _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=424243)
        orphan = _plant_probe_orphan(
            tmp_path,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", None, 1]],
            identity=_f2_identity(_UUID_A),
            pid=proc.pid,
            birth=birth + 1,
        )
        records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
        partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
        assert len(partials) == 1
        assert partials[0]["total_calls"] == 1
        assert not orphan.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_probe_tmp_pid_mismatch_ignored(tmp_path: Path) -> None:
    """#88R3F4: a probe tmp from another incarnation never replays."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(tmp_path, uuid=_UUID_A, pid=pid, birth=birth)
    orphan = _plant_probe_orphan(
        tmp_path,
        parent_uuid=_UUID_A,
        seq=0,
        counters=[["m", "C_Digest", None, 1]],
        identity=_f2_identity(_UUID_A),
        pid=111111,
        birth=222222,
    )
    payload = _probe_tmp_payload(_UUID_B, 0, [["m", "C_Digest", 0, 1]])
    payload["pid"] = 333333
    payload["birth_token"] = 444444
    _plant_probe_tmp(orphan, payload)
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert _fn_leaf(partials[0], "C_Digest")["by_rv"] == {}


def test_complete_returns_omit_in_flight(tmp_path: Path) -> None:
    """#88: no missing return means no in_flight field at all."""
    pid, birth = _dead_pid_with_birth()
    _plant_producer(
        tmp_path,
        uuid=_UUID_A,
        pid=pid,
        birth=birth,
        in_progress=_counts_block(2, fn="C_Digest"),
    )
    records = _collect_crashed88(tmp_path, tmp_path / "child.jsonl")
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert "in_flight" not in partials[0]


_ISSUE88_VICTIM = '''"""Die inside record_return's sidecar rewrite (#88 durable repro)."""

import ctypes
import os
import sys

try:
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except (ImportError, OSError, ValueError):
    pass

from pkcs11_check.core import _counters_durability as durability
from pkcs11_check.core import call_counters


def _die():
    if sys.platform == "win32":
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel.TerminateProcess(kernel.GetCurrentProcess(), 0xC0000005)
    else:
        ctypes.string_at(0)


def _die_on_replace(src, dst):
    sys.stderr.write(f"HOOK: inside sidecar rewrite tmp_exists={os.path.exists(src)}\\n")
    sys.stderr.flush()
    _die()
    raise AssertionError("unreachable: survived the fatal hook")


call_counters.record_call("C_Digest", module="m")
info = call_counters.registration_info()
assert info is not None
sys.stderr.write(f"ENTRY-DURABLE sidecar={info['sidecar_path']}\\n")
sys.stderr.flush()
durability.os.replace = _die_on_replace
call_counters.record_return("C_Digest", 0, module="m")
sys.stderr.write("UNREACHABLE: survived record_return\\n")
'''


def test_sigsegv_in_rewrite_replays_return(tmp_path: Path) -> None:
    """#88 durable: death inside the rewrite still replays the return.

    A real subprocess records one call, then dies inside the return
    flush's os.replace (genuine SIGSEGV / access violation, no Python
    teardown). The committed sidecar stays pre-return while the orphan
    tmp holds the return; collection must adopt it: by_rv shows the
    CKR_OK, nothing is named in-flight, and no tmp survives.
    """
    counters = tmp_path / "counters"
    counters.mkdir()
    victim = tmp_path / "victim88.py"
    victim.write_text(_ISSUE88_VICTIM, encoding="utf-8")
    src_root = str(Path(durability.__file__).resolve().parents[2])
    env = dict(
        os.environ,
        PYTHONPATH=src_root + os.pathsep + os.environ.get("PYTHONPATH", ""),
        PKCS11_CHECK_COUNTERS_DIR=str(counters),
        PKCS11_CHECK_COUNTERS_UNIT="a.py",
        PKCS11_CHECK_COUNTERS_ATTEMPT="0",
        PKCS11_CHECK_COUNTERS_ROLE="unit",
        PKCS11_CHECK_RUN_ID="R1",
        PKCS11_CHECK_COUNTERS_FLUSH_K="1",
    )
    proc = subprocess.run(
        [sys.executable, str(victim)],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    if sys.platform == "win32":
        assert proc.returncode == 0xC0000005, proc
    else:
        assert proc.returncode == -signal.SIGSEGV, proc
    assert "ENTRY-DURABLE" in proc.stderr, proc.stderr
    assert "HOOK: inside sidecar rewrite tmp_exists=True" in proc.stderr, proc.stderr
    assert "UNREACHABLE" not in proc.stderr, proc.stderr
    sidecars = sorted(counters.glob("*.partial.json"))
    assert len(sidecars) == 1, [path.name for path in counters.iterdir()]
    committed = json.loads(sidecars[0].read_text(encoding="utf-8"))
    assert committed["in_progress"]["total_calls"] == 1
    committed_leaf = committed["in_progress"]["by_module"]["m"]["buckets"]["session_provisioning"][
        "by_fn"
    ]["C_Digest"]
    assert committed_leaf == {"calls": 1, "by_rv": {}}, committed_leaf
    orphans = sorted(counters.glob("*.tmp-*"))
    assert len(orphans) == 1, [path.name for path in counters.iterdir()]
    orphaned = json.loads(orphans[0].read_text(encoding="utf-8"))
    orphan_leaf = orphaned["in_progress"]["by_module"]["m"]["buckets"]["session_provisioning"][
        "by_fn"
    ]["C_Digest"]
    assert orphan_leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, orphan_leaf
    records = _collect_crashed88(counters, tmp_path / "child.jsonl", returncode=proc.returncode)
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    leaf = _fn_leaf(partials[0], "C_Digest")
    assert leaf["calls"] == 1, leaf
    assert leaf["by_rv"] == {"0": {"name": "CKR_OK", "count": 1}}, leaf
    assert _lost_returns(partials[0]) == 0
    assert "in_flight" not in partials[0]
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    assert list(counters.glob("*.tmp-*")) == []
    assert schema.is_sidecar_partial(partials[0]) is True


_ISSUE88_DIED_INSIDE_VICTIM = '''"""One default-module call, then die before its return (#88)."""

import ctypes
import os
import signal
import sys

from pkcs11_check.core import call_counters

call_counters.record_call("C_Digest")
info = call_counters.registration_info()
assert info is not None
sys.stderr.write(f"ENTRY-DURABLE sidecar={info['sidecar_path']}\\n")
sys.stderr.flush()
if sys.platform == "win32":
    kernel = ctypes.windll.kernel32
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel.TerminateProcess(kernel.GetCurrentProcess(), 0xC0000005)
else:
    os.kill(os.getpid(), signal.SIGKILL)
sys.stderr.write("UNREACHABLE: survived the kill\\n")
'''


def test_sigkill_after_entry_names_unknown_module_row(tmp_path: Path) -> None:
    """#88R4 durable: died-inside with the default module names its row.

    A real subprocess records one call under the default (unknown)
    module, flushes it (K=1), then dies before the return: no orphan
    tmp exists, so the committed entry-without-RV must surface as an
    in-flight row carrying the "" module sentinel.
    """
    counters = tmp_path / "counters"
    counters.mkdir()
    victim = tmp_path / "victim88b.py"
    victim.write_text(_ISSUE88_DIED_INSIDE_VICTIM, encoding="utf-8")
    src_root = str(Path(durability.__file__).resolve().parents[2])
    env = dict(
        os.environ,
        PYTHONPATH=src_root + os.pathsep + os.environ.get("PYTHONPATH", ""),
        PKCS11_CHECK_COUNTERS_DIR=str(counters),
        PKCS11_CHECK_COUNTERS_UNIT="a.py",
        PKCS11_CHECK_COUNTERS_ATTEMPT="0",
        PKCS11_CHECK_COUNTERS_ROLE="unit",
        PKCS11_CHECK_RUN_ID="R1",
        PKCS11_CHECK_COUNTERS_FLUSH_K="1",
    )
    proc = subprocess.run(
        [sys.executable, str(victim)],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    if sys.platform == "win32":
        assert proc.returncode == 0xC0000005, proc
    else:
        assert proc.returncode == -signal.SIGKILL, proc
    assert "ENTRY-DURABLE" in proc.stderr, proc.stderr
    assert "UNREACHABLE" not in proc.stderr, proc.stderr
    assert list(counters.glob("*.tmp-*")) == []
    records = _collect_crashed88(counters, tmp_path / "child.jsonl", returncode=proc.returncode)
    partials = [rec for rec in records if rec["$report_type"] == "CallCountersPartial"]
    assert len(partials) == 1
    assert partials[0]["total_calls"] == 1
    assert partials[0]["in_flight"] == [
        {"module": "", "bucket": "session_provisioning", "fn": "C_Digest", "count": 1}
    ]
    assert schema.is_sidecar_partial(partials[0]) is True


def _fault_stat_once(
    monkeypatch: pytest.MonkeyPatch, target: Path, *, at_call: int = 1
) -> list[str]:
    """Fail one os.stat of ``target`` with EACCES, then behave (deterministic).

    Simulates a transient stat fault (perms flap, AV lock) at exactly
    one lookup: the faulted call raises the real PermissionError and
    every other stat behaves normally. ``at_call`` selects which
    matching stat faults (1-based; single-threaded tests make the
    order deterministic). Returns the fired list (assert it fired).
    """
    real_stat = os.stat
    fired: list[str] = []
    seen = 0

    def _flaky_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal seen
        if str(path) == str(target):
            seen += 1
            if seen == at_call:
                fired.append(str(target))
                raise PermissionError(errno.EACCES, "injected stat fault", str(target))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _flaky_stat)
    return fired


class TestStatFaultTolerance:
    """#88R24-1: stat faults fail closed, identically on every interpreter."""

    def test_path_state_distinguishes_all_three(self, tmp_path: Path) -> None:
        present = tmp_path / "present.json"
        present.write_text("{}", encoding="utf-8")
        assert durability._path_state(present) == "present"
        assert durability._path_state(tmp_path / "absent.json") == "missing"
        locked = tmp_path / "locked"
        locked.mkdir()
        target = locked / "file.json"
        target.write_text("{}", encoding="utf-8")
        locked.chmod(0o000)
        try:
            assert durability._path_state(target) == "unreadable"
        finally:
            locked.chmod(0o755)

    def test_unreadable_seal_reads_sealed(self, tmp_path: Path) -> None:
        """#88R24-1: a seal that cannot be proven absent blocks admission."""
        root = tmp_path / "counters"
        (root / "registrations").mkdir(parents=True)
        root.chmod(0o000)
        try:
            assert durability.is_sealed(root) is True
        finally:
            root.chmod(0o755)

    def test_seal_fault_falls_through_to_exclusive_create(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: a faulted seal lookup defers to O_EXCL, never raw."""
        root = tmp_path / "counters"
        (root / "registrations").mkdir(parents=True)
        seal_path = durability.seal(root, reason="test")
        fired = _fault_stat_once(monkeypatch, seal_path)
        assert durability.seal(root, reason="test") == seal_path
        assert fired, "the fault must hit the seal lookup"

    def test_finalize_unreadable_marker_skips_recorded(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: an unreadable marker withholds loudly, never bare-skips."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        msrc = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = msrc.with_name(msrc.name.replace("probe-", "probe-consumed-", 1))
        msrc.rename(marker)
        slot = engaged / f"probe-{_UUID_A[:8]}-0-feedface.json"
        baseline = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        assert baseline == slot
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        fired = _fault_stat_once(monkeypatch, marker)
        with pytest.warns(UserWarning, match="later pass"):
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert fired, "the fault must hit the marker lookup"
        assert marker.exists(), "an unreadable marker is retained, not skipped past"
        assert Path(planted["registry"]).exists(), "the parent waits out the fault"

    def test_spawn_consume_unreadable_slot_retains(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: a spawn file is never consumed through an unreadable slot."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        assert not slot.exists()
        dead_pid, dead_birth = _dead_pid_with_birth()
        entry: dict[str, Any] = {"probe_seq": 1, "slot": str(slot), "pid": dead_pid}
        if dead_birth is not None:
            entry["birth_token"] = dead_birth
        spawn = engaged / "spawn-aaaaaaaa-1-bead01.json"
        spawn.write_text(json.dumps({"parent_uuid": _UUID_A, **entry}), encoding="utf-8")
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        # First slot stat (the outstanding check) reads missing cleanly
        # so the pass proceeds; the reunion-consumption stat faults.
        fired = _fault_stat_once(monkeypatch, slot, at_call=2)
        with pytest.warns(UserWarning, match="later pass"):
            durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert fired, "the fault must hit the consumption lookup"
        assert spawn.exists(), "no reunion through an unreadable slot"

    def test_outstanding_unreadable_slot_defers(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: an unreadable slot is outstanding, never absorbed."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        slot = engaged / "probe-aaaaaaaa-1-00000000.json"
        dead_pid, dead_birth = _dead_pid_with_birth()
        sidecar_path = Path(planted["sidecar"])
        payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
        record: dict[str, Any] = {"probe_seq": 1, "slot": str(slot), "pid": dead_pid}
        if dead_birth is not None:
            record["birth_token"] = dead_birth
        payload["spawned_children"] = [record]
        sidecar_path.write_text(json.dumps(payload), encoding="utf-8")
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        fired = _fault_stat_once(monkeypatch, slot)
        with pytest.warns(UserWarning, match="unflushed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert fired, "the fault must hit the outstanding check"
        assert records == []
        assert Path(planted["registry"]).exists()

    def test_known_uuids_unreadable_dir_warns_empty(self, tmp_path: Path) -> None:
        """#88R24-1: an unreadable registry dir yields no uuids, loudly."""
        root = tmp_path / "counters"
        reg_dir = root / "registrations"
        reg_dir.mkdir(parents=True)
        (reg_dir / "x.json").write_text("{}", encoding="utf-8")
        root.chmod(0o000)
        try:
            with pytest.warns(UserWarning, match="unreadable"):
                uuids, complete = durability._known_producer_uuids(root)
                assert uuids == set()
                assert complete is False
        finally:
            root.chmod(0o755)

    def test_collect_counters_dir_unreadable_retains_all(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R24-1: an unreadable counters dir defers the whole collect."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        engaged.chmod(0o000)
        try:
            with pytest.warns(UserWarning, match="unreadable"):
                records = durability.collect_unit(
                    engaged,
                    unit="a.py",
                    child_jsonl=child,
                    status="crashed",
                    returncode=-11,
                )
        finally:
            engaged.chmod(0o755)
        assert records == []
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_collect_unreadable_child_jsonl_degrades_loudly(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        """#88R24-1: an unreadable child routes to the loud-retain path."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=birth,
            in_progress=_counts_block(5),
        )
        reports = tmp_path / "reports"
        reports.mkdir()
        child = reports / "child.jsonl"
        child.write_text("", encoding="utf-8")
        reports.chmod(0o000)
        try:
            with pytest.warns(UserWarning, match="unreadable"):
                records = durability.collect_unit(
                    engaged,
                    unit="a.py",
                    child_jsonl=child,
                    status="crashed",
                    returncode=-11,
                )
        finally:
            reports.chmod(0o755)
        assert Path(planted["registry"]).exists()
        assert all(rec.get("$report_type") != "CallCountersPartial" for rec in records)

    def test_consume_unreadable_listed_holds(self, tmp_path: Path) -> None:
        """#88R24-1: an unverifiable cleanup target holds, never deletes."""
        import hashlib

        target = tmp_path / "locked" / "victim.partial.json"
        target.parent.mkdir(parents=True)
        target.write_text("{}", encoding="utf-8")
        digest = hashlib.sha256(b"{}").hexdigest()
        target.parent.chmod(0o000)
        try:
            with pytest.warns(UserWarning, match="held"):
                held = durability._consume_producer_files([target], {str(target): digest})
        finally:
            target.parent.chmod(0o755)
        assert held == [target]
        assert target.exists()

    def test_consume_unreadable_unlisted_holds(self, tmp_path: Path) -> None:
        """#88R24-1: an unprovable-gone target holds instead of escaping."""
        target = tmp_path / "locked" / "victim.windows.jsonl"
        target.parent.mkdir(parents=True)
        target.write_text("{}", encoding="utf-8")
        target.parent.chmod(0o000)
        try:
            with pytest.warns(UserWarning):
                held = durability._consume_producer_files([target], {})
        finally:
            target.parent.chmod(0o755)
        assert held == [target]
        assert target.exists()

    def test_sweep_unreadable_reg_dir_warns_zeros(self, tmp_path: Path) -> None:
        """#88R24-1: the sweep never raises on an unreadable registry dir."""
        root = tmp_path / "counters"
        (root / "registrations").mkdir(parents=True)
        root.chmod(0o000)
        try:
            with pytest.warns(UserWarning, match="unreadable"):
                assert durability.sweep_orphans(root, current_run="R1") == {
                    "removed": 0,
                    "retained": 0,
                }
        finally:
            root.chmod(0o755)

    def test_sweep_unreadable_sidecar_counts_retained(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: retention counts stay truthful through stat faults."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        sidecar = Path(planted["sidecar"])
        fired = _fault_stat_once(monkeypatch, sidecar)
        with pytest.warns(UserWarning):
            swept = durability.sweep_orphans(engaged, current_run="R1")
        assert fired
        assert swept["removed"] == 0
        assert swept["retained"] == 2

    def test_sweep_journal_shield_holds_on_fault(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: an unreadable registry still shields its orphan journal."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        reg_path = Path(planted["registry"])
        journal = Path(planted["journal"])
        journal.write_text("", encoding="utf-8")
        Path(planted["sidecar"]).unlink()
        fired = _fault_stat_once(monkeypatch, reg_path)
        with pytest.warns(UserWarning):
            swept = durability.sweep_orphans(engaged, current_run="R1")
        assert fired
        assert swept["removed"] == 0
        assert journal.exists()

    def test_sweep_registry_shield_holds_on_fault(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: an unreadable registry still shields its sidecar."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        reg_path = Path(planted["registry"])
        sidecar = Path(planted["sidecar"])
        fired = _fault_stat_once(monkeypatch, reg_path)
        with pytest.warns(UserWarning):
            swept = durability.sweep_orphans(engaged, current_run="R1")
        assert fired
        assert swept["removed"] == 0
        assert sidecar.exists()

    def test_sweep_torn_registry_readable_sidecar_shields_on_fault(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: the torn-registry shield path fails closed on faults."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        reg_path = Path(planted["registry"])
        reg_path.write_text("{torn", encoding="utf-8")
        sidecar = Path(planted["sidecar"])
        fired = _fault_stat_once(monkeypatch, reg_path)
        with pytest.warns(UserWarning):
            swept = durability.sweep_orphans(engaged, current_run="R1")
        assert fired
        assert swept["removed"] == 0
        assert sidecar.exists()

    def test_sweep_tmp_precheck_fault_counts_survivors(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: a faulted tmp check holds its primaries, counted."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        sidecar = Path(planted["sidecar"])
        Path(planted["journal"]).write_text("", encoding="utf-8")
        tmp = sidecar.with_name(f"{sidecar.name}.tmp-999")
        tmp.write_text("{}", encoding="utf-8")
        fired = _fault_stat_once(monkeypatch, tmp)
        with pytest.warns(UserWarning):
            swept = durability.sweep_orphans(
                engaged, current_run="R1", committed_uuids=frozenset({_UUID_A})
            )
        assert fired
        assert swept["removed"] == 0
        assert swept["retained"] == 4
        assert sidecar.exists() and tmp.exists()

    def test_resume_unreadable_staging_refuses_loudly(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: unreadable barrier memory fails the barrier, released."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        staging = engaged / durability.BARRIER_STAGING_FILENAME
        staging.write_text("{}", encoding="utf-8")
        fired = _fault_stat_once(monkeypatch, staging)
        with pytest.warns(UserWarning, match="staged|barrier"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert fired, "the fault must hit the staging lookup"
        assert plan["barrier_ok"] is False
        assert durability.is_sealed(engaged) is False, "no stuck seal on refusal"
        assert Path(planted["registry"]).exists()

    def test_resume_unreadable_prior_refuses(self, engaged: Path, tmp_path: Path) -> None:
        """#88R25-1: an unreadable prior refuses (empty misreads heal losses)."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        reports = tmp_path / "reports"
        reports.mkdir()
        prior = reports / "merged.jsonl"
        prior.write_text("", encoding="utf-8")
        reports.chmod(0o000)
        try:
            with pytest.warns(UserWarning, match="cannot read prior"):
                plan = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        finally:
            reports.chmod(0o755)
        assert plan["barrier_ok"] is False
        assert durability.is_sealed(engaged) is False
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_resume_prior_stat_flap_keeps_authority(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-1: a flapped prior stat never empties authority (the read decides)."""
        pid, birth = _dead_pid_with_birth()
        _plant_producer(engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5))
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(5),
                    extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        fired = _fault_stat_once(monkeypatch, prior, at_call=1)
        plan = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        assert fired, "the fault must hit the prior lookup"
        assert plan["barrier_ok"] is True
        assert plan["cache_records"] == {}, "committed authority suppresses re-emit"

    def test_resume_prior_read_fault_refuses(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R26-1: a prior that stats present but reads faulted refuses once."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(5)
        )
        prior = _write_jsonl(
            tmp_path / "prior.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(
                    pid,
                    _counts_block(5),
                    extra={"worker_uuid": _UUID_A, "run_id": _RUN},
                ),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        real_read = durability._read_jsonl_lines
        calls: list[str] = []

        def _flaky_read(path: Path) -> Any:
            if str(path) == str(prior):
                calls.append(str(path))
                return None
            return real_read(path)

        monkeypatch.setattr(durability, "_read_jsonl_lines", _flaky_read)
        with pytest.warns(UserWarning, match="cannot read prior"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=prior)
        assert calls == [str(prior)], "the prior reads once, from one snapshot"
        assert plan["barrier_ok"] is False
        assert durability.is_sealed(engaged) is False
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_supplements_unreadable_tail_returns_false(self, tmp_path: Path) -> None:
        """#88R24-1: an unreadable supplements file fails the append loudly."""
        locked = tmp_path / "locked"
        locked.mkdir()
        state = locked / "state.json"
        state.write_text("{}", encoding="utf-8")
        locked.chmod(0o000)
        try:
            with pytest.warns(UserWarning):
                ok = durability.append_supplement_records(
                    state, "a.py", [{"$report_type": "CallCountersPartial"}]
                )
        finally:
            locked.chmod(0o755)
        assert ok is False

    def test_list_evidence_files_distinguishes_faults(self, tmp_path: Path) -> None:
        """#88R24-1: evidence listing reports faults instead of empty."""
        root = tmp_path / "counters"
        root.mkdir()
        (root / "probe-aaaaaaaa-0-nonce.json").write_text("{}", encoding="utf-8")
        (root / "spawn-aaaaaaaa-0-bead01.json").write_text("{}", encoding="utf-8")
        (root / "other.txt").write_text("{}", encoding="utf-8")
        assert [path.name for path in durability._list_evidence_files(root, "probe-", ".json")] == [
            "probe-aaaaaaaa-0-nonce.json"
        ]
        assert [path.name for path in durability._list_evidence_files(root, "spawn-", ".json")] == [
            "spawn-aaaaaaaa-0-bead01.json"
        ]
        assert durability._list_evidence_files(root / "absent", "probe-", ".json") == []
        root.chmod(0o000)
        try:
            assert durability._list_evidence_files(root, "probe-", ".json") is None
        finally:
            root.chmod(0o755)

    def test_orphan_listing_fault_defers(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1: an unlistable orphan dir defers, never silently misses."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        orphan = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[["m", "C_Digest", 0, 1]],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        real_list = durability._list_evidence_files
        calls = 0

        def _fault_once(directory: Path, prefix: str, suffix: str) -> Any:
            nonlocal calls
            calls += 1
            if prefix == "probe-":
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_once)
        with pytest.warns(UserWarning, match="listing failed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert calls >= 1
        assert records == []
        assert Path(planted["registry"]).exists()
        assert orphan.exists()

    @pytest.mark.parametrize("fault_at_call", [1, 2])
    def test_marker_listing_fault_defers(
        self,
        engaged: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fault_at_call: int,
    ) -> None:
        """#88R25-2: an unlistable marker dir defers (prescan and loop)."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        rows = [["m", "C_Digest", 0, 1]]
        msrc = _plant_probe_orphan(
            engaged,
            parent_uuid=_UUID_A,
            seq=0,
            counters=[list(row) for row in rows],
            identity=_f2_identity(_UUID_A),
            pid=pid,
            birth=None,
        )
        marker = msrc.with_name(msrc.name.replace("probe-", "probe-consumed-", 1))
        msrc.rename(marker)
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        real_list = durability._list_evidence_files
        calls = 0

        def _fault_once(directory: Path, prefix: str, suffix: str) -> Any:
            nonlocal calls
            if prefix != "probe-consumed-":
                return real_list(directory, prefix, suffix)
            calls += 1
            if calls == fault_at_call:
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_once)
        with pytest.warns(UserWarning, match="listing failed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert calls >= fault_at_call
        assert records == []
        assert marker.exists()
        assert Path(planted["registry"]).exists()

    def test_registry_listing_fault_refuses_barrier_credit(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R25-3: an unlistable registry grants no run-wide authority."""
        pid_a, _ = _dead_pid_with_birth()
        _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid_a,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        pid_b, birth_b = _dead_pid_with_birth()
        planted_b = _plant_producer(
            engaged,
            uuid=_UUID_B,
            pid=pid_b,
            birth=birth_b,
            in_progress=_counts_block(4, fn="C_Digest"),
        )
        Path(planted_b["registry"]).unlink()
        real_list = durability._list_evidence_files
        faulted: list[str] = []

        def _fault_listings(directory: Path, prefix: str, suffix: str) -> Any:
            if directory.name == "registrations":
                faulted.append("registries")
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_listings)
        with pytest.warns(UserWarning, match="listing failed|unlistable|refus"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert faulted
        assert plan["barrier_ok"] is False
        assert plan["collected_runs"] == []
        assert durability.is_sealed(engaged) is False

    def test_collect_registry_listing_fault_defers_all(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R25-3: unit collection degrades loudly on listing faults."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        real_list = durability._list_evidence_files
        faulted: list[str] = []

        def _fault_listings(directory: Path, prefix: str, suffix: str) -> Any:
            if directory.name == "registrations":
                faulted.append("registries")
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_listings)
        with pytest.warns(UserWarning, match="listing failed|unlistable|deferred"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert faulted
        assert records == []
        assert Path(planted["registry"]).exists()

    def test_collect_sidecar_listing_fault_skips_loop(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R25-3: unit collection skips an unlistable sidecar loop loudly."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        pid_b, birth_b = _dead_pid_with_birth()
        planted_b = _plant_producer(
            engaged,
            uuid=_UUID_B,
            pid=pid_b,
            birth=birth_b,
            in_progress=_counts_block(4),
        )
        Path(planted_b["registry"]).unlink()
        orphan_sidecar = Path(planted_b["sidecar"])
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        real_list = durability._list_evidence_files
        faulted: list[str] = []

        def _fault_listings(directory: Path, prefix: str, suffix: str) -> Any:
            if suffix == ".partial.json":
                faulted.append("sidecars")
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_listings)
        with pytest.warns(UserWarning, match="unlistable"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert faulted
        assert any(rec.get("$report_type") == "CallCountersPartial" for rec in records)
        assert not Path(planted["registry"]).exists(), "registry loop still converges"
        assert orphan_sidecar.exists(), "unlisted sidecars wait for a later pass"

    def test_resume_sidecar_listing_fault_refuses(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R25-3: the barrier refuses when sidecars cannot be inventoried."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )
        real_list = durability._list_evidence_files
        faulted: list[str] = []

        def _fault_listings(directory: Path, prefix: str, suffix: str) -> Any:
            if suffix == ".partial.json":
                faulted.append("sidecars")
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_listings)
        with pytest.warns(UserWarning, match="unlistable|cannot list"):
            plan = durability.prepare_resume(engaged, prior_merged_jsonl=None)
        assert faulted
        assert plan["barrier_ok"] is False
        assert durability.is_sealed(engaged) is False
        assert Path(planted["registry"]).exists()

    def test_sweep_listing_fault_deletes_nothing(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R25-3: the sweep never deletes through an unlistable dir."""
        pid, birth = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged, uuid=_UUID_A, pid=pid, birth=birth, in_progress=_counts_block(2)
        )

        def _fault_all(directory: Path, prefix: str, suffix: str) -> Any:
            return None

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_all)
        with pytest.warns(UserWarning):
            swept = durability.sweep_orphans(
                engaged, current_run="R1", committed_uuids=frozenset({_UUID_A})
            )
        assert swept["removed"] == 0
        assert Path(planted["registry"]).exists()
        assert Path(planted["sidecar"]).exists()

    def test_spawn_listing_fault_defers(
        self, engaged: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#88R24-1/2: an unlistable spawn dir defers, never hides launches."""
        pid, _ = _dead_pid_with_birth()
        planted = _plant_producer(
            engaged,
            uuid=_UUID_A,
            pid=pid,
            birth=424243,
            in_progress=_counts_block(2, fn="C_Digest"),
        )
        child = tmp_path / "child.jsonl"
        child.write_text("", encoding="utf-8")
        real_list = durability._list_evidence_files
        calls = 0

        def _fault_once(directory: Path, prefix: str, suffix: str) -> Any:
            nonlocal calls
            calls += 1
            if prefix == "spawn-":
                return None
            return real_list(directory, prefix, suffix)

        monkeypatch.setattr(durability, "_list_evidence_files", _fault_once)
        with pytest.warns(UserWarning, match="listing failed"):
            records = durability.collect_unit(
                engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-11
            )
        assert calls >= 1
        assert records == []
        assert Path(planted["registry"]).exists()
