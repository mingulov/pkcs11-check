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

    def test_probe_sidecar_with_wrong_seq_is_not_evidence(
        self, engaged: Path, tmp_path: Path
    ) -> None:
        from pkcs11_check.testcases._probes.runner import ingest_probe_payload

        seq = call_counters.assign_probe_seq()
        cov = tmp_path / "cov.json"
        cov.write_text('{"call_log": ', encoding="utf-8")
        sidecar = tmp_path / "probe-2.json"
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
        assert ingest_probe_payload(cov, seq=seq, sidecar_path=sidecar) == "lost"
        assert call_counters.serialize_current()["total_calls"] == 0
        assert not sidecar.exists()

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
        merged, claimed, consumed, recovered, orphan_keys, adopted = (
            durability._adopt_probe_orphans(
                engaged,
                worker_uuid=parent_uuid,
                sidecar=parent_sidecar,
                journal_lines=[],
                claims={},
                known_uuids={parent_uuid},
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
        merged, claimed, consumed, recovered, orphan_keys, adopted = (
            durability._adopt_probe_orphans(
                engaged,
                worker_uuid=_UUID_A,
                sidecar=None,
                journal_lines=[],
                claims={},
                known_uuids={_UUID_A},
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

    def test_double_apply_folds_identically(self, tmp_path: Path) -> None:
        """Guard: whole-plan re-apply is absorbed by extractor dedup."""
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
        _apply_counters_barrier_plan(state_file, plan, ["a.py"], console)
        twice = (
            durability.supplements_path(state_file, "a.py").read_text(encoding="utf-8").splitlines()
        )
        assert len(twice) == 2 * len(once)
        assert not (root / durability.BARRIER_STAGING_FILENAME).exists()

        def _fold(line_count: int) -> dict[str, Any]:
            stream = [{"$report_type": "SessionStart"}, _marker("a.py", 0)]
            stream.extend(json.loads(line) for line in twice[:line_count])
            payload = extract_call_counters_from_jsonl(
                _write_jsonl(tmp_path / f"fold-{line_count}.jsonl", stream)
            )
            assert payload is not None
            return payload

        single, double = _fold(len(once)), _fold(len(twice))
        assert double["total_calls"] == single["total_calls"]
        assert double["complete"] == single["complete"]
        assert double["lost_processes"] == single["lost_processes"]

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
        assert durability.is_sealed(root) is True, "failed barrier stays sealed for retry"

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
        from types import SimpleNamespace

        from pkcs11_check.testcases._probes.runner import run_probe

        # Codex 6.2 F1: a commit failure must not skip the keyed loss
        # note the success path records -- note, then re-raise, so the
        # killed probe's unflushed tail can never read complete.
        seen_seq: list[int] = []

        def _killed(*args: Any, **kwargs: Any) -> Any:
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
            return SimpleNamespace(returncode=-9, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _killed)
        monkeypatch.setattr(call_counters, "write_sidecar_atomic", _broken_writer)
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
        merged, claimed, consumed, recovered, orphan_keys, adopted = (
            durability._adopt_probe_orphans(
                engaged,
                worker_uuid=_UUID_A,
                sidecar=sidecar,
                journal_lines=[],
                claims={},
                known_uuids={_UUID_A},
                producer_run=_RUN,
                producer_unit="a.py",
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

        def _flaky_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
            if failing[0] and self == Path(planted["registry"]):
                raise OSError("transient read failure")
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _flaky_read_text)
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
                "isolation": "a b",
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
        assert " " in child.read_text(encoding="utf-8"), "literal U+2028 on disk"
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

        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise OSError("no spawn")

        monkeypatch.setattr(subprocess, "run", _boom)
        with pytest.raises(OSError, match="no spawn"):
            run_probe("_echo", {"module_path": "/x.so"})
        # The parent registered before the (failed) spawn: a child that
        # dies instantly still leaves attributable evidence.
        assert list((engaged / "registrations").glob("*.json")) != []

    def test_run_probe_sealed_fails_before_spawn(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from pkcs11_check.testcases._probes.runner import run_probe

        durability.seal(engaged, reason="test")
        calls: list[Any] = []

        def _spy(*args: Any, **kwargs: Any) -> Any:
            calls.append(1)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _spy)
        with pytest.raises(durability.CounterPersistenceError):
            run_probe("_echo", {"module_path": "/x.so"})
        assert calls == [], "sealed probes never spawn (fail fast, no phantom traffic)"

    def test_run_probe_strips_ambient_probe_context_when_disengaged(
        self, disengaged: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

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

        def _capture(*args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs.get("env", {}))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _capture)
        result = run_probe("_echo", {"module_path": "/x.so"})
        assert result.returncode == 0
        for key in f2_keys:
            assert key not in seen, "ambient probe context never leaks (H gap pin)"

    def test_run_probe_child_inherits_flush_k(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from pkcs11_check.testcases._probes.runner import run_probe

        # Cadence policy inherits: the child batches (or not) exactly
        # like its parent run (default 1 when unset anywhere).
        monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "9")
        seen: dict[str, str] = {}

        def _capture(*args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs.get("env", {}))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _capture)
        run_probe("_echo", {"module_path": "/x.so"})
        assert seen[durability.COUNTERS_FLUSH_K_ENV] == "9"

    def test_run_probe_exports_parent_context(
        self, engaged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from pkcs11_check.testcases._probes.runner import run_probe

        monkeypatch.setenv(call_counters.ISOLATION_ENV, "file")
        seen: dict[str, str] = {}

        def _capture(*args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs.get("env", {}))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _capture)
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
        real_read = durability._read_probe_orphan
        planted: list[bool] = []

        def _planting_read(path: Path) -> Any:
            if not planted:
                planted.append(True)
                _plant_probe_orphan(engaged, parent_uuid=parent, seq=1)
            return real_read(path)

        monkeypatch.setattr(durability, "_read_probe_orphan", _planting_read)
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
