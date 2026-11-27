"""Flush-cadence knob (K): opt-in batching for speed-sensitive runs.

`PKCS11_CHECK_COUNTERS_FLUSH_K` sets how many evidence units accumulate
before the sidecar snapshot persists. Unset (or garbage, with a loud
one-per-process warning) means 1: every unit persists immediately, the
0.3.0 exactness default. K counts evidence units -- entries, returns,
and zero-call mutations each add one; ingests add their row counts --
not completed PKCS#11 calls: a crash can lose up to the last K-1
unflushed units of sidecar tail (counts and key detail alike), always
flagged incomplete by the producer's death. Boundary, exit, probe
flush-before-delete, and persistence-recovery flushes stay
unconditional at any K.
"""

from __future__ import annotations

import json
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core import _counters_durability as durability
from pkcs11_check.core import call_counters


@pytest.fixture
def engaged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    call_counters.reset_for_tests()
    root = tmp_path / "counters"
    monkeypatch.setenv(durability.COUNTERS_DIR_ENV, str(root))
    monkeypatch.setenv(durability.COUNTERS_UNIT_ENV, "a.py")
    monkeypatch.setenv(durability.COUNTERS_ATTEMPT_ENV, "0")
    monkeypatch.setenv(durability.COUNTERS_ROLE_ENV, "unit")
    monkeypatch.setenv(call_counters.RUN_ID_ENV, "R1")
    yield root
    call_counters.reset_for_tests()
    monkeypatch.undo()


def _sidecar_or_none() -> dict[str, Any] | None:
    info = call_counters.registration_info()
    if info is None:
        return None
    path = Path(info["sidecar_path"])
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def test_default_k_is_twenty(engaged: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The default resolves with the variable genuinely absent (the
    # conftest pin would otherwise mask it).
    monkeypatch.delenv(durability.COUNTERS_FLUSH_K_ENV, raising=False)
    call_counters.reset_for_tests()
    assert call_counters.effective_flush_k() == 20


def test_explicit_k_parses(engaged: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "25")
    call_counters.reset_for_tests()
    assert call_counters.effective_flush_k() == 25


@pytest.mark.parametrize("garbage", ["bogus", "0", "-3", "2.5"])
def test_garbage_k_warns_once_and_defaults(
    engaged: Path, monkeypatch: pytest.MonkeyPatch, garbage: str
) -> None:
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, garbage)
    call_counters.reset_for_tests()
    with pytest.warns(UserWarning, match="FLUSH_K"):
        assert call_counters.effective_flush_k() == 1
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert call_counters.effective_flush_k() == 1


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_k_is_silent_default(
    engaged: Path, monkeypatch: pytest.MonkeyPatch, blank: str
) -> None:
    # Blank reads as unset (the durability_dir convention), never a warning.
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, blank)
    call_counters.reset_for_tests()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert call_counters.effective_flush_k() == 20


def test_garbage_k_under_warnings_error_never_phantoms(
    engaged: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Codex R1: under -W error the garbage diagnostic raises. It must
    # raise BEFORE admission (cadence resolves in _ensure), so repeated
    # calls keep failing loudly with zero admitted counts, zero
    # registration, and no provider execution -- never phantoms.
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "bogus")
    call_counters.reset_for_tests()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for _ in range(3):
            with pytest.raises(UserWarning, match="FLUSH_K"):
                call_counters.record_call("C_Login", module="m")
    assert call_counters.serialize_current()["total_calls"] == 0
    assert call_counters.registration_info() is None
    assert list(engaged.glob("registrations/*.json")) == []


def test_k3_flushes_every_third_unit(engaged: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "3")
    call_counters.reset_for_tests()
    call_counters.record_call("C_Login", module="m")
    assert _sidecar_or_none() is None
    call_counters.record_call("C_Login", module="m")
    assert _sidecar_or_none() is None
    call_counters.record_call("C_Login", module="m")
    snap = _sidecar_or_none()
    assert snap is not None
    assert snap["in_progress"]["total_calls"] == 3


def test_no_snapshot_before_k_dies_loud(
    engaged: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl

    # K=100 with 5 recorded units: no sidecar exists (the tail is
    # memory-only). A dead producer in exactly this state yields a
    # lost record and incomplete -- never silent exactness, and no
    # partial is owed (nothing recoverable was ever persisted).
    monkeypatch.setenv(durability.COUNTERS_FLUSH_K_ENV, "100")
    call_counters.reset_for_tests()
    for _ in range(5):
        call_counters.record_call("C_Login", module="m")
    assert _sidecar_or_none() is None
    # An impossible pid is verifiably dead on every platform. A real
    # spawn-and-reap pid registered post-mortem (birth 0) is
    # reuse-blind: if Windows recycles it to an unopenable process
    # before collection, the verdict degrades to unknown and the
    # producer skips silently (smoke-windows flake).
    dead_pid = 2**31 - 1
    worker = "d" * 32
    durability.register_worker(
        engaged,
        run_id="R1",
        unit="a.py",
        attempt=0,
        role="unit",
        isolation="file",
        worker_uuid=worker,
        pid=dead_pid,
    )
    child = tmp_path / "child.jsonl"
    child.write_text(
        "".join(
            json.dumps(rec) + "\n"
            for rec in [
                {"$report_type": "SessionStart"},
                {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            ]
        ),
        encoding="utf-8",
    )
    records = durability.collect_unit(
        engaged, unit="a.py", child_jsonl=child, status="crashed", returncode=-9
    )
    assert [rec for rec in records if rec["$report_type"] == "CallCountersPartial"] == []
    lost = [rec for rec in records if rec["$report_type"] == "CallCountersLost"]
    assert len(lost) == 1
    payload = extract_call_counters_from_jsonl(child)
    assert payload is not None
    assert payload["complete"] is False
    assert payload["total_calls"] == 0
