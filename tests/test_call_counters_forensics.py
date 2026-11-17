"""Task-0 forensics gate: dead-end disposition mapping for the rc2 counter gaps (plan v8).

No src behavior change in this task: these tests pin what the REAL runner
collection + counter extractor do today on the two evidence-death paths, and
record the paired exact-or-named-or-partial acceptance that Task 3 (durability)
must turn green:

- GREEN characterization: a SIGKILLed stub mid-first-test yields the zero-record
  shape (C2 empty group, ``complete: false``, dead pid unnamed); a recovery
  requeue drops the first attempt's counters (archived-but-opaque, rerun only).
- RED acceptance (``strict=False`` xfail): the XOR from codex R7 — fully
  recovered exact counts, or partial counts plus an identity-bearing
  loss/truncated disposition, or zero recoverable plus an identity-bearing
  loss; counts exactly once; an unrecovered tail forces incomplete.

A counting fake module stands in for the provider: every stub call lands in an
oracle file (independent provider-side evidence) AND in the fw#73 counting
layer, so the acceptance compares extraction against ground truth.
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core._report_records import (
    _ISOLATED_UNIT_REPORT_TYPE,
    _report_record_cache_path,
    _write_report_jsonl_from_record_sources,
    _write_unit_report_record_cache_from_jsonl_paths,
)
from pkcs11_check.core._run_state import load_run_state, save_run_state
from pkcs11_check.core._run_units import FileRunState
from pkcs11_check.core.call_counters import (
    CALL_COUNTERS_PROPERTY,
    CALL_COUNTERS_REPORT_TYPE,
)
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    RunnerGranularity,
    _append_process_observation,
    run_isolated_pytest_units,
)
from pkcs11_check.core.recovery import RecoveryConfig
from pkcs11_check.core.report_log import iter_report_log_records

# Five calls through the counting fake module before the stub dies mid-first-test.
_KILL_PLAN: tuple[tuple[str, int], ...] = (
    ("C_Initialize", 0),
    ("C_GetSlotList", 0),
    ("C_OpenSession", 0),
    ("C_Login", 0),
    ("C_GetTokenInfo", 0),
)

# First attempt (dropped by the recovery requeue) vs rerun (kept) call plans.
_DROP_PLAN: tuple[tuple[str, int], ...] = (
    ("C_Initialize", 0),
    ("C_OpenSession", 0),
    ("C_Login", 0),
    ("C_FindObjectsInit", 0),
)
_RERUN_PLAN: tuple[tuple[str, int], ...] = (
    ("C_Initialize", 0),
    ("C_OpenSession", 0),
    ("C_Logout", 0),
)

_HINT_RV = "CKR_DEVICE_REMOVED"

# Plan v8 end_state enum: any record carrying one of these plus an identity is
# an identity-bearing loss disposition (no such record type exists pre-Task-3).
_LOSS_END_STATES = frozenset({"crashed", "timeout", "killed", "unknown", "unresolved", "conflict"})


@pytest.fixture(autouse=True)
def _fast_child_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the unit-child plugin set like the file-runner integration tests."""
    monkeypatch.setattr(
        file_runner_mod,
        "_unit_plugin_addopts",
        lambda _path: "-p pkcs11-check -p pytest_reportlog -p timeout",
    )


def _plan_literal(plan: tuple[tuple[str, int], ...]) -> str:
    return "[" + ", ".join(f"[{fn!r}, {rv}]" for fn, rv in plan) + "]"


def _counting_preamble(oracle: Path, plan: tuple[tuple[str, int], ...]) -> str:
    """Shared stub header: the counting fake module + oracle writer."""
    return (
        "import ctypes\n"
        "import json\n"
        "import os\n"
        "import signal\n"
        "import sys\n"
        "from pathlib import Path\n"
        "\n"
        "from pkcs11_check.core import call_counters\n"
        "\n"
        f"_ORACLE = Path({str(oracle)!r})\n"
        f"_PLAN = {_plan_literal(plan)}\n"
        "\n"
        "\n"
        "class CountingFakeModule:\n"
        '    """Stand-in PKCS#11 module: each call lands in the oracle file\n'
        "\n"
        "    (independent provider-side evidence) and in the counting layer.\n"
        '    """\n'
        "\n"
        "    def __init__(self) -> None:\n"
        "        self.log = []\n"
        "\n"
        "    def call(self, fn, rv=0):\n"
        "        self.log.append([fn, rv])\n"
        "        call_counters.record_call(fn)\n"
        "        call_counters.record_return(fn, rv)\n"
        "\n"
        "    def flush(self):\n"
        '        _ORACLE.write_text(json.dumps({"pid": os.getpid(), "calls": self.log}))\n'
        "\n"
        "\n"
        "def _run_plan():\n"
        "    module = CountingFakeModule()\n"
        "    for fn, rv in _PLAN:\n"
        "        module.call(fn, rv)\n"
        "    module.flush()\n"
        "\n"
        "\n"
        "def _die_now():\n"
        '    """Die with no teardown report, no session record, no SessionFinish."""\n'
        '    if sys.platform == "win32":\n'
        "        kernel = ctypes.windll.kernel32\n"
        "        kernel.GetCurrentProcess.restype = ctypes.c_void_p\n"
        "        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]\n"
        "        kernel.TerminateProcess(kernel.GetCurrentProcess(), 0xC0000005)\n"
        "    else:\n"
        "        os.kill(os.getpid(), signal.SIGKILL)\n"
        "\n"
        "\n"
    )


def _write_kill_stub(stub: Path, oracle: Path) -> None:
    """A stub that records five provider calls, then dies mid-first-test."""
    stub.write_text(
        _counting_preamble(oracle, _KILL_PLAN)
        + "def test_first():\n"
        + "    _run_plan()\n"
        + "    _die_now()\n"
        + "\n"
        + "\n"
        + "def test_second():\n"
        + "    pass\n",
        encoding="utf-8",
    )


def _write_fail_once_stub(stub: Path, marker: Path, oracle1: Path, oracle2: Path) -> None:
    """A stub that fails loudly once (hint RV in the failure text), then passes."""
    stub.write_text(
        _counting_preamble(oracle1, _DROP_PLAN)
        + f"_MARKER = Path({str(marker)!r})\n"
        + f"_ORACLE2 = Path({str(oracle2)!r})\n"
        + f"_PLAN2 = {_plan_literal(_RERUN_PLAN)}\n"
        + "\n"
        + "\n"
        + "def test_one():\n"
        + "    if _MARKER.exists():\n"
        + "        module = CountingFakeModule()\n"
        + "        for fn, rv in _PLAN2:\n"
        + "            module.call(fn, rv)\n"
        + '        _ORACLE2.write_text(json.dumps({"pid": os.getpid(), "calls": module.log}))\n'
        + "        return\n"
        + "    _run_plan()\n"
        + '    _MARKER.write_text("attempt one recorded", encoding="utf-8")\n'
        + f"    raise AssertionError({_HINT_RV!r} + ' lines the failure summary')\n",
        encoding="utf-8",
    )


def _run_units(
    units: list[str],
    state_file: Path,
    results_path: Path,
    jsonl_path: Path,
    *,
    granularity: RunnerGranularity = "file",
    recovery_config: RecoveryConfig | None = None,
) -> int:
    """Drive the REAL isolated runner over stub units with a fake module path."""
    return run_isolated_pytest_units(
        units,
        ["--p11-module=/nonexistent/fake.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig("json", results_path, jsonl_path=jsonl_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity=granularity,
        recovery_config=recovery_config,
    )


def _stream_records(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL stream through the REAL report-log loader."""
    return list(iter_report_log_records(path))


def _of_type(records: list[dict[str, Any]], report_type: str) -> list[dict[str, Any]]:
    return [rec for rec in records if rec.get("$report_type", "TestReport") == report_type]


def _counter_lines(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every counters-shaped record: session records + entries on TestReports."""
    shaped = [rec for rec in records if rec.get("$report_type") == CALL_COUNTERS_REPORT_TYPE]
    for rec in _of_type(records, "TestReport"):
        props = rec.get("user_properties")
        if isinstance(props, list) and any(
            isinstance(prop, (list, tuple)) and len(prop) == 2 and prop[0] == CALL_COUNTERS_PROPERTY
            for prop in props
        ):
            shaped.append(rec)
    return shaped


def _loss_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identity-bearing loss dispositions (none exist before Task 3)."""
    return [
        rec
        for rec in records
        if isinstance(rec, dict)
        and rec.get("end_state") in _LOSS_END_STATES
        and (rec.get("worker_uuid") is not None or rec.get("pid") is not None)
    ]


def _assert_exact_or_named_or_partial(
    *,
    extracted: dict[str, Any] | None,
    oracle_total: int,
    report_records: list[dict[str, Any]],
) -> None:
    """The codex-R7 XOR acceptance: exact counts, or a named accounting path.

    Fully recovered executions carry exact counts with no loss record;
    partially recovered ones carry counts plus an identity-bearing
    loss/truncated disposition; zero recoverable evidence carries an
    identity-bearing loss; recovered counts appear exactly once; and an
    unrecovered tail forces the process/round incomplete. Under K=1 a dead
    producer routinely recovers numerically exact counts through its
    truncated partial while staying honestly incomplete (the in-flight
    checkpoint at kill time is unobservable, so completeness is unprovable):
    exact counts plus a named loss plus incomplete is the fourth accepted arm.
    """
    recovered = extracted["total_calls"] if extracted is not None else 0
    assert recovered <= oracle_total, "counter evidence counted twice"
    complete = bool(extracted is not None and extracted["complete"])
    losses = _loss_records(report_records)
    fully_recovered = recovered == oracle_total and not losses and complete
    named_partial = 0 < recovered < oracle_total and bool(losses) and not complete
    named_zero = recovered == 0 and bool(losses) and not complete
    exact_but_truncated = recovered == oracle_total and bool(losses) and not complete
    assert fully_recovered or named_partial or named_zero or exact_but_truncated, (
        f"recovered {recovered}/{oracle_total} with {len(losses)} loss records "
        f"(complete={complete}): no exact-or-named-or-partial accounting"
    )


def _oracle_total(oracle: Path) -> tuple[int, int]:
    """Return (call count, writer pid) from one oracle file."""
    payload = json.loads(oracle.read_text(encoding="utf-8"))
    return len(payload["calls"]), int(payload["pid"])


def _run_kill_fixture(tmp_path: Path) -> dict[str, Any]:
    """Run the SIGKILL stub through the real runner; return the evidence bundle."""
    case_dir = tmp_path / "testcases"
    case_dir.mkdir()
    stub = case_dir / "test_kill_stub.py"
    oracle = tmp_path / "oracle.json"
    _write_kill_stub(stub, oracle)
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    jsonl_path = tmp_path / "report.jsonl"
    exit_code = _run_units([str(stub)], state_file, results_path, jsonl_path)
    return {
        "unit": str(stub),
        "exit_code": exit_code,
        "state_file": state_file,
        "results_path": results_path,
        "jsonl_path": jsonl_path,
        "oracle": oracle,
    }


def test_sigkill_mid_first_test_leaves_zero_counter_shape(tmp_path: Path) -> None:
    """GREEN: a first-test death leaves partial JSONL with zero counter evidence."""
    bundle = _run_kill_fixture(tmp_path)
    unit = bundle["unit"]
    assert bundle["exit_code"] == 1

    state = load_run_state(bundle["state_file"])
    assert state is not None
    (result,) = [item for item in state.results if item.target == unit]
    assert result.status == "crashed"
    # Crashes bypass completion verification (never an inferred harness error).
    assert result.completion_verified is True

    cache_records = _stream_records(_report_record_cache_path(bundle["state_file"], unit))
    test_reports = _of_type(cache_records, "TestReport")
    assert [rec.get("when") for rec in test_reports] == ["setup"], (
        "mid-first-test death: only the setup-phase report made it to the stream"
    )
    assert _of_type(cache_records, "SessionFinish") == []
    assert _counter_lines(cache_records) == [], "zero counters-shaped lines in the cache"
    assert [
        (rec.get("target"), rec.get("attempt"))
        for rec in _of_type(cache_records, _ISOLATED_UNIT_REPORT_TYPE)
    ] == [(unit, 0)]

    merged = _stream_records(bundle["jsonl_path"])
    assert _counter_lines(merged) == [], "the extractor missed nothing: nothing to extract"
    assert _loss_records(merged) == []

    extracted = extract_call_counters_from_jsonl(bundle["jsonl_path"])
    assert extracted is not None
    assert extracted["complete"] is False
    assert extracted["total_calls"] == 0
    assert extracted["by_process"] == []
    assert list(extracted["by_round"]) == [""]

    oracle_total, dead_pid = _oracle_total(bundle["oracle"])
    assert oracle_total == len(_KILL_PLAN)
    assert all(row["pid"] != dead_pid for row in extracted["by_process"])
    payload = json.loads(bundle["results_path"].read_text(encoding="utf-8"))
    assert payload["call_counters"]["complete"] is False

    observations = [obs for obs in state.process_observations if obs.get("target") == unit]
    assert len(observations) == 1
    (observation,) = observations
    assert observation["role"] == "unit"
    assert observation["attempt"] == 0
    termination = observation["termination"]
    if sys.platform == "win32":
        assert termination["kind"] == "exception"
    else:
        assert termination["kind"] == "signal"
        assert termination["signal_name"] == "SIGKILL"
    # The observation carries no pid: today a zero-evidence death is
    # unnameable anywhere in the durable artifacts (Task 3 registry fills this).
    assert "pid" not in observation


def _run_recovery_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Run the fail-once stub through the real runner with scripted dead/alive probes."""
    case_dir = tmp_path / "testcases"
    case_dir.mkdir()
    stub = case_dir / "test_fail_once_stub.py"
    marker = tmp_path / "attempt-one-done"
    oracle1 = tmp_path / "oracle1.json"
    oracle2 = tmp_path / "oracle2.json"
    _write_fail_once_stub(stub, marker, oracle1, oracle2)
    script = iter([False, False, True])
    monkeypatch.setattr(
        file_runner_mod,
        "probe_provider_liveness",
        lambda *args, **kwargs: next(script),
    )
    config = RecoveryConfig(
        mode="wait",
        recover_cmd=None,
        wait_s=0.0,
        max_attempts=3,
        max_total=20,
        hint_rvs=frozenset({_HINT_RV}),
        consecutive_threshold=1,
        quarantine_after=2,
        cmd_timeout_s=30.0,
        probe_timeout_s=30.0,
    )
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    jsonl_path = tmp_path / "report.jsonl"
    exit_code = _run_units(
        [str(stub)], state_file, results_path, jsonl_path, recovery_config=config
    )
    return {
        "unit": str(stub),
        "exit_code": exit_code,
        "state_file": state_file,
        "results_path": results_path,
        "jsonl_path": jsonl_path,
        "oracle1": oracle1,
        "oracle2": oracle2,
    }


def test_recovery_requeue_drops_first_attempt_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GREEN: a requeued attempt's counters survive only as opaque archive rows."""
    bundle = _run_recovery_fixture(tmp_path, monkeypatch)
    unit = bundle["unit"]
    assert bundle["exit_code"] == 1

    state = load_run_state(bundle["state_file"])
    assert state is not None
    (result,) = [item for item in state.results if item.target == unit]
    assert result.status == "passed"
    assert len(state.attempt_history) == 1
    archived = state.attempt_history[0]
    assert archived["target"] == unit
    assert archived["status"] == "failed"
    assert archived["attempt"] == 1
    assert archived["reason"] == "daemon-recovery-requeue"
    archived_sessions = [
        rec for rec in archived["records"] if rec.get("$report_type") == CALL_COUNTERS_REPORT_TYPE
    ]
    assert len(archived_sessions) == 1
    assert archived_sessions[0]["total_calls"] == len(_DROP_PLAN)

    # The unit cache holds the rerun only: one session scope, one session record.
    cache_records = _stream_records(_report_record_cache_path(bundle["state_file"], unit))
    assert len(_of_type(cache_records, "SessionStart")) == 1
    cache_sessions = [
        rec for rec in cache_records if rec.get("$report_type") == CALL_COUNTERS_REPORT_TYPE
    ]
    assert [rec["total_calls"] for rec in cache_sessions] == [len(_RERUN_PLAN)]

    merged = _stream_records(bundle["jsonl_path"])
    wrappers = _of_type(merged, "RecoveryAttempt")
    assert len(wrappers) == 1
    assert wrappers[0]["attempt"]["reason"] == "daemon-recovery-requeue"
    top_level_sessions = [
        rec for rec in merged if rec.get("$report_type") == CALL_COUNTERS_REPORT_TYPE
    ]
    assert [rec["total_calls"] for rec in top_level_sessions] == [len(_RERUN_PLAN)]

    extracted = extract_call_counters_from_jsonl(bundle["jsonl_path"])
    assert extracted is not None
    assert extracted["total_calls"] == len(_RERUN_PLAN)
    # The dropped tail does NOT force incomplete today: the archive is opaque
    # to the extractor, so the rerun reads as a fully complete round.
    assert extracted["complete"] is True

    oracle1_total, _ = _oracle_total(bundle["oracle1"])
    oracle2_total, _ = _oracle_total(bundle["oracle2"])
    assert (oracle1_total, oracle2_total) == (len(_DROP_PLAN), len(_RERUN_PLAN))


def test_sigkill_accounting_exact_or_named_or_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Task-3 acceptance (was RED): the five calls are exact, or named as a loss.

    Durability engaged: the SIGKILLed worker registered but never flushed
    (5 calls < K=10, no boundary reached), so the parent collects a
    zero-evidence loss record and the run reads named-zero, incomplete.
    """
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV

    monkeypatch.setenv(COUNTERS_DIR_ENV, str(tmp_path / "counters"))
    bundle = _run_kill_fixture(tmp_path)
    oracle_total, _ = _oracle_total(bundle["oracle"])
    _assert_exact_or_named_or_partial(
        extracted=extract_call_counters_from_jsonl(bundle["jsonl_path"]),
        oracle_total=oracle_total,
        report_records=_stream_records(bundle["jsonl_path"]),
    )


def test_retry_dropped_accounting_exact_or_named_or_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Task-3 acceptance (was RED): the dropped attempt is recovered, or named.

    Durability engaged: the requeued attempt's session archives into the
    rerun's cache via recovery supplements, so both attempts fold exactly
    with no loss record (fully recovered).
    """
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV

    monkeypatch.setenv(COUNTERS_DIR_ENV, str(tmp_path / "counters"))
    bundle = _run_recovery_fixture(tmp_path, monkeypatch)
    oracle1_total, _ = _oracle_total(bundle["oracle1"])
    oracle2_total, _ = _oracle_total(bundle["oracle2"])
    _assert_exact_or_named_or_partial(
        extracted=extract_call_counters_from_jsonl(bundle["jsonl_path"]),
        oracle_total=oracle1_total + oracle2_total,
        report_records=_stream_records(bundle["jsonl_path"]),
    )


def test_framing_marker_always_attempt_zero(tmp_path: Path) -> None:
    """Identity: the merged writer frames marker-less shards as (unit, 0)."""
    state_file = tmp_path / "state.json"
    output_path = tmp_path / "report.jsonl"
    unit = str(tmp_path / "testcases" / "test_legacy.py")
    inline = [
        {"$report_type": "SessionStart"},
        {"nodeid": f"{unit}::test_a", "when": "call", "outcome": "passed"},
    ]
    wrote = _write_report_jsonl_from_record_sources(
        state_file,
        units=[unit],
        inline_records_by_unit={unit: inline},
        output_path=output_path,
    )
    assert wrote is True
    merged = _stream_records(output_path)
    (marker,) = _of_type(merged, _ISOLATED_UNIT_REPORT_TYPE)
    assert marker["target"] == unit
    assert marker["attempt"] == 0
    assert "reason" not in marker and "skipped" not in marker


def test_cache_markers_carry_per_source_attempt_counts(tmp_path: Path) -> None:
    """Identity: cached markers number each appended source; true counters resume."""
    state_file = tmp_path / "state.json"
    unit = str(tmp_path / "testcases" / "test_retry.py")
    first = tmp_path / "attempt1.jsonl"
    first.write_text(
        '{"$report_type": "SessionStart"}\n'
        '{"nodeid": "x::t", "when": "call", "outcome": "passed"}\n',
        encoding="utf-8",
    )
    second = tmp_path / "attempt2.jsonl"
    second.write_text(
        '{"$report_type": "SessionStart"}\n'
        '{"nodeid": "x::t", "when": "call", "outcome": "failed"}\n',
        encoding="utf-8",
    )
    resumed = tmp_path / "resumed.jsonl"
    # json.dumps, never an f-string: a raw OS path breaks JSON escaping on
    # Windows (backslashes), silently dropping this marker line.
    resumed.write_text(
        json.dumps({"$report_type": "IsolatedUnitReport", "target": unit, "attempt": 5})
        + "\n"
        + '{"nodeid": "x::t", "when": "call", "outcome": "passed"}\n',
        encoding="utf-8",
    )
    _write_unit_report_record_cache_from_jsonl_paths(state_file, unit, [first, second, resumed])
    markers = [
        (rec.get("target"), rec.get("attempt"))
        for rec in _of_type(
            _stream_records(_report_record_cache_path(state_file, unit)),
            _ISOLATED_UNIT_REPORT_TYPE,
        )
    ]
    assert markers == [(unit, 0), (unit, 1), (unit, 5)]


def test_observation_attempt_numbers_per_target_and_role() -> None:
    """Identity: process observations count attempts per (target, role), from 0."""
    state = FileRunState(units=[], fingerprint="", results=[])
    clean = {"termination": {"kind": "exit"}}
    for _ in range(2):
        _append_process_observation(state, clean, target="u", role="unit")
    _append_process_observation(state, clean, target="u", role="retry")
    _append_process_observation(state, clean, target="v", role="unit")
    assert [(obs["target"], obs["role"], obs["attempt"]) for obs in state.process_observations] == [
        ("u", "unit", 0),
        ("u", "unit", 1),
        ("u", "retry", 0),
        ("v", "unit", 0),
    ]


def test_save_run_state_clears_absorbed_recovery_sidecar(tmp_path: Path) -> None:
    """Cadence: every state save absorbs history, then drops the sidecar."""
    state_file = tmp_path / "state.json"
    sidecar = state_file.with_name(f"{state_file.name}.recovery.jsonl")
    sidecar.write_text('{"$report_type": "RecoveryAttempt"}\n', encoding="utf-8")
    save_run_state(state_file, FileRunState(units=["u"], fingerprint="fp", results=[]))
    assert not sidecar.exists()
    assert load_run_state(state_file) is not None
