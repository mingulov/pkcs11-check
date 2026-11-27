"""Per-test call-counter windows and the session CallCountersReport (fw#73, Task 3).

Direct unit tests drive the wrapper hooks generator-by-generator (pre-yield /
post-yield) with fake items/reports in the ``test_unclassified_gate.py``
``SimpleNamespace`` style, plus hermetic ``pytest_sessionfinish`` drivers in the
``test_teardown_finalize.py`` style. One pytester E2E runs two stub tests through
the live wrappers and asserts the phase attribution in ``report.jsonl``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import pkcs11_check._plugin_counters as plugin_counters
import pkcs11_check.plugin as plugin_mod
from pkcs11_check._plugin_state import _is_testcase_item
from pkcs11_check.core import call_counters
from pkcs11_check.core import counters_schema as schema
from pkcs11_check.core.call_counters import (
    CALL_COUNTERS_PROPERTY,
    ISOLATION_ENV,
    RUN_ID_ENV,
)

pytest_plugins = ["pytester"]


@pytest.fixture(autouse=True)
def _reset_counters() -> Any:
    """Isolate the process-global counters around each test."""
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


def _config_ns(*, p11_module: str | None = "/tmp/fake-module.so") -> SimpleNamespace:
    return SimpleNamespace(
        getoption=lambda name, default=None: {"p11_module": p11_module}.get(name, default),
    )


def _testcase_item(*, p11_module: str | None = "/tmp/fake-module.so") -> pytest.Item:
    ns = SimpleNamespace(
        path=Path("/repo/src/pkcs11_check/testcases/test_x.py"),
        nodeid="src/pkcs11_check/testcases/test_x.py::test_y",
        stash=pytest.Stash(),
        config=_config_ns(p11_module=p11_module),
    )
    item = cast("pytest.Item", ns)
    assert _is_testcase_item(item), "fixture item must be recognised as a testcase item"
    return item


def _meta_item() -> pytest.Item:
    ns = SimpleNamespace(
        path=Path("/repo/tests/test_meta.py"),
        nodeid="tests/test_meta.py::test_y",
        stash=pytest.Stash(),
        config=_config_ns(),
    )
    item = cast("pytest.Item", ns)
    assert not _is_testcase_item(item), "fixture item must NOT be a testcase item"
    return item


def _report(*, when: str = "teardown", outcome: str = "passed") -> Any:
    return SimpleNamespace(when=when, outcome=outcome, user_properties=[])


def _advance(gen: Any) -> None:
    """Run a wrapper-hook generator up to its yield point (runs the pre code)."""
    next(gen)


def _resume(gen: Any, value: Any = None) -> None:
    """Resume a wrapper-hook generator past its yield (runs the post code)."""
    try:
        gen.send(value)
    except StopIteration:
        return


def _drive_makereport(item: pytest.Item, report: Any) -> Any:
    """Drive the makereport wrapper; returns the outcome the wrapper passes on."""
    gen = plugin_counters.pytest_runtest_makereport(
        item, cast("pytest.CallInfo[Any]", SimpleNamespace(when=getattr(report, "when", None)))
    )
    _advance(gen)
    try:
        gen.send(report)
    except StopIteration as done:
        return done.value
    raise AssertionError("makereport wrapper yielded twice")


def _record(fn: str, rv: int = 0) -> None:
    call_counters.record_call(fn)
    call_counters.record_return(fn, rv)


def _unknown_buckets(snap: dict[str, Any]) -> dict[str, Any]:
    """Inner buckets of the single unknown-module block (no handle involved)."""
    assert set(snap["by_module"]) == {""}
    return snap["by_module"][""]["buckets"]


def _prop(report: Any) -> dict[str, Any] | None:
    for name, value in report.user_properties:
        if name == CALL_COUNTERS_PROPERTY:
            return dict(value)
    return None


# --------------------------------------------------------------------------
# Session record shape
# --------------------------------------------------------------------------


def test_session_record_shape() -> None:
    call_counters.reset_for_tests()
    call_counters.record_call("C_OpenSession")
    call_counters.record_return("C_OpenSession", 0)
    rec = plugin_counters.build_session_record()
    assert rec["$report_type"] == "CallCountersReport" and rec["total_calls"] == 1


def test_session_record_carries_pid_and_buckets() -> None:
    _record("C_OpenSession")
    rec = plugin_counters.build_session_record()
    assert rec["pid"] == os.getpid()
    entry = _unknown_buckets(rec)["session_provisioning"]["by_fn"]["C_OpenSession"]
    assert entry["calls"] == 1
    assert entry["by_rv"]["0"]["count"] == 1


def test_session_record_isolation_defaults_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ISOLATION_ENV, raising=False)
    assert plugin_counters.build_session_record()["isolation"] == "unknown"


def test_session_record_isolation_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ISOLATION_ENV, "file")
    assert plugin_counters.build_session_record()["isolation"] == "file"


def test_session_record_probes_lost_only() -> None:
    call_counters.note_lost_probe()
    call_counters.note_lost_probe()
    rec = plugin_counters.build_session_record()
    assert rec["probes_lost"] == 2
    assert "probes_completed" not in rec


def test_emit_session_record_writes_via_report_log() -> None:
    _record("C_OpenSession")
    written: list[dict[str, Any]] = []
    config = SimpleNamespace(
        _report_log_plugin=SimpleNamespace(_write_json_data=written.append),
    )
    plugin_counters.emit_session_record(cast("pytest.Config", config))
    assert len(written) == 1
    assert written[0]["$report_type"] == "CallCountersReport"
    assert written[0]["total_calls"] == 1


def test_emit_session_record_without_report_log_is_silent() -> None:
    plugin_counters.emit_session_record(cast("pytest.Config", SimpleNamespace()))
    plugin_counters.emit_session_record(
        cast("pytest.Config", SimpleNamespace(_report_log_plugin=SimpleNamespace()))
    )


def test_emit_probe_attestation_writes_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R44-G7: session emission attests admitted folded-probe digests."""
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV, _publication_digest

    call_counters.reset_for_tests()
    root = tmp_path / "counters"
    root.mkdir()
    monkeypatch.setenv(COUNTERS_DIR_ENV, str(root))
    monkeypatch.delenv(call_counters.RUN_ID_ENV, raising=False)
    call_counters.note_folded_probe_digest(child_uuid="b" * 32, probe_seq=3, digest="e" * 64)
    written: list[dict[str, Any]] = []
    config = SimpleNamespace(
        _report_log_plugin=SimpleNamespace(_write_json_data=written.append),
    )
    plugin_counters.emit_session_record(cast("pytest.Config", config))
    assert len(written) == 1
    worker = call_counters.get_worker_uuid()
    path = root / f"attestations-{worker}.jsonl"
    assert path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["worker_uuid"] == worker
    assert record["run_id"] == ""
    assert record["publication"] == _publication_digest(json.loads(json.dumps(written[0])))
    assert record["attestations"] == [{"worker_uuid": "b" * 32, "probe_seq": 3, "digest": "e" * 64}]
    call_counters.reset_for_tests()


def test_emit_probe_attestation_skips_when_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R44-G7: no admitted digests means no attestation artifact."""
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV

    call_counters.reset_for_tests()
    root = tmp_path / "counters"
    root.mkdir()
    monkeypatch.setenv(COUNTERS_DIR_ENV, str(root))
    written: list[dict[str, Any]] = []
    config = SimpleNamespace(
        _report_log_plugin=SimpleNamespace(_write_json_data=written.append),
    )
    plugin_counters.emit_session_record(cast("pytest.Config", config))
    assert len(written) == 1
    assert list(root.glob("attestations-*")) == []
    call_counters.reset_for_tests()


def test_emit_probe_attestation_skips_when_disengaged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R44-G7: disengaged durability means no attestation artifact."""
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV

    call_counters.reset_for_tests()
    root = tmp_path / "counters"
    root.mkdir()
    monkeypatch.delenv(COUNTERS_DIR_ENV, raising=False)
    call_counters.note_folded_probe_digest(child_uuid="b" * 32, probe_seq=3, digest="e" * 64)
    written: list[dict[str, Any]] = []
    config = SimpleNamespace(
        _report_log_plugin=SimpleNamespace(_write_json_data=written.append),
    )
    plugin_counters.emit_session_record(cast("pytest.Config", config))
    assert len(written) == 1
    assert list(root.glob("attestations-*")) == []
    call_counters.reset_for_tests()


# --------------------------------------------------------------------------
# Attach helper
# --------------------------------------------------------------------------


def test_attach_without_entry_is_noop() -> None:
    item = _testcase_item()
    report = _report()
    plugin_counters.attach_call_counters(item, report)
    assert report.user_properties == []


def test_attach_empty_entry_is_noop() -> None:
    item = _testcase_item()
    item.stash[plugin_counters._ENTRY_KEY] = {"pid": os.getpid(), "total_calls": 0, "buckets": {}}
    report = _report()
    plugin_counters.attach_call_counters(item, report)
    assert report.user_properties == []


def test_attach_appends_entry() -> None:
    item = _testcase_item()
    entry = {"pid": 1234, "total_calls": 2, "buckets": {"test": {"calls": 2, "by_fn": {}}}}
    item.stash[plugin_counters._ENTRY_KEY] = entry
    report = _report()
    plugin_counters.attach_call_counters(item, report)
    assert report.user_properties == [(CALL_COUNTERS_PROPERTY, entry)]


def test_attach_does_not_duplicate() -> None:
    item = _testcase_item()
    entry = {"pid": 1234, "total_calls": 1, "buckets": {}}
    item.stash[plugin_counters._ENTRY_KEY] = entry
    report = _report()
    report.user_properties.append((CALL_COUNTERS_PROPERTY, entry))
    plugin_counters.attach_call_counters(item, report)
    assert report.user_properties == [(CALL_COUNTERS_PROPERTY, entry)]


def test_attach_without_property_list_is_noop() -> None:
    item = _testcase_item()
    item.stash[plugin_counters._ENTRY_KEY] = {"pid": 1, "total_calls": 1, "buckets": {}}
    plugin_counters.attach_call_counters(item, SimpleNamespace(when="teardown"))


# --------------------------------------------------------------------------
# Phase wrappers: setup / call buckets
# --------------------------------------------------------------------------


def test_setup_wrapper_attributes_to_setup_teardown() -> None:
    item = _testcase_item()
    gen = plugin_counters.pytest_runtest_setup(item)
    _advance(gen)
    assert call_counters.current_bucket() == "setup_teardown"
    _record("C_SetupCall")
    _resume(gen)
    assert call_counters.current_bucket() == "session_provisioning"
    snap = call_counters.serialize_current()
    assert _unknown_buckets(snap)["setup_teardown"]["by_fn"]["C_SetupCall"]["calls"] == 1


def test_setup_wrapper_skipped_without_module() -> None:
    item = _testcase_item(p11_module=None)
    gen = plugin_counters.pytest_runtest_setup(item)
    _advance(gen)
    assert call_counters.current_bucket() == "session_provisioning"
    _resume(gen)
    assert plugin_counters._BASELINE_KEY not in item.stash


def test_setup_wrapper_skipped_for_meta_item() -> None:
    item = _meta_item()
    gen = plugin_counters.pytest_runtest_setup(item)
    _advance(gen)
    assert call_counters.current_bucket() == "session_provisioning"
    _resume(gen)
    assert plugin_counters._BASELINE_KEY not in item.stash


def test_setup_wrapper_balances_bucket_on_inner_raise() -> None:
    item = _testcase_item()
    gen = plugin_counters.pytest_runtest_setup(item)
    _advance(gen)
    with pytest.raises(RuntimeError, match="boom"):
        gen.throw(RuntimeError("boom"))
    assert call_counters.current_bucket() == "session_provisioning"


def test_call_wrapper_attributes_to_test() -> None:
    item = _testcase_item()
    gen = plugin_counters.pytest_runtest_call(item)
    _advance(gen)
    assert call_counters.current_bucket() == "test"
    _record("C_BodyCall")
    _resume(gen)
    assert call_counters.current_bucket() == "session_provisioning"
    snap = call_counters.serialize_current()
    assert _unknown_buckets(snap)["test"]["by_fn"]["C_BodyCall"]["calls"] == 1


def test_call_wrapper_balances_bucket_on_inner_raise() -> None:
    item = _testcase_item()
    gen = plugin_counters.pytest_runtest_call(item)
    _advance(gen)
    with pytest.raises(RuntimeError, match="boom"):
        gen.throw(RuntimeError("boom"))
    assert call_counters.current_bucket() == "session_provisioning"


def test_call_wrapper_skipped_without_module_or_meta_item() -> None:
    for item in (_testcase_item(p11_module=None), _meta_item()):
        gen = plugin_counters.pytest_runtest_call(item)
        _advance(gen)
        assert call_counters.current_bucket() == "session_provisioning"
        _resume(gen)


# --------------------------------------------------------------------------
# Phase wrappers: teardown entry
# --------------------------------------------------------------------------


def _drive_phase(hook: Any, item: pytest.Item, *args: Any, calls: tuple[str, ...] = ()) -> None:
    gen = hook(item, *args)
    _advance(gen)
    for fn in calls:
        _record(fn)
    _resume(gen)


def test_teardown_wrapper_computes_windowed_entry() -> None:
    _record("C_Before")  # outside the window: must not leak into the entry
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    _drive_phase(plugin_counters.pytest_runtest_call, item, calls=("C_BodyCall",))
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None, calls=("C_TeardownCall",))
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert entry["pid"] == os.getpid()
    assert entry["total_calls"] == 3
    assert set(_unknown_buckets(entry)) == set(schema.BUCKETS_5)
    assert _unknown_buckets(entry)["setup_teardown"]["calls"] == 2
    assert _unknown_buckets(entry)["test"]["calls"] == 1
    provisioning = _unknown_buckets(entry).get("session_provisioning", {}).get("by_fn", {})
    assert "C_Before" not in provisioning


def test_teardown_entry_carries_window_scoped_consumed() -> None:
    # Codex RC4-R3: the teardown entry stamps fallback-absorption
    # proofs absorbed inside the window only (pre-window proofs stay
    # out), in entry-schema-valid shape.
    pre_uuid = "a" * 32
    in_uuid = "b" * 32
    call_counters.ingest_child_evidence([["m", "C_Pre", 0, 1]], 0, (), consumed_probe=(pre_uuid, 0))
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item)
    call_counters.ingest_child_evidence([["m", "C_In", 0, 1]], 0, (), consumed_probe=(in_uuid, 3))
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None)
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert entry["consumed_probes"] == [{"worker_uuid": in_uuid, "probe_seq": 3}]
    assert "receipts" not in entry
    assert schema.is_test_entry(entry) is True


def test_teardown_entry_omits_consumed_when_window_empty() -> None:
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None)
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert "consumed_probes" not in entry


def test_teardown_wrapper_skip_in_setup_yields_setup_only_entry() -> None:
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    # Call phase never runs (skip/fail in setup); teardown still runs.
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None)
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert entry["total_calls"] == 1
    assert set(_unknown_buckets(entry)) == set(schema.BUCKETS_5)


def test_teardown_wrapper_computes_entry_despite_inner_raise() -> None:
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    gen = plugin_counters.pytest_runtest_teardown(item, None)
    _advance(gen)
    with pytest.raises(RuntimeError, match="boom"):
        gen.throw(RuntimeError("boom"))
    assert call_counters.current_bucket() == "session_provisioning"
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert entry["total_calls"] == 1


def test_teardown_wrapper_without_baseline_stashes_nothing() -> None:
    item = _testcase_item()  # setup wrapper never ran: no baseline
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None, calls=("C_X",))
    assert plugin_counters._ENTRY_KEY not in item.stash
    assert call_counters.current_bucket() == "session_provisioning"


def test_teardown_wrapper_skipped_without_module_or_meta_item() -> None:
    for item in (_testcase_item(p11_module=None), _meta_item()):
        _drive_phase(plugin_counters.pytest_runtest_teardown, item, None, calls=("C_X",))
        assert plugin_counters._ENTRY_KEY not in item.stash


def test_makereport_wrapper_attaches_entry_to_teardown_report() -> None:
    item = _testcase_item()
    entry = {"pid": 1234, "total_calls": 1, "buckets": {}}
    item.stash[plugin_counters._ENTRY_KEY] = entry
    report = _report(when="teardown")
    assert _drive_makereport(item, report) is report
    assert report.user_properties == [(CALL_COUNTERS_PROPERTY, entry)]


def test_makereport_wrapper_without_entry_is_noop() -> None:
    item = _testcase_item()
    report = _report(when="call")
    assert _drive_makereport(item, report) is report
    assert report.user_properties == []


def test_makereport_wrapper_skipped_without_module_or_meta_item() -> None:
    entry = {"pid": 1234, "total_calls": 1, "buckets": {}}
    for item in (_testcase_item(p11_module=None), _meta_item()):
        item.stash[plugin_counters._ENTRY_KEY] = entry
        report = _report(when="teardown")
        assert _drive_makereport(item, report) is report
        assert report.user_properties == []


# --------------------------------------------------------------------------
# pytest_sessionfinish emission (hermetic drivers, test_teardown_finalize style)
# --------------------------------------------------------------------------


class _FakeReportLogPlugin:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def _write_json_data(self, payload: dict[str, Any]) -> None:
        self.records.append(payload)


def _session_config(
    report_log: _FakeReportLogPlugin, raw: Any, *, p11_module: str | None = "/tmp/module.so"
) -> SimpleNamespace:
    stash: dict[Any, Any] = {
        plugin_mod._CUMULATIVE_FUNCTIONS: set(),
        plugin_mod._CUMULATIVE_MECHANISMS: set(),
        plugin_mod._CUMULATIVE_USED_MECHANISMS: set(),
        plugin_mod._CUMULATIVE_MECHANISM_DETAILS: set(),
        plugin_mod._CUMULATIVE_FUNCTION_COUNTS: {},
        plugin_mod._CUMULATIVE_MECHANISM_COUNTS: {},
        plugin_mod._CUMULATIVE_DETAIL_COUNTS: {},
        plugin_mod._BOOTSTRAP_FUNCTION_COUNTS: {},
        plugin_mod._SELECTION_TELEMETRY_KEY: {},
    }
    if raw is not None:
        stash[plugin_mod._RAW_INSTANCE] = raw
    return SimpleNamespace(
        stash=stash,
        getoption=lambda name, default=None: {"p11_module": p11_module}.get(name, default),
        _report_log_plugin=report_log,
    )


def _run_sessionfinish(config: SimpleNamespace) -> SimpleNamespace:
    session = SimpleNamespace(config=config, exitstatus=pytest.ExitCode.OK)
    plugin_mod.pytest_sessionfinish(cast("pytest.Session", session), 0)
    return session


def _counters_records(report_log: _FakeReportLogPlugin) -> list[dict[str, Any]]:
    return [r for r in report_log.records if r.get("$report_type") == "CallCountersReport"]


def test_sessionfinish_emits_when_raw_is_none() -> None:
    _record("C_OpenSession")
    report_log = _FakeReportLogPlugin()
    _run_sessionfinish(_session_config(report_log, None))
    records = _counters_records(report_log)
    assert len(records) == 1
    assert records[0]["total_calls"] == 1
    assert records[0]["pid"] == os.getpid()
    assert records[0]["probes_lost"] == 0
    assert not [r for r in report_log.records if r.get("$report_type") == "CoverageReport"]


def test_sessionfinish_emits_after_finalize_includes_finalize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The normal-path emission runs after C_Finalize, so the finalize call counts."""
    monkeypatch.setenv(plugin_mod.UNIT_CHILD_ENV, "1")  # skip the git-shell-out provenance leg

    class _CountingRaw:
        def available_function_names(self) -> set[str]:
            return set()

        def C_Finalize(self, arg: Any) -> int:  # noqa: N802
            # The real raw funnels through _call (Task 2 wiring counts it); the
            # spy bypasses _call, so it records the entry/exit explicitly.
            _record("C_Finalize")
            return 0

    report_log = _FakeReportLogPlugin()
    _run_sessionfinish(_session_config(report_log, _CountingRaw()))
    records = _counters_records(report_log)
    assert len(records) == 1
    by_fn = _unknown_buckets(records[0])["module_init"]["by_fn"]
    assert by_fn["C_Finalize"]["calls"] == 1
    kinds = [r.get("$report_type") for r in report_log.records]
    assert kinds.index("TeardownFinalize") < kinds.index("CallCountersReport")


def test_sessionfinish_without_module_emits_nothing() -> None:
    _record("C_OpenSession")
    report_log = _FakeReportLogPlugin()
    _run_sessionfinish(_session_config(report_log, None, p11_module=None))
    assert report_log.records == []


# --------------------------------------------------------------------------
# E2E: two stub tests through the live wrappers
# --------------------------------------------------------------------------


def test_phase_buckets_end_to_end(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytester.mkdir("testcases")
    (pytester.path / "testcases" / "test_stub_c.py").write_text(
        "import pytest\n"
        "from pkcs11_check.core import call_counters\n"
        "\n"
        "\n"
        "@pytest.fixture\n"
        "def _counted():\n"
        '    call_counters.record_call("C_SetupCall")\n'
        '    call_counters.record_return("C_SetupCall", 0)\n'
        "    yield\n"
        '    call_counters.record_call("C_TeardownCall")\n'
        '    call_counters.record_return("C_TeardownCall", 0)\n'
        "\n"
        "\n"
        "def test_one(_counted):\n"
        '    call_counters.record_call("C_BodyCall")\n'
        '    call_counters.record_return("C_BodyCall", 0)\n'
        "\n"
        "\n"
        "def test_two(_counted):\n"
        '    call_counters.record_call("C_BodyCall")\n'
        '    call_counters.record_return("C_BodyCall", 0)\n',
        encoding="utf-8",
    )
    monkeypatch.setenv(ISOLATION_ENV, "e2e-probe")
    result = pytester.runpytest_subprocess(
        "--p11-module=/nonexistent/fake.so", "--report-log=report.jsonl", "-q"
    )
    result.assert_outcomes(passed=2)
    lines = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    test_reports = [ln for ln in lines if ln.get("$report_type") == "TestReport"]
    assert len(test_reports) == 6  # setup/call/teardown x 2 tests
    for ln in test_reports:
        props = dict(ln.get("user_properties", []))
        if ln["when"] == "teardown":
            entry = props[CALL_COUNTERS_PROPERTY]
            assert entry["total_calls"] == 3
            assert _unknown_buckets(entry)["setup_teardown"]["calls"] == 2
            assert _unknown_buckets(entry)["test"]["calls"] == 1
            assert isinstance(entry["pid"], int)
        else:
            assert CALL_COUNTERS_PROPERTY not in props
    session_records = [ln for ln in lines if ln.get("$report_type") == "CallCountersReport"]
    assert len(session_records) == 1
    assert session_records[0]["total_calls"] == 6
    assert session_records[0]["isolation"] == "e2e-probe"
    assert session_records[0]["probes_lost"] == 0


# --------------------------------------------------------------------------
# Per-round run_id attribution (fw#73 round dimension)
# --------------------------------------------------------------------------


def test_session_record_run_id_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RUN_ID_ENV, "20261115T120000000000Z-p1234")
    assert plugin_counters.build_session_record()["run_id"] == "20261115T120000000000Z-p1234"


def test_session_record_omits_run_id_when_env_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Direct-pytest runs (no CLI seed) carry no run_id; the extractor folds
    # such records into the implicit "" round.
    monkeypatch.delenv(RUN_ID_ENV, raising=False)
    assert "run_id" not in plugin_counters.build_session_record()


def test_teardown_entry_run_id_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RUN_ID_ENV, "20261115T120000000000Z-p1234")
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None)
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert entry["run_id"] == "20261115T120000000000Z-p1234"


def test_teardown_entry_omits_run_id_when_env_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(RUN_ID_ENV, raising=False)
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    _drive_phase(plugin_counters.pytest_runtest_teardown, item, None)
    entry = item.stash[plugin_counters._ENTRY_KEY]
    assert "run_id" not in entry


def test_teardown_entry_rejects_reserved_unknown_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First-tier R9: the per-test window stamps the same ambient run
    # id, so it guards the reservation too -- no "unknown" entry may
    # flow into report user_properties.
    monkeypatch.setenv(RUN_ID_ENV, "unknown")
    item = _testcase_item()
    _drive_phase(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
    with pytest.raises(call_counters.CounterPersistenceError, match="reserved run_id"):
        _drive_phase(plugin_counters.pytest_runtest_teardown, item, None)


def _write_fault_stub(pytester: pytest.Pytester, *, direct_raise: bool) -> None:
    if direct_raise:
        body = (
            "from pkcs11_check.core.call_counters import CounterPersistenceError\n"
            "\n\n"
            "def test_fault():\n"
            '    raise CounterPersistenceError("synthetic persistence fault")\n'
        )
    else:
        body = (
            "from pkcs11_check.core import call_counters\n"
            "\n\n"
            "def test_fault():\n"
            '    call_counters.record_call("C_Login")\n'
        )
    (pytester.path / "test_fault_c.py").write_text(
        body + "\n\n"
        "def test_never_runs():\n"
        "    import pathlib\n"
        '    pathlib.Path("ran-marker.txt").write_text("ran", encoding="utf-8")\n',
        encoding="utf-8",
    )


def test_persistence_fault_aborts_session_as_harness_error(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """F11 live: an uncaught persistence fault aborts with ONE harness error (exit 2)."""
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV

    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    monkeypatch.setenv(COUNTERS_DIR_ENV, str(blocker))
    _write_fault_stub(pytester, direct_raise=False)
    result = pytester.runpytest_subprocess("--p11-module=/nonexistent/fake.so", "-q")
    assert result.ret == pytest.ExitCode.INTERRUPTED
    out = result.stdout.str() + result.stderr.str()
    assert out.count("counter persistence failed") == 1
    assert not (pytester.path / "ran-marker.txt").exists()


def test_persistence_fault_disengaged_stays_per_test_error(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F11 control: disengaged runs keep per-test errors (no abort)."""
    from pkcs11_check.core._counters_durability import COUNTERS_DIR_ENV

    monkeypatch.delenv(COUNTERS_DIR_ENV, raising=False)
    _write_fault_stub(pytester, direct_raise=True)
    result = pytester.runpytest_subprocess("--p11-module=/nonexistent/fake.so", "-q")
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    out = result.stdout.str() + result.stderr.str()
    assert "counter persistence failed" not in out
    assert (pytester.path / "ran-marker.txt").exists()
