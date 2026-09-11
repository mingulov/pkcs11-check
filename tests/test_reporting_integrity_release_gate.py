"""Integrated release gate for classification, crash, and report integrity (F11 slice D).

Binding: ``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md``
and ``f11-d-release-gate-brief.md``. Slice A (``iter_classification_occurrences``,
``extract_quality_report_evidence_from_jsonl``) and slice B (the ``classification_observability``
block in ``build_quality_audit``, wired through ``core/merge.py``/``cli/test_cmd.py``/
``report/render.py``) are prerequisites reused here, not re-derived.

Two halves:

1. ONE integrated pytester scenario, run through the real isolated file-runner (the exact
   crash/retry machinery under test in production -- no second runner is added), serializing
   the exact sequence the brief specifies and asserting the release-acceptance properties on
   the raw JSONL, the grouped classification occurrences, the unified logical counts, and the
   JUnit artifact.
2. Two classification-observability fixtures: a *clean* one (reusing part (1)'s own real
   report.jsonl -- it never emits ``unclassified``, so it is exactly the "declared source read
   with zero unclassified occurrences" shape) and a *deliberately explained raw-unclassified*
   one. The dirty fixture is a literal constructed JSONL, not a second pytester run: as
   ``tests/test_unclassified_gate.py`` documents, the plugin's ``pytest_collection_modifyitems``
   skips every item under ``testcases/`` without a real ``--p11-module`` (the auto-injection
   gate in ``_attach_classification_to_report`` is scoped to ``testcases/`` paths), so a
   pytester file under ``testcases/`` never reaches the ``call`` phase where the synthetic
   ``unclassified`` record would be injected. The fixture instead uses
   ``pkcs11_check.classification.serialize`` (production's own serializer) to build the exact
   dict shape ``_synthetic_unclassified_record`` would have produced, so the fixture is
   byte-faithful to the real injection without depending on a real PKCS#11 module.
"""

from __future__ import annotations

import json
from collections import Counter
from io import StringIO

import pytest
from rich.console import Console

from pkcs11_check.classification import Classification, serialize
from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core._report_records import extract_quality_report_evidence_from_jsonl
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    _build_per_unit_details_from_record_sources,
    load_run_state,
    run_isolated_pytest_units,
    write_isolated_junit_report,
)
from pkcs11_check.core.quality_audit import build_quality_audit
from pkcs11_check.core.report_log import QualityReportEvidence
from pkcs11_check.report.extract import extract_groups
from pkcs11_check.report.render import render_provider

pytest_plugins = ["pytester"]
pytestmark = pytest.mark.usefixtures("classification_report_plugin_enabled")


def _classifications(report: dict[str, object]) -> list[dict[str, object]]:
    properties = report.get("user_properties")
    if not isinstance(properties, list):
        return []
    for entry in properties:
        if (
            isinstance(entry, (list, tuple))
            and len(entry) == 2
            and entry[0] == "pkcs11_classification"
            and isinstance(entry[1], list)
        ):
            return [dict(item) for item in entry[1] if isinstance(item, dict)]
    return []


def _assert_observability_gate_accepts(evidence: QualityReportEvidence) -> None:
    """The F11 slice D release-acceptance shape: never a threshold on unclassified count.

    Requires a fully readable, well-formed declared source (``complete``, no missing or
    malformed evidence) -- release acceptance fails for missing/partial contract evidence
    over the declared scope, per the brief. Deliberately absent: any assertion on
    ``evidence.unclassified.occurrences``. A nonzero provider-wide ``unclassified`` count
    must NEVER fail this gate (F11 is observability, not a cleanliness policy) -- that is
    the property this helper exists to lock in, not to threaten.
    """
    assert evidence.status == "complete"
    assert evidence.unclassified is not None
    assert evidence.missing_sources == 0
    assert evidence.malformed_records == 0
    assert evidence.malformed_markers == 0
    assert evidence.malformed_properties == 0
    assert evidence.malformed_entries == 0


def test_reporting_integrity_release_gate(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve phase evidence, hard failures, a real crash, and later tests."""
    marker = pytester.path / "crasher-ran"
    target = pytester.makepyfile(
        test_release_sequence=f"""
import ctypes
import os
import signal
import sys
from pathlib import Path

import pytest
from pkcs11_check import classification as C
from pkcs11_check.classification import Classification, record

@pytest.fixture
def setup_deviation(request):
    if request.node.name == "test_setup_xfail":
        C.xfail_as(
            "not_operational", kind="session", label="setup refusal",
            operation="C_OpenSession", summary="setup refusal",
        )

@pytest.fixture
def cleanup_failure():
    yield
    record(Classification(
        reason="harness_error", outcome="fail", severity="HIGH", kind="lifecycle",
        label="cleanup failure", operation="C_DestroyObject",
        summary="cleanup failed after provider measurement",
    ))

@pytest.fixture
def teardown_deviation():
    yield
    record(Classification(
        reason="honest_deviation", outcome="xfail", severity="LOW", kind="metadata",
        label="teardown deviation", operation="C_CloseSession",
        summary="teardown deviation",
    ))

def test_setup_xfail(setup_deviation):
    raise AssertionError("setup xfail must prevent this call")

def test_independent_after_setup():
    pass

def test_strict_raw_point_encoding():
    C.xfail_as(
        "honest_deviation", kind="metadata", label="strict raw EC point",
        operation="C_GetAttributeValue", summary="raw CKA_EC_POINT encoding",
    )

def test_operational_wrong_point():
    C.fail_as(
        "wrong_result", kind="crypto", label="operational wrong EC point",
        operation="C_DeriveKey", summary="point is not on expected curve",
    )

def test_measurement_then_cleanup(cleanup_failure):
    record(Classification(
        reason="accepted_invalid", outcome="fail", severity="CRITICAL", kind="crypto",
        label="provider measurement", operation="C_Verify",
        summary="provider accepted invalid signature",
    ))

def test_real_child_crash():
    marker = Path({str(marker)!r})
    if marker.exists():
        return
    marker.write_text("first attempt", encoding="utf-8")
    if sys.platform == "win32":
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel.TerminateProcess(kernel.GetCurrentProcess(), 0xC0000005)
    else:
        os.kill(os.getpid(), signal.SIGSEGV)

def test_independent_after_crash():
    pass

def test_teardown_finding(teardown_deviation):
    pass

def test_no_teardown_leak():
    pass
"""
    )
    state_path = pytester.path / "state.json"
    json_path = pytester.path / "results.json"
    jsonl_path = pytester.path / "report.jsonl"
    junit_path = pytester.path / "results.xml"
    monkeypatch.setattr(
        file_runner_mod,
        "_unit_plugin_addopts",
        lambda _path: "-p pkcs11-check -p pytest_reportlog -p timeout",
    )

    exit_code = run_isolated_pytest_units(
        [str(target)],
        [],
        timeout=15,
        state_file=state_path,
        policy_file=None,
        report_config=IsolatedReportConfig("json", json_path, jsonl_path=jsonl_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    assert exit_code == 1
    records = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records, "the raw JSONL must not be empty"

    test_reports = [r for r in records if r.get("$report_type", "TestReport") == "TestReport"]
    phase_reports = {
        (str(record.get("nodeid")), str(record.get("when"))): record for record in test_reports
    }

    def phase(name: str, when: str) -> dict[str, object]:
        suffix = f"::test_{name}"
        return next(
            report
            for (nodeid, report_when), report in phase_reports.items()
            if nodeid.endswith(suffix) and report_when == when
        )

    # --- property: setup XFAIL carries operation provenance and blocks the call -----------
    setup = _classifications(phase("setup_xfail", "setup"))
    assert [(item["reason"], item["operation"]) for item in setup] == [
        ("not_operational", "C_OpenSession")
    ]

    # --- property: an independent testcase still runs and passes after setup xfail --------
    assert phase("independent_after_setup", "call")["outcome"] == "passed"
    assert _classifications(phase("independent_after_setup", "call")) == []

    # --- property: strict representation XFAIL and operational wrong-result FAIL stay
    # separate records -- neither absorbs nor masks the other -----------------------------
    strict = _classifications(phase("strict_raw_point_encoding", "call"))
    assert [(item["reason"], item["operation"]) for item in strict] == [
        ("honest_deviation", "C_GetAttributeValue")
    ]
    assert phase("strict_raw_point_encoding", "call")["outcome"] == "skipped"

    operational = _classifications(phase("operational_wrong_point", "call"))
    assert [(item["reason"], item["outcome"]) for item in operational] == [("wrong_result", "fail")]
    assert phase("operational_wrong_point", "call")["outcome"] == "failed", (
        "the operational wrong-result FAIL must never be hidden by the earlier "
        "compatibility (strict-encoding) evidence"
    )

    # --- property: a harness cleanup failure does not erase the preceding provider
    # measurement -- both phases retain their own finding independently ---------------------
    measurement = _classifications(phase("measurement_then_cleanup", "call"))
    assert [item["reason"] for item in measurement] == ["accepted_invalid"]
    assert phase("measurement_then_cleanup", "call")["outcome"] == "failed"
    cleanup = _classifications(phase("measurement_then_cleanup", "teardown"))
    assert [item["reason"] for item in cleanup] == ["harness_error"]
    assert phase("measurement_then_cleanup", "teardown")["outcome"] == "failed"

    # --- property: every serialized setup/call/teardown/retry observation remains
    # inspectable exactly once -- a retried phase is a distinct, additional observation,
    # never an overwrite of the earlier one. Naive (nodeid, when) keying (as in the
    # `phase_reports` dict above) silently collapses this; assert on the raw stream instead.
    crash_setup_reports = [
        r
        for r in test_reports
        if str(r.get("nodeid", "")).endswith("::test_real_child_crash") and r.get("when") == "setup"
    ]
    assert len(crash_setup_reports) == 2, (
        "both the crashed attempt's setup and the retried attempt's setup must be "
        "independently inspectable, not collapsed to one"
    )
    assert [r["outcome"] for r in crash_setup_reports] == ["passed", "passed"]
    isolated_markers = [r for r in records if r.get("$report_type") == "IsolatedUnitReport"]
    assert len(isolated_markers) >= 2, "at least the crashed and the retried attempt are marked"
    attempts_seen = [m["attempt"] for m in isolated_markers]
    assert attempts_seen == sorted(attempts_seen), "attempt numbers must be non-decreasing"

    # Every other (non-retried) testcase's phases each appear exactly once (no drop, no dup).
    key_counts = Counter((str(r.get("nodeid")), str(r.get("when"))) for r in test_reports)
    for (nodeid, when), count in key_counts.items():
        if nodeid.endswith("::test_real_child_crash"):
            continue
        assert count == 1, f"{nodeid} phase {when} observed {count} times, expected exactly 1"

    # --- property: an independent testcase still runs and still passes after a
    # neighbouring real crash --------------------------------------------------------------
    assert phase("independent_after_crash", "call")["outcome"] == "passed"
    assert _classifications(phase("independent_after_crash", "call")) == []

    # --- property: a real crash remains a finding; a clean response, a positive exit, or a
    # missing marker is never falsely reported as a crash -----------------------------------
    process_reports = [r for r in records if r.get("$report_type") == "ProcessReport"]
    assert len(process_reports) == 3, "crashed attempt + confirmation + retry"
    signal_terminations = [
        r for r in process_reports if r["observation"]["termination"]["kind"] == "signal"
    ]
    clean_terminations = [
        r for r in process_reports if r["observation"]["termination"]["kind"] == "exit"
    ]
    assert len(signal_terminations) == 1, "only the genuine SIGSEGV counts as a crash"
    assert len(clean_terminations) == 2, (
        "the confirmation and retry runs both exited cleanly (exit code 0) and must "
        "never be reported as crashes"
    )
    assert all(r["observation"]["termination"]["raw_code"] == 0 for r in clean_terminations)
    assert signal_terminations[0]["observation"]["termination"]["raw_code"] == -11

    # Reuse the existing file-runner helpers directly on the boundary values they exist to
    # classify, rather than re-deriving crash detection here.
    assert file_runner_mod._status_from_returncode(-11) == "crashed"
    assert file_runner_mod._status_from_returncode(0) == "passed"
    assert file_runner_mod._status_from_returncode(1) == "failed", (
        "a positive exit code is an ordinary failure, never a crash"
    )

    crashed_slice = [
        r for r in test_reports if str(r.get("nodeid", "")).endswith("::test_real_child_crash")
    ][:1]
    culprit, completed = file_runner_mod._identify_crash_culprit_from_records(crashed_slice)
    assert culprit is not None and culprit.endswith("::test_real_child_crash"), (
        "a real unfinished setup-with-no-teardown must be identified as the crash culprit"
    )

    fully_completed_slice = [
        r
        for r in test_reports
        if str(r.get("nodeid", "")).endswith("::test_independent_after_setup")
    ]
    no_culprit, completed_ids = file_runner_mod._identify_crash_culprit_from_records(
        fully_completed_slice
    )
    assert no_culprit is None, (
        "a fully completed testcase (setup+call+teardown, no missing marker) must never "
        "be falsely reported as a crash culprit"
    )
    assert completed_ids == [str(fully_completed_slice[0]["nodeid"])]
    assert file_runner_mod._identify_crash_culprit_from_records([]) == (None, [])

    # --- property: teardown finding is retained and no classification leaks into the
    # next testcase --------------------------------------------------------------------
    teardown_finding = _classifications(phase("teardown_finding", "teardown"))
    assert [item["reason"] for item in teardown_finding] == ["honest_deviation"]
    assert _classifications(phase("teardown_finding", "call")) == []
    assert _classifications(phase("no_teardown_leak", "call")) == []
    assert _classifications(phase("no_teardown_leak", "setup")) == []
    assert _classifications(phase("no_teardown_leak", "teardown")) == []

    groups = extract_groups(jsonl_path, crashes=[])
    grouped_reasons: dict[str, int] = {}
    for group in groups:
        reason = str(group["reason"])
        grouped_reasons[reason] = grouped_reasons.get(reason, 0) + int(group["count"])
    assert grouped_reasons == {
        "accepted_invalid": 1,
        "harness_error": 1,
        "honest_deviation": 2,
        "not_operational": 1,
        "wrong_result": 1,
    }
    # honest_deviation's count of 2 is the strict-encoding xfail PLUS the teardown-finding
    # xfail on a *different* testcase -- confirm both contribute (neither is a duplicate of
    # the other) and that the unrelated wrong_result FAIL group was not collapsed into it.
    assert grouped_reasons["wrong_result"] == 1
    assert grouped_reasons["honest_deviation"] == 2

    # --- property (M1): F11 attribution is not merely present but actually effective on
    # this real, writer-produced stream (the exact cache/assembly pipeline under test here,
    # crash-retry accumulation included) -- every classification occurrence must be
    # attributed to the isolation marker that precedes it. A marker that is written but
    # immediately wiped by the reader's SessionStart reset (M1) leaves every occurrence
    # unattributed while still passing every other assertion above; assert the positive
    # claim directly rather than relying only on `_assert_observability_gate_accepts`
    # (which deliberately never thresholds `unclassified`, and would not catch this).
    for group in groups:
        assert group["unattributed_count"] == 0, (
            f"{group['reason']} occurrences in {group['test_file']!r} lost isolation-marker "
            "attribution -- F11 attribution is inert on this writer-produced stream"
        )

    unified = json.loads(json_path.read_text(encoding="utf-8"))
    summary = unified["summary"]
    assert summary["crashed"] == 1
    assert summary["crashed"] == len(signal_terminations)
    assert summary["failed"] >= 1
    assert summary["error"] >= 1
    assert summary["xfailed"] >= 3
    assert summary["passed"] >= 2
    outcome_keys = (
        "passed",
        "failed",
        "skipped",
        "xfailed",
        "xpassed",
        "error",
        "crashed",
        "timeout",
        "crash_limited",
    )
    for key in outcome_keys:
        assert summary[key] == sum(int(unit["counts"].get(key, 0)) for unit in unified["units"])
    assert summary["total"] == sum(int(summary[key]) for key in outcome_keys)

    state = load_run_state(state_path)
    assert state is not None
    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit=state.report_records_by_unit,
    )
    write_isolated_junit_report(junit_path, state, per_unit_details=details)
    junit = junit_path.read_text(encoding="utf-8")
    assert 'type="crashed"' in junit
    assert "isolated unit crashed" in junit
    assert "provider accepted invalid signature" in junit
    assert "cleanup failed after provider measurement" in junit
    assert "raw CKA_EC_POINT encoding" in junit
    assert "point is not on expected curve" in junit

    # ==========================================================================
    # Observability fixtures (F11 slices A/B, reused unmodified).
    # ==========================================================================

    # --- clean fixture: this very run's own raw report.jsonl. It never emits reason ==
    # "unclassified" (every finding above was emitted via classify()/record()), so reading
    # it back through slice A's extractor must be `complete` with a genuine zero (not `--`,
    # not a fabricated absence) -----------------------------------------------------------
    clean_evidence = extract_quality_report_evidence_from_jsonl([jsonl_path])
    assert clean_evidence.status == "complete"
    assert clean_evidence.unclassified is not None
    assert clean_evidence.unclassified.occurrences == 0
    assert clean_evidence.unclassified.unique_testcases == 0
    _assert_observability_gate_accepts(clean_evidence)

    # --- dirty fixture: a deliberately explained raw-unclassified source. Constructed
    # directly (see module docstring for why a live pytester run cannot exercise the
    # testcases/-scoped synthetic-injection gate without a real --p11-module), but built
    # from production's OWN Classification/serialize() so the shape is byte-faithful to
    # what `_synthetic_unclassified_record` actually emits. ------------------------------
    dirty_jsonl_path = pytester.path / "dirty-report.jsonl"
    legacy_file = "src/pkcs11_check/testcases/test_legacy_provider.py"
    legacy_fail_nodeid = f"{legacy_file}::test_legacy_unmigrated_fail"
    legacy_xfail_nodeid = f"{legacy_file}::test_legacy_unmigrated_xfail"

    def _unclassified_property(nodeid: str) -> list[object]:
        synthetic = Classification(
            reason="unclassified",
            outcome="fail",
            severity="HIGH",
            label=nodeid,
            summary="raw pytest.fail/xfail with no classification",
            detail={"raw": True},
        )
        return [["pkcs11_classification", serialize([synthetic])]]

    dirty_records = [
        {"$report_type": "IsolatedUnitReport", "target": legacy_file, "attempt": 0},
        {
            "$report_type": "TestReport",
            "nodeid": legacy_fail_nodeid,
            "when": "call",
            "outcome": "failed",
            "user_properties": _unclassified_property(legacy_fail_nodeid),
        },
        {
            "$report_type": "TestReport",
            "nodeid": legacy_xfail_nodeid,
            "when": "call",
            "outcome": "skipped",
            "wasxfail": "unmigrated legacy skip",
            "user_properties": _unclassified_property(legacy_xfail_nodeid),
        },
    ]
    dirty_jsonl_path.write_text(
        "".join(json.dumps(record) + "\n" for record in dirty_records), encoding="utf-8"
    )

    dirty_evidence = extract_quality_report_evidence_from_jsonl([dirty_jsonl_path])
    assert dirty_evidence.status == "complete"
    assert dirty_evidence.unclassified is not None
    assert dirty_evidence.unclassified.occurrences == 2
    assert dirty_evidence.unclassified.unique_testcases == 2
    assert dirty_evidence.unclassified.phase_counts == {"call": 2}
    assert dirty_evidence.unclassified.per_file_counts == {legacy_file: 2}
    assert dirty_evidence.unclassified.unattributed_occurrences == 0
    assert len(dirty_evidence.unclassified.samples) == 2
    explained_summaries = {
        sample.classification.get("summary") for sample in dirty_evidence.unclassified.samples
    }
    assert explained_summaries == {"raw pytest.fail/xfail with no classification"}, (
        "a nonzero unclassified count must be reported WITH its explanation, not just a bare number"
    )

    # The central F11 disposition guard: a nonzero unclassified count is accepted by the
    # exact same gate function as the zero-count clean fixture -- no threshold anywhere.
    _assert_observability_gate_accepts(dirty_evidence)
    assert dirty_evidence.unclassified.occurrences > 0, "the dirty fixture must be genuinely dirty"

    # Prove the count is rendered and explained, not silently suppressed (reusing slice B's
    # renderer, not re-deriving it).
    dirty_audit = build_quality_audit(quality_report_evidence=dirty_evidence)
    rendered = render_provider("dirty-fixture", [], quality=dirty_audit)
    assert "unclassified occurrences: 2 across 2 logical testcase(s)" in rendered
    assert "unclassified occurrences: --" not in rendered
    assert "unclassified occurrences: 0" not in rendered
