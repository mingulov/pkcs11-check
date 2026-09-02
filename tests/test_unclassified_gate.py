"""Runtime ``unclassified`` gate (Phase 5.1).

Every testcase that ends as a ``fail``/``xfail`` WITHOUT emitting a classification
gets a synthetic ``reason="unclassified"`` record auto-injected by
``_attach_classification_to_report``, so the report stays 100% covered and the live
``unclassified`` count IS the Phase 7 migration backlog. The gate is scoped to
testcase items (path under ``testcases/``); raw ``pytest.fail``/``pytest.xfail`` in
meta-tests (under ``tests/``) must NOT be flagged.

Why a direct unit test (plan approach *c*), not a pytester run (approaches *a*/*b*):
the pkcs11_check plugin is loaded in any inner pytester subprocess via its
``pytest11`` entry point, and ``pytest_collection_modifyitems`` *skips every item
under ``testcases/`` when no ``--p11-module`` is given* (plugin.py: "If no module
specified, skip all tests in testcases/"). A pytester file placed under ``testcases/``
to satisfy ``_is_testcase_item`` therefore never reaches the ``call`` phase where the
synthetic record is injected (it is skipped at setup), so approaches *a*/*b* cannot
exercise the gate without a real loaded module. Calling the hook helper directly with
a fake item/report drives the exact gate branches deterministically.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.classification import Classification, clear, record
from pkcs11_check.plugin import _attach_classification_to_report, _is_testcase_item


def _as_item(ns: SimpleNamespace) -> pytest.Item:
    """The plugin helpers read item attributes via ``getattr`` only, so a
    duck-typed ``SimpleNamespace`` is a valid stand-in for a real ``pytest.Item``."""
    return cast("pytest.Item", ns)


@pytest.fixture(autouse=True)
def _clear_classification_store() -> Any:
    """Isolate the process-global classification record store around each test."""
    clear()
    yield
    clear()


def _testcase_item(nodeid: str = "src/pkcs11_check/testcases/test_x.py::test_y") -> pytest.Item:
    item = _as_item(
        SimpleNamespace(path=Path("/repo/src/pkcs11_check/testcases/test_x.py"), nodeid=nodeid)
    )
    assert _is_testcase_item(item), "fixture item must be recognised as a testcase item"
    return item


def _meta_item(nodeid: str = "tests/test_meta.py::test_y") -> pytest.Item:
    item = _as_item(SimpleNamespace(path=Path("/repo/tests/test_meta.py"), nodeid=nodeid))
    assert not _is_testcase_item(item), "fixture item must NOT be a testcase item"
    return item


def _call_report(
    outcome: str,
    *,
    when: str = "call",
    wasxfail: str | None = None,
    message: str = "",
) -> Any:
    report = SimpleNamespace(
        when=when,
        outcome=outcome,
        longrepr=message,
        user_properties=[],
    )
    if wasxfail is not None:
        report.wasxfail = wasxfail
    return report


def _call_info(exc: BaseException) -> Any:
    return SimpleNamespace(excinfo=SimpleNamespace(type=type(exc), value=exc))


def _classification_prop(report: Any) -> list[dict[str, Any]] | None:
    for name, value in report.user_properties:
        if name == "pkcs11_classification":
            return list(value)
    return None


def test_raw_fail_in_testcase_yields_synthetic_unclassified() -> None:
    """A raw ``pytest.fail()`` (outcome == "failed") in a testcase item with no emitted
    record gets exactly one synthetic ``unclassified`` record appended."""
    item = _testcase_item()
    report = _call_report("failed", message="module returned the wrong code")

    _attach_classification_to_report(item, report)

    records = _classification_prop(report)
    assert records is not None, "raw testcase fail must be auto-classified"
    assert len(records) == 1
    rec = records[0]
    assert rec["reason"] == "unclassified"
    assert rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH"
    assert rec["detail"] == {"raw": True}
    assert rec["label"] == item.nodeid
    assert "module returned the wrong code" in rec["summary"]


def test_direct_ctypes_access_violation_yields_synthetic_crash() -> None:
    item = _testcase_item()
    report = _call_report(
        "failed", message="OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF"
    )

    _attach_classification_to_report(
        item,
        report,
        call=_call_info(OSError("exception: access violation reading 0xFFFFFFFFFFFFFFFF")),
    )

    records = _classification_prop(report)
    assert records is not None
    assert records[0]["reason"] == "crash"
    assert records[0]["detail"] == {
        "windows_status": 0xC0000005,
        "signal": "EXCEPTION_ACCESS_VIOLATION",
    }


@pytest.mark.parametrize("when", ["setup", "teardown"])
def test_fixture_ctypes_access_violation_yields_synthetic_crash(when: str) -> None:
    report = _call_report(
        "failed",
        when=when,
        message="OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
    )

    _attach_classification_to_report(
        _testcase_item(),
        report,
        call=_call_info(OSError("exception: access violation reading 0xFFFFFFFFFFFFFFFF")),
    )

    records = _classification_prop(report)
    assert records is not None
    assert [record["reason"] for record in records] == ["crash"]


@pytest.mark.parametrize("when", ["setup", "teardown"])
def test_ordinary_fixture_oserror_is_not_synthetically_classified(when: str) -> None:
    report = _call_report("failed", when=when, message="OSError: provider I/O error")

    _attach_classification_to_report(
        _testcase_item(), report, call=_call_info(OSError("provider I/O error"))
    )

    assert _classification_prop(report) is None


def test_ordinary_oserror_stays_synthetic_unclassified() -> None:
    report = _call_report("failed", message="OSError: ordinary provider error")

    _attach_classification_to_report(
        _testcase_item(), report, call=_call_info(OSError("ordinary provider error"))
    )

    records = _classification_prop(report)
    assert records is not None
    assert records[0]["reason"] == "unclassified"


def test_nested_wrapper_with_access_violation_text_stays_synthetic_unclassified() -> None:
    from _pytest.outcomes import Failed

    report = _call_report(
        "failed", message="Failed: child subprocess failed: exception: access violation reading 0"
    )

    _attach_classification_to_report(
        _testcase_item(),
        report,
        call=_call_info(Failed("child subprocess failed: exception: access violation reading 0")),
    )

    records = _classification_prop(report)
    assert records is not None
    assert records[0]["reason"] == "unclassified"


def test_raw_xfail_in_testcase_yields_synthetic_unclassified() -> None:
    """An imperative ``pytest.xfail()`` is a skipped report carrying ``wasxfail``; it is
    also covered by the gate."""
    item = _testcase_item()
    report = _call_report("skipped", wasxfail="advertised but not operational")

    _attach_classification_to_report(item, report)

    records = _classification_prop(report)
    assert records is not None, "raw testcase xfail must be auto-classified"
    assert len(records) == 1
    assert records[0]["reason"] == "unclassified"


def test_synthetic_summary_falls_back_when_no_message() -> None:
    """With no longrepr message, the synthetic record uses the default summary string."""
    report = _call_report("failed", message="")

    _attach_classification_to_report(_testcase_item(), report)

    records = _classification_prop(report)
    assert records is not None
    assert records[0]["summary"] == "raw pytest.fail/xfail with no classification"


def test_non_testcase_fail_is_not_flagged() -> None:
    """A raw fail in a NON-testcase (meta-test) item must NOT get the synthetic record:
    the gate must not leak into meta-tests that legitimately use ``pytest.fail``/``xfail``."""
    report = _call_report("failed", message="a legitimate meta-test assertion")

    _attach_classification_to_report(_meta_item(), report)

    assert _classification_prop(report) is None, (
        "non-testcase fail must not be auto-classified (no gate leakage into meta-tests)"
    )


def test_passing_testcase_is_not_flagged() -> None:
    """A passing testcase (outcome == "passed", no emitted record) gets nothing injected:
    the synthetic record is only for fail/xfail."""
    report = _call_report("passed")

    _attach_classification_to_report(_testcase_item(), report)

    assert _classification_prop(report) is None


def test_emitted_record_takes_precedence_over_synthetic() -> None:
    """A testcase that emitted a real classification keeps it; no synthetic injection."""
    item = _testcase_item()
    report = _call_report("failed", message="ignored because a real record exists")

    record(
        Classification(
            reason="self_contradiction",
            outcome="fail",
            severity="HIGH",
            kind="policy",
            label="probe",
        )
    )
    _attach_classification_to_report(item, report)

    records = _classification_prop(report)
    assert records is not None
    assert len(records) == 1
    assert records[0]["reason"] == "self_contradiction"
    assert records[0]["reason"] != "unclassified"


def test_only_call_phase_is_classified() -> None:
    """Setup/teardown reports are never touched (gate runs on the call phase only)."""
    report = SimpleNamespace(when="setup", outcome="failed", longrepr="x", user_properties=[])

    _attach_classification_to_report(_testcase_item(), report)

    assert _classification_prop(report) is None
