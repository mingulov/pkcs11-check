from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from pkcs11_check.classification import clear, get_records
from pkcs11_check.testcases import test_interface_negotiation as tin

pytest_plugins = ["pytester"]
pytestmark = pytest.mark.usefixtures("classification_report_plugin_enabled")


def _raw(missing: set[str]) -> SimpleNamespace:
    return SimpleNamespace(missing_function_list_names=lambda: set(missing))


def test_strict_selected_function_table_null_is_metadata_xfail() -> None:
    clear()

    with pytest.raises(pytest.xfail.Exception, match="NULL C_GetOperationState"):
        tin.TestInterfaceVersion().test_selected_function_table_entry(
            _raw({"C_GetOperationState"}), "C_GetOperationState"
        )

    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.kind == "metadata"
    assert record.label == "selected function table"


def test_strict_selected_function_table_passes_independently() -> None:
    clear()

    tin.TestInterfaceVersion().test_selected_function_table_entry(
        _raw({"C_GetOperationState"}), "C_SetOperationState"
    )

    assert get_records() == []


def test_strict_deviation_does_not_block_later_pytest_item(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(
        test_function_table="""
from types import SimpleNamespace

import pytest

from pkcs11_check.testcases import test_interface_negotiation as tin


def _session(missing):
    return SimpleNamespace(missing_function_list_names=lambda: set(missing))


@pytest.mark.parametrize("name", ["C_Initialize", "C_GetSlotList", "C_OpenSession"])
def test_null_entry_is_reported(name):
    tin.TestInterfaceVersion().test_selected_function_table_entry(
        _session({name}), name
    )


def test_independent_entry_still_runs():
    tin.TestInterfaceVersion().test_selected_function_table_entry(
        _session({"C_Initialize"}), "C_Finalize"
    )
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")
    result.assert_outcomes(xfailed=3, passed=1)

    reports = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    calls = [
        report
        for report in reports
        if report.get("$report_type") == "TestReport" and report.get("when") == "call"
    ]
    assert len(calls) == 4
    null_calls = [report for report in calls if "null_entry" in str(report["nodeid"])]
    assert {
        name
        for name in ("C_Initialize", "C_GetSlotList", "C_OpenSession")
        if any(name in str(report["nodeid"]) for report in null_calls)
    } == {"C_Initialize", "C_GetSlotList", "C_OpenSession"}
    independent_call = next(
        report for report in calls if "independent_entry" in str(report["nodeid"])
    )
    assert {report["outcome"] for report in null_calls} == {"skipped"}
    for null_call in null_calls:
        null_properties = dict(null_call.get("user_properties", []))
        assert null_properties["pkcs11_classification"][0]["reason"] == "honest_deviation"
    assert independent_call["outcome"] == "passed"
    assert "pkcs11_classification" not in dict(independent_call.get("user_properties", []))


def test_load_only_raw_does_not_bootstrap_a_session(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def missing_function_list_names() -> set[str]:
        return set()

    spy = SimpleNamespace(missing_function_list_names=missing_function_list_names)
    for name in ("C_Initialize", "C_GetSlotList", "C_OpenSession"):
        setattr(spy, name, lambda *_args, _name=name: calls.append(_name))
    monkeypatch.setattr(tin.RawPKCS11, "from_lib", lambda _path: spy)
    raw = tin._load_only_raw(SimpleNamespace(module="module.so"))

    tin.TestInterfaceVersion().test_selected_function_table_entry(raw, "C_Initialize")
    assert calls == []


def test_load_only_raw_does_not_hide_loader_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_loader(_path: str) -> object:
        raise RuntimeError("loader failed")

    monkeypatch.setattr(tin.RawPKCS11, "from_lib", fail_loader)
    with pytest.raises(RuntimeError, match="loader failed"):
        tin._load_only_raw(SimpleNamespace(module="module.so"))
