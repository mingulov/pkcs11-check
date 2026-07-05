"""The shared report-log JSONL reader (core.report_log) that the run/report/merge layers use."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.core.report_log import (
    iter_report_log_records,
    map_report_outcome,
    user_property,
    user_property_names,
)


def test_iter_yields_only_dict_records_skipping_blank_and_garbage(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text(
        '{"a": 1}\n'
        "\n"  # blank line skipped
        "   \n"  # whitespace-only skipped
        "not json\n"  # undecodable skipped
        "[1, 2, 3]\n"  # non-dict JSON skipped
        '  {"b": 2}  \n',  # surrounding whitespace stripped
        encoding="utf-8",
    )
    records = list(iter_report_log_records(p))
    assert records == [{"a": 1}, {"b": 2}]


def test_iter_is_silent_on_missing_file(tmp_path: Path) -> None:
    assert list(iter_report_log_records(tmp_path / "nope.jsonl")) == []


def test_map_report_outcome_covers_xfail_and_xpass() -> None:
    assert map_report_outcome("passed", None) == "passed"
    assert map_report_outcome("failed", None) == "failed"
    assert map_report_outcome("skipped", None) == "skipped"
    assert map_report_outcome("passed", "known bug") == "xpassed"
    assert map_report_outcome("skipped", "known bug") == "xfailed"
    # a strict-xfail failure stays failed even with wasxfail set
    assert map_report_outcome("failed", "known bug") == "failed"


def test_user_property_returns_first_matching_value() -> None:
    record = {"user_properties": [["k1", "v1"], ["k2", {"nested": True}], ["k1", "v-dup"]]}
    assert user_property(record, "k2") == {"nested": True}
    assert user_property(record, "k1") == "v1"  # first match
    assert user_property(record, "absent") is None
    assert user_property({}, "k1") is None  # no user_properties key


def test_user_property_names_returns_all_property_names() -> None:
    record = {"user_properties": [["k1", "v1"], ["k2", "v2"], []]}  # empty pair ignored
    assert user_property_names(record) == {"k1", "k2"}
    assert user_property_names({}) == set()
