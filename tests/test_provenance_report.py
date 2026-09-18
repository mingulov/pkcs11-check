"""Tests for the ProvenanceReport JSONL record (framework issue #19b)."""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import extract_provenance_from_jsonl
from pkcs11_check.provenance import build_provenance_record


def _write_jsonl(path: Path, records: list[dict]) -> None:  # type: ignore[type-arg]
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def test_builder_prefers_env_override() -> None:
    record = build_provenance_record(
        env={"PKCS11_CHECK_FRAMEWORK_VERSION": "9.9.9-test"}, repo_root=None
    )
    assert record["framework"]["version"] == "9.9.9-test"
    assert record["framework"]["source"] == "env"


def test_builder_falls_back_to_package_version() -> None:
    record = build_provenance_record(env={}, repo_root=None)
    assert record["framework"]["version"]
    assert record["framework"]["source"] == "package"


def test_extract_first_provenance_record_wins(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    _write_jsonl(
        jsonl,
        [
            {"nodeid": "some_test::foo", "outcome": "passed"},
            {
                "$report_type": "ProvenanceReport",
                "framework": {"version": "1.2.3", "dirty": False, "source": "git-describe"},
            },
            {
                "$report_type": "ProvenanceReport",
                "framework": {"version": "9.9.9", "dirty": False, "source": "env"},
            },
        ],
    )
    result = extract_provenance_from_jsonl(jsonl)
    assert result is not None
    assert result["version"] == "1.2.3"


def test_extract_returns_none_when_absent(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    _write_jsonl(jsonl, [{"nodeid": "x", "outcome": "passed"}])
    assert extract_provenance_from_jsonl(jsonl) is None


def test_extract_survives_corrupt_byte_before_provenance(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    with jsonl.open("wb") as fh:
        fh.write(b'{"nodeid": "x", "outcome": "passed"}\n')
        fh.write(b'{"truncated": "\xff\xfe broken mid-line"\n')
        fh.write(
            json.dumps(
                {
                    "$report_type": "ProvenanceReport",
                    "framework": {"version": "9.9.9", "source": "env"},
                }
            ).encode("utf-8")
            + b"\n"
        )
    result = extract_provenance_from_jsonl(jsonl)
    assert result is not None
    assert result["version"] == "9.9.9"


def test_sessionfinish_emits_provenance_report(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import pytest

    import pkcs11_check.plugin as plugin
    from pkcs11_check.plugin import pytest_sessionfinish

    monkeypatch.setenv("PKCS11_CHECK_FRAMEWORK_VERSION", "9.9.9-test")
    monkeypatch.setattr(plugin, "_finalize_on_teardown", lambda config, raw: "ok")

    written: list[dict] = []  # type: ignore[type-arg]

    class _ReportLog:
        def _write_json_data(self, record):  # type: ignore[no-untyped-def]
            written.append(record)

    class _Raw:
        def available_function_names(self):  # type: ignore[no-untyped-def]
            return set()

    class _Config:
        stash = {
            plugin._CUMULATIVE_FUNCTIONS: set(),
            plugin._RAW_INSTANCE: _Raw(),
        }
        _report_log_plugin = _ReportLog()

        def getoption(self, name, default=None):  # type: ignore[no-untyped-def]
            if name == "p11_module":
                return "/tmp/fake-module.so"
            return default

    class _Session:
        config = _Config()
        exitstatus = pytest.ExitCode.OK

    pytest_sessionfinish(_Session(), int(pytest.ExitCode.OK))  # type: ignore[arg-type]

    provenance = [r for r in written if r.get("$report_type") == "ProvenanceReport"]
    assert len(provenance) == 1
    assert provenance[0]["framework"]["version"] == "9.9.9-test"
    assert provenance[0]["framework"]["source"] == "env"


def test_report_output_surfaces_jsonl_harness_provenance(tmp_path: Path) -> None:
    from pkcs11_check.report.__main__ import main

    report = tmp_path / "report.jsonl"
    _write_jsonl(
        report,
        [
            {
                "$report_type": "ProvenanceReport",
                "framework": {"version": "9.9.9-test", "source": "env"},
            },
            {
                "$report_type": "TestReport",
                "when": "call",
                "nodeid": "t/test_x.py::a",
                "outcome": "passed",
                "user_properties": [],
            },
        ],
    )
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"summary": {}}), encoding="utf-8")
    out = tmp_path / "out"

    rc = main(
        [
            "--report-log",
            str(report),
            "--results-json",
            str(results),
            "--provider",
            "demo",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    assert "by pkcs11-check 9.9.9-test" in (out / "demo.md").read_text(encoding="utf-8")
