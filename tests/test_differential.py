"""Tests for the N-way differential cross-provider oracle (core/differential.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.cli.app import app
from pkcs11_check.core.differential import (
    find_disagreements,
    is_kat_nodeid,
    load_provider_outcomes,
    provenance_fingerprint,
)
from tests._plain_cli_runner import PlainCliRunner

# Strips ANSI so assertions on message content hold regardless of the caller's
# terminal environment (FORCE_COLOR/TERM). See tests/_plain_cli_runner.py.
runner = PlainCliRunner()


def _write_records(path: Path, records: list[object]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def _write_report(path: Path, nodeid_outcomes: dict[str, str]) -> None:
    records: list[dict[str, object]] = [{"$report_type": "SessionStart", "pytest_version": "test"}]
    records.extend(
        {
            "$report_type": "TestReport",
            "when": "call",
            "outcome": outcome,
            "nodeid": nodeid,
        }
        for nodeid, outcome in nodeid_outcomes.items()
    )
    records.append({"$report_type": "SessionFinish", "exitstatus": 0})
    _write_records(path, records)


_KAT_A = "src/pkcs11_check/testcases/wycheproof/test_rsa.py::test_kat[a]"
_KAT_B = "src/pkcs11_check/testcases/acvp/aes/test_cbc.py::test_kat[b]"
_TEST_DATA = [
    {
        "name": "wycheproof",
        "repo": "C2SP/wycheproof",
        "commit": "abc123",
        "archive_sha256": "deadbeef",
        "present": True,
    }
]


def _write_artifact(
    root: Path,
    name: str,
    nodeid_outcomes: dict[str, str],
    *,
    framework_version: str = "v0.1.8",
    test_data: list[dict[str, object]] | None = None,
) -> Path:
    artifact = root / name
    artifact.mkdir()
    report = artifact / "report.jsonl"
    _write_report(report, nodeid_outcomes)
    (artifact / "results.json").write_text(
        json.dumps(
            {
                "provenance": {
                    "framework": {"version": framework_version, "dirty": False},
                    "test_data": _TEST_DATA if test_data is None else test_data,
                }
            }
        ),
        encoding="utf-8",
    )
    return report


def test_differential_requires_sibling_results_json(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {"t.py::x": "passed"})
    b = _write_artifact(tmp_path, "b", {"t.py::x": "passed"})
    a.with_name("results.json").unlink()
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", "--all"])
    assert result.exit_code == 2
    assert "sibling results.json not found" in result.output


def test_differential_rejects_framework_mismatch(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {"t.py::x": "passed"})
    b = _write_artifact(tmp_path, "b", {"t.py::x": "passed"}, framework_version="v0.1.7")
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", "--all"])
    assert result.exit_code == 2
    assert "incompatible framework/test-data provenance" in result.output


def test_differential_rejects_test_data_mismatch(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {"t.py::x": "passed"})
    changed = [{**_TEST_DATA[0], "commit": "different"}]
    b = _write_artifact(tmp_path, "b", {"t.py::x": "passed"}, test_data=changed)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", "--all"])
    assert result.exit_code == 2
    assert "incompatible framework/test-data provenance" in result.output


def test_differential_override_is_visible_once(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {"t.py::x": "passed"})
    b = _write_artifact(tmp_path, "b", {"t.py::x": "passed"})
    b.with_name("results.json").unlink()
    result = runner.invoke(
        app,
        [
            "differential",
            f"a={a}",
            f"b={b}",
            "--all",
            "--allow-unverified-provenance",
        ],
    )
    assert result.exit_code == 0
    assert result.output.count("WARNING: provenance verification disabled") == 1


def test_differential_rejects_malformed_results_json(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    b.with_name("results.json").write_text("{not json}\n", encoding="utf-8")
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "cannot read provenance" in result.output


def test_differential_rejects_non_utf8_results_json(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    b.with_name("results.json").write_bytes(b"\xff\xfe")
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "cannot read provenance" in result.output


@pytest.mark.parametrize("error", [OSError("denied"), RuntimeError("path loop")])
def test_differential_translates_results_is_file_error(tmp_path, monkeypatch, error) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    blocked = b.with_name("results.json")
    original_is_file = Path.is_file

    def deny_is_file(path: Path, *args, **kwargs):
        if path == blocked:
            raise error
        return original_is_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", deny_is_file)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "cannot read provenance" in result.output


def test_differential_override_keeps_report_validation_mandatory(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "malformed.jsonl"
    b.write_text("{not json}\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["differential", f"a={a}", f"b={b}", "--allow-unverified-provenance"],
    )
    assert result.exit_code == 2
    assert "malformed report log" in result.output


def test_differential_override_keeps_comparability_mandatory(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_B: "passed"})
    result = runner.invoke(
        app,
        ["differential", f"a={a}", f"b={b}", "--allow-unverified-provenance"],
    )
    assert result.exit_code == 2
    assert "no comparable deterministic KAT node-ids" in result.output


def test_provenance_fingerprint_normalizes_test_data_order() -> None:
    first = {
        "provenance": {
            "framework": {"version": "v0.1.8", "dirty": False},
            "test_data": [_TEST_DATA[0], {**_TEST_DATA[0], "name": "acvp"}],
        }
    }
    second = {
        "provenance": {
            "framework": {"version": "v0.1.8", "dirty": False},
            "test_data": list(reversed(first["provenance"]["test_data"])),
        }
    }
    assert provenance_fingerprint(first) == provenance_fingerprint(second)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"provenance": {}},
        {
            "provenance": {
                "framework": {"version": "v0.1.8", "dirty": True},
                "test_data": _TEST_DATA,
            }
        },
        {
            "provenance": {
                "framework": {"version": "v0.1.8", "dirty": False},
                "test_data": [_TEST_DATA[0], _TEST_DATA[0]],
            }
        },
        {
            "provenance": {
                "framework": {"version": "v0.1.8", "dirty": False},
                "test_data": [{**_TEST_DATA[0], "commit": None}],
            }
        },
        {
            "provenance": {
                "framework": {"version": "v0.1.8", "dirty": False},
                "test_data": [{**_TEST_DATA[0], "archive_sha256": ""}],
            }
        },
    ],
)
def test_provenance_fingerprint_rejects_untrusted_identity(payload) -> None:
    assert provenance_fingerprint(payload) is None


@pytest.mark.parametrize("field", ["name", "repo", "commit", "archive_sha256"])
def test_provenance_fingerprint_rejects_whitespace_only_test_data_identity(field) -> None:
    payload = {
        "provenance": {
            "framework": {"version": "v0.1.8", "dirty": False},
            "test_data": [{**_TEST_DATA[0], field: " \t\n"}],
        }
    }
    assert provenance_fingerprint(payload) is None


def test_provenance_fingerprint_rejects_whitespace_only_framework_version() -> None:
    payload = {
        "provenance": {
            "framework": {"version": " \t\n", "dirty": False},
            "test_data": _TEST_DATA,
        }
    }
    assert provenance_fingerprint(payload) is None


def test_provenance_fingerprint_retains_valid_identity_values() -> None:
    payload = {
        "provenance": {
            "framework": {"version": " v0.1.8 ", "dirty": False},
            "test_data": [
                {
                    "name": " wycheproof ",
                    "repo": " C2SP/wycheproof ",
                    "commit": " abc123 ",
                    "archive_sha256": " deadbeef ",
                    "present": True,
                }
            ],
        }
    }
    assert provenance_fingerprint(payload) == (
        " v0.1.8 ",
        False,
        ((" wycheproof ", " C2SP/wycheproof ", " abc123 ", " deadbeef ", True),),
    )


def test_provenance_fingerprint_ignores_nonidentity_context() -> None:
    base = {
        "provenance": {
            "framework": {"version": "v0.1.8", "dirty": False},
            "test_data": _TEST_DATA,
        }
    }
    enriched = {
        "provenance": {
            **base["provenance"],
            "framework": {
                "version": "v0.1.8",
                "dirty": False,
                "source": "git-describe",
            },
            "provider": {"name": "softhsm2"},
            "crypto_backend": {"name": "openssl"},
            "environment": {"slots": 1},
        }
    }
    assert provenance_fingerprint(base) == provenance_fingerprint(enriched)


def test_differential_rejects_duplicate_provider_names(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    result = runner.invoke(app, ["differential", f"same={a}", f"same={b}"])
    assert result.exit_code == 2
    assert "duplicate provider name" in result.output


def test_differential_rejects_duplicate_report_paths(tmp_path) -> None:
    report = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    alias_dir = report.parent / "alias"
    alias_dir.mkdir()
    alias = alias_dir / ".." / report.name
    result = runner.invoke(app, ["differential", f"a={report}", f"b={alias}"])
    assert result.exit_code == 2
    assert "duplicate report path" in result.output


@pytest.mark.parametrize("minimum", [0, 1, 3])
def test_differential_rejects_invalid_minimum(tmp_path, minimum: int) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    result = runner.invoke(
        app,
        ["differential", f"a={a}", f"b={b}", "--min-providers", str(minimum)],
    )
    assert result.exit_code == 2
    if minimum < 2:
        assert "--min-providers must be at least 2" in result.output
    else:
        assert "--min-providers 3 exceeds 2 unique provider inputs" in result.output


def test_differential_rejects_blank_explicit_provider_name(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    result = runner.invoke(app, ["differential", f" ={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "provider name must not be empty" in result.output


def test_differential_rejects_empty_report_path(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", "b="])
    assert result.exit_code == 2
    assert "report path must not be empty" in result.output


def test_differential_rejects_directory_report_path(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    directory = tmp_path / "directory"
    directory.mkdir()
    result = runner.invoke(app, ["differential", f"a={a}", f"b={directory}"])
    assert result.exit_code == 2
    assert "report log is not a file" in result.output


def test_differential_translates_is_file_oserror(tmp_path, monkeypatch) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    blocked = _write_artifact(tmp_path, "blocked", {_KAT_A: "passed"})
    original_is_file = Path.is_file

    def deny_is_file(path: Path, *args, **kwargs):
        if path == blocked:
            raise OSError("denied")
        return original_is_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", deny_is_file)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={blocked}"])
    assert result.exit_code == 2
    assert "cannot resolve report path" in result.output


@pytest.mark.parametrize("method_name", ["expanduser", "resolve"])
def test_differential_translates_path_runtime_error(
    tmp_path, monkeypatch, method_name: str
) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    blocked = _write_artifact(tmp_path, "blocked", {_KAT_A: "passed"})
    original_method = getattr(Path, method_name)

    def fail_blocked(path: Path, *args, **kwargs):
        if path == blocked:
            raise RuntimeError("path loop")
        return original_method(path, *args, **kwargs)

    monkeypatch.setattr(Path, method_name, fail_blocked)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={blocked}"])
    assert result.exit_code == 2
    assert "cannot resolve report path" in result.output


def test_differential_rejects_empty_report_log(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "empty.jsonl"
    b.write_text(" \n", encoding="utf-8")
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "report log is empty" in result.output


def test_differential_rejects_malformed_report_log(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "malformed.jsonl"
    b.write_text("{not json}\n", encoding="utf-8")
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "malformed report log" in result.output


@pytest.mark.parametrize(
    ("records", "message"),
    [
        ([[]], "expected JSON object"),
        (
            [
                {
                    "$report_type": "TestReport",
                    "nodeid": _KAT_A,
                    "when": "call",
                    "outcome": "passed",
                },
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
            "first record is not SessionStart",
        ),
        (
            [
                {"$report_type": "SessionStart"},
                {"$report_type": "SessionStart"},
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
            "duplicate SessionStart",
        ),
        (
            [
                {"$report_type": "SessionStart"},
                {"$report_type": "SessionFinish", "exitstatus": 0},
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
            "invalid SessionFinish",
        ),
        (
            [
                {"$report_type": "SessionStart"},
                {"$report_type": "SessionFinish", "exitstatus": True},
            ],
            "invalid SessionFinish",
        ),
        (
            [
                {"$report_type": "SessionStart"},
                {"$report_type": "SessionFinish", "exitstatus": "1"},
            ],
            "invalid SessionFinish",
        ),
    ],
)
def test_differential_rejects_structurally_malformed_report_log(
    tmp_path, records: list[object], message: str
) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "structurally-invalid.jsonl"
    _write_records(b, records)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert message in result.output


def test_differential_rejects_invalid_utf8_report_log(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "invalid-utf8.jsonl"
    b.write_bytes(b"\xff\n")
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "cannot read report log" in result.output


def test_differential_rejects_report_without_test_outcomes(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "session-only.jsonl"
    _write_records(
        b,
        [
            {"$report_type": "SessionStart", "pytest_version": "test"},
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "report log contains no test outcomes" in result.output


@pytest.mark.parametrize(
    "record",
    [
        {"nodeid": _KAT_A, "when": "call", "outcome": "passed"},
        {"$report_type": "TestReport", "when": "call", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": _KAT_A, "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": _KAT_A, "when": "call"},
        {
            "$report_type": "TestReport",
            "nodeid": _KAT_A,
            "when": "unknown",
            "outcome": "passed",
        },
        {
            "$report_type": "TestReport",
            "nodeid": _KAT_A,
            "when": "call",
            "outcome": "unknown",
        },
        {
            "$report_type": "TestReport",
            "nodeid": _KAT_A,
            "when": [],
            "outcome": "passed",
        },
        {
            "$report_type": "TestReport",
            "nodeid": _KAT_A,
            "when": "call",
            "outcome": {},
        },
    ],
)
def test_differential_rejects_semantically_malformed_report_record(
    tmp_path, record: dict[str, object]
) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "invalid-record.jsonl"
    _write_records(
        b,
        [
            {"$report_type": "SessionStart", "pytest_version": "test"},
            record,
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "malformed report log" in result.output


def test_differential_rejects_incomplete_report_log(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = tmp_path / "incomplete.jsonl"
    _write_records(
        b,
        [
            {"$report_type": "SessionStart", "pytest_version": "test"},
            {
                "$report_type": "TestReport",
                "nodeid": _KAT_A,
                "when": "call",
                "outcome": "passed",
            },
        ],
    )
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "incomplete report log" in result.output


def test_differential_rejects_unreadable_report_log(tmp_path, monkeypatch) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    blocked = _write_artifact(tmp_path, "blocked", {_KAT_A: "passed"})
    original_open = Path.open

    def deny_blocked(path: Path, *args, **kwargs):
        if path == blocked:
            raise OSError("denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_blocked)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={blocked}"])
    assert result.exit_code == 2
    assert "cannot read report log" in result.output


def test_differential_rejects_disjoint_evidence(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_B: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "no comparable deterministic KAT node-ids" in result.output


def test_differential_rejects_provider_outside_comparison_graph(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    c = _write_artifact(tmp_path, "c", {_KAT_B: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", f"c={c}"])
    assert result.exit_code == 2
    assert "provider evidence is disconnected" in result.output
    assert "c" in result.output


def test_differential_rejects_disconnected_comparison_islands(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    c = _write_artifact(tmp_path, "c", {_KAT_B: "passed"})
    d = _write_artifact(tmp_path, "d", {_KAT_B: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", f"c={c}", f"d={d}"])
    assert result.exit_code == 2
    assert "provider evidence is disconnected" in result.output


def test_differential_accepts_connected_comparison_chain(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed", _KAT_B: "passed"})
    c = _write_artifact(tmp_path, "c", {_KAT_B: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", f"c={c}"])
    assert result.exit_code == 0
    assert "2 comparable deterministic KAT node-ids" in result.output


def test_differential_reports_comparable_node_count(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 0
    assert "1 comparable deterministic KAT node-ids" in result.output


def test_differential_accepts_nonzero_integer_exitstatus_and_summary_after_finish(
    tmp_path,
) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    records = [
        {"$report_type": "SessionStart", "pytest_version": "test"},
        {
            "$report_type": "TestReport",
            "when": "call",
            "outcome": "passed",
            "nodeid": _KAT_A,
        },
        {"$report_type": "SessionFinish", "exitstatus": 1},
        {"$report_type": "TeardownFinalize", "outcome": "ok"},
    ]
    _write_records(b, records)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 0
    assert "1 comparable deterministic KAT node-ids" in result.output


def test_differential_rejects_test_report_after_session_finish(tmp_path) -> None:
    a = _write_artifact(tmp_path, "a", {_KAT_A: "passed"})
    b = _write_artifact(tmp_path, "b", {_KAT_A: "passed"})
    records = [
        {"$report_type": "SessionStart", "pytest_version": "test"},
        {"$report_type": "SessionFinish", "exitstatus": 0},
        {
            "$report_type": "TestReport",
            "when": "call",
            "outcome": "passed",
            "nodeid": _KAT_A,
        },
    ]
    _write_records(b, records)
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 2
    assert "malformed report log" in result.output


def test_differential_cli_flags_kat_odd_one_out(tmp_path) -> None:
    kat = _KAT_A
    a = _write_artifact(tmp_path, "a", {kat: "passed"})
    b = _write_artifact(tmp_path, "b", {kat: "passed"})
    c = _write_artifact(tmp_path, "c", {kat: "failed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", f"c={c}"])
    assert result.exit_code == 1  # a disagreement is a finding
    assert "DISAGREE" in result.output
    assert "odd-one-out=c" in result.output


def test_differential_cli_clean_when_unanimous(tmp_path) -> None:
    kat = _KAT_A
    a = _write_artifact(tmp_path, "a", {kat: "passed"})
    b = _write_artifact(tmp_path, "b", {kat: "passed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}"])
    assert result.exit_code == 0


def test_load_provider_outcomes_uses_call_phase_and_setup_skips() -> None:
    records = [
        {"$report_type": "TestReport", "when": "setup", "outcome": "passed", "nodeid": "t::a"},
        {"$report_type": "TestReport", "when": "call", "outcome": "failed", "nodeid": "t::a"},
        {"$report_type": "TestReport", "when": "setup", "outcome": "skipped", "nodeid": "t::b"},
        {
            "$report_type": "TestReport",
            "when": "call",
            "outcome": "skipped",
            "wasxfail": "reason",
            "nodeid": "t::c",
        },
        {"$report_type": "TestReport", "when": "setup", "outcome": "failed", "nodeid": "t::d"},
        {"when": "call", "outcome": "passed", "nodeid": "t::fabricated"},
        {"$report_type": "TestReport", "when": "call", "nodeid": "t::missing-outcome"},
    ]
    got = load_provider_outcomes(records)
    assert got == {"t::a": "failed", "t::b": "skipped", "t::c": "xfailed", "t::d": "failed"}
    assert "t::fabricated" not in got
    assert "t::missing-outcome" not in got


@pytest.mark.parametrize(
    "nodeid",
    [
        "src/pkcs11_check/testcases/wycheproof/test_rsa.py::test_kat[v1]",
        "src/pkcs11_check/testcases/acvp/aes/test_cbc.py::test_kat[v1]",
        "src/pkcs11_check/testcases/test_cctv_ecdsa.py::test_kat[v1]",
        r"src\pkcs11_check\testcases\wycheproof\test_rsa.py::test_kat[v1]",
    ],
)
def test_is_kat_nodeid_accepts_only_explicit_kat_paths(nodeid: str) -> None:
    assert is_kat_nodeid(nodeid)


@pytest.mark.parametrize(
    "nodeid",
    [
        "src/pkcs11_check/testcases/x509/test_store.py::test_round_trip",
        "src/pkcs11_check/testcases/test_x509.py::test_identity",
        "src/pkcs11_check/testcases/not_wycheproof/test_fake.py::test_case",
        "src/pkcs11_check/testcases/security/test_cctv_fake.py::test_case",
        "vendor/wycheproof/test_fake.py::test_case",
    ],
)
def test_is_kat_nodeid_rejects_non_kat_paths(nodeid: str) -> None:
    assert not is_kat_nodeid(nodeid)


def test_cross_platform_nodeids_compare_as_one_test() -> None:
    windows = load_provider_outcomes(
        [
            {
                "$report_type": "TestReport",
                "when": "call",
                "outcome": "passed",
                "nodeid": r"src\pkcs11_check\testcases\wycheproof\test_rsa.py::test_kat[v1]",
            }
        ]
    )
    posix = load_provider_outcomes(
        [
            {
                "$report_type": "TestReport",
                "when": "call",
                "outcome": "failed",
                "nodeid": "src/pkcs11_check/testcases/wycheproof/test_rsa.py::test_kat[v1]",
            }
        ]
    )

    disagreements = find_disagreements({"windows": windows, "posix": posix})

    assert len(disagreements) == 1
    assert disagreements[0].nodeid == (
        "src/pkcs11_check/testcases/wycheproof/test_rsa.py::test_kat[v1]"
    )


def test_odd_one_out_on_deterministic_vector() -> None:
    # 3 providers run the same KAT node-id; two pass, one fails -> the failer is the suspect.
    per_provider = {
        "prov_a": {"t.py::kat[v1]": "passed"},
        "prov_b": {"t.py::kat[v1]": "passed"},
        "prov_c": {"t.py::kat[v1]": "failed"},
    }
    disagreements = find_disagreements(per_provider)
    assert len(disagreements) == 1
    d = disagreements[0]
    assert d.nodeid == "t.py::kat[v1]"
    assert d.majority == "pass"
    assert d.minority_providers == ["prov_c"]


def test_unanimous_pass_is_not_flagged() -> None:
    per_provider = {
        "a": {"t.py::v": "passed"},
        "b": {"t.py::v": "passed"},
        "c": {"t.py::v": "passed"},
    }
    assert find_disagreements(per_provider) == []


def test_skips_excluded_as_capability_gaps() -> None:
    # A provider that SKIPPED (capability gap) is not a disagreement with those that ran.
    per_provider = {
        "a": {"t.py::v": "passed"},
        "b": {"t.py::v": "passed"},
        "c": {"t.py::v": "skipped"},
    }
    assert find_disagreements(per_provider) == []


def test_below_min_providers_not_flagged() -> None:
    # Only one provider actually attempted -> nothing to compare.
    per_provider = {
        "a": {"t.py::v": "passed"},
        "b": {"t.py::v": "skipped"},
    }
    assert find_disagreements(per_provider, min_providers=2) == []


def test_two_way_disagreement_flagged_without_majority() -> None:
    # With exactly 2 attempts that disagree, both are named (no majority to single one out).
    per_provider = {"a": {"t.py::v": "passed"}, "b": {"t.py::v": "failed"}}
    d = find_disagreements(per_provider, min_providers=2)
    assert len(d) == 1
    assert d[0].majority == "tie"
    assert sorted(d[0].minority_providers) == ["a", "b"]


def test_nodeid_filter_restricts_to_kat_suites() -> None:
    per_provider = {
        "a": {"wp.py::kat[v]": "passed", "other.py::x": "passed"},
        "b": {"wp.py::kat[v]": "failed", "other.py::x": "failed"},
    }
    d = find_disagreements(per_provider, nodeid_filter=frozenset({"wp.py::kat[v]"}))
    assert [x.nodeid for x in d] == ["wp.py::kat[v]"]
