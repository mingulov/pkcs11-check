"""Tests for the N-way differential cross-provider oracle (core/differential.py)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from pkcs11_check.cli.app import app
from pkcs11_check.core.differential import (
    find_disagreements,
    is_kat_nodeid,
    load_provider_outcomes,
)

runner = CliRunner()


def _write_report(path, nodeid_outcomes: dict[str, str]) -> None:
    lines = []
    for nodeid, outcome in nodeid_outcomes.items():
        lines.append(
            json.dumps(
                {"$report_type": "TestReport", "when": "call", "outcome": outcome, "nodeid": nodeid}
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_differential_cli_flags_kat_odd_one_out(tmp_path) -> None:
    kat = "src/pkcs11_check/testcases/wycheproof/test_rsa.py::test_kat[v1]"
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    c = tmp_path / "c.jsonl"
    _write_report(a, {kat: "passed"})
    _write_report(b, {kat: "passed"})
    _write_report(c, {kat: "failed"})
    result = runner.invoke(app, ["differential", f"a={a}", f"b={b}", f"c={c}"])
    assert result.exit_code == 1  # a disagreement is a finding
    assert "DISAGREE" in result.output
    assert "odd-one-out=c" in result.output


def test_differential_cli_clean_when_unanimous(tmp_path) -> None:
    kat = "src/pkcs11_check/testcases/acvp/test_aes.py::test_kat[v]"
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _write_report(a, {kat: "passed"})
    _write_report(b, {kat: "passed"})
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
    ]
    got = load_provider_outcomes(records)
    assert got == {"t::a": "failed", "t::b": "skipped", "t::c": "xfailed"}


def test_is_kat_nodeid() -> None:
    assert is_kat_nodeid("src/pkcs11_check/testcases/wycheproof/test_x.py::t[v]")
    assert is_kat_nodeid("src/.../acvp/test_y.py::t")
    assert not is_kat_nodeid("src/pkcs11_check/testcases/test_encrypt.py::t")


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
