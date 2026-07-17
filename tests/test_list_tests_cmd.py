"""Tests for the list-tests node-id enumeration command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pkcs11_check.cli import list_tests_cmd
from pkcs11_check.cli.app import app

runner = CliRunner()


def _args(**kw):
    base = dict(
        match=None,
        marker=None,
        category=None,
        skip_slow=False,
        only_slow=False,
        module=None,
        interface="auto",
        slot=0,
    )
    base.update(kw)
    return list_tests_cmd._build_list_selection_args(**base)


def test_match_maps_to_dash_k() -> None:
    assert _args(match="tc249") == ["-k", "tc249"]


def test_marker_maps_to_dash_m() -> None:
    assert _args(marker="not slow") == ["-m", "not slow"]


def test_category_maps_to_dash_k_when_no_match() -> None:
    assert _args(category="encrypt") == ["-k", "encrypt"]


def test_match_beats_category() -> None:
    assert _args(match="tc249", category="encrypt") == ["-k", "tc249"]


def test_skip_slow_composes_via_combine_marker() -> None:
    assert _args(marker="acvp", skip_slow=True) == ["-m", "(acvp) and (not slow)"]


def test_module_adds_p11_trio() -> None:
    got = _args(module=Path("/m.so"), match="x")
    assert got == ["--p11-module", "/m.so", "--p11-interface", "auto", "--p11-slot", "0", "-k", "x"]


def test_no_module_has_no_p11_module() -> None:
    assert "--p11-module" not in _args(match="x")


def test_enumerate_sorts_and_dedups(monkeypatch) -> None:
    monkeypatch.setattr(
        list_tests_cmd,
        "collect_pytest_nodeids",
        lambda targets, args, **kw: ["b.py::t2", "a.py::t1", "b.py::t2"],
    )
    got = list_tests_cmd.enumerate_nodeids(
        [],
        match=None,
        marker=None,
        category=None,
        skip_slow=False,
        only_slow=False,
        module=None,
        interface="auto",
        slot=0,
    )
    assert got == ["a.py::t1", "b.py::t2"]


def test_enumerate_defaults_targets_to_testcases_dir(monkeypatch) -> None:
    seen = {}

    def _fake(targets, args, **kw):
        seen["targets"] = targets
        return []

    monkeypatch.setattr(list_tests_cmd, "collect_pytest_nodeids", _fake)
    list_tests_cmd.enumerate_nodeids(
        [],
        match="x",
        marker=None,
        category=None,
        skip_slow=False,
        only_slow=False,
        module=None,
        interface="auto",
        slot=0,
    )
    assert seen["targets"] == [list_tests_cmd._TESTCASES_DIR]


def test_emit_nodeids_to_stdout_only(capsys) -> None:
    list_tests_cmd._emit_nodeids(["a.py::t1", "b.py::t2"])
    cap = capsys.readouterr()
    assert cap.out == "a.py::t1\nb.py::t2\n"
    assert cap.err == ""


def test_command_prints_nodeids_and_exits_zero(monkeypatch) -> None:
    monkeypatch.setattr(
        list_tests_cmd, "enumerate_nodeids", lambda *a, **k: ["a.py::t1", "b.py::t2"]
    )
    result = runner.invoke(app, ["list-tests", "--match", "t"])
    assert result.exit_code == 0
    assert "a.py::t1" in result.output
    assert "b.py::t2" in result.output


def test_command_zero_matches_exits_zero(monkeypatch) -> None:
    monkeypatch.setattr(list_tests_cmd, "enumerate_nodeids", lambda *a, **k: [])
    result = runner.invoke(app, ["list-tests", "--match", "nope"])
    assert result.exit_code == 0
    assert "0 node-ids matched" in result.output


def test_command_collection_error_exits_one(monkeypatch) -> None:
    def _boom(*a, **k):
        raise ValueError("pytest collection failed: boom")

    monkeypatch.setattr(list_tests_cmd, "enumerate_nodeids", _boom)
    result = runner.invoke(app, ["list-tests", "--match", "t"])
    assert result.exit_code == 1
    assert "boom" in result.output


def test_command_registered_help() -> None:
    result = runner.invoke(app, ["list-tests", "--help"])
    assert result.exit_code == 0
    assert "node-id" in result.output.lower() or "enumerate" in result.output.lower()
