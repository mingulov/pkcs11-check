"""Tests for the list-tests node-id enumeration command."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.cli import list_tests_cmd


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
