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
