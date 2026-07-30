"""Disabled-tests matching must be separator-invariant so a Windows-collected node-id
(backslash path) still matches a forward-slash disabled-tests file entry."""

from __future__ import annotations

from pkcs11_check.core.test_selection import parse_disabled_nodeids


def test_parse_normalizes_backslash_paths() -> None:
    text = "src\\pkcs11_check\\testcases\\test_x.py::test_m\n"
    assert parse_disabled_nodeids(text) == ["src/pkcs11_check/testcases/test_x.py::test_m"]


def test_parse_keeps_posix_and_dedups() -> None:
    text = (
        "# comment\n"
        "src/pkcs11_check/testcases/test_x.py::test_a\n"
        "src/pkcs11_check/testcases/test_x.py::test_a\n"  # dup
    )
    assert parse_disabled_nodeids(text) == ["src/pkcs11_check/testcases/test_x.py::test_a"]
