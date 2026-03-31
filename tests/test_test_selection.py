"""Tests for production disabled-baseline loading and planning."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.core.test_selection import (
    DisabledBaseline,
    load_disabled_baseline,
    parse_disabled_nodeids,
)


def test_parse_disabled_nodeids_ignores_comments_blanks_and_duplicates() -> None:
    text = """
    # comment
    src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip

    src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip
    src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb[AES-enc-tc1021]
    """.strip()

    nodeids = parse_disabled_nodeids(text)

    assert nodeids == [
        "src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip",
        "src/pkcs11_check/testcases/acvp/aes/test_cfb.py::"
        "test_acvp_aes_cfb[AES-enc-tc1021]",
    ]


def test_load_disabled_baseline_returns_none_for_none_path() -> None:
    assert load_disabled_baseline(None) is None


def test_load_disabled_baseline_raises_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="disabled"):
        load_disabled_baseline(tmp_path / "missing.txt")


def test_load_disabled_baseline_fingerprint_changes_with_content(tmp_path: Path) -> None:
    path = tmp_path / "disabled.txt"
    path.write_text("a.py::test_one\n")

    first = load_disabled_baseline(path)
    assert isinstance(first, DisabledBaseline)

    path.write_text("a.py::test_one\nb.py::test_two\n")
    second = load_disabled_baseline(path)
    assert isinstance(second, DisabledBaseline)

    assert first.fingerprint != second.fingerprint
