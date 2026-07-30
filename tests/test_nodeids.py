"""Unit tests for pytest node-id normalization (core/nodeids.py)."""

from __future__ import annotations

from pkcs11_check.core.nodeids import normalize_nodeid


def test_posix_nodeid_unchanged() -> None:
    nid = "src/pkcs11_check/testcases/test_x.py::TestC::test_m[rsa-2048]"
    assert normalize_nodeid(nid) == nid


def test_windows_separators_converted() -> None:
    win = r"src\pkcs11_check\testcases\test_x.py::TestC::test_m[rsa-2048]"
    assert normalize_nodeid(win) == "src/pkcs11_check/testcases/test_x.py::TestC::test_m[rsa-2048]"


def test_only_path_portion_touched() -> None:
    # A backslash inside a parametrization id (after ::) must NOT be rewritten.
    nid = r"a\b.py::test_p[weird\id]"
    assert normalize_nodeid(nid) == r"a/b.py::test_p[weird\id]"


def test_no_separator_at_all() -> None:
    assert normalize_nodeid("test_x.py") == "test_x.py"
    assert normalize_nodeid("") == ""
